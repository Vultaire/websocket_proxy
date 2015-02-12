import socket
import threading
import hashlib
import base64
import struct
import Queue
import httplib
import logging
import sys
logging.basicConfig(level=logging.INFO, stream=sys.stderr)

import os
import ConfigParser


"""
Regarding bit orders...

Byte: C7
Binary: 1100 0111
bit 0 appears to be highest order bit, bit 7 is lowest order
Get first 4: >> 4
Get last 4: & 0xF

Big endian *is* network byte order (MSB @ 0)
Intel arch is little endian (LSB @ 0)

According to Wikipedia, bit endianness is typically little endian, but
meaningful conversion is taken care of for you.  Or something like that...

"""

BLOCK_SIZE = 4096

open_sockets = {}

class CriticalError(Exception):
    pass


# Note: ctypes is *supposed* to have a BigEndianUnion class, but it
# apparently is not implemented.  Here is an implementation, based
# upon a patch submitted here: http://bugs.python.org/issue19023
# ######################################################################
# Begin hacks
import ctypes
import ctypes._endian
class _swapped_meta(object):
    def __setattr__(self, attrname, value):
        if attrname == "_fields_":
            fields = []
            for desc in value:
                name = desc[0]
                typ = desc[1]
                rest = desc[2:]
                fields.append((name, ctypes._endian._other_endian(typ)) + rest)
            value = fields
        super(_swapped_meta, self).__setattr__(attrname, value)
class _swapped_union_meta(_swapped_meta, type(ctypes.Union)): pass

import sys
if sys.byteorder == "little":
    LittleEndianUnion = ctypes.Union
    class BigEndianUnion(ctypes.Union):
        """Union with big endian byte order"""
        __metaclass__ = _swapped_union_meta
        _swappedbytes_ = None
elif sys.byteorder == "big":
    BigEndianUnion = ctypes.Union
    class LittleEndianUnion(ctypes.Union):
        """Union with little endian byte order"""
        __metaclass__ = _swapped_union_meta
        _swappedbytes_ = None
else:
    raise RuntimeError("Invalid byteorder")

ctypes.LittleEndianUnion = LittleEndianUnion
ctypes.BigEndianUnion = BigEndianUnion
# End hacks
# ######################################################################

# Note to self: RFC indicates that bit 0 should be the most significant.
# Thus, byte >> 7 is bit 0, byte & 1 is bit 7.
# ...Regardless, will rely on BigEndianUnion/BigEndianStructure to
# make this easier to grok for others (or myself down the road).

# Technique borrowed from: https://wiki.python.org/moin/BitManipulation

import ctypes

class HeaderBits(ctypes.BigEndianStructure):
    _fields_ = [
        ('fin', ctypes.c_uint8, 1),     # bit 0
        ('res1', ctypes.c_uint8, 1),    # bit 1
        ('res2', ctypes.c_uint8, 1),    # bit 2
        ('res3', ctypes.c_uint8, 1),    # bit 3
        ('opcode', ctypes.c_uint8, 4),  # bit 4-7
        ('mask', ctypes.c_uint8, 1),            # bit 8
        ('payload_length', ctypes.c_uint8, 7),  # bit 9-15
    ]

class Header(ctypes.BigEndianUnion):
    _fields_ = [
        ('b', HeaderBits),
        ('raw', ctypes.c_uint16),
    ]
    _anonymous_ = ['b']


def main():
    if not os.path.exists('config.ini'):
        with open('config.ini', 'w') as outfile:
            parser = ConfigParser.RawConfigParser()
            parser.add_section('passthru_server')
            parser.set('passthru_server', 'host', 'localhost')
            parser.set('passthru_server', 'port', '50008')
            parser.add_section('remote_server')
            parser.set('remote_server', 'host', 'aardwolf.org')
            parser.set('remote_server', 'port', '4000')
            parser.write(outfile)

    parser = ConfigParser.RawConfigParser()
    parser.read('config.ini')
    passthru_host = parser.get('passthru_server', 'host')
    passthru_port = int(parser.get('passthru_server', 'port'))
    remote_host = parser.get('remote_server', 'host')
    remote_port = int(parser.get('remote_server', 'port'))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((passthru_host, passthru_port))
    s.listen(400)
    try:
        while True:
            conn, addr = s.accept()
            ws = WebSocketProxyConnection(conn, addr, remote_host, remote_port)
            t = threading.Thread(target=ws.main_thread)
            t.start()
            open_sockets[addr] = {'conn': conn, 'thread': t}
    except KeyboardError:
        logging.info("Ctrl-C captured...")


class WebSocketProxyConnection(object):

    """Proxy a websocket connection to a backend native TCP socket."""

    MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, conn, addr, remote_host, remote_port):
        self.client_conn = BufferedWebSocket(conn)
        self.client_addr = addr
        self.backend_conn = None
        self.remote_host = remote_host
        self.remote_port = remote_port

    def main_thread(self):
        # Two stages:
        # - The handshake
        # - The connection (decode frames from client and transmit to server,
        #   receive from server, encode frames and send back to client
        try:
            logging.info("Client parent thread started. ({})".format(self.client_addr))
            valid = self.handshake()
            if valid:
                self.communicate()
        finally:
            self.client_conn.close()
            logging.info("Client parent thread terminated, removing reference. ({})".format(self.client_addr))
            del open_sockets[self.client_addr]

    def handshake(self):
        logging.info("Performing HTTP handshake...")
        data = self.client_conn.read_until("\r\n\r\n")
        lines = data.split('\r\n')

        def http_response(code, reason):
            resp = 'HTTP/1.1 {} {}'.format(code, httplib.responses[code])
            full_resp = resp + '\r\n\r\n' + reason
            self.client_conn.sendall(full_resp)

        # Validate HTTP websocket request
        method, path, protocol_id = lines[0].split(' ')
        if method != 'GET':
            http_response(httplib.BAD_REQUEST, 'Unexpected method')
            return False
        protocol, version = protocol_id.split('/')
        if protocol != 'HTTP':
            http_response(httplib.BAD_REQUEST, 'Unexpected protocol')
            return False
        if float(version) < 1.1:
            http_response(httplib.BAD_REQUEST, 'Unexpected protocol version')
            return False

        if path != '/':
            http_response(httplib.BAD_REQUEST, 'Unexpected path')
            return False

        headers = {}
        for line in lines[1:-2]:  # Skip first line and last 2 empty lines
            key, value = line.split(':', 1)
            value = value.lstrip()
            headers[key.lower()] = value

        required_headers = ['connection', 'upgrade',
                            'sec-websocket-version', 'sec-websocket-key']
        if any(header not in headers for header in required_headers):
            http_response(httplib.BAD_REQUEST, 'Request is missing required headers')
            return False

        assert headers['connection'].lower() == 'upgrade'
        assert headers['upgrade'].lower() == 'websocket'
        assert headers['sec-websocket-version'].lower() == '13'

        websocket_key = headers['sec-websocket-key']
        logging.info("Received valid websocket request")

        # For our purposes explicitly: we want telnet protocol
        assert headers['sec-websocket-protocol'] == 'telnet'
        logging.info("Telnet protocol confirmed")

        # Validate HTTP websocket request
        websocket_accept_val = "asdfb"
        response = "\r\n".join([
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            'Sec-WebSocket-Protocol: telnet',
            "Connection: Upgrade",
            self.get_websocket_accept_header(websocket_key),
        ]) + "\r\n\r\n"
        logging.info("Sending response...")
        self.client_conn.sendall(response)
        logging.info("Handshake complete")
        return True

    def get_websocket_accept_header(self, websocket_key):
        val = websocket_key + self.MAGIC_KEY
        sha1_b64 = base64.b64encode(hashlib.sha1(val).digest())
        return "Sec-WebSocket-Accept: {}".format(sha1_b64)

    def communicate(self):
        """Establishes a socket connection to the real destination
        server, and translates to/from websockets."""

        logging.info("Connecting to remove server... ",)
        self.backend_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        resp_thread = None
        write_thread = None
        try:
            self.backend_conn.connect((self.remote_host, self.remote_port))
            logging.info("Connected.")

            # Launch socket->WS message monitoring/sending thread
            resp_thread = self.client_conn.start_websocket_response_thread()

            # Launch WS->socket thread
            write_thread = threading.Thread(
                target=self.websocket_to_socket_thread)
            write_thread.start()

            # socket-> thread is called inline below, to avoid
            # spawning another thread.
            self.socket_to_websocket_thread()
        finally:
            self.backend_conn.close()
            self.client_conn.close_response_queue()
            if write_thread:
                write_thread.join()
            if resp_thread:
                resp_thread.join()

    def websocket_to_socket_thread(self):
        try:
            while True:
                try:
                    data = self.client_conn.get_websocket_message()
                except EOFError as e:
                    # Socket likely terminated, close.
                    logging.error('EOFError encountered: {}'.format(repr(e)))
                    logging.error('Terminating...')
                    break
                self.backend_conn.sendall(data)
                logging.info("Wrote {} bytes of data to remote host".format(len(data)))
        finally:
            logging.info("Client write thread terminated.")

    def socket_to_websocket_thread(self):
        try:
            while True:
                data = self.backend_conn.recv(BLOCK_SIZE)
                logging.info("recv of {} bytes from remote server".format(len(data)))
                if len(data) == 0:
                    # Socket likely terminated, close.
                    break
                self.client_conn.send_websocket_message(data)
                logging.info("Passed {} bytes of data back to my client".format(len(data)))
        except:
            import traceback
            traceback.print_exc()
        finally:
            logging.info('Client read "thread" terminated.')


class BufferedSocket(object):

    """Helper class for reading from and writing to a socket efficiently."""

    def __init__(self, socket_):
        self.socket = socket_
        self.buffer = ""

    def read(self, count):
        """Buffered socket read."""
        while True:
            if count <= len(self.buffer):
                result = self.buffer[:count]
                self.buffer = self.buffer[count:]
                return result
            else:
                self._read_into_buffer()

    def _read_into_buffer(self):
        """Read a block into the socket buffer."""
        data = self.socket.recv(BLOCK_SIZE)
        #if len(data) == 0:
        #    raise EOFError()   # ...how is EOF detected?  Need to test.
        self.buffer += data

    def read_until(self, pattern):
        """A buffered raw socket read."""
        while True:
            try:
                pattern_index = self.buffer.index(pattern)
            except ValueError:
                self._read_into_buffer()
                continue
            else:
                split_index = pattern_index + len(pattern)
                result = self.buffer[:split_index]
                self.buffer = self.buffer[split_index:]
                return result

    def sendall(self, *args):
        return self.socket.sendall(*args)

    def close(self):
        self.socket.close()


CloseQueue = object()


class BufferedWebSocket(BufferedSocket):

    """Helper class for reading from and writing to a web socket."""

    def __init__(self, socket_):
        super(BufferedWebSocket, self).__init__(socket_)
        self.pinged = False
        self.messages = Queue.Queue()
        # A thread will monitor the message queue and handle actual
        # sending of messages.  This allows for pong responses to be
        # efficiently handled.

    def start_websocket_response_thread(self):
        t = threading.Thread(target=self._websocket_response_thread)
        t.start()
        return t

    def _websocket_response_thread(self):
        while True:
            if self.pinged:
                logging.info("Was pinged; sending pong...")
                self.send_pong()
                logging.info("Pong sent.")
            message = self.messages.get()
            if message is CloseQueue:
                logging.info("Response queue close signal detected; closing response thread.")
                break

            logging.info("Sending message, length of websocket frame: {}".format(len(message)))
            self.socket.sendall(message)

    def send_websocket_message(self, body):
        header = Header()
        header.fin = 1
        header.opcode = 0x2
        length = len(body)
        if length <= 125:
            header.payload_length = length
            extra = ""
        elif 126 <= length <= 0xFFFF:
            header.payload_length = 126
            extra = struct.pack('>H', length)
        else:
            header.payload_length = 127
            extra = struct.pack('>Q', length)

        header = struct.pack('>H', header.raw) + extra
        message = header + body

        self.messages.put(message)

    def send_pong(self):
        header = Header()
        header.fin = 1
        header.opcode = 0xA  # Means "PONG"
        header.payload_length = 0
        message = struct.pack('>H', header.raw)
        self.socket.sendall(message)
        self.pinged = False

    def close_response_queue(self):
        self.messages.put(CloseQueue)

    def get_websocket_message(self):
        message = []
        type_ = None
        while True:
            logging.info("Getting header...")
            header = Header()
            try:
                header_bytes = self.read(2)
                logging.info("RAW BYTES: {}".format(repr(header_bytes)))
                header.raw = struct.unpack('>H', header_bytes)[0]
            except:
                raise
            if (header.res1 or header.res2 or header.res3):
                # Reserved bits... we're not using extensions, so this is BAD!
                raise CriticalError("Reserved bits in use when they shouldn't be")
            # Probably this will be received as text...  Is this really a problem?
            # ...will need to use MCCP later, which will be binary.
            logging.info("opcode: {}".format(header.opcode))
            if header.opcode == 0x8:
                # Close control frame
                raise EOFError('Websocket close opcode detected')
            if header.opcode == 0x9:
                # Ping control frame
                self.pinged = True
                continue
            if type_ is None:
                if header.opcode == 0x1:
                    type_ = "text"
                elif header.opcode == 0x2:
                    type_ = "binary"
                else:
                    raise CriticalError('Unexpected opcode', header.opcode)
            else:
                if header.opcode != 0x0:
                    raise CriticalError("Expected a continuation frame, did not get one")
            if not header.mask:
                raise CriticalError('Client data must always be masked')
            payload_len = header.payload_length
            if payload_len == 126:
                payload_len = struct.unpack('>H', self.read(2))[0]
            if payload_len == 127:
                payload_len = struct.unpack('>Q', self.read(8))[0]
            mask = map(ord, self.read(4))
            enc_payload = map(ord, self.read(payload_len))
            payload = []
            for i in xrange(len(enc_payload)):
                byte_mask = mask[i%4]
                dec_byte = enc_payload[i] ^ byte_mask
                payload.append(chr(dec_byte))
            message.append("".join(payload))
            if header.fin:
                break
        return "".join(message)


if __name__ == "__main__":
    try:
        main()
    finally:
        logging.info("Closing all remaining sockets...")
        for socket_info in open_sockets.itervalues():
            socket_info['conn'].close()
        logging.info("Joining all remaining threads...")
        for socket_info in open_sockets.itervalues():
            socket_info['thread'].join()
        logging.info("Done.")
