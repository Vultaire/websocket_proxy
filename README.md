# websocket_proxy
A simple websockets-to-sockets proxy server written in Python.

License: MIT

This proxy was written to allow me to write a WebSockets-based MUD
client for Aardwolf.  However, it is fairly generic and should be
usable as a front-end for other sockets-based services.

Current defaults are for the proxy to bind to localhost:50008 and
proxy to aardwolf.org:4000.  To change these settings, simply run the
server once, terminate it, and edit the generated config.ini.
