#!/usr/bin/python

import socket


if __name__ == '__main__':
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 8001))
    s.listen(1024)
    c = None
    while True:
        c = s.accept()
