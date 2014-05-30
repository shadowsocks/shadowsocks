#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import time
import threading
import socket
import logging
import struct
import encrypt
import eventloop
import errno


class TCPRelayHandler(object):
    def __init__(self, fd_to_handlers, loop, conn, config, is_local):
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_conn = conn
        self._remote_conn = None
        self._remains_data_for_local = None
        self._remains_data_for_remote = None
        self._config = config
        self._is_local = is_local
        self._stage = 0
        fd_to_handlers[conn.fileno()] = self
        conn.setblocking(False)
        loop.add(conn, eventloop.POLL_IN)

    def on_local_read(self):
        pass

    def on_remote_read(self):
        pass

    def on_local_write(self):
        pass

    def on_remote_write(self):
        pass

    def on_local_error(self):
        self.destroy()

    def on_remote_error(self):
        self.destroy()

    def handle_event(self, sock, event):
        # order is important
        if sock == self._local_conn:
            if event & eventloop.POLL_IN:
                self.on_local_read()
            if event & eventloop.POLL_OUT:
                self.on_local_write()
            if event & eventloop.POLL_ERR:
                self.on_local_error()
        elif sock == self._remote_conn:
            if event & eventloop.POLL_IN:
                self.on_remote_read()
            if event & eventloop.POLL_OUT:
                self.on_remote_write()
            if event & eventloop.POLL_ERR:
                self.on_remote_error()
        else:
            logging.warn('unknown socket')

    def destroy(self):
        if self._local_conn:
            self._local_conn.close()
            eventloop.remove(self._local_conn)
            # TODO maybe better to delete the key
            self._fd_to_handlers[self._local_conn.fileno()] = None
        if self._remote_conn:
            self._remote_conn.close()
            eventloop.remove(self._remote_conn)
            self._fd_to_handlers[self._local_conn.fileno()] = None


class TCPRelay(object):
    def __init__(self, config, is_local):
        self._config = config
        self._is_local = is_local
        self._closed = False
        self._fd_to_handlers = {}

        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
        self._server_socket = server_socket

    def _run(self):
        server_socket = self._server_socket
        self._eventloop = eventloop.EventLoop()
        self._eventloop.add(server_socket, eventloop.POLL_IN)
        last_time = time.time()
        while not self._closed:
            try:
                events = self._eventloop.poll(1)
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == errno.EPIPE:
                    # Happens when the client closes the connection
                    continue
                else:
                    logging.error(e)
                    continue
            for sock, event in events:
                if sock == self._server_socket:
                    try:
                        conn = self._server_socket.accept()
                        TCPRelayHandler(loop, conn, remote_addr, remote_port, 
                                        password, method, timeout, is_local)
                    except (OSError, IOError) as e:
                        error_no = eventloop.errno_from_exception(e)
                        if error_no in [errno.EAGAIN, errno.EINPROGRESS]:
                            continue
                else:
                    handler = self._fd_to_handlers.get(sock.fileno(), None)
                    if handler:
                        handler.handle_event(sock, event)
                    else:
                        logging.warn('can not find handler for fd %d',
                                     sock.fileno())
            now = time.time()
            if now - last_time > 5:
                # TODO sweep timeouts
                last_time = now



