#!/usr/bin/env python
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
import os
import socket
import struct
import re
import logging
from shadowsocks import common
from shadowsocks import lru_cache
from shadowsocks import eventloop
import server_pool
import Config

class ServerMgr(object):

    def __init__(self):
        self._loop = None
        self._request_id = 1
        self._hosts = {}
        self._hostname_status = {}
        self._hostname_to_cb = {}
        self._cb_to_hostname = {}
        self._last_time = time.time()
        self._sock = None
        self._servers = None

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        # TODO when dns server is IPv6
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        self._sock.bind((Config.MANAGE_BIND_IP, Config.MANAGE_PORT))
        self._sock.setblocking(False)
        loop.add(self._sock, eventloop.POLL_IN, self)

    def _handle_data(self, sock):
        data, addr = sock.recvfrom(128)
        #manage pwd:port:passwd:action
        args = data.split(':')
        if len(args) < 4:
            return
        if args[0] == Config.MANAGE_PASS:
            if args[3] == '0':
                server_pool.ServerPool.get_instance().cb_del_server(args[1])
            elif args[3] == '1':
                server_pool.ServerPool.get_instance().new_server(args[1], args[2])

    def handle_event(self, sock, fd, event):
        if sock != self._sock:
            return
        if event & eventloop.POLL_ERR:
            logging.error('mgr socket err')
            self._loop.remove(self._sock)
            self._sock.close()
            # TODO when dns server is IPv6
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                       socket.SOL_UDP)
            self._sock.setblocking(False)
            self._loop.add(self._sock, eventloop.POLL_IN, self)
        else:
            self._handle_data(sock)

    def close(self):
        if self._sock:
            if self._loop:
                self._loop.remove(self._sock)
            self._sock.close()
            self._sock = None


def test():
    pass

if __name__ == '__main__':
    test()
