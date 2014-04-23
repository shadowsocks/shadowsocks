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

# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+

# HOW TO NAME THINGS
# ------------------
# `dest`    means destination server, which is from DST fields in the SOCKS5
#           request
# `local`   means local server of shadowsocks
# `remote`  means remote server of shadowsocks
# `client`  means UDP clients that connects to other servers
# `server`  means the UDP server that handles user requests


import threading
import socket
import logging
import struct
import encrypt
import eventloop

BUF_SIZE = 65536


def parse_header(data):
    addrtype = ord(data[0])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype == 1:
        if len(data) >= 7:
            dest_addr = socket.inet_ntoa(data[1:5])
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('[udp] header is too short')
    elif addrtype == 3:
        if len(data) > 2:
            addrlen = ord(data[1])
            if len(data) >= 2 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                          addrlen])[0]
                header_length = 4 + addrlen
            else:
                logging.warn('[udp] header is too short')
        else:
            logging.warn('[udp] header is too short')
    elif addrtype == 4:
        if len(data) >= 19:
            dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            dest_port = struct.unpack('>H', data[17:19])[0]
            header_length = 19
        else:
            logging.warn('[udp] header is too short')
    else:
        logging.warn('unsupported addrtype %d' % addrtype)
    if dest_addr is None:
        return None
    return (addrtype, dest_addr, dest_port, header_length)


def client_key(a, b, c, d):
    return '%s:%s:%s:%s' % (a, b, c, d)


class UDPRelay(object):
    def __init__(self, listen_addr='127.0.0.1', listen_port=1080,
                 remote_addr='127.0.0.1', remote_port=8387, password=None,
                 method='table', timeout=300, is_local=True):
        self._listen_addr = listen_addr
        self._listen_port = listen_port
        self._remote_addr = remote_addr
        self._remote_port = remote_port
        self._password = password
        self._method = method
        self._timeout = timeout
        self._is_local = is_local
        self._eventloop = eventloop.EventLoop()
        self._cache = {}  # TODO replace ith an LRU cache
        self._client_fd_to_server_addr = {}  # TODO replace ith an LRU cache

    def _handle_server(self):
        server = self._server_socket
        data, r_addr = server.recvfrom(BUF_SIZE)
        if self._is_local:
            frag = ord(data[2])
            if frag != 0:
                logging.warn('drop a message since frag is not 0')
                return
            else:
                data = data[3:]
        else:
            # decrypt data
            data = encrypt.encrypt_all(self._password, self._method, 0, data)
            if not data:
                return
        header_result = parse_header(data)
        if header_result is None:
            return
        addrtype, dest_addr, dest_port, header_length = header_result

        if self._is_local:
            server_addr, server_port = self._remote_addr, self._remote_port
        else:
            server_addr, server_port = dest_addr, dest_port

        key = client_key(r_addr[0], r_addr[1], dest_addr, dest_port)
        client = self._cache.get(key, None)
        if not client:
            # TODO async getaddrinfo
            addrs = socket.getaddrinfo(server_addr, server_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
            if addrs:
                af, socktype, proto, canonname, sa = addrs[0]
                client = socket.socket(af, socktype, proto)
                client.setblocking(False)
                self._cache[key] = client
                self._client_fd_to_server_addr[client.fileno()] = r_addr
            else:
                # drop
                return
            self._eventloop.add(client, eventloop.MODE_IN)

        data = data[header_length:]
        if not data:
            return
        if self._is_local:
            data = encrypt.encrypt_all(self._password, self._method, 1, data)
            if not data:
                return
        client.sendto(data, (server_addr, server_port))

    def _handle_client(self, sock):
        data, r_addr = sock.recvfrom(BUF_SIZE)
        if not self._is_local:
            addrlen = len(r_addr[0])
            if addrlen > 255:
                # drop
                return
            data = '\x03' + chr(addrlen) + r_addr[0] + \
                   struct.pack('>H', r_addr[1]) + data
            response = encrypt.encrypt_all(self._password, self._method, 1,
                                           data)
            if not response:
                return
        else:
            data = encrypt.encrypt_all(self._password, self._method, 0,
                                       data)
            if not data:
                return
            header_result = parse_header(data)
            if header_result is None:
                return
            # addrtype, dest_addr, dest_port, header_length = header_result
            response = '\x00\x00\0x00' + data
        client_addr = self._client_fd_to_server_addr.get(sock.fileno(), None)
        if client_addr:
            self._server_socket.sendto(response, client_addr)
        else:
            pass
            # self._eventloop.remove(sock)
            # sock.close()
            # TODO remove it from cache else we can't close it

    def _run(self):
        server_socket = self._server_socket
        self._eventloop.add(server_socket, eventloop.MODE_IN)
        while True:
            events = self._eventloop.poll()
            for sock, event in events:
                if sock == self._server_socket:
                    self._handle_server()
                else:
                    self._handle_client(sock)

    def start(self):
        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
        self._server_socket = server_socket

        t = threading.Thread(target=self._run)
        t.setDaemon(True)
        t.start()
        self._thread = t
