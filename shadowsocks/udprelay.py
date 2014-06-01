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


import time
import threading
import socket
import logging
import struct
import errno
import encrypt
import eventloop
import lru_cache
from common import parse_header


BUF_SIZE = 65536


def client_key(a, b, c, d):
    return '%s:%s:%s:%s' % (a, b, c, d)


class UDPRelay(object):
    def __init__(self, config, is_local):
        if is_local:
            self._listen_addr = config['local_address']
            self._listen_port = config['local_port']
            self._remote_addr = config['server']
            self._remote_port = config['server_port']
        else:
            self._listen_addr = config['server']
            self._listen_port = config['server_port']
            self._remote_addr = None
            self._remote_port = None
        self._password = config['password']
        self._method = config['method']
        self._timeout = config['timeout']
        self._is_local = is_local
        self._cache = lru_cache.LRUCache(timeout=config['timeout'],
                                         close_callback=self._close_client)
        self._client_fd_to_server_addr = \
            lru_cache.LRUCache(timeout=config['timeout'])
        self._closed = False
        self._thread = None

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

    def _close_client(self, client):
        if hasattr(client, 'close'):
            self._eventloop.remove(client)
            client.close()
        else:
            # just an address
            pass

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
            self._eventloop.add(client, eventloop.POLL_IN)

        data = data[header_length:]
        if not data:
            return
        if self._is_local:
            data = encrypt.encrypt_all(self._password, self._method, 1, data)
            if not data:
                return
        try:
            client.sendto(data, (server_addr, server_port))
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            if err in (errno.EINPROGRESS, errno.EAGAIN):
                pass
            else:
                logging.error(e)

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
            response = '\x00\x00\x00' + data
        client_addr = self._client_fd_to_server_addr.get(sock.fileno())
        if client_addr:
            self._server_socket.sendto(response, client_addr)
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    def _run(self):
        server_socket = self._server_socket
        self._eventloop = eventloop.EventLoop()
        self._eventloop.add(server_socket, eventloop.POLL_IN)
        last_time = time.time()
        while not self._closed:
            try:
                events = self._eventloop.poll(10)
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == errno.EPIPE:
                    # Happens when the client closes the connection
                    continue
                else:
                    logging.error(e)
                    continue
            for sock, event in events:
                if sock == self._server_socket:
                    self._handle_server()
                else:
                    self._handle_client(sock)
            now = time.time()
            if now - last_time > 3.5:
                self._cache.sweep()
            if now - last_time > 7:
                self._client_fd_to_server_addr.sweep()
                last_time = now

    def start(self):
        if self._closed:
            raise Exception('closed')
        t = threading.Thread(target=self._run)
        t.setName('UDPThread')
        t.setDaemon(False)
        t.start()
        self._thread = t

    def close(self):
        self._closed = True
        self._server_socket.close()

    def thread(self):
        return self._thread
