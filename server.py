#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
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

PORT = 8499
KEY = "foobar!"

try:
    import gevent, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    gevent = None

import socket
import select
import SocketServer
import struct
import string
import hashlib
import sys

#disable ThreadingTCPServer dns revsere lookup, sometimes it will be slow
socket.getfqdn = lambda x:x

def socket_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None):
    """python 2.7 socket.create_connection"""
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock

        except socket.error as _:
            err = _
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")

def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    if remote.send(self.decrypt(sock.recv(4096))) <= 0:
                        break
                if remote in r:
                    if sock.send(self.encrypt(remote.recv(4096))) <= 0:
                        break
        finally:
            remote.close()

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def send_encrpyt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        try:
            print 'socks connection from ', self.client_address
            sock = self.connection
            sock.recv(262)
            self.send_encrpyt(sock, "\x05\x00")
            data = self.decrypt(self.rfile.read(4))
            mode = ord(data[1])
            addrtype = ord(data[3])
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            elif addrtype == 3:
                addr = self.decrypt(
                    self.rfile.read(ord(self.decrypt(sock.recv(1)))))
            else:
                # not support
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))
            reply = "\x05\x00\x00\x01"
            try:
                if mode == 1:
                    remote = socket_create_connection((addr, port[0]))
                    local = remote.getsockname()
                    reply += socket.inet_aton(local[0]) + struct.pack(">H",
                        local[1])
                    print 'Tcp connect to', addr, port[0]
                else:
                    reply = "\x05\x07\x00\x01" # Command not supported
                    print 'command not supported'
            except socket.error:
                # Connection refused
                reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            self.send_encrpyt(sock, reply)
            if reply[1] == '\x00':
                if mode == 1:
                    self.handle_tcp(sock, remote)
        except socket.error as e:
            print 'socket error'


def main():
    if '-6' in sys.argv[1:]:
        ThreadingTCPServer.address_family = socket.AF_INET6
    server = ThreadingTCPServer(('', PORT), Socks5Server)
    server.allow_reuse_address = True
    print "starting server at port %d ..." % PORT
    server.serve_forever()

if __name__ == '__main__':
    encrypt_table = ''.join(get_table(KEY))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    main()
