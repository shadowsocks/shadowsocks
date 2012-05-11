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

SERVER = 'my_server_ip_or_host'
REMOTE_PORT = 8499
PORT = 1080
KEY = "foobar!"

import socket
import select
import string
import struct
import hashlib
import threading
import time
import SocketServer

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
        raise error("getaddrinfo returns an empty list")

def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table

encrypt_table = ''.join(get_table(KEY))
decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))

my_lock = threading.Lock()

def lock_print(msg):
    my_lock.acquire()
    try:
        print "[%s] %s" % (time.ctime(), msg)
    finally:
        my_lock.release()


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class Socks5Server(SocketServer.StreamRequestHandler):
    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            counter = 0
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    r_data = sock.recv(4096)
                    if counter == 1:
                        try:
                            lock_print(
                                "Connecting " + r_data[5:5 + ord(r_data[4])])
                        except Exception:
                            pass
                    if counter < 2:
                        counter += 1
                    if remote.send(self.encrypt(r_data)) <= 0:
                        break
                if remote in r:
                    if sock.send(self.decrypt(remote.recv(4096))) <= 0:
                        break
        finally:
            remote.close()

    def handle(self):
        try:
            sock = self.connection
            remote = socket_create_connection((SERVER, REMOTE_PORT))
            self.handle_tcp(sock, remote)
        except socket.error as e:
            lock_print('socket error: %s' % str(e))


def main():
    print 'Starting proxy at port %d' % PORT
    server = ThreadingTCPServer(('', PORT), Socks5Server)
    server.serve_forever()

if __name__ == '__main__':
    main()
