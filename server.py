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

from __future__ import with_statement
import sys
if sys.version_info < (2, 6):
    import simplejson as json
else:
    import json
import struct
import os
import logging
import getopt
import socket
import encrypt


class RemoteHandler(object):
    def __init__(self, conn, local_handler):
        self.conn = conn
        self.local_handler = local_handler
        conn.on('connect', self.on_connect)
        conn.on('data', self.on_data)
        conn.on('drain', self.on_drain)
        conn.on('close', self.on_close)
        conn.on('end', self.on_end)
        conn.connect(local_handler.remote_addr_pair)

    def on_connect(self, s):
        logging.debug('on_connnect')
        for piece in self.local_handler.cached_pieces:
            self.conn.write(piece)
        # TODO write cached pieces
        self.local_handler.stage = 5

    def on_data(self, s, data):
        data = self.local_handler.encryptor.encrypt(data)
        if not self.local_handler.conn.write(data):
            self.conn.pause()

    def on_drain(self, s):
        if self.local_handler:
            self.local_handler.conn.resume()

    def on_close(self, s):
        # self.local_handler.conn.end()
        pass

    def on_end(self, s):
        self.local_handler.conn.end()


class LocalHandler(object):
    def on_data(self, s, data):
        data = self.encryptor.decrypt(data)
        if self.stage == 5:
            if not self.remote_handler.conn.write(data):
                self.conn.pause()
            return
        if self.stage == 0:
            try:
                addrtype = ord(data[0])
                # TODO check cmd == 1
                if addrtype == 1:
                    remote_addr = socket.inet_ntoa(data[1:5])
                    remote_port = data[5:7]
                    header_length = 7
                elif addrtype == 4:
                    remote_addr = socket.inet_ntop(data[1:17])
                    remote_port = data[17:19]
                    header_length = 19
                elif addrtype == 3:
                    addr_len = ord(data[1])
                    remote_addr = data[2:2 + addr_len]
                    remote_port = data[2 + addr_len:2 + addr_len + 2]
                    header_length = 2 + addr_len + 2
                else:
                    # TODO check addrtype in (1, 3, 4)
                    # raise 'addrtype wrong'
                    raise something
                remote_port = struct.unpack('>H', remote_port)[0]
                self.remote_addr_pair = (remote_addr, remote_port)
                logging.info('connecting %s:%d' % self.remote_addr_pair)
                remote_conn = ssloop.Socket()
                self.remote_handler = RemoteHandler(remote_conn, self)

                if len(data) > header_length:
                    self.cached_pieces.append(data[header_length:])

                # TODO save other bytes
                self.stage = 4
                return
            except:
                logging.exception('')

        if self.stage == 4:
            self.cached_pieces.append(data)

    def on_drain(self, s):
        if self.remote_handler:
            self.remote_handler.conn.resume()

    def on_end(self, s):
        if self.remote_handler:
            self.remote_handler.conn.end()

    def on_close(self, s):
        pass
        # self.remote_handler.conn.end()

    def __init__(self, conn):
        self.stage = 0
        self.remote = None
        self.addr_len = 0
        self.addr_to_send = ''
        self.conn = conn
        self.cached_pieces = []
        self.encryptor = encrypt.Encryptor(KEY, METHOD)
        self.remote_handler = None

        conn.on('data', self.on_data)
        conn.on('drain', self.on_drain)
        conn.on('end', self.on_end)
        conn.on('close', self.on_close)


def on_connection(s, conn):
    LocalHandler(conn)

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    sys.path.append('./ssloop')
    import ssloop
    print 'shadowsocks v2.0'

    with open('config.json', 'rb') as f:
        config = json.load(f)
    PORT = config['server_port']
    KEY = config['password']
    METHOD = config.get('method', None)

    argv = sys.argv[1:]

    level = logging.INFO

    optlist, args = getopt.getopt(sys.argv[1:], 'p:k:m:')
    for key, value in optlist:
        if key == '-p':
            PORT = int(value)
        elif key == '-k':
            KEY = value
        elif key == '-m':
            METHOD = value
        elif key == '-v':
            level = logging.NOTSET

    logging.basicConfig(level=level, format='%(asctime)s %(levelname)1.1s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    encrypt.init_table(KEY, METHOD)
    try:
        logging.info("starting server at port %d ..." % PORT)
        loop = ssloop.instance()
        s = ssloop.Server(('0.0.0.0', PORT))
        s.on('connection', on_connection)
        s.listen()
        loop.start()
    except KeyboardInterrupt:
        sys.exit(0)
