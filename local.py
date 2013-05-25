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
        conn.connect((SERVER, REMOTE_PORT))

    def on_connect(self, s):
        self.conn.write(self.local_handler.encryptor.encrypt(self.local_handler.addr_to_send))
        for piece in self.local_handler.cached_pieces:
            self.conn.write(self.local_handler.encryptor.encrypt(piece))
        # TODO write cached pieces
        self.local_handler.stage = 5

    def on_data(self, s, data):
        data = self.local_handler.encryptor.decrypt(data)
        if not self.local_handler.conn.write(data):
            self.conn.pause()

    def on_drain(self, s):
        logging.debug('remote drain')
        if self.local_handler:
            self.local_handler.conn.resume()

    def on_close(self, s):
        # self.local_handler.conn.end()
        pass

    def on_end(self, s):
        self.local_handler.conn.end()


class LocalHandler(object):
    def on_data(self, s, data):
        if self.stage == 5:
            data = self.encryptor.encrypt(data)
            if not self.remote_handler.conn.write(data):
                self.conn.pause()
            return
        if self.stage == 0:
            self.conn.write('\x05\00')
            self.stage = 1
            return
        if self.stage == 1:
            try:
                cmd = ord(data[1])
                addrtype = ord(data[3])
                # TODO check cmd == 1
                if addrtype == 1:
                    remote_addr = socket.inet_ntoa(data[4:8])
                    remote_port = data[8:10]
                    self.addr_to_send = data[3:10]
                    header_length = 10
                elif addrtype == 4:
                    remote_addr = socket.inet_ntop(data[4:20])
                    remote_port = data[20:22]
                    self.addr_to_send = data[3:22]
                    header_length = 22
                elif addrtype == 3:
                    addr_len = ord(data[4])
                    remote_addr = data[5:5 + addr_len]
                    remote_port = data[5 + addr_len:5 + addr_len + 2]
                    self.addr_to_send = data[3:5 + addr_len + 2]
                    header_length = 5 + addr_len + 2
                else:
                    # TODO check addrtype in (1, 3, 4)
                    # raise Exception('addrtype wrong')
                    raise something
                remote_port = struct.unpack('>H', remote_port)[0]
                logging.info('connecting %s:%d' % (remote_addr, remote_port))
                self.conn.write('\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10')
                remote_conn = ssloop.Socket()
                self.remote_handler = RemoteHandler(remote_conn, self)

                if len(data) > header_length:
                    self.cached_pieces.append(data[header_length:])

                # TODO save other bytes
                self.stage = 4
                return
            except:
                import traceback
                traceback.print_exc()

        if self.stage == 4:
            self.cached_pieces.append(data)

    def on_drain(self, s):
        logging.debug('local drain')
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
    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']
    METHOD = config.get('method', None)

    argv = sys.argv[1:]

    level = logging.INFO

    optlist, args = getopt.getopt(argv, 's:p:k:l:m:v')
    for key, value in optlist:
        if key == '-p':
            REMOTE_PORT = int(value)
        elif key == '-k':
            KEY = value
        elif key == '-l':
            PORT = int(value)
        elif key == '-s':
            SERVER = value
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
