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

import hashlib
import json
import logging
import optparse
import os
import socket
import string
import struct

from tornado import ioloop
from tornado import iostream
from tornado import netutil


class Crypto(object):
    def __init__(self, password):
        m = hashlib.md5()
        m.update(password)
        s = m.digest()
        a, b = struct.unpack('<QQ', s)
        trans = string.maketrans('', '')
        table = list(trans)
        for i in xrange(1, 1024):
            table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
        self.encrypt_table = ''.join(table)
        self.decrypt_table = string.maketrans(self.encrypt_table, trans)

    def encrypt(self, data):
        return data.translate(self.encrypt_table)

    def decrypt(self, data):
        return data.translate(self.decrypt_table)


class Socks5Server(netutil.TCPServer):
    def handle_stream(self, stream, address):
        soc = stream.socket
        soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        ConnHandler(soc).wait_for_data()


class PairedStream(iostream.IOStream):
    def __init__(self, soc):
        super(PairedStream, self).__init__(soc)
        self.remote = None

    def on_close(self):
        remote = self.remote
        if isinstance(remote, PairedStream) and not remote.closed():
            if remote.writing():
                remote.write("", callback=remote.close())
            else:
                remote.close()


class ConnHandler(PairedStream):
    def wait_for_data(self):
        self.read_bytes(1, self.on_addrtype)

    def on_addrtype(self, addrtype):
        addrtype = ord(crypto.decrypt(addrtype))
        if addrtype == 1:
            self.read_bytes(4, self.on_ipaddr)
        elif addrtype == 3:
            self.read_bytes(1, self.on_hostname_length)
        else:
            logging.warn("addr_type %d not support" % addrtype)
            self.close()

    def on_ipaddr(self, addr):
        self.remote_addr = socket.inet_ntoa(crypto.decrypt(addr))
        self.read_bytes(2, self.on_port)

    def on_hostname_length(self, length):
        length = ord(crypto.decrypt(length))
        self.read_bytes(length, self.on_hostname)

    def on_hostname(self, addr):
        self.remote_addr = crypto.decrypt(addr)
        self.read_bytes(2, self.on_port)

    def on_port(self, port):
        self.remote_port = struct.unpack('>H', crypto.decrypt(port))[0]
        logging.debug("Connecting to %s:%d" % (self.remote_addr, self.remote_port))
        remote_soc = socket.socket()
        remote_soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        self.remote = PairedStream(remote_soc)
        self.set_close_callback(self.remote.on_close)
        self.remote.set_close_callback(self.on_close)

        self.remote.connect((self.remote_addr, self.remote_port), self.on_remote_connected)

    def on_remote_connected(self):
        self.read_until_close(callback=self.on_client_read, streaming_callback=self.on_client_read)
        self.remote.read_until_close(callback=self.on_remote_read, streaming_callback=self.on_remote_read)
        self._try_inline_read()  # We must call this to empty filled buffer otherwise nothing will be read in again.

    def on_client_read(self, data):
        if data and not self.remote.closed():
            self.remote.write(crypto.decrypt(data))

    def on_remote_read(self, data):
        if data and not self.closed():
            self.write(crypto.encrypt(data))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    parser = optparse.OptionParser("usage: %prog [options] arg")
    parser.add_option("-c", "--config", dest="config_path",
                      default=os.path.join(os.path.dirname(__file__), "config.json"))
    parser.add_option("-p", "--port", dest="server_port")
    parser.add_option("-k", "--key", dest="server_password")
    parser.add_option("-6", "--ipv6", action="store_true", dest="ipv6")
    options, args = parser.parse_args()

    with open(options.config_path, "rb") as f:
        config = json.load(f)

    server_port = int(options.server_port) if options.server_port else config["server_port"]
    server_password = options.server_password if options.server_password else config['password']

    if getattr(options, "ipv6"):
        address_family = socket.AF_INET6
    else:
        address_family = socket.AF_INET

    crypto = Crypto(server_password)

    logging.info("starting server at port %d ..." % server_port)
    server = Socks5Server()
    server.bind(port=server_port, family=address_family)
    server.start()
    try:
        ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        pass
    except Exception:
        logging.exception("Uncaught Exception")
