#!/usr/bin/env python

# Copyright (c) 2013 clowwindy
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

try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'

import socket
import select
import threading
import SocketServer
import struct
import os
import logging
import getopt
import encrypt
import utils

logger = logging.getLogger('server')

def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


class Socks5Server(SocketServer.StreamRequestHandler):

    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = self.decrypt(sock.recv(4096))
                    if len(data) <= 0:
                        break
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = self.encrypt(remote.recv(4096))
                    if len(data) <= 0:
                        break
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')

        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def handle(self):
        try:
            self.encryptor = encrypt.Encryptor(
                self.server.key, self.server.method)
            sock = self.connection
            iv_len = self.encryptor.iv_len()
            if iv_len:
                self.decrypt(sock.recv(iv_len))
            addrtype = ord(self.decrypt(sock.recv(1)))
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            elif addrtype == 3:
                addr = self.decrypt(
                    self.rfile.read(ord(self.decrypt(sock.recv(1)))))
            elif addrtype == 4:
                addr = socket.inet_ntop(socket.AF_INET6,
                                        self.decrypt(self.rfile.read(16)))
            else:
                # not supported
                logger.warn('addr_type not supported, maybe wrong password')
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))
            try:
                logger.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.create_connection((addr, port[0]))
            except socket.error, e:
                # Connection refused
                logger.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logger.warn(e)


class ShadowSocksServer(object):

    def __init__(self):

        self.options = self.default_options()

    def default_options(self):
        return {
            "server":"localhost",
            "server_port":8388,
            "local_port":1080,
            "password":"barfoo!",
            "timeout":600,
            "method":"table"
            "IPv6": False
        }

    def serve_forever(self):

        self.set_logging()
        self.run_info()
        self.set_options()
        self.check_config()

        SERVER = self.options['server']
        PORT = self.options['server_port']
        KEY = self.options['password']
        METHOD = self.options.get('method', None)
        PORTPASSWORD = self.options.get('port_password', None)
        TIMEOUT = self.options.get('timeout', 600)

        if PORTPASSWORD:
            if PORT or KEY:
                logger.warn(
                    'warning: port_password should not be used with server_port and password. server_port and password will be ignored')
        else:
            PORTPASSWORD = {}
            PORTPASSWORD[str(PORT)] = KEY

        encrypt.init_table(KEY, METHOD)
        if self.options['IPv6']:
            ThreadingTCPServer.address_family = socket.AF_INET6
        for port, key in PORTPASSWORD.items():
            server = ThreadingTCPServer((SERVER, int(port)), Socks5Server)
            server.key, server.method, server.timeout = key, METHOD, int(
                TIMEOUT)
            logger.info("starting server at %s:%d" %
                         tuple(server.server_address[:2]))
            threading.Thread(target=server.serve_forever).start()

    def check_config(self):
        utils.check_config(self.options)

    def set_logging(self):
        logfmt = '[%%(levelname)s] %s%%(message)s' % '%(name)s - '
        config = lambda x: logging.basicConfig(level=x,
                                               format='[%(asctime)s] ' + logfmt, datefmt='%Y%m%d %H:%M:%S')
        if self.options.get('debug'):
            config(logging.DEBUG)
        else:
            config(logging.INFO)
        # logging.basicConfig(level=logging.DEBUG,
        #                     format='%(asctime)s %(levelname)-8s %(message)s',
        #                     datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    def set_options(self):
        config_path = self._find_options()
        config = self._parse_file_options(config_path)
        config = self._parse_cmd_options(config)
        self.options.update(config)

    def _parse_file_options(self, config_path):
        if config_path:
            logger.info('loading config from %s' % config_path)
            with open(config_path, 'rb') as f:
                try:
                    config = json.load(f)
                except ValueError as e:
                    logger.error(
                        'found an error in config.json: %s', e.message)
                    sys.exit(1)
        else:
            config = {}

        return config

    def _find_options(self):
        config_path = utils.find_config()
        print config_path
        optlist, args = getopt.getopt(sys.argv[1:], 's:b:p:k:l:m:c:6')
        for key, value in optlist:
            if key == '-c':
                config_path = value
        return config_path

    def _parse_cmd_options(self, config):
        optlist, args = getopt.getopt(sys.argv[1:], 's:b:p:k:l:m:c:6')
        for key, value in optlist:
            if key == '-p':
                config['server_port'] = int(value)
            elif key == '-k':
                self.options['password'] = value
            elif key == '-l':
                config['local_port'] = int(value)
            elif key == '-s':
                config['server'] = value
            elif key == '-m':
                config['method'] = value
            elif key == '-b':
                config['local'] = value
            elif key == '-6':
                config['IPv6'] = True
        return config

    def run_info(self):

        if hasattr(sys, "frozen") and sys.frozen in \
                ("windows_exe", "console_exe"):
            p = os.path.dirname(os.path.abspath(sys.executable))
            os.chdir(p)
        version = ''
        try:
            import pkg_resources
            version = pkg_resources.get_distribution('shadowsocks').version
        except:
            pass
        logger.info('shadowsocks %s' % version)


if __name__ == '__main__':
    try:
        ShadowSocksServer().serve_forever()
    except socket.error, e:
        logger.error(e)
