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
import SocketServer
import struct
import os
import random
import re
import logging
import getopt
import encrypt
import utils
import udprelay


MSG_FASTOPEN = 0x20000000


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
    def getServer(self):
        aPort = REMOTE_PORT
        aServer = SERVER
        if isinstance(REMOTE_PORT, list):
            # support config like "server_port": [8081, 8082]
            aPort = random.choice(REMOTE_PORT)
        if isinstance(SERVER, list):
            # support config like "server": ["123.123.123.1", "123.123.123.2"]
            aServer = random.choice(SERVER)

        r = re.match(r'^(.*)\:(\d+)$', aServer)
        if r:
            # support config like "server": "123.123.123.1:8381"
            # or "server": ["123.123.123.1:8381", "123.123.123.2:8381"]
            aServer = r.group(1)
            aPort = int(r.group(2))
        return (aServer, aPort)

    def handle_tcp(self, sock, remote, pending_data=None, server=None, port=None):
        connected = False
        try:
            if FAST_OPEN:
                fdset = [sock]
            else:
                fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    if not connected and FAST_OPEN:
                        data = sock.recv(4096)
                        data = self.encrypt(pending_data + data)
                        remote.sendto(data, MSG_FASTOPEN, (server, port))
                        connected = True
                        fdset = [sock, remote]
                        logging.info('fast open %s:%d' % (server, port))
                    else:
                        data = self.encrypt(sock.recv(4096))
                        if len(data) <= 0:
                            break
                        result = send_all(remote, data)
                        if result < len(data):
                            raise Exception('failed to send all data')

                if remote in r:
                    data = self.decrypt(remote.recv(4096))
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

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        try:
            self.encryptor = encrypt.Encryptor(KEY, METHOD)
            sock = self.connection
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            data = sock.recv(262)
            if not data:
                sock.close()
                return
            if len(data) < 3:
                return
            method = ord(data[2])
            if method == 2:
                logging.warn('client tries to use username/password auth, prete'
                             'nding the password is OK')
                sock.send('\x05\x02')
                try:
                    ver_ulen = sock.recv(2)
                    ulen = ord(ver_ulen[1])
                    if ulen:
                        username = sock.recv(ulen)
                        assert(ulen == len(username))
                    plen = ord(sock.recv(1))
                    if plen:
                        _password = sock.recv(plen)
                        assert(plen == len(_password))
                    sock.send('\x01\x00')
                except Exception as e:
                    logging.error(e)
                    return
            elif method == 0:
                sock.send("\x05\x00")
            else:
                logging.error('unsupported method %d' % method)
                return
            data = self.rfile.read(4) or '\x00' * 4
            mode = ord(data[1])
            if mode == 1:
                pass
            elif mode == 3:
                # UDP
                logging.debug('UDP assc request')
                if sock.family == socket.AF_INET6:
                    header = '\x05\x00\x00\x04'
                else:
                    header = '\x05\x00\x00\x01'
                addr, port = sock.getsockname()
                addr_to_send = socket.inet_pton(sock.family, addr)
                port_to_send = struct.pack('>H', port)
                sock.send(header + addr_to_send + port_to_send)
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                return
            else:
                logging.warn('unknown mode %d' % mode)
                return
            addrtype = ord(data[3])
            addr_to_send = data[3]
            if addrtype == 1:
                addr_ip = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:
                addr_len = self.rfile.read(1)
                addr = self.rfile.read(ord(addr_len))
                addr_to_send += addr_len + addr
            elif addrtype == 4:
                addr_ip = self.rfile.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
                addr_to_send += addr_ip
            else:
                logging.warn('addr_type not supported')
                # not supported
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port
            port = struct.unpack('>H', addr_port)
            try:
                reply = "\x05\x00\x00\x01"
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)
                self.wfile.write(reply)
                # reply immediately
                aServer, aPort = self.getServer()
                addrs = socket.getaddrinfo(aServer, aPort)
                if addrs:
                    af, socktype, proto, canonname, sa = addrs[0]
                    if FAST_OPEN:
                        remote = socket.socket(af, socktype, proto)
                        # remote.setsockopt(socket.IPPROTO_TCP,
                        #                   socket.TCP_NODELAY, 1)
                        self.handle_tcp(sock, remote, addr_to_send, aServer,
                                        aPort)
                    else:
                        remote = socket.create_connection((aServer, aPort))
                        remote.setsockopt(socket.IPPROTO_TCP,
                                          socket.TCP_NODELAY, 1)
                        self.send_encrypt(remote, addr_to_send)
                        logging.info('connecting %s:%d' % (addr, port[0]))
                        self.handle_tcp(sock, remote)
            finally:
                pass
            # except socket.error, e:
            #     raise e
                # logging.warn(e)
                # return
        finally:
            pass
        # except socket.error, e:
        #     raise e
        #     logging.warn(e)


def main():
    global SERVER, REMOTE_PORT, KEY, METHOD, FAST_OPEN

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    # fix py2exe
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
    print 'shadowsocks %s' % version

    KEY = None
    METHOD = None
    LOCAL = ''
    IPv6 = False

    config_path = utils.find_config()
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 's:b:p:k:l:m:c:6')
        for key, value in optlist:
            if key == '-c':
                config_path = value

        if config_path:
            logging.info('loading config from %s' % config_path)
            with open(config_path, 'rb') as f:
                try:
                    config = json.load(f)
                except ValueError as e:
                    logging.error('found an error in config.json: %s',
                                  e.message)
                    sys.exit(1)
        else:
            config = {}

        optlist, args = getopt.getopt(sys.argv[1:], 's:b:p:k:l:m:c:6')
        for key, value in optlist:
            if key == '-p':
                config['server_port'] = int(value)
            elif key == '-k':
                config['password'] = value
            elif key == '-l':
                config['local_port'] = int(value)
            elif key == '-s':
                config['server'] = value
            elif key == '-m':
                config['method'] = value
            elif key == '-b':
                config['local_address'] = value
            elif key == '-6':
                IPv6 = True
    except getopt.GetoptError:
        utils.print_local_help()
        sys.exit(2)

    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']
    METHOD = config.get('method', None)
    LOCAL = config.get('local_address', '127.0.0.1')
    TIMEOUT = config.get('timeout', 600)
    FAST_OPEN = config.get('fast_open', False)

    if not KEY and not config_path:
        sys.exit('config not specified, please read '
                 'https://github.com/clowwindy/shadowsocks')

    utils.check_config(config)

    encrypt.init_table(KEY, METHOD)

    if IPv6:
        ThreadingTCPServer.address_family = socket.AF_INET6
    try:
        udprelay.UDPRelay(LOCAL, int(PORT), SERVER, REMOTE_PORT, KEY, METHOD,
                          int(TIMEOUT), True).start()
        server = ThreadingTCPServer((LOCAL, PORT), Socks5Server)
        logging.info("starting local at %s:%d" %
                     tuple(server.server_address[:2]))
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)

if __name__ == '__main__':
    main()
