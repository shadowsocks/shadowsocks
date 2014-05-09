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
import eventloop
import errno
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
    @staticmethod
    def get_server():
        a_port = config_server_port
        a_server = config_server
        if isinstance(config_server_port, list):
            # support config like "server_port": [8081, 8082]
            a_port = random.choice(config_server_port)
        if isinstance(config_server, list):
            # support config like "server": ["123.123.123.1", "123.123.123.2"]
            a_server = random.choice(config_server)

        r = re.match(r'^(.*):(\d+)$', a_server)
        if r:
            # support config like "server": "123.123.123.1:8381"
            # or "server": ["123.123.123.1:8381", "123.123.123.2:8381"]
            a_server = r.group(1)
            a_port = int(r.group(2))
        return a_server, a_port

    @staticmethod
    def handle_tcp(sock, remote, encryptor, pending_data=None,
                   server=None, port=None):
        connected = False
        try:
            if config_fast_open:
                fdset = [sock]
            else:
                fdset = [sock, remote]
            while True:
                should_break = False
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    if not connected and config_fast_open:
                        data = sock.recv(4096)
                        data = encryptor.encrypt(pending_data + data)
                        pending_data = None
                        logging.info('fast open %s:%d' % (server, port))
                        try:
                            remote.sendto(data, MSG_FASTOPEN, (server, port))
                        except (OSError, IOError) as e:
                            if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                                pass
                            else:
                                raise e
                        connected = True
                        fdset = [sock, remote]
                    else:
                        data = sock.recv(4096)
                        if pending_data:
                            data = pending_data + data
                            pending_data = None
                        data = encryptor.encrypt(data)
                        if len(data) <= 0:
                            should_break = True
                        else:
                            result = send_all(remote, data)
                            if result < len(data):
                                raise Exception('failed to send all data')

                if remote in r:
                    data = encryptor.decrypt(remote.recv(4096))
                    if len(data) <= 0:
                        should_break = True
                    else:
                        result = send_all(sock, data)
                        if result < len(data):
                            raise Exception('failed to send all data')
                if should_break:
                    # make sure all data are read before we close the sockets
                    # TODO: we haven't read ALL the data, actually
                    # http://cs.ecs.baylor.edu/~donahoo/practical/CSockets/TCPRST.pdf
                    break
        finally:
            sock.close()
            remote.close()

    def handle(self):
        try:
            encryptor = encrypt.Encryptor(config_password, config_method)
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
                a_server, a_port = Socks5Server.get_server()
                addrs = socket.getaddrinfo(a_server, a_port)
                if addrs:
                    af, socktype, proto, canonname, sa = addrs[0]
                    if config_fast_open:
                        remote = socket.socket(af, socktype, proto)
                        remote.setsockopt(socket.IPPROTO_TCP,
                                          socket.TCP_NODELAY, 1)
                        Socks5Server.handle_tcp(sock, remote, encryptor,
                                                addr_to_send, a_server, a_port)
                    else:
                        logging.info('connecting %s:%d' % (addr, port[0]))
                        remote = socket.create_connection((a_server, a_port))
                        remote.setsockopt(socket.IPPROTO_TCP,
                                          socket.TCP_NODELAY, 1)
                        Socks5Server.handle_tcp(sock, remote, encryptor,
                                                addr_to_send)
            except (OSError, IOError) as e:
                logging.warn(e)
                return
        except (OSError, IOError) as e:
            raise e
            logging.warn(e)


def main():
    global config_server, config_server_port, config_password, config_method,\
        config_fast_open

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

    config_password = None
    config_method = None

    config_path = utils.find_config()
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 's:b:p:k:l:m:c:',
                                      ['fast-open'])
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

        optlist, args = getopt.getopt(sys.argv[1:], 's:b:p:k:l:m:c:',
                                      ['fast-open'])
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
            elif key == '--fast-open':
                config['fast_open'] = True
    except getopt.GetoptError as e:
        logging.error(e)
        utils.print_local_help()
        sys.exit(2)

    config_server = config['server']
    config_server_port = config['server_port']
    config_local_port = config['local_port']
    config_password = config['password']
    config_method = config.get('method', None)
    config_local_address = config.get('local_address', '127.0.0.1')
    config_timeout = config.get('timeout', 600)
    config_fast_open = config.get('fast_open', False)

    if not config_password and not config_path:
        sys.exit('config not specified, please read '
                 'https://github.com/clowwindy/shadowsocks')

    utils.check_config(config)

    encrypt.init_table(config_password, config_method)

    addrs = socket.getaddrinfo(config_local_address, config_local_port)
    if not addrs:
        logging.error('cant resolve listen address')
        sys.exit(1)
    ThreadingTCPServer.address_family = addrs[0][0]
    try:
        udprelay.UDPRelay(config_local_address, int(config_local_port),
                          config_server, config_server_port, config_password,
                          config_method, int(config_timeout), True).start()
        server = ThreadingTCPServer((config_local_address, config_local_port),
                                    Socks5Server)
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
