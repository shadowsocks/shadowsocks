#!/usr/bin/env python

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


class SocksServer(SocketServer.StreamRequestHandler):
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
            # or "server": ["123.123.123.1:8381", "123.123.123.2:8381", "123.123.123.2:8382"]
            aServer = r.group(1)
            aPort = int(r.group(2))
        return (aServer, aPort)

    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
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
        except Exception as e:
            pass
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
            self.process()
        except socket.error as e:
            logging.warn(e)
        except Exception as e:
            logging.warn(e)

    def process(self):
        data = self.rfile.read(1)
        ver = ord(data[0])
        logging.debug("{0} => comes a new request".format(self.client_address) )
        if ver == 4:
            (addr_to_send, addr, port ) = self.process_v4()
        elif ver == 5:
            (addr_to_send, addr, port ) = self.process_v5()
        else:
            raise Exception("unsupported protocol")
        aServer, aPort = self.getServer()
        logging.debug("{0} => trying to connect to {1}:{2}".format(self.client_address, addr, port) )
        try:
            remote = socket.create_connection((aServer, aPort))
            self.send_encrypt(remote, addr_to_send)
            logging.info('{0} => connecting {1}:{2}'.format(self.client_address, addr, port))
        except socket.error, e:
            logging.warn("error when connecting to {0}:{1} => {2}".format(addr,port, e) )
            return
        self.handle_tcp(self.connection, remote)

    def process_v4(self):
        cmd = self.rfile.read(1)
        cmd = ord(cmd[0])
        if( cmd != 1 ):
            raise Exception("unsupported command, reject")
        addr_port = self.rfile.read(2)
        port = struct.unpack('>H', addr_port)[0]
        addr_ip = self.rfile.read(4)
        ip = struct.unpack('>bbbb',addr_ip)
        is4A = False
        if( ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] != 0 ):
            is4A = True
        data = self.connection.recv(256)# 256 should be enough to hold the user name and domain address
        addr_to_send = '\x03' if is4A else '\x01'
        if not is4A:
            addr_to_send += addr_ip
            addr_to_send += addr_port
            host = socket.inet_ntoa(addr_ip)
        else:
            if len(data) < 2:
                raise Exception("bad socks4A data, reject")
            pos = data.find("\0")
            if pos == -1:
                raise Exception("bad socks4A data")
            host = data[pos+1:-1]
            addr_to_send += len(host) + host
            addr_to_send += addr_port
        self.wfile.write("\x00\x5a\x22\x22\x00\x00\x00\x00")
        return (addr_to_send, host, port)

    def process_v5(self):
        #copy from original implementation
        self.connection.recv(256)
        self.wfile.write("\x05\x00")#version 5, no auth
        data = self.rfile.read(4) or '\x00' * 4
        if ord(data[1]) != 1:
            raise Exception("not supported command")
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
            raise Exception("not supported addr type")

        addr_port = self.rfile.read(2)
        addr_to_send += addr_port
        port = struct.unpack('>H', addr_port)
        reply = "\x05\x00\x00\x01"
        reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)
        self.wfile.write(reply)
        return (addr_to_send, addr, port[0])

def main():
    global SERVER, REMOTE_PORT, KEY, METHOD

    logging.basicConfig(level=logging.INFO,
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
                    logging.error('found an error in config.json: %s', e.message)
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
                config['local'] = value
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
    LOCAL = config.get('local', '127.0.0.1')

    if not KEY and not config_path:
        sys.exit('config not specified, please read https://github.com/clowwindy/shadowsocks')

    utils.check_config(config)

    encrypt.init_table(KEY, METHOD)

    try:
        if IPv6:
            ThreadingTCPServer.address_family = socket.AF_INET6
        server = ThreadingTCPServer((LOCAL, PORT), SocksServer)
        logging.info("starting local at %s:%d" % tuple(server.server_address[:2]))
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)

if __name__ == '__main__':
    main()
