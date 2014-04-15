#!/usr/bin/env python
#coding: utf8

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

import sys
if sys.version_info < (2, 6):
    import simplejson as json
else:
    import json

"""
try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'
"""

sys.setrecursionlimit(30)
import socket
import struct
import os
import time
import errno
import logging
import getopt
import encrypt
import utils
import ioloop

def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent

def parse_options():
    version = ''
    try:
        import pkg_resources
        version = pkg_resources.get_distribution('shadowsocks').version
    except:
        pass
    print 'shadowsocks %s' % version

    KEY = None
    METHOD = None
    IPv6 = False

    config_path = utils.find_config()
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:m:c:6')
        for key, value in optlist:
            if key == '-c':
                config_path = value

        if config_path:
            logging.info('loading config from %s' % config_path)
            try:
                f = open(config_path, 'rb')
                config = json.load(f)
            except ValueError as e:
                logging.error('found an error in config.json: %s', e.message)
                sys.exit(1)
        else:
            config = {}

        optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:m:c:6')
        for key, value in optlist:
            if key == '-p':
                config['server_port'] = int(value)
            elif key == '-k':
                config['password'] = value
            elif key == '-s':
                config['server'] = value
            elif key == '-m':
                config['method'] = value
            elif key == '-6':
                IPv6 = True
    except getopt.GetoptError:
        utils.print_server_help()
        sys.exit(2)

    return config

class TunnelStream(ioloop.SocketStream): 
    def read(self, *args, **kwargs):
        s = ioloop.SocketStream.read(self, *args, **kwargs)
        return s
    def real_write(self, *args, **kwargs):
        ioloop.SocketStream.real_write(self, *args, **kwargs)

class BaseTunnelHandler(ioloop.IOHandler):
    def __init__(self, *args, **kwargs):
        ioloop.IOHandler.__init__(self, *args, **kwargs)
        self.encryptor = encrypt.Encryptor(G_CONFIG["password"], G_CONFIG["method"])
        self._remote_ios = None

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def close_tunnel(self):
        if self._remote_ios:
            logging.debug('!!!!!!!!!!! close remote ios %d', self._remote_ios.fileno())
            self._ioloop.remove_handler(self._remote_ios.fileno())
            self._remote_ios._obj.close()

        logging.debug('!!!!!!!!!!! close local ios %d', self._ios.fileno())
        self._ioloop.remove_handler(self._ios.fileno())
        self._ios.close()

    def left_to_local(self, data):
        """解密"""
        return self.decrypt(data)
        
    def local_to_left(self, data):
        """加密"""
        return self.encrypt(data)

    def do_stream_read(self):
        raise

    def write_to_remote(self, data):
        raise

    def connect_to_remote(self):
        raise

    def handle_read(self):
        """fd 可读事件出现"""
        if not self._remote_ios:
            self._remote_ios = self.connect_to_remote()
            if not self._remote_ios:
                self.close_tunnel()
                return

        logging.info("handle_read(), local:%d, remote:%d, Handler:%r", 
                        self._ios.fileno(), self._remote_ios.fileno(), self)
        try:
            s = self.do_stream_read()
            if len(s) == 0:
                logging.debug('iostream[%s].read() return len(s) == 0, close it', self._fd)
                self.close_tunnel()

            return self.write_to_remote(s)

        except socket.error, _e:
            if _e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                # logging.debug('socket error, %s', _e)
                return
            else:
                raise

class LeftTunnelHandler(BaseTunnelHandler):
    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self._remote_ios = None

    def connect_to_remote(self):
        rfile = self._ios
        iv_len = self.encryptor.iv_len()
        if iv_len:
            self.decrypt(rfile.read(iv_len))
        addrtype = ord(self.decrypt(rfile.read(1)))
        if addrtype == 1:
            addr = socket.inet_ntoa(self.decrypt(rfile.read(4)))
        elif addrtype == 3:
            addr = self.decrypt(rfile.read(ord(self.decrypt(rfile.read(1)))))
        elif addrtype == 4:
            addr = socket.inet_ntop(socket.AF_INET6, self.decrypt(rfile.read(16)))
        else:
            # not supported
            logging.warn('addr_type not supported, maybe wrong password')
            return None
        port = struct.unpack('>H', self.decrypt(rfile.read(2)))[0]
        try:
            logging.info('connecting to remote %s:%d', addr, port)
            _start_time = time.time()
            remote_socket = socket.socket()
            remote_socket.connect((addr, port))
            remote_socket.setblocking(0)
            logging.info('cost time: %d', time.time()-_start_time)
        except socket.error, e:
            # Connection refused
            logging.warn(e)
            return None

        remote_ts = TunnelStream(remote_socket)
        handler = RightTunnelHandler( self._ios, self._ioloop, remote_ts)
        self._ioloop.add_handler(remote_ts.fileno(), handler, m_read=True, m_write=True) 
        logging.info('New tunnel %d <=> %d' % (self._ios.fileno(), remote_ts.fileno()))
        return remote_ts

    def do_stream_read(self, size=4096):
        """从客户端读"""
        return self.left_to_local(self._ios.read(size))

    def write_to_remote(self, data):
        """发送到目标服务器"""
        return self._remote_ios.write(data)

class RightTunnelHandler(BaseTunnelHandler):
    def __init__(self, remote_ios, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self._remote_ios = remote_ios

    def do_stream_read(self, size=4096):
        """从目标服务器读"""
        data = self._ios.read(size)
        # logging.debug('recv from right: %s', list(data))
        return data

    def write_to_remote(self, data):
        """发送到客户端"""
        data = self.local_to_left(data)
        # logging.debug('send to left: %s', list(data))
        self._remote_ios.write(data)

class MyAcceptHandler(ioloop.BaseHandler):
    def __init__(self, ioloop, srv_socket):
        self._ioloop = ioloop
        self._srv_socket = srv_socket

    def handle_read(self):
        cli_socket, cli_addr = self._srv_socket.accept()
        logging.debug("accept connect[%s] from %s:%s" % (
            cli_socket.fileno(), cli_addr[0], cli_addr[1]))
        cli_socket.setblocking(0)
        ts = TunnelStream(cli_socket)
        handler = LeftTunnelHandler( self._ioloop, ts)
        self._ioloop.add_handler(cli_socket.fileno(), handler, m_read=True, m_write=True) 

def main():
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s # %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    config = parse_options()

    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']

    config['method'] = config.get('method', None)
    METHOD = config.get('method')

    config['port_password'] = config.get('port_password', None)
    PORTPASSWORD = config.get('port_password')

    config['timeout'] = config.get('timeout', 600)

    if not KEY and not config_path:
        sys.exit('config not specified, please read https://github.com/clowwindy/shadowsocks')

    utils.check_config(config)

    global G_CONFIG
    G_CONFIG = config

    if PORTPASSWORD:
        if PORT or KEY:
            logging.warn('warning: port_password should not be used with server_port and password. server_port and password will be ignored')
    else:
        PORTPASSWORD = {}
        PORTPASSWORD[str(PORT)] = KEY

    encrypt.init_table(KEY, METHOD)

    io = ioloop.IOLoop()
    import socket
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(0)
    sock.bind((SERVER, PORT))
    logging.info("listing on %s", str(sock.getsockname()))
    sock.listen(1024)
    io.add_handler(sock.fileno(), MyAcceptHandler(io, sock), m_read=True)
    while True:
        io.wait_events(0.1)

global G_CONFIG 
if __name__ == '__main__':
    while 1: 
        try:
            main()
        except (socket.error, ioloop.IOLoopError), e:
            import traceback
            logging.error(traceback.format_exc())
            break
