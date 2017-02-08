#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import errno
import logging
import socket

from shadowsocks.selectors import (EVENT_READ, EVENT_WRITE, EVENT_ERROR,
                                   errno_from_exception, get_sock_error)
from shadowsocks.common import parse_header, to_str
from shadowsocks import encrypt


BUF_SIZE = 32 * 1024
CMD_CONNECT = 1


def create_sock(ip, port):
    addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM,
                               socket.SOL_TCP)
    if len(addrs) == 0:
        raise Exception("Getaddrinfo failed for %s:%d" % (ip, port))

    af, socktype, proto, canonname, sa = addrs[0]
    sock = socket.socket(af, socktype, proto)
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    return sock


class TcpRelayHanler(object):

    def __init__(self, local_sock, local_addr, remote_addr=None,
                 dns_resolver=None):
        self._loop = None
        self._local_sock = local_sock
        self._local_addr = local_addr
        self._remote_addr = remote_addr
        # self._crypt = None
        self._crypt = encrypt.Encryptor(b'PassThrouthGFW', 'aes-256-cfb')
        self._dns_resolver = dns_resolver
        self._remote_sock = None
        self._local_sock_mode = 0
        self._remote_sock_mode = 0
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._id = id(self)

    def handle_event(self, sock, event, call, *args):
        if event & EVENT_ERROR:
            logging.error(get_sock_error(sock))
            self.close()
        else:
            try:
                call(sock, event, *args)
            except Exception as e:
                logging.error(e)
                self.close()

    def __del__(self):
        logging.debug('Deleting {}'.format(self._id))

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('Already added to loop')
        self._loop = loop
        loop.add(self._local_sock, EVENT_READ, (self, self.start))

    def modify_local_sock_mode(self, event):
        if self._local_sock_mode != event:
            self._local_sock_mode = self.modify_sock_mode(self._local_sock,
                                                          event)

    def modify_remote_sock_mode(self, event):
        if self._remote_sock_mode != event:
            self._remote_sock_mode = self.modify_sock_mode(self._remote_sock,
                                                           event)

    def modify_sock_mode(self, sock, event):
        key = self._loop.modify(sock, event, (self, self.stream))
        return key.events

    def close_sock(self, sock):
        self._loop.remove(sock)
        sock.close()

    def close(self):
        if self._local_sock:
            self.close_sock(self._local_sock)
            self._local_sock = None
        if self._remote_sock:
            self.close_sock(self._remote_sock)
            self._remote_sock = None

    def sock_connect(self, sock, addr):
        while True:
            try:
                sock.connect(addr)
            except (OSError, IOError) as e:
                err = errno_from_exception(e)
                if err == errno.EINTR:
                    pass
                elif err == errno.EINPROGRESS:
                    break
                else:
                    raise
            else:
                break

    def sock_recv(self, sock, size=BUF_SIZE):
        try:
            data = sock.recv(size)
            if not data:
                self.close()
        except (OSError, IOError) as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK,
                                           errno.EINTR):
                return
            else:
                raise
        return data

    def sock_send(self, sock, data):
        try:
            s = sock.send(data)
            data = data[s:]
        except (OSError, IOError) as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EWOULDBLOCK,
                                           errno.EINPROGRESS, errno.EINTR):
                pass
            else:
                raise

        return data

    def on_local_read(self, size=BUF_SIZE):
        logging.debug('on_local_read')
        if not self._local_sock:
            return

        data = self.sock_recv(self._local_sock, size)
        if not data:
            return

        logging.debug('Received {} bytes from {}:{}'.format(len(data),
                                                            *self._local_addr))
        if self._crypt:
            if self._is_client:
                data = self._crypt.encrypt(data)
            else:
                data = self._crypt.decrypt(data)

        if data:
            self._data_to_write_to_remote.append(data)
            self.on_remote_write()

    def on_remote_read(self, size=BUF_SIZE):
        logging.debug('on_remote_read')
        if not self._remote_sock:
            return

        data = self.sock_recv(self._remote_sock, size)
        if not data:
            return

        logging.debug('Received {} bytes from {}:{}'.format(
            len(data), *self._remote_addr))

        if self._crypt:
            if self._is_client:
                data = self._crypt.decrypt(data)
            else:
                data = self._crypt.encrypt(data)

        if data:
            self._data_to_write_to_local.append(data)
            self.on_local_write()

    def on_local_write(self):
        logging.debug('on_local_write')
        if not self._local_sock:
            return

        if not self._data_to_write_to_local:
            self.modify_local_sock_mode(EVENT_READ)
            return

        data = b''.join(self._data_to_write_to_local)
        self._data_to_write_to_local = []

        data = self.sock_send(self._local_sock, data)

        if data:
            self._data_to_write_to_local.append(data)
            self.modify_local_sock_mode(EVENT_WRITE)
        else:
            self.modify_local_sock_mode(EVENT_READ)

    def on_remote_write(self):
        logging.debug('on_remote_write')
        if not self._remote_sock:
            return

        if not self._data_to_write_to_remote:
            self.modify_remote_sock_mode(EVENT_READ)
            return

        data = b''.join(self._data_to_write_to_remote)
        self._data_to_write_to_remote = []

        data = self.sock_send(self._remote_sock, data)

        if data:
            self._data_to_write_to_remote.append(data)
            self.modify_remote_sock_mode(EVENT_WRITE)
        else:
            self.modify_remote_sock_mode(EVENT_READ)

    def stream(self, sock, event):
        logging.debug('stream')

        if sock == self._local_sock:
            if event & EVENT_READ:
                self.on_local_read()
            if event & EVENT_WRITE:
                self.on_local_write()
        elif sock == self._remote_sock:
            if event & EVENT_READ:
                self.on_remote_read()
            if event & EVENT_WRITE:
                self.on_remote_write()
        else:
            logging.warn('Unknow sock {}'.format(sock))


class TcpRelayClientHanler(TcpRelayHanler):

    _is_client = True

    def start(self, sock, event):
        data = self.sock_recv(sock)
        if not data:
            return
        reply = b'\x05\x00'
        self.send_reply(sock, None, reply)

    def send_reply(self, sock, event, data):
        data = self.sock_send(sock, data)
        if data:
            self._loop.modify(sock, EVENT_WRITE, (self, self.send_reply, data))
        else:
            self._loop.modify(sock, EVENT_READ, (self, self.handle_addr))

    def handle_addr(self, sock, event):
        data = self.sock_recv(sock)
        if not data:
            return
        # self._loop.remove(sock)

        if ord(data[1:2]) != CMD_CONNECT:
            raise Exception('Command not suppored')

        result = parse_header(data[3:])
        if not result:
            raise Exception('Header cannot be parsed')

        self._remote_sock = create_sock(*self._remote_addr)
        self.sock_connect(self._remote_sock, self._remote_addr)

        dest_addr = (to_str(result[1]), result[2])
        logging.info('Connecting to {}:{}'.format(*dest_addr))
        data = '{}:{}\n'.format(*dest_addr).encode('utf-8')
        if self._crypt:
            data = self._crypt.encrypt(data)
        self._data_to_write_to_remote.append(data)

        bind_addr = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        self.send_bind_addr(sock, None, bind_addr)

    def send_bind_addr(self, sock, event, data):
        data = self.sock_send(sock, data)
        if data:
            self._loop.modify(sock, EVENT_WRITE, (self, self.send_bind_addr,
                                                  data))
        else:
            self.modify_local_sock_mode(EVENT_READ)


class TcpRelayServerHandler(TcpRelayHanler):

    _is_client = False

    def start(self, sock, event, data=None):
        data = self.sock_recv(sock)
        if not data:
            return
        self._loop.remove(sock)

        if self._crypt:
            data = self._crypt.decrypt(data)
        remote, data = data.split(b'\n', 1)
        host, port = remote.split(b':')
        self._remote = (host, int(port))
        self._data_to_write_to_remote.append(data)
        self._dns_resolver.resolve(host, self.dns_resolved)

    def dns_resolved(self, result, error):
        try:
            ip = result[1]
        except (TypeError, IndexError):
            ip = None

        if not ip:
            raise Exception('Hostname {} cannot resolved'.format(
                self._remote[0]))

        self._remote_addr = (ip, self._remote[1])
        self._remote_sock = create_sock(*self._remote_addr)
        logging.info('Connecting to {}'.format(self._remote[0]))
        self.sock_connect(self._remote_sock, self._remote_addr)
        self.modify_remote_sock_mode(EVENT_WRITE)
        self.modify_local_sock_mode(EVENT_READ)


class TcpRelay(object):

    def __init__(self, handler_type, listen_addr, remote_addr=None,
                 dns_resolver=None):
        self._loop = None
        self._handler_type = handler_type
        self._listen_addr = listen_addr
        self._remote_addr = remote_addr
        self._dns_resolver = dns_resolver
        self._create_listen_sock()

    def _create_listen_sock(self):
        sock = create_sock(*self._listen_addr)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(self._listen_addr)
        sock.listen(1024)
        self._listen_sock = sock
        logging.info('Listening on {}:{}'.format(*self._listen_addr))

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('Already added to loop')
        self._loop = loop
        loop.add(self._listen_sock, EVENT_READ, (self, self.accept))

    def _accept(self, listen_sock):
        try:
            sock, addr = listen_sock.accept()
        except (OSError, IOError) as e:
            if errno_from_exception(e) in (
                errno.EAGAIN, errno.EWOULDBLOCK, errno.EINPROGRESS,
                errno.EINTR, errno.ECONNABORTED
            ):
                pass
            else:
                raise
        logging.info('Connected from {}:{}'.format(*addr))
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        return (sock, addr)

    def accept(self, listen_sock, event):
        sock, addr = self._accept(listen_sock)
        handler = self._handler_type(sock, addr, self._remote_addr,
                                     self._dns_resolver)
        handler.add_to_loop(self._loop)

    def close(self):
        self._loop.remove(self._listen_sock)

    def handle_event(self, sock, event, call, *args):
        if event & EVENT_ERROR:
            logging.error(get_sock_error(sock))
            self.close()
        else:
            try:
                call(sock, event, *args)
            except Exception as e:
                logging.error(e)
                self.close()
