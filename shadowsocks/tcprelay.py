#!/usr/bin/python
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

import time
import socket
import errno
import struct
import logging
import traceback
import random
import encrypt
import eventloop
import utils
from common import parse_header


TIMEOUTS_CLEAN_SIZE = 512
TIMEOUT_PRECISION = 4

MSG_FASTOPEN = 0x20000000

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

# local:
# stage 0 init
# stage 1 hello received, hello sent
# stage 2 UDP assoc
# stage 3 DNS
# stage 4 addr received, reply sent
# stage 5 remote connected

# remote:
# stage 0 init
# stage 3 DNS
# stage 4 addr received, reply sent
# stage 5 remote connected

STAGE_INIT = 0
STAGE_HELLO = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_REPLY = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# stream direction
STREAM_UP = 0
STREAM_DOWN = 1

# stream wait status
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024


class TCPRelayHandler(object):
    def __init__(self, server, fd_to_handlers, loop, local_sock, config,
                 dns_resolver, is_local):
        self._server = server
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._config = config
        self._dns_resolver = dns_resolver
        self._is_local = is_local
        self._stage = STAGE_INIT
        self._encryptor = encrypt.Encryptor(config['password'],
                                            config['method'])
        self._fastopen_connected = False
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT
        self._remote_address = None
        if is_local:
            self._chosen_server = self._get_a_server()
        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        loop.add(local_sock, eventloop.POLL_IN | eventloop.POLL_ERR)
        self.last_activity = 0
        self._update_activity()

    def __hash__(self):
        # default __hash__ is id / 16
        # we want to eliminate collisions
        return id(self)

    @property
    def remote_address(self):
        return self._remote_address

    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if type(server_port) == list:
            server_port = random.choice(server_port)
        logging.debug('chosen server: %s:%d', server, server_port)
        # TODO support multiple server IP
        return server, server_port

    def _update_activity(self):
        self._server.update_activity(self)

    def _update_stream(self, stream, status):
        dirty = False
        if stream == STREAM_DOWN:
            if self._downstream_status != status:
                self._downstream_status = status
                dirty = True
        elif stream == STREAM_UP:
            if self._upstream_status != status:
                self._upstream_status = status
                dirty = True
        if dirty:
            if self._local_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                if self._upstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                self._loop.modify(self._local_sock, event)
            if self._remote_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                if self._upstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                self._loop.modify(self._remote_sock, event)

    def _write_to_sock(self, data, sock):
        if not data or not sock:
            return False
        uncomplete = False
        try:
            l = len(data)
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True
        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                            errno.EWOULDBLOCK):
                uncomplete = True
            else:
                logging.error(e)
                if self._config['verbose']:
                    traceback.print_exc()
                self.destroy()
                return False
        if uncomplete:
            if sock == self._local_sock:
                self._data_to_write_to_local.append(data)
                self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)
            elif sock == self._remote_sock:
                self._data_to_write_to_remote.append(data)
                self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            else:
                logging.error('write_all_to_sock:unknown socket')
        else:
            if sock == self._local_sock:
                self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            else:
                logging.error('write_all_to_sock:unknown socket')
        return True

    def _handle_stage_reply(self, data):
        if self._is_local:
            data = self._encryptor.encrypt(data)
        self._data_to_write_to_remote.append(data)
        if self._is_local and not self._fastopen_connected and \
                self._config['fast_open']:
            try:
                self._fastopen_connected = True
                remote_sock = self._create_remote_socket(self._chosen_server[0],
                                                         self._chosen_server[1])
                self._loop.add(remote_sock, eventloop.POLL_ERR)
                data = ''.join(self._data_to_write_to_local)
                l = len(data)
                s = remote_sock.sendto(data, MSG_FASTOPEN, self._chosen_server)
                if s < l:
                    data = data[s:]
                    self._data_to_write_to_local = [data]
                    self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                else:
                    self._data_to_write_to_local = []
                    self._update_stream(STREAM_UP, WAIT_STATUS_READING)
                    self._stage = STAGE_STREAM
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                    self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                elif eventloop.errno_from_exception(e) == errno.ENOTCONN:
                    logging.error('fast open not supported on this OS')
                    self._config['fast_open'] = False
                    self.destroy()
                else:
                    logging.error(e)
                    if self._config['verbose']:
                        traceback.print_exc()
                    self.destroy()

    def _handle_stage_hello(self, data):
        try:
            if self._is_local:
                cmd = ord(data[1])
                if cmd == CMD_UDP_ASSOCIATE:
                    logging.debug('UDP associate')
                    if self._local_sock.family == socket.AF_INET6:
                        header = '\x05\x00\x00\x04'
                    else:
                        header = '\x05\x00\x00\x01'
                    addr, port = self._local_sock.getsockname()
                    addr_to_send = socket.inet_pton(self._local_sock.family,
                                                    addr)
                    port_to_send = struct.pack('>H', port)
                    self._write_to_sock(header + addr_to_send + port_to_send,
                                        self._local_sock)
                    self._stage = STAGE_UDP_ASSOC
                    # just wait for the client to disconnect
                    return
                elif cmd == CMD_CONNECT:
                    # just trim VER CMD RSV
                    data = data[3:]
                else:
                    logging.error('unknown command %d', cmd)
                    self.destroy()
                    return
            header_result = parse_header(data)
            if header_result is None:
                raise Exception('can not parse header')
            addrtype, remote_addr, remote_port, header_length = header_result
            logging.info('connecting %s:%d' % (remote_addr, remote_port))
            self._remote_address = (remote_addr, remote_port)
            # pause reading
            self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            self._stage = STAGE_DNS
            if self._is_local:
                # forward address to remote
                self._write_to_sock('\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10',
                                    self._local_sock)
                data_to_send = self._encryptor.encrypt(data)
                self._data_to_write_to_remote.append(data_to_send)
                # notice here may go into _handle_dns_resolved directly
                self._dns_resolver.resolve(self._chosen_server[0],
                                           self._handle_dns_resolved)
            else:
                if len(data) > header_length:
                    self._data_to_write_to_remote.append(data[header_length:])
                # notice here may go into _handle_dns_resolved directly
                self._dns_resolver.resolve(remote_addr,
                                           self._handle_dns_resolved)
        except Exception as e:
            logging.error(e)
            if self._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
            self.destroy()

    def _create_remote_socket(self, ip, port):
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM,
                                   socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip,  port))
        af, socktype, proto, canonname, sa = addrs[0]
        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock
        self._fd_to_handlers[remote_sock.fileno()] = self
        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        return remote_sock

    def _handle_dns_resolved(self, result, error):
        if error:
            logging.error(error)
            self.destroy()
            return
        if result:
            ip = result[1]
            if ip:
                try:
                    self._stage = STAGE_REPLY
                    remote_addr = ip
                    if self._is_local:
                        remote_port = self._chosen_server[1]
                    else:
                        remote_port = self._remote_address[1]

                    if self._is_local and self._config['fast_open']:
                        # wait for more data to arrive and send them in one SYN
                        self._stage = STAGE_REPLY
                        self._update_stream(STREAM_UP, WAIT_STATUS_READING)
                        # TODO when there is already data in this packet
                    else:
                        remote_sock = self._create_remote_socket(remote_addr,
                                                                 remote_port)
                        try:
                            remote_sock.connect((remote_addr, remote_port))
                        except (OSError, IOError) as e:
                            if eventloop.errno_from_exception(e) == \
                                    errno.EINPROGRESS:
                                pass
                        self._loop.add(remote_sock,
                                       eventloop.POLL_ERR | eventloop.POLL_OUT)
                        self._stage = STAGE_REPLY
                        self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                        self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
                    return
                except (OSError, IOError) as e:
                    logging.error(e)
                    if self._config['verbose']:
                        traceback.print_exc()
        self.destroy()

    def _on_local_read(self):
        self._update_activity()
        if not self._local_sock:
            return
        is_local = self._is_local
        data = None
        try:
            data = self._local_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in \
                    (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        if not is_local:
            data = self._encryptor.decrypt(data)
            if not data:
                return
        if self._stage == STAGE_STREAM:
            if self._is_local:
                data = self._encryptor.encrypt(data)
            self._write_to_sock(data, self._remote_sock)
            return
        elif is_local and self._stage == STAGE_INIT:
            # TODO check auth method
            self._write_to_sock('\x05\00', self._local_sock)
            self._stage = STAGE_HELLO
            return
        elif self._stage == STAGE_REPLY:
            self._handle_stage_reply(data)
        elif (is_local and self._stage == STAGE_HELLO) or \
                (not is_local and self._stage == STAGE_INIT):
            self._handle_stage_hello(data)

    def _on_remote_read(self):
        self._update_activity()
        data = None
        try:
            data = self._remote_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in \
                    (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        if self._is_local:
            data = self._encryptor.decrypt(data)
        else:
            data = self._encryptor.encrypt(data)
        try:
            self._write_to_sock(data, self._local_sock)
        except Exception as e:
            logging.error(e)
            if self._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
            self.destroy()

    def _on_local_write(self):
        if self._data_to_write_to_local:
            data = ''.join(self._data_to_write_to_local)
            self._data_to_write_to_local = []
            self._write_to_sock(data, self._local_sock)
        else:
            self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

    def _on_remote_write(self):
        self._stage = STAGE_STREAM
        if self._data_to_write_to_remote:
            data = ''.join(self._data_to_write_to_remote)
            self._data_to_write_to_remote = []
            self._write_to_sock(data, self._remote_sock)
        else:
            self._update_stream(STREAM_UP, WAIT_STATUS_READING)

    def _on_local_error(self):
        logging.debug('got local error')
        if self._local_sock:
            logging.error(eventloop.get_sock_error(self._local_sock))
        self.destroy()

    def _on_remote_error(self):
        logging.debug('got remote error')
        if self._remote_sock:
            logging.error(eventloop.get_sock_error(self._remote_sock))
        self.destroy()

    def handle_event(self, sock, event):
        if self._stage == STAGE_DESTROYED:
            logging.debug('ignore handle_event: destroyed')
            return
        # order is important
        if sock == self._remote_sock:
            if event & eventloop.POLL_ERR:
                self._on_remote_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_remote_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_remote_write()
        elif sock == self._local_sock:
            if event & eventloop.POLL_ERR:
                self._on_local_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_local_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_local_write()
        else:
            logging.warn('unknown socket')

    def destroy(self):
        if self._stage == STAGE_DESTROYED:
            logging.debug('already destroyed')
            return
        self._stage = STAGE_DESTROYED
        if self._remote_address:
            logging.debug('destroy: %s:%d' %
                          self._remote_address)
        else:
            logging.debug('destroy')
        if self._remote_sock:
            logging.debug('destroying remote')
            self._loop.remove(self._remote_sock)
            del self._fd_to_handlers[self._remote_sock.fileno()]
            self._remote_sock.close()
            self._remote_sock = None
        if self._local_sock:
            logging.debug('destroying local')
            self._loop.remove(self._local_sock)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        self._dns_resolver.remove_callback(self._handle_dns_resolved)
        self._server.remove_handler(self)


class TCPRelay(object):
    def __init__(self, config, dns_resolver, is_local):
        self._config = config
        self._is_local = is_local
        self._dns_resolver = dns_resolver
        self._closed = False
        self._eventloop = None
        self._fd_to_handlers = {}
        self._last_time = time.time()

        self._timeout = config['timeout']
        self._timeouts = []  # a list for all the handlers
        self._timeout_offset = 0  # last checked position for timeout
                                  # we trim the timeouts once a while
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        if is_local:
            listen_addr = config['local_address']
            listen_port = config['local_port']
        else:
            listen_addr = config['server']
            listen_port = config['server_port']

        addrs = socket.getaddrinfo(listen_addr, listen_port, 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (listen_addr, listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)
        if config['fast_open']:
            try:
                server_socket.setsockopt(socket.SOL_TCP, 23, 5)
            except socket.error:
                logging.error('warning: fast open is not available')
                self._config['fast_open'] = False
        server_socket.listen(1024)
        self._server_socket = server_socket

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        loop.add_handler(self._handle_events)

        self._eventloop.add(self._server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR)

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def update_activity(self, handler):
        """ set handler to active """
        now = int(time.time())
        if now - handler.last_activity < TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
        length = len(self._timeouts)
        self._timeouts.append(handler)
        self._handler_to_timeouts[hash(handler)] = length

    def _sweep_timeout(self):
        # tornado's timeout memory management is more flexible than we need
        # we just need a sorted last_activity queue and it's faster than heapq
        # in fact we can do O(1) insertion/remove so we invent our own
        if self._timeouts:
            logging.log(utils.VERBOSE_LEVEL, 'sweeping timeouts')
            now = time.time()
            length = len(self._timeouts)
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeout:
                        break
                    else:
                        if handler.remote_address:
                            logging.warn('timed out: %s:%d' %
                                         handler.remote_address)
                        else:
                            logging.warn('timed out')
                        handler.destroy()
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                # clean up the timeout queue when it gets larger than half
                # of the queue
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos

    def _handle_events(self, events):
        for sock, fd, event in events:
            if sock:
                logging.log(utils.VERBOSE_LEVEL, 'fd %d %s', fd,
                            eventloop.EVENT_NAMES.get(event, event))
            if sock == self._server_socket:
                if event & eventloop.POLL_ERR:
                    # TODO
                    raise Exception('server_socket error')
                try:
                    logging.debug('accept')
                    conn = self._server_socket.accept()
                    TCPRelayHandler(self, self._fd_to_handlers, self._eventloop,
                                    conn[0], self._config, self._dns_resolver,
                                    self._is_local)
                except (OSError, IOError) as e:
                    error_no = eventloop.errno_from_exception(e)
                    if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                    errno.EWOULDBLOCK):
                        continue
                    else:
                        logging.error(e)
                        if self._config['verbose']:
                            traceback.print_exc()
            else:
                if sock:
                    handler = self._fd_to_handlers.get(fd, None)
                    if handler:
                        handler.handle_event(sock, event)
                else:
                    logging.warn('poll removed fd')

        now = time.time()
        if now - self._last_time > TIMEOUT_PRECISION:
            self._sweep_timeout()
            self._last_time = now

    def close(self):
        self._closed = True
        self._server_socket.close()
