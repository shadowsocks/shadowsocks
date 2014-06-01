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
import logging
import encrypt
import errno
import threading
import eventloop
from common import parse_header


# local:
# stage 0 init
# stage 1 hello received, hello sent
# stage 4 addr received, reply sent
# stage 5 remote connected

# remote:
# stage 0 init
# stage 4 addr received, reply sent
# stage 5 remote connected


BUF_SIZE = 8 * 1024


class TCPRelayHandler(object):
    def __init__(self, fd_to_handlers, loop, local_sock, config, is_local):
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._config = config
        self._is_local = is_local
        self._stage = 0
        self._encryptor = encrypt.Encryptor(config['password'],
                                            config['method'])
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        loop.add(local_sock, eventloop.POLL_IN)

    def resume_reading(self, sock):
        pass

    def pause_reading(self, sock):
        pass

    def resume_writing(self, sock):
        pass

    def pause_writing(self, sock):
        pass

    def write_all_to_sock(self, data, sock):
        # write to sock
        # put remaining bytes into buffer
        # return true if all written
        # return false if some bytes left in buffer
        # raise if encounter error
        return True

    def on_local_read(self):
        if not self._local_sock:
            return
        is_local = self._is_local
        data = self._local_sock.recv(BUF_SIZE)
        if not is_local:
            data = self._encryptor.decrypt(data)
        if self._stage == 5:
            if self._is_local:
                data = self._encryptor.encrypt(data)
            if not self.write_all_to_sock(data, self._remote_sock):
                self.pause_reading(self._local_sock)
            return
        if is_local and self._stage == 0:
            # TODO check auth method
            self.write_all_to_sock('\x05\00', self._local_sock)
            self._stage = 1
            return
        if self._stage == 4:
            self._data_to_write_to_remote.append(data)
        if (is_local and self._stage == 0) or \
                (not is_local and self._stage == 1):
            try:
                if is_local:
                    cmd = ord(data[1])
                    # TODO check cmd == 1
                    assert cmd == 1
                    # just trim VER CMD RSV
                    data = data[3:]
                header_result = parse_header(data)
                if header_result is None:
                    raise Exception('can not parse header')
                addrtype, remote_addr, remote_port, header_length =\
                    header_result
                logging.info('connecting %s:%d' % (remote_addr, remote_port))
                if is_local:
                    # forward address to remote
                    self._data_to_write_to_remote.append(data[:header_length])
                    self.write_all_to_sock('\x05\x00\x00\x01' +
                                           '\x00\x00\x00\x00\x10\x10',
                                           self._local_sock)
                else:
                    remote_addr = self._config['server']
                    remote_port = self._config['server_port']

                # TODO async DNS
                addrs = socket.getaddrinfo(remote_addr, remote_port, 0,
                                           socket.SOCK_STREAM, socket.SOL_TCP)
                if len(addrs) == 0:
                    raise Exception("can't get addrinfo for %s:%d" %
                                    (remote_addr, remote_port))
                af, socktype, proto, canonname, sa = addrs[0]
                self._remote_sock = socket.socket(af, socktype, proto)
                self._remote_sock.setblocking(False)
                # TODO support TCP fast open
                self._remote_sock.connect(sa)
                self._loop.add(self._remote_sock, eventloop.POLL_OUT)

                if len(data) > header_length:
                    self._data_to_write_to_remote.append(data[header_length:])

                self._stage = 4
                self.pause_reading(self._local_sock)
                return
            except Exception:
                import traceback
                traceback.print_exc()
                # TODO use logging when debug completed
                self.destroy()

        if self._stage == 4:
            self._data_to_write_to_remote.append(data)

    def on_remote_read(self):
        data = self._remote_sock.recv(BUF_SIZE)
        if self._is_local:
            data = self._encryptor.decrypt(data)
        try:
            if not self.write_all_to_sock(data, self._local_sock):
                self.pause_reading(self._remote_sock)
                self.resume_writing(self._local_sock)
        except Exception:
            import traceback
            traceback.print_exc()
            # TODO use logging when debug completed
            self.destroy()

    def on_local_write(self):
        if self._data_to_write_to_local:
            written = self.write_all_to_sock(
                ''.join(self._data_to_write_to_local), self._local_sock)
            if written:
                self.pause_writing(self._local_sock)
        else:
            self.pause_writing(self._local_sock)

    def on_remote_write(self):
        if self._data_to_write_to_remote:
            written = self.write_all_to_sock(
                ''.join(self._data_to_write_to_remote), self._remote_sock)
            if written:
                self.pause_writing(self._remote_sock)
        else:
            self.pause_writing(self._remote_sock)

    def on_local_error(self):
        self.destroy()

    def on_remote_error(self):
        self.destroy()

    def handle_event(self, sock, event):
        # order is important
        if sock == self._remote_sock:
            if event & eventloop.POLL_IN:
                self.on_remote_read()
            if event & eventloop.POLL_OUT:
                self.on_remote_write()
            if event & eventloop.POLL_ERR:
                self.on_remote_error()
        elif sock == self._local_sock:
            if event & eventloop.POLL_IN:
                self.on_local_read()
            if event & eventloop.POLL_OUT:
                self.on_local_write()
            if event & eventloop.POLL_ERR:
                self.on_local_error()
        else:
            logging.warn('unknown socket')

    def destroy(self):
        if self._remote_sock:
            self._remote_sock.close()
            self._loop.remove(self._remote_sock)
            del self._fd_to_handlers[self._remote_sock.fileno()]
            self._remote_sock = None
        if self._local_sock:
            self._local_sock.close()
            self._loop.remove(self._local_sock)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock = None


class TCPRelay(object):
    def __init__(self, config, is_local):
        self._config = config
        self._is_local = is_local
        self._closed = False
        self._thread = None
        self._fd_to_handlers = {}

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
        server_socket.bind(sa)
        server_socket.setblocking(False)
        server_socket.listen(1024)
        self._server_socket = server_socket

    def _run(self):
        server_socket = self._server_socket
        self._eventloop = eventloop.EventLoop()
        self._eventloop.add(server_socket, eventloop.POLL_IN)
        last_time = time.time()
        while not self._closed:
            try:
                events = self._eventloop.poll(1)
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == errno.EPIPE:
                    # Happens when the client closes the connection
                    continue
                else:
                    logging.error(e)
                    continue
            for sock, event in events:
                if sock == self._server_socket:
                    try:
                        conn = self._server_socket.accept()
                        TCPRelayHandler(self._fd_to_handlers, self._eventloop,
                                        conn, self._config, self._is_local)
                    except (OSError, IOError) as e:
                        error_no = eventloop.errno_from_exception(e)
                        if error_no in [errno.EAGAIN, errno.EINPROGRESS]:
                            continue
                else:
                    handler = self._fd_to_handlers.get(sock.fileno(), None)
                    if handler:
                        handler.handle_event(sock, event)
                    else:
                        logging.warn('can not find handler for fd %d',
                                     sock.fileno())
            now = time.time()
            if now - last_time > 5:
                # TODO sweep timeouts
                last_time = now

    def start(self):
        if self._closed:
            raise Exception('closed')
        t = threading.Thread(target=self._run)
        t.setName('UDPThread')
        t.setDaemon(False)
        t.start()
        self._thread = t

    def close(self):
        self._closed = True
        self._server_socket.close()

    def thread(self):
        return self._thread