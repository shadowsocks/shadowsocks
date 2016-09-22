#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import socket
import errno
import struct
import logging
import binascii
import traceback
import random
import platform

from shadowsocks import encrypt, obfs, eventloop, shell, common
from shadowsocks.common import pre_parse_header, parse_header

# we clear at most TIMEOUTS_CLEAN_SIZE timeouts each time
TIMEOUTS_CLEAN_SIZE = 512

MSG_FASTOPEN = 0x20000000

# SOCKS command definition
CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

# for each opening port, we have a TCP Relay

# for each connection, we have a TCP Relay Handler to handle the connection

# for each handler, we have 2 sockets:
#    local:   connected to the client
#    remote:  connected to remote server

# for each handler, it could be at one of several stages:

# as sslocal:
# stage 0 SOCKS hello received from local, send hello to local
# stage 1 addr received from local, query DNS for remote
# stage 2 UDP assoc
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

# as ssserver:
# stage 0 just jump to stage 1
# stage 1 addr received from local, query DNS for remote
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# for each handler, we have 2 stream directions:
#    upstream:    from client to server direction
#                 read local and write to remote
#    downstream:  from server to client direction
#                 read remote and write to local

STREAM_UP = 0
STREAM_DOWN = 1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024
UDP_MAX_BUF_SIZE = 65536

class TCPRelayHandler(object):
    def __init__(self, server, fd_to_handlers, loop, local_sock, config,
                 dns_resolver, is_local):
        self._server = server
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._remote_sock_v6 = None
        self._remote_udp = False
        self._config = config
        self._dns_resolver = dns_resolver
        self._client_address = local_sock.getpeername()[:2]
        self._accept_address = local_sock.getsockname()[:2]

        # TCP Relay works as either sslocal or ssserver
        # if is_local, this is sslocal
        self._is_local = is_local
        self._stage = STAGE_INIT
        try:
            self._encryptor = encrypt.Encryptor(config['password'],
                                                config['method'])
        except Exception:
            self._stage = STAGE_DESTROYED
            logging.error('create encryptor fail at port %d', server._listen_port)
            return
        self._encrypt_correct = True
        self._obfs = obfs.obfs(config['obfs'])
        server_info = obfs.server_info(server.obfs_data)
        server_info.host = config['server']
        server_info.port = server._listen_port
        server_info.client = self._client_address[0]
        server_info.client_port = self._client_address[1]
        server_info.protocol_param = ''
        server_info.obfs_param = config['obfs_param']
        server_info.iv = self._encryptor.cipher_iv
        server_info.recv_iv = b''
        server_info.key = self._encryptor.cipher_key
        server_info.head_len = 30
        server_info.tcp_mss = 1460
        self._obfs.set_server_info(server_info)

        self._protocol = obfs.obfs(config['protocol'])
        server_info = obfs.server_info(server.protocol_data)
        server_info.host = config['server']
        server_info.port = server._listen_port
        server_info.client = self._client_address[0]
        server_info.client_port = self._client_address[1]
        server_info.protocol_param = config['protocol_param']
        server_info.obfs_param = ''
        server_info.iv = self._encryptor.cipher_iv
        server_info.recv_iv = b''
        server_info.key = self._encryptor.cipher_key
        server_info.head_len = 30
        server_info.tcp_mss = 1460
        self._protocol.set_server_info(server_info)

        self._redir_list = config.get('redirect', ["0.0.0.0:0"])
        self._bind = config.get('out_bind', '')
        self._bindv6 = config.get('out_bindv6', '')
        self._ignore_bind_list = config.get('ignore_bind', [])

        self._fastopen_connected = False
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._udp_data_send_buffer = b''
        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT
        self._remote_address = None
        if 'forbidden_ip' in config:
            self._forbidden_iplist = config['forbidden_ip']
        else:
            self._forbidden_iplist = None
        if 'forbidden_port' in config:
            self._forbidden_portset = config['forbidden_port']
        else:
            self._forbidden_portset = None
        if is_local:
            self._chosen_server = self._get_a_server()
        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        loop.add(local_sock, eventloop.POLL_IN | eventloop.POLL_ERR,
                 self._server)
        self.last_activity = 0
        self._update_activity()
        self._server.add_connection(1)
        self._server.stat_add(self._client_address[0], 1)

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
        if type(server) == list:
            server = random.choice(server)
        logging.debug('chosen server: %s:%d', server, server_port)
        return server, server_port

    def _update_activity(self, data_len=0):
        # tell the TCP Relay we have activities recently
        # else it will think we are inactive and timed out
        self._server.update_activity(self, data_len)

    def _update_stream(self, stream, status):
        # update a stream to a new waiting status

        # check if status is changed
        # only update if dirty
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
                if self._remote_sock_v6:
                    self._loop.modify(self._remote_sock_v6, event)

    def _write_to_sock(self, data, sock):
        # write data to sock
        # if only some of the data are written, put remaining in the buffer
        # and update the stream to wait for writing
        if not sock:
            return False
        #logging.debug("_write_to_sock %s %s %s" % (self._remote_sock, sock, self._remote_udp))
        uncomplete = False
        if self._remote_udp and sock == self._remote_sock:
            try:
                self._udp_data_send_buffer += data
                #logging.info('UDP over TCP sendto %d %s' % (len(data), binascii.hexlify(data)))
                while len(self._udp_data_send_buffer) > 6:
                    length = struct.unpack('>H', self._udp_data_send_buffer[:2])[0]
                    if length >= 0xff00:
                        length = struct.unpack('>H', self._udp_data_send_buffer[1:3])[0] + 0xff00

                    if length > len(self._udp_data_send_buffer):
                        break

                    data = self._udp_data_send_buffer[:length]
                    if length >= 0xff00:
                        data = data[1:]
                    self._udp_data_send_buffer = self._udp_data_send_buffer[length:]

                    frag = common.ord(data[2])
                    if frag != 0:
                        logging.warn('drop a message since frag is %d' % (frag,))
                        continue
                    else:
                        data = data[3:]
                    header_result = parse_header(data)
                    if header_result is None:
                        continue
                    connecttype, dest_addr, dest_port, header_length = header_result
                    addrs = socket.getaddrinfo(dest_addr, dest_port, 0,
                            socket.SOCK_DGRAM, socket.SOL_UDP)
                    #logging.info('UDP over TCP sendto %s:%d %d bytes from %s:%d' % (dest_addr, dest_port, len(data), self._client_address[0], self._client_address[1]))
                    if addrs:
                        af, socktype, proto, canonname, server_addr = addrs[0]
                        data = data[header_length:]
                        if af == socket.AF_INET6:
                            self._remote_sock_v6.sendto(data, (server_addr[0], dest_port))
                        else:
                            sock.sendto(data, (server_addr[0], dest_port))

            except Exception as e:
                #trace = traceback.format_exc()
                #logging.error(trace)
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    uncomplete = True
                else:
                    shell.print_exception(e)
                    logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
                    self.destroy()
                    return False
            return True
        else:
            try:
                if self._encrypt_correct:
                    if sock == self._remote_sock:
                        self._server.server_transfer_ul += len(data)
                        self._update_activity(len(data))
                if data:
                    l = len(data)
                    s = sock.send(data)
                    if s < l:
                        data = data[s:]
                        uncomplete = True
                else:
                    return
            except (OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    uncomplete = True
                else:
                    #traceback.print_exc()
                    shell.print_exception(e)
                    logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
                    self.destroy()
                    return False
            except Exception as e:
                shell.print_exception(e)
                logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
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
                logging.error('write_all_to_sock:unknown socket from %s:%d' % (self._client_address[0], self._client_address[1]))
        else:
            if sock == self._local_sock:
                self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            else:
                logging.error('write_all_to_sock:unknown socket from %s:%d' % (self._client_address[0], self._client_address[1]))
        return True

    def _get_redirect_host(self, client_address, ogn_data):
        host_list = self._redir_list or ["0.0.0.0:0"]
        hash_code = binascii.crc32(ogn_data)
        addrs = socket.getaddrinfo(client_address[0], client_address[1], 0, socket.SOCK_STREAM, socket.SOL_TCP)
        af, socktype, proto, canonname, sa = addrs[0]
        address_bytes = common.inet_pton(af, sa[0])
        if af == socket.AF_INET6:
            addr = struct.unpack('>Q', address_bytes[8:])[0]
        elif af == socket.AF_INET:
            addr = struct.unpack('>I', address_bytes)[0]
        else:
            addr = 0

        host_port = []
        match_port = False
        if type(host_list) != list:
            host_list = [host_list]
        for host in host_list:
            items = common.to_str(host).rsplit(':', 1)
            if len(items) > 1:
                try:
                    port = int(items[1])
                    if port == self._server._listen_port:
                        match_port = True
                    host_port.append((items[0], port))
                except:
                    pass
            else:
                host_port.append((host, 80))

        if match_port:
            last_host_port = host_port
            host_port = []
            for host in last_host_port:
                if host[1] == self._server._listen_port:
                    host_port.append(host)

        return host_port[((hash_code & 0xffffffff) + addr) % len(host_port)]

    def _handel_protocol_error(self, client_address, ogn_data):
        logging.warn("Protocol ERROR, TCP ogn data %s from %s:%d via port %d" % (binascii.hexlify(ogn_data), client_address[0], client_address[1], self._server._listen_port))
        self._encrypt_correct = False
        #create redirect or disconnect by hash code
        host, port = self._get_redirect_host(client_address, ogn_data)
        if port == 0:
            raise Exception('can not parse header')
        data = b"\x03" + common.to_bytes(common.chr(len(host))) + common.to_bytes(host) + struct.pack('>H', port)
        logging.warn("TCP data redir %s:%d %s" % (host, port, binascii.hexlify(data)))
        return data + ogn_data

    def _handle_stage_connecting(self, data):
        if self._is_local:
            if self._encryptor is not None:
                data = self._protocol.client_pre_encrypt(data)
                data = self._encryptor.encrypt(data)
                data = self._obfs.client_encode(data)
        if data:
            self._data_to_write_to_remote.append(data)
        if self._is_local and not self._fastopen_connected and \
                self._config['fast_open']:
            # for sslocal and fastopen, we basically wait for data and use
            # sendto to connect
            try:
                # only connect once
                self._fastopen_connected = True
                remote_sock = \
                    self._create_remote_socket(self._chosen_server[0],
                                               self._chosen_server[1])
                self._loop.add(remote_sock, eventloop.POLL_ERR, self._server)
                data = b''.join(self._data_to_write_to_remote)
                l = len(data)
                s = remote_sock.sendto(data, MSG_FASTOPEN, self._chosen_server)
                if s < l:
                    data = data[s:]
                    self._data_to_write_to_remote = [data]
                else:
                    self._data_to_write_to_remote = []
                self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                    # in this case data is not sent at all
                    self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                elif eventloop.errno_from_exception(e) == errno.ENOTCONN:
                    logging.error('fast open not supported on this OS')
                    self._config['fast_open'] = False
                    self.destroy()
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
                    logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
                    self.destroy()

    def _get_head_size(self, buf, def_value):
        if len(buf) < 2:
            return def_value
        head_type = common.ord(buf[0]) & 0xF
        if head_type == 1:
            return 7
        if head_type == 4:
            return 19
        if head_type == 3:
            return 4 + common.ord(buf[1])
        return def_value

    def _handle_stage_addr(self, ogn_data, data):
        try:
            if self._is_local:
                cmd = common.ord(data[1])
                if cmd == CMD_UDP_ASSOCIATE:
                    logging.debug('UDP associate')
                    if self._local_sock.family == socket.AF_INET6:
                        header = b'\x05\x00\x00\x04'
                    else:
                        header = b'\x05\x00\x00\x01'
                    addr, port = self._local_sock.getsockname()[:2]
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

            before_parse_data = data
            if self._is_local:
                header_result = parse_header(data)
            else:
                data = pre_parse_header(data)
                if data is None:
                    data = self._handel_protocol_error(self._client_address, ogn_data)
                header_result = parse_header(data)
                if header_result is not None:
                    try:
                        common.to_str(header_result[1])
                    except Exception as e:
                        header_result = None
                if header_result is None:
                    data = self._handel_protocol_error(self._client_address, ogn_data)
                    header_result = parse_header(data)
            connecttype, remote_addr, remote_port, header_length = header_result
            common.connect_log('%s connecting %s:%d via port %d' %
                        ((connecttype == 0) and 'TCP' or 'UDP',
                            common.to_str(remote_addr), remote_port, self._server._listen_port))
            self._remote_address = (common.to_str(remote_addr), remote_port)
            self._remote_udp = (connecttype != 0)
            # pause reading
            self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            self._stage = STAGE_DNS
            if self._is_local:
                # forward address to remote
                self._write_to_sock((b'\x05\x00\x00\x01'
                                     b'\x00\x00\x00\x00\x10\x10'),
                                    self._local_sock)
                head_len = self._get_head_size(data, 30)
                self._obfs.obfs.server_info.head_len = head_len
                self._protocol.obfs.server_info.head_len = head_len
                if self._encryptor is not None:
                    data = self._protocol.client_pre_encrypt(data)
                    data_to_send = self._encryptor.encrypt(data)
                    data_to_send = self._obfs.client_encode(data_to_send)
                if data_to_send:
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
            self._log_error(e)
            if self._config['verbose']:
                traceback.print_exc()
            self.destroy()

    def _create_remote_socket(self, ip, port):
        if self._remote_udp:
            addrs_v6 = socket.getaddrinfo("::", 0, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
            addrs = socket.getaddrinfo("0.0.0.0", 0, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
        else:
            addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]
        if not self._remote_udp:
            if self._forbidden_iplist:
                if common.to_str(sa[0]) in self._forbidden_iplist:
                    if self._remote_address:
                        raise Exception('IP %s is in forbidden list, when connect to %s:%d via port %d' %
                            (common.to_str(sa[0]), self._remote_address[0], self._remote_address[1], self._server._listen_port))
                    raise Exception('IP %s is in forbidden list, reject' %
                                    common.to_str(sa[0]))
            if self._forbidden_portset:
                if sa[1] in self._forbidden_portset:
                    if self._remote_address:
                        raise Exception('Port %d is in forbidden list, when connect to %s:%d via port %d' %
                            (sa[1], self._remote_address[0], self._remote_address[1], self._server._listen_port))
                    raise Exception('Port %d is in forbidden list, reject' % sa[1])
        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock
        self._fd_to_handlers[remote_sock.fileno()] = self

        if self._remote_udp:
            af, socktype, proto, canonname, sa = addrs_v6[0]
            remote_sock_v6 = socket.socket(af, socktype, proto)
            self._remote_sock_v6 = remote_sock_v6
            self._fd_to_handlers[remote_sock_v6.fileno()] = self

        remote_sock.setblocking(False)
        if self._remote_udp:
            remote_sock_v6.setblocking(False)
        else:
            remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

            if not self._is_local:
                bind_addr = ''
                if self._bind and af == socket.AF_INET:
                    bind_addr = self._bind
                elif self._bindv6 and af == socket.AF_INET6:
                    bind_addr = self._bindv6
                else:
                    bind_addr = self._accept_address[0]

                bind_addr = bind_addr.replace("::ffff:", "")
                if bind_addr in self._ignore_bind_list:
                    bind_addr = None
                if bind_addr:
                    local_addrs = socket.getaddrinfo(bind_addr, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
                    if local_addrs[0][0] == af:
                        logging.debug("bind %s" % (bind_addr,))
                        remote_sock.bind((bind_addr, 0))
        return remote_sock

    def _handle_dns_resolved(self, result, error):
        if error:
            self._log_error(error)
            self.destroy()
            return
        if result:
            ip = result[1]
            if ip:

                try:
                    self._stage = STAGE_CONNECTING
                    remote_addr = ip
                    if self._is_local:
                        remote_port = self._chosen_server[1]
                    else:
                        remote_port = self._remote_address[1]

                    if self._is_local and self._config['fast_open']:
                        # for fastopen:
                        # wait for more data to arrive and send them in one SYN
                        self._stage = STAGE_CONNECTING
                        # we don't have to wait for remote since it's not
                        # created
                        self._update_stream(STREAM_UP, WAIT_STATUS_READING)
                        # TODO when there is already data in this packet
                    else:
                        # else do connect
                        remote_sock = self._create_remote_socket(remote_addr,
                                                                 remote_port)
                        if self._remote_udp:
                            self._loop.add(remote_sock,
                                           eventloop.POLL_IN,
                                           self._server)
                            if self._remote_sock_v6:
                                self._loop.add(self._remote_sock_v6,
                                        eventloop.POLL_IN,
                                        self._server)
                        else:
                            try:
                                remote_sock.connect((remote_addr, remote_port))
                            except (OSError, IOError) as e:
                                if eventloop.errno_from_exception(e) in (errno.EINPROGRESS,
                                        errno.EWOULDBLOCK):
                                    pass # always goto here
                                else:
                                    raise e
                            self._loop.add(remote_sock,
                                       eventloop.POLL_ERR | eventloop.POLL_OUT,
                                       self._server)
                        self._stage = STAGE_CONNECTING
                        self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                        self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
                        if self._remote_udp:
                            while self._data_to_write_to_remote:
                                data = self._data_to_write_to_remote[0]
                                del self._data_to_write_to_remote[0]
                                self._write_to_sock(data, self._remote_sock)
                    return
                except Exception as e:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
                    logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
        self.destroy()

    def _on_local_read(self):
        # handle all local read events and dispatch them to methods for
        # each stage
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
        ogn_data = data
        if not is_local:
            if self._encryptor is not None:
                if self._encrypt_correct:
                    try:
                        obfs_decode = self._obfs.server_decode(data)
                    except Exception as e:
                        shell.print_exception(e)
                        logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
                        self.destroy()
                        return
                    if obfs_decode[2]:
                        data = self._obfs.server_encode(b'')
                        self._write_to_sock(data, self._local_sock)
                    if obfs_decode[1]:
                        if not self._protocol.obfs.server_info.recv_iv:
                            iv_len = len(self._protocol.obfs.server_info.iv)
                            self._protocol.obfs.server_info.recv_iv = obfs_decode[0][:iv_len]
                        data = self._encryptor.decrypt(obfs_decode[0])
                    else:
                        data = obfs_decode[0]
                    try:
                        data, sendback = self._protocol.server_post_decrypt(data)
                        if sendback:
                            backdata = self._protocol.server_pre_encrypt(b'')
                            backdata = self._encryptor.encrypt(backdata)
                            backdata = self._obfs.server_encode(backdata)
                            try:
                                self._write_to_sock(backdata, self._local_sock)
                            except Exception as e:
                                shell.print_exception(e)
                                if self._config['verbose']:
                                    traceback.print_exc()
                                logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
                                self.destroy()
                                return
                    except Exception as e:
                        shell.print_exception(e)
                        logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
                        self.destroy()
            else:
                return
            if not data:
                return
        if self._stage == STAGE_STREAM:
            if self._is_local:
                if self._encryptor is not None:
                    data = self._protocol.client_pre_encrypt(data)
                    data = self._encryptor.encrypt(data)
                    data = self._obfs.client_encode(data)
            self._write_to_sock(data, self._remote_sock)
            return
        elif is_local and self._stage == STAGE_INIT:
            # TODO check auth method
            self._write_to_sock(b'\x05\00', self._local_sock)
            self._stage = STAGE_ADDR
            return
        elif self._stage == STAGE_CONNECTING:
            self._handle_stage_connecting(data)
        elif (is_local and self._stage == STAGE_ADDR) or \
                (not is_local and self._stage == STAGE_INIT):
            self._handle_stage_addr(ogn_data, data)

    def _on_remote_read(self, is_remote_sock):
        # handle all remote read events
        data = None
        try:
            if self._remote_udp:
                if is_remote_sock:
                    data, addr = self._remote_sock.recvfrom(UDP_MAX_BUF_SIZE)
                else:
                    data, addr = self._remote_sock_v6.recvfrom(UDP_MAX_BUF_SIZE)
                port = struct.pack('>H', addr[1])
                try:
                    ip = socket.inet_aton(addr[0])
                    data = b'\x00\x01' + ip + port + data
                except Exception as e:
                    ip = socket.inet_pton(socket.AF_INET6, addr[0])
                    data = b'\x00\x04' + ip + port + data
                size = len(data) + 2
                if size >= 0xff00:
                    data = common.chr(0xff) + struct.pack('>H', size - 0xff00 + 1) + data
                else:
                    data = struct.pack('>H', size) + data
                #logging.info('UDP over TCP recvfrom %s:%d %d bytes to %s:%d' % (addr[0], addr[1], len(data), self._client_address[0], self._client_address[1]))
            else:
                data = self._remote_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in \
                    (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK, 10035): #errno.WSAEWOULDBLOCK
                return
        if not data:
            self.destroy()
            return
        if self._encryptor is not None:
            if self._is_local:
                try:
                    obfs_decode = self._obfs.client_decode(data)
                except Exception as e:
                    shell.print_exception(e)
                    logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
                    self.destroy()
                    return
                if obfs_decode[1]:
                    send_back = self._obfs.client_encode(b'')
                    self._write_to_sock(send_back, self._remote_sock)
                if not self._protocol.obfs.server_info.recv_iv:
                    iv_len = len(self._protocol.obfs.server_info.iv)
                    self._protocol.obfs.server_info.recv_iv = obfs_decode[0][:iv_len]
                data = self._encryptor.decrypt(obfs_decode[0])
                try:
                    data = self._protocol.client_post_decrypt(data)
                except Exception as e:
                    shell.print_exception(e)
                    logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
                    self.destroy()
                    return
            else:
                if self._encrypt_correct:
                    data = self._protocol.server_pre_encrypt(data)
                    data = self._encryptor.encrypt(data)
                    data = self._obfs.server_encode(data)
            self._update_activity(len(data))
            self._server.server_transfer_dl += len(data)
        else:
            return
        try:
            self._write_to_sock(data, self._local_sock)
        except Exception as e:
            shell.print_exception(e)
            if self._config['verbose']:
                traceback.print_exc()
            logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
            self.destroy()

    def _on_local_write(self):
        # handle local writable event
        if self._data_to_write_to_local:
            data = b''.join(self._data_to_write_to_local)
            self._data_to_write_to_local = []
            self._write_to_sock(data, self._local_sock)
        else:
            self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

    def _on_remote_write(self):
        # handle remote writable event
        self._stage = STAGE_STREAM
        if self._data_to_write_to_remote:
            data = b''.join(self._data_to_write_to_remote)
            self._data_to_write_to_remote = []
            self._write_to_sock(data, self._remote_sock)
        else:
            self._update_stream(STREAM_UP, WAIT_STATUS_READING)

    def _on_local_error(self):
        logging.debug('got local error')
        if self._local_sock:
            logging.error(eventloop.get_sock_error(self._local_sock))
            logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
        self.destroy()

    def _on_remote_error(self):
        logging.debug('got remote error')
        if self._remote_sock:
            logging.error(eventloop.get_sock_error(self._remote_sock))
            if self._remote_address:
                logging.error("when connect to %s:%d" % (self._remote_address[0], self._remote_address[1]))
            else:
                logging.error("exception from %s:%d" % (self._client_address[0], self._client_address[1]))
        self.destroy()

    def handle_event(self, sock, event):
        # handle all events in this handler and dispatch them to methods
        if self._stage == STAGE_DESTROYED:
            logging.debug('ignore handle_event: destroyed')
            return
        # order is important
        if sock == self._remote_sock or sock == self._remote_sock_v6:
            if event & eventloop.POLL_ERR:
                self._on_remote_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_remote_read(sock == self._remote_sock)
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
            logging.warn('unknown socket from %s:%d' % (self._client_address[0], self._client_address[1]))

    def _log_error(self, e):
        logging.error('%s when handling connection from %s:%d' %
                      (e, self._client_address[0], self._client_address[1]))

    def stage(self):
        return self._stage

    def destroy(self):
        # destroy the handler and release any resources
        # promises:
        # 1. destroy won't make another destroy() call inside
        # 2. destroy releases resources so it prevents future call to destroy
        # 3. destroy won't raise any exceptions
        # if any of the promises are broken, it indicates a bug has been
        # introduced! mostly likely memory leaks, etc
        if self._stage == STAGE_DESTROYED:
            # this couldn't happen
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
            try:
                self._loop.remove(self._remote_sock)
            except Exception as e:
                pass
            del self._fd_to_handlers[self._remote_sock.fileno()]
            self._remote_sock.close()
            self._remote_sock = None
        if self._remote_sock_v6:
            logging.debug('destroying remote')
            try:
                self._loop.remove(self._remote_sock_v6)
            except Exception as e:
                pass
            del self._fd_to_handlers[self._remote_sock_v6.fileno()]
            self._remote_sock_v6.close()
            self._remote_sock_v6 = None
        if self._local_sock:
            logging.debug('destroying local')
            self._loop.remove(self._local_sock)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        if self._obfs:
            self._obfs.dispose()
            self._obfs = None
        if self._protocol:
            self._protocol.dispose()
            self._protocol = None
        self._encryptor = None
        self._dns_resolver.remove_callback(self._handle_dns_resolved)
        self._server.remove_handler(self)
        self._server.add_connection(-1)
        self._server.stat_add(self._client_address[0], -1)

class TCPRelay(object):
    def __init__(self, config, dns_resolver, is_local, stat_callback=None, stat_counter=None):
        self._config = config
        self._is_local = is_local
        self._dns_resolver = dns_resolver
        self._closed = False
        self._eventloop = None
        self._fd_to_handlers = {}
        self.server_transfer_ul = 0
        self.server_transfer_dl = 0
        self.server_connections = 0
        self.protocol_data = obfs.obfs(config['protocol']).init_data()
        self.obfs_data = obfs.obfs(config['obfs']).init_data()

        if config.get('connect_verbose_info', 0) > 0:
            common.connect_log = logging.info

        self._timeout = config['timeout']
        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0   # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        if is_local:
            listen_addr = config['local_address']
            listen_port = config['local_port']
        else:
            listen_addr = config['server']
            listen_port = config['server_port']
        self._listen_port = listen_port

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
        server_socket.listen(config.get('max_connect', 1024))
        self._server_socket = server_socket
        self._stat_counter = stat_counter
        self._stat_callback = stat_callback

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        self._eventloop.add(self._server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self._eventloop.add_periodic(self.handle_periodic)

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def add_connection(self, val):
        self.server_connections += val
        logging.debug('server port %5d connections = %d' % (self._listen_port, self.server_connections,))

    def update_stat(self, port, stat_dict, val):
        newval = stat_dict.get(0, 0) + val
        stat_dict[0] = newval
        logging.debug('port %d connections %d' % (port, newval))
        connections_step = 25
        if newval >= stat_dict.get(-1, 0) + connections_step:
            logging.info('port %d connections up to %d' % (port, newval))
            stat_dict[-1] = stat_dict.get(-1, 0) + connections_step
        elif newval <= stat_dict.get(-1, 0) - connections_step:
            logging.info('port %d connections down to %d' % (port, newval))
            stat_dict[-1] = stat_dict.get(-1, 0) - connections_step

    def stat_add(self, local_addr, val):
        if self._stat_counter is not None:
            if self._listen_port not in self._stat_counter:
                self._stat_counter[self._listen_port] = {}
            newval = self._stat_counter[self._listen_port].get(local_addr, 0) + val
            logging.debug('port %d addr %s connections %d' % (self._listen_port, local_addr, newval))
            self._stat_counter[self._listen_port][local_addr] = newval
            self.update_stat(self._listen_port, self._stat_counter[self._listen_port], val)
            if newval <= 0:
                if local_addr in self._stat_counter[self._listen_port]:
                    del self._stat_counter[self._listen_port][local_addr]

            newval = self._stat_counter.get(0, 0) + val
            self._stat_counter[0] = newval
            logging.debug('Total connections %d' % newval)

            connections_step = 50
            if newval >= self._stat_counter.get(-1, 0) + connections_step:
                logging.info('Total connections up to %d' % newval)
                self._stat_counter[-1] = self._stat_counter.get(-1, 0) + connections_step
            elif newval <= self._stat_counter.get(-1, 0) - connections_step:
                logging.info('Total connections down to %d' % newval)
                self._stat_counter[-1] = self._stat_counter.get(-1, 0) - connections_step

    def update_activity(self, handler, data_len):
        if data_len and self._stat_callback:
            self._stat_callback(self._listen_port, data_len)

        # set handler to active
        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
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
            logging.log(shell.VERBOSE_LEVEL, 'sweeping timeouts')
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
                            logging.debug('timed out: %s:%d' %
                                         handler.remote_address)
                        else:
                            logging.debug('timed out')
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

    def handle_event(self, sock, fd, event):
        # handle events and dispatch to handlers
        if sock:
            logging.log(shell.VERBOSE_LEVEL, 'fd %d %s', fd,
                        eventloop.EVENT_NAMES.get(event, event))
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                # TODO
                raise Exception('server_socket error')
            try:
                logging.debug('accept')
                conn = self._server_socket.accept()
                handler = TCPRelayHandler(self, self._fd_to_handlers,
                                self._eventloop, conn[0], self._config,
                                self._dns_resolver, self._is_local)
                if handler.stage() == STAGE_DESTROYED:
                    conn[0].close()
            except (OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
        else:
            if sock:
                handler = self._fd_to_handlers.get(fd, None)
                if handler:
                    handler.handle_event(sock, event)
            else:
                logging.warn('poll removed fd')

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._eventloop.remove(self._server_socket)
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed TCP port %d', self._listen_port)
            for handler in list(self._fd_to_handlers.values()):
                handler.destroy()
        self._sweep_timeout()

    def close(self, next_tick=False):
        logging.debug('TCP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            for handler in list(self._fd_to_handlers.values()):
                handler.destroy()
