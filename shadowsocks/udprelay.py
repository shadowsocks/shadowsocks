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

# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+

# HOW TO NAME THINGS
# ------------------
# `dest`    means destination server, which is from DST fields in the SOCKS5
#           request
# `local`   means local server of shadowsocks
# `remote`  means remote server of shadowsocks
# `client`  means UDP clients that connects to other servers
# `server`  means the UDP server that handles user requests

from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import socket
import logging
import struct
import errno
import random
import binascii
import traceback

from shadowsocks import encrypt, eventloop, lru_cache, common, shell
from shadowsocks.common import pre_parse_header, parse_header, pack_addr

# we clear at most TIMEOUTS_CLEAN_SIZE timeouts each time
TIMEOUTS_CLEAN_SIZE = 512

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

BUF_SIZE = 65536
DOUBLE_SEND_BEG_IDS = 16
POST_MTU_MIN = 500
POST_MTU_MAX = 1400
SENDING_WINDOW_SIZE = 8192

STAGE_INIT = 0
STAGE_RSP_ID = 1
STAGE_DNS = 2
STAGE_CONNECTING = 3
STAGE_STREAM = 4
STAGE_DESTROYED = -1

CMD_CONNECT = 0
CMD_RSP_CONNECT = 1
CMD_CONNECT_REMOTE = 2
CMD_RSP_CONNECT_REMOTE = 3
CMD_POST = 4
CMD_SYN_STATUS = 5
CMD_POST_64 = 6
CMD_SYN_STATUS_64 = 7
CMD_DISCONNECT = 8

CMD_VER_STR = b"\x08"

RSP_STATE_EMPTY = b""
RSP_STATE_REJECT = b"\x00"
RSP_STATE_CONNECTED = b"\x01"
RSP_STATE_CONNECTEDREMOTE = b"\x02"
RSP_STATE_ERROR = b"\x03"
RSP_STATE_DISCONNECT = b"\x04"
RSP_STATE_REDIRECT = b"\x05"

class UDPLocalAddress(object):
    def __init__(self, addr):
        self.addr = addr
        self.last_activity = time.time()

    def is_timeout(self):
        return time.time() - self.last_activity > 30

class PacketInfo(object):
    def __init__(self, data):
        self.data = data
        self.time = time.time()

class SendingQueue(object):
    def __init__(self):
        self.queue = {}
        self.begin_id = 0
        self.end_id = 1
        self.interval = 0.5

    def append(self, data):
        self.queue[self.end_id] = PacketInfo(data)
        self.end_id += 1
        return self.end_id - 1

    def empty(self):
        return self.begin_id + 1 == self.end_id

    def size(self):
        return self.end_id - self.begin_id - 1

    def get_begin_id(self):
        return self.begin_id

    def get_end_id(self):
        return self.end_id

    def get_data_list(self, pack_id_base, pack_id_list):
        ret_list = []
        curtime = time.time()
        for pack_id in pack_id_list:
            offset = pack_id_base + pack_id
            if offset <= self.begin_id or self.end_id <= offset:
                continue
            ret_data = self.queue[offset]
            if curtime - ret_data.time > self.interval:
                ret_data.time = curtime
                ret_list.append( (offset, ret_data.data) )
        return ret_list

    def set_finish(self, begin_id, done_list):
        while self.begin_id < begin_id:
            self.begin_id += 1
            del self.queue[self.begin_id]

class RecvQueue(object):
    def __init__(self):
        self.queue = {}
        self.miss_queue = set()
        self.begin_id = 0
        self.end_id = 1

    def empty(self):
        return self.begin_id + 1 == self.end_id

    def insert(self, pack_id, data):
        if (pack_id not in self.queue) and pack_id > self.begin_id:
            self.queue[pack_id] = PacketInfo(data)
            if self.end_id == pack_id:
                self.end_id = pack_id + 1
            elif self.end_id < pack_id:
                eid = self.end_id
                while eid < pack_id:
                    self.miss_queue.add(eid)
                    eid += 1
                self.end_id = pack_id + 1
            else:
                self.miss_queue.remove(pack_id)

    def set_end(self, end_id):
        if end_id > self.end_id:
            eid = self.end_id
            while eid < end_id:
                self.miss_queue.add(eid)
                eid += 1
            self.end_id = end_id

    def get_begin_id(self):
        return self.begin_id

    def has_data(self):
        return (self.begin_id + 1) in self.queue

    def get_data(self):
        if (self.begin_id + 1) in self.queue:
            self.begin_id += 1
            pack_id = self.begin_id
            ret_data = self.queue[pack_id]
            del self.queue[pack_id]
            return (pack_id, ret_data.data)

    def get_missing_id(self, begin_id):
        missing = []
        if begin_id == 0:
            begin_id = self.begin_id
        for i in self.miss_queue:
            if i - begin_id > 32768:
                break
            missing.append(i - begin_id)
        return (begin_id, missing)

class AddressMap(object):
    def __init__(self):
        self._queue = []
        self._addr_map = {}

    def add(self, addr):
        if addr in self._addr_map:
            self._addr_map[addr] = UDPLocalAddress(addr)
        else:
            self._addr_map[addr] = UDPLocalAddress(addr)
            self._queue.append(addr)

    def keys(self):
        return self._queue

    def get(self):
        if self._queue:
            while True:
                if len(self._queue) == 1:
                    return self._queue[0]
                index = random.randint(0, len(self._queue) - 1)
                addr = self._queue[index]
                if self._addr_map[addr].is_timeout():
                    self._queue[index] = self._queue[len(self._queue) - 1]
                    del self._queue[len(self._queue) - 1]
                    del self._addr_map[addr]
                else:
                    break
            return addr
        else:
            return None

class TCPRelayHandler(object):
    def __init__(self, server, reqid_to_handlers, fd_to_handlers, loop,
                local_sock, local_id, client_param, config,
                dns_resolver, is_local):
        self._server = server
        self._reqid_to_handlers = reqid_to_handlers
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._remote_udp = False
        self._config = config
        self._dns_resolver = dns_resolver
        self._local_id = local_id

        self._is_local = is_local
        self._stage = STAGE_INIT
        self._password = config['password']
        self._method = config['method']
        self._fastopen_connected = False
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT
        self._request_id = 0
        self._client_address = AddressMap()
        self._remote_address = None
        self._sendingqueue = SendingQueue()
        self._recvqueue = RecvQueue()
        if 'forbidden_ip' in config:
            self._forbidden_iplist = config['forbidden_ip']
        else:
            self._forbidden_iplist = None
        #fd_to_handlers[local_sock.fileno()] = self
        #local_sock.setblocking(False)
        #loop.add(local_sock, eventloop.POLL_IN | eventloop.POLL_ERR)
        self.last_activity = 0
        self._update_activity()
        self._random_mtu_size = [random.randint(POST_MTU_MIN, POST_MTU_MAX) for i in range(1024)]
        self._random_mtu_index = 0

        self._rand_data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" * 4

    def __hash__(self):
        # default __hash__ is id / 16
        # we want to eliminate collisions
        return id(self)

    @property
    def remote_address(self):
        return self._remote_address

    def add_local_address(self, addr):
        self._client_address.add(addr)

    def get_local_address(self):
        return self._client_address.get()

    def _update_activity(self):
        # tell the TCP Relay we have activities recently
        # else it will think we are inactive and timed out
        self._server.update_activity(self)

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
            '''
            if self._local_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                if self._upstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                self._loop.modify(self._local_sock, event)
            '''
            if self._remote_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                if self._upstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                self._loop.modify(self._remote_sock, event)

    def _write_to_sock(self, data, sock, addr = None):
        # write data to sock
        # if only some of the data are written, put remaining in the buffer
        # and update the stream to wait for writing
        if not data or not sock:
            return False

        uncomplete = False
        retry = 0
        if sock == self._local_sock:
            data = encrypt.encrypt_all(self._password, self._method, 1, data)
            if addr is None:
                return False
            try:
                self._server.write_to_server_socket(data, addr)
            except (OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                uncomplete = True
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    pass
                else:
                    #traceback.print_exc()
                    shell.print_exception(e)
                    self.destroy()
                    return False
        else:
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
                    #logging.error(traceback.extract_stack())
                    #traceback.print_exc()
                    shell.print_exception(e)
                    self.destroy()
                    return False
        if uncomplete:
            if sock == self._local_sock:
                self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)
            elif sock == self._remote_sock:
                self._data_to_write_to_remote.append(data)
                self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            else:
                logging.error('write_all_to_sock:unknown socket')
        else:
            if sock == self._local_sock:
                if self._sendingqueue.size() > SENDING_WINDOW_SIZE:
                    self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)
                else:
                    self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            else:
                logging.error('write_all_to_sock:unknown socket')
        return True

    def _create_remote_socket(self, ip, port):
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]
        if self._forbidden_iplist:
            if common.to_str(sa[0]) in self._forbidden_iplist:
                raise Exception('IP %s is in forbidden list, reject' %
                                common.to_str(sa[0]))
        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock

        self._fd_to_handlers[remote_sock.fileno()] = self

        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
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
                    remote_port = self._remote_address[1]
                    logging.info("connect to %s : %d" % (remote_addr, remote_port))

                    remote_sock = self._create_remote_socket(remote_addr,
                                                             remote_port)
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
                    self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                    self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
                    self._stage = STAGE_STREAM

                    addr = self.get_local_address()

                    for i in range(2):
                        rsp_data = self._pack_rsp_data(CMD_RSP_CONNECT_REMOTE, RSP_STATE_CONNECTEDREMOTE)
                        self._write_to_sock(rsp_data, self._local_sock, addr)

                    return
                except Exception as e:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
        self.destroy()

    def _on_local_read(self):
        # handle all local read events and dispatch them to methods for
        # each stage
        self._update_activity()
        if not self._local_sock:
            return
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
        if not data:
            return
        self._server.server_transfer_ul += len(data)
        #TODO ============================================================
        if self._stage == STAGE_STREAM:
            self._write_to_sock(data, self._remote_sock)
            return

    def _on_remote_read(self):
        # handle all remote read events
        self._update_activity()
        data = None
        try:
            data = self._remote_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in \
                    (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK, 10035): #errno.WSAEWOULDBLOCK
                return
        if not data:
            self.destroy()
            return
        self._server.server_transfer_dl += len(data)
        try:
            recv_data = data
            beg_pos = 0
            max_len = len(recv_data)
            while beg_pos < max_len:
                if beg_pos + POST_MTU_MAX >= max_len:
                    split_pos = max_len
                else:
                    split_pos = beg_pos + self._random_mtu_size[self._random_mtu_index]
                    self._random_mtu_index = (self._random_mtu_index + 1) & 0x3ff
                    #split_pos = beg_pos + random.randint(POST_MTU_MIN, POST_MTU_MAX)
                data = recv_data[beg_pos:split_pos]
                beg_pos = split_pos

                pack_id = self._sendingqueue.append(data)
                post_data = self._pack_post_data(CMD_POST, pack_id, data)
                addr = self.get_local_address()
                self._write_to_sock(post_data, self._local_sock, addr)
                if pack_id <= DOUBLE_SEND_BEG_IDS:
                    post_data = self._pack_post_data(CMD_POST, pack_id, data)
                    self._write_to_sock(post_data, self._local_sock, addr)

        except Exception as e:
            shell.print_exception(e)
            if self._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
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
        self.destroy()

    def _on_remote_error(self):
        logging.debug('got remote error')
        if self._remote_sock:
            logging.error(eventloop.get_sock_error(self._remote_sock))
        self.destroy()

    def _pack_rsp_data(self, cmd, data):
        reqid_str = struct.pack(">H", self._request_id)
        return b''.join([CMD_VER_STR, common.chr(cmd), reqid_str, data, self._rand_data[:random.randint(0, len(self._rand_data))], reqid_str])

    def _pack_rnd_data(self, data):
        length = random.randint(0, len(self._rand_data))
        if length == 0:
            return data
        elif length == 1:
            return b"\x81" + data
        elif length < 256:
            return b"\x80" + common.chr(length) + self._rand_data[:length - 2] + data
        else:
            return b"\x82" + struct.pack(">H", length) + self._rand_data[:length - 3] + data

    def _pack_post_data(self, cmd, pack_id, data):
        reqid_str = struct.pack(">H", self._request_id)
        recv_id = self._recvqueue.get_begin_id()
        rsp_data = b''.join([CMD_VER_STR, common.chr(cmd), reqid_str, struct.pack(">I", recv_id), struct.pack(">I", pack_id), data, reqid_str])
        return rsp_data

    def _pack_post_data_64(self, cmd, send_id, pack_id, data):
        reqid_str = struct.pack(">H", self._request_id)
        recv_id = self._recvqueue.get_begin_id()
        rsp_data = b''.join([CMD_VER_STR, common.chr(cmd), reqid_str, struct.pack(">Q", recv_id), struct.pack(">Q", pack_id), data, reqid_str])
        return rsp_data

    def sweep_timeout(self):
        logging.info("sweep_timeout")
        if self._stage == STAGE_STREAM:
            pack_id, missing = self._recvqueue.get_missing_id(0)
            logging.info("sweep_timeout %s %s" % (pack_id, missing))
            data = b''
            for pid in missing:
                data += struct.pack(">H", pid)
            rsp_data = self._pack_post_data(CMD_SYN_STATUS, pack_id, data)
            addr = self.get_local_address()
            self._write_to_sock(rsp_data, self._local_sock, addr)

    def handle_stream_sync_status(self, addr, cmd, request_id, pack_id, max_send_id, data):
        missing_list = []
        while len(data) >= 2:
            pid = struct.unpack(">H", data[0:2])[0]
            data = data[2:]
            missing_list.append(pid)
        done_list = []
        self._recvqueue.set_end(max_send_id)
        self._sendingqueue.set_finish(pack_id, done_list)

        if self._stage == STAGE_DESTROYED and self._sendingqueue.empty():
            self.destroy_local()
            return

        # post CMD_SYN_STATUS
        send_id = self._sendingqueue.get_end_id()
        post_pack_id, missing = self._recvqueue.get_missing_id(0)
        pack_ids_data = b''
        for pid in missing:
            pack_ids_data += struct.pack(">H", pid)

        rsp_data = self._pack_rnd_data(self._pack_post_data(CMD_SYN_STATUS, send_id, pack_ids_data))
        self._write_to_sock(rsp_data, self._local_sock, addr)

        send_list = self._sendingqueue.get_data_list(pack_id, missing_list)
        for post_pack_id, post_data in send_list:
            rsp_data = self._pack_post_data(CMD_POST, post_pack_id, post_data)
            self._write_to_sock(rsp_data, self._local_sock, addr)
            if post_pack_id <= DOUBLE_SEND_BEG_IDS:
                rsp_data = self._pack_post_data(CMD_POST, post_pack_id, post_data)
                self._write_to_sock(rsp_data, self._local_sock, addr)

    def handle_client(self, addr, cmd, request_id, data):
        self.add_local_address(addr)
        if cmd == CMD_DISCONNECT:
            rsp_data = self._pack_rsp_data(CMD_DISCONNECT, RSP_STATE_EMPTY)
            self._write_to_sock(rsp_data, self._local_sock, addr)
            self.destroy()
            self.destroy_local()
            return
        if self._stage == STAGE_INIT:
            if cmd == CMD_CONNECT:
                self._request_id = request_id
                self._stage = STAGE_RSP_ID
            return
        if self._request_id != request_id:
            return

        if self._stage == STAGE_RSP_ID:
            if cmd == CMD_CONNECT:
                for i in range(2):
                    rsp_data = self._pack_rsp_data(CMD_RSP_CONNECT, RSP_STATE_CONNECTED)
                    self._write_to_sock(rsp_data, self._local_sock, addr)
            elif cmd == CMD_CONNECT_REMOTE:
                local_id = data[0:4]
                if self._local_id == local_id:
                    data = data[4:]
                    header_result = parse_header(data)
                    if header_result is None:
                        return
                    connecttype, remote_addr, remote_port, header_length = header_result
                    self._remote_address = (common.to_str(remote_addr), remote_port)
                    self._stage = STAGE_DNS
                    self._dns_resolver.resolve(remote_addr,
                                               self._handle_dns_resolved)
                    logging.info('TCP connect %s:%d from %s:%d' % (remote_addr, remote_port, addr[0], addr[1]))
                else:
                    # ileagal request
                    rsp_data = self._pack_rsp_data(CMD_DISCONNECT, RSP_STATE_EMPTY)
                    self._write_to_sock(rsp_data, self._local_sock, addr)
        elif self._stage == STAGE_CONNECTING:
            if cmd == CMD_CONNECT_REMOTE:
                local_id = data[0:4]
                if self._local_id == local_id:
                    for i in range(2):
                        rsp_data = self._pack_rsp_data(CMD_RSP_CONNECT_REMOTE, RSP_STATE_CONNECTEDREMOTE)
                        self._write_to_sock(rsp_data, self._local_sock, addr)
                else:
                    # ileagal request
                    rsp_data = self._pack_rsp_data(CMD_DISCONNECT, RSP_STATE_EMPTY)
                    self._write_to_sock(rsp_data, self._local_sock, addr)
        elif self._stage == STAGE_STREAM:
            if len(data) < 4:
                # ileagal request
                rsp_data = self._pack_rsp_data(CMD_DISCONNECT, RSP_STATE_EMPTY)
                self._write_to_sock(rsp_data, self._local_sock, addr)
                return
            local_id = data[0:4]
            if self._local_id != local_id:
                # ileagal request
                rsp_data = self._pack_rsp_data(CMD_DISCONNECT, RSP_STATE_EMPTY)
                self._write_to_sock(rsp_data, self._local_sock, addr)
                return
            else:
                data = data[4:]
            if cmd == CMD_CONNECT_REMOTE:
                rsp_data = self._pack_rsp_data(CMD_RSP_CONNECT_REMOTE, RSP_STATE_CONNECTEDREMOTE)
                self._write_to_sock(rsp_data, self._local_sock, addr)
            elif cmd == CMD_POST:
                recv_id = struct.unpack(">I", data[0:4])[0]
                pack_id = struct.unpack(">I", data[4:8])[0]
                self._recvqueue.insert(pack_id, data[8:])
                self._sendingqueue.set_finish(recv_id, [])
            elif cmd == CMD_POST_64:
                recv_id = struct.unpack(">Q", data[0:8])[0]
                pack_id = struct.unpack(">Q", data[8:16])[0]
                self._recvqueue.insert(pack_id, data[16:])
                self._sendingqueue.set_finish(recv_id, [])
            elif cmd == CMD_DISCONNECT:
                rsp_data = self._pack_rsp_data(CMD_DISCONNECT, RSP_STATE_EMPTY)
                self._write_to_sock(rsp_data, self._local_sock, addr)
                self.destroy()
                self.destroy_local()
                return
            elif cmd == CMD_SYN_STATUS:
                pack_id = struct.unpack(">I", data[0:4])[0]
                max_send_id = struct.unpack(">I", data[4:8])[0]
                data = data[8:]
                self.handle_stream_sync_status(addr, cmd, request_id, pack_id, max_send_id, data)
            elif cmd == CMD_SYN_STATUS_64:
                pack_id = struct.unpack(">Q", data[0:8])[0]
                max_send_id = struct.unpack(">Q", data[8:16])[0]
                data = data[16:]
                self.handle_stream_sync_status(addr, cmd, request_id, pack_id, max_send_id, data)
            while self._recvqueue.has_data():
                pack_id, post_data = self._recvqueue.get_data()
                self._write_to_sock(post_data, self._remote_sock)
        elif self._stage == STAGE_DESTROYED:
            local_id = data[0:4]
            if self._local_id != local_id:
                # ileagal request
                rsp_data = self._pack_rsp_data(CMD_DISCONNECT, RSP_STATE_EMPTY)
                self._write_to_sock(rsp_data, self._local_sock, addr)
                return
            else:
                data = data[4:]
            if cmd == CMD_SYN_STATUS:
                pack_id = struct.unpack(">I", data[0:4])[0]
                max_send_id = struct.unpack(">I", data[4:8])[0]
                data = data[8:]
                self.handle_stream_sync_status(addr, cmd, request_id, pack_id, max_send_id, data)
            elif cmd == CMD_SYN_STATUS_64:
                pack_id = struct.unpack(">Q", data[0:8])[0]
                max_send_id = struct.unpack(">Q", data[8:16])[0]
                data = data[16:]
                self.handle_stream_sync_status(addr, cmd, request_id, pack_id, max_send_id, data)

    def handle_event(self, sock, event):
        # handle all events in this handler and dispatch them to methods
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

    def _log_error(self, e):
        logging.error('%s when handling connection from %s' %
                      (e, self._client_address.keys()))

    def destroy(self):
        # destroy the handler and release any resources
        # promises:
        # 1. destroy won't make another destroy() call inside
        # 2. destroy releases resources so it prevents future call to destroy
        # 3. destroy won't raise any exceptions
        # if any of the promises are broken, it indicates a bug has been
        # introduced! mostly likely memory leaks, etc
        #logging.info('tcp destroy called')
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
            self._loop.remove(self._remote_sock)
            try:
                del self._fd_to_handlers[self._remote_sock.fileno()]
            except Exception as e:
                pass
            self._remote_sock.close()
            self._remote_sock = None
        if self._sendingqueue.empty():
            self.destroy_local()
        self._dns_resolver.remove_callback(self._handle_dns_resolved)

    def destroy_local(self):
        if self._local_sock:
            logging.debug('disconnect local')
            rsp_data = self._pack_rsp_data(CMD_DISCONNECT, RSP_STATE_EMPTY)
            addr = None
            addr = self.get_local_address()
            self._write_to_sock(rsp_data, self._local_sock, addr)
            self._local_sock = None
            try:
                del self._reqid_to_handlers[self._request_id]
            except Exception as e:
                pass

        self._server.remove_handler(self)

def client_key(source_addr, server_af):
    # notice this is server af, not dest af
    return '%s:%s:%d' % (source_addr[0], source_addr[1], server_af)


class UDPRelay(object):
    def __init__(self, config, dns_resolver, is_local, stat_callback=None):
        self._config = config
        if is_local:
            self._listen_addr = config['local_address']
            self._listen_port = config['local_port']
            self._remote_addr = config['server']
            self._remote_port = config['server_port']
        else:
            self._listen_addr = config['server']
            self._listen_port = config['server_port']
            self._remote_addr = None
            self._remote_port = None
        self._dns_resolver = dns_resolver
        self._password = common.to_bytes(config['password'])
        self._method = config['method']
        self._timeout = config['timeout']
        self._is_local = is_local
        self._cache = lru_cache.LRUCache(timeout=config['timeout'],
                                         close_callback=self._close_client)
        self._client_fd_to_server_addr = \
            lru_cache.LRUCache(timeout=config['timeout'])
        self._dns_cache = lru_cache.LRUCache(timeout=300)
        self._eventloop = None
        self._closed = False
        self.server_transfer_ul = 0
        self.server_transfer_dl = 0

        self._sockets = set()
        self._fd_to_handlers = {}
        self._reqid_to_hd = {}
        self._data_to_write_to_server_socket = []

        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0   # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        if 'forbidden_ip' in config:
            self._forbidden_iplist = config['forbidden_ip']
        else:
            self._forbidden_iplist = None

        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 32)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 32)
        self._server_socket = server_socket
        self._stat_callback = stat_callback

    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if type(server_port) == list:
            server_port = random.choice(server_port)
        if type(server) == list:
            server = random.choice(server)
        logging.debug('chosen server: %s:%d', server, server_port)
        return server, server_port

    def _close_client(self, client):
        if hasattr(client, 'close'):
            self._sockets.remove(client.fileno())
            self._eventloop.remove(client)
            client.close()
        else:
            # just an address
            pass

    def _pre_parse_udp_header(self, data):
        if data is None:
            return
        datatype = common.ord(data[0])
        if datatype == 0x8:
            if len(data) >= 8:
                crc = binascii.crc32(data) & 0xffffffff
                if crc != 0xffffffff:
                    logging.warn('uncorrect CRC32, maybe wrong password or '
                                 'encryption method')
                    return None
                cmd = common.ord(data[1])
                request_id = struct.unpack('>H', data[2:4])[0]
                data = data[4:-4]
                return (cmd, request_id, data)
            elif len(data) >= 6 and common.ord(data[1]) == 0x0:
                crc = binascii.crc32(data) & 0xffffffff
                if crc != 0xffffffff:
                    logging.warn('uncorrect CRC32, maybe wrong password or '
                                 'encryption method')
                    return None
                cmd = common.ord(data[1])
                data = data[2:-4]
                return (cmd, 0, data)
            else:
                logging.warn('header too short, maybe wrong password or '
                             'encryption method')
                return None
        return data

    def _pack_rsp_data(self, cmd, request_id, data):
        _rand_data = b"123456789abcdefghijklmnopqrstuvwxyz" * 2
        reqid_str = struct.pack(">H", request_id)
        return b''.join([CMD_VER_STR, common.chr(cmd), reqid_str, data, _rand_data[:random.randint(0, len(_rand_data))], reqid_str])

    def _handel_protocol_error(self, client_address, ogn_data):
        #raise Exception('can not parse header')
        logging.warn("Protocol ERROR, UDP ogn data %s from %s:%d" % (binascii.hexlify(ogn_data), client_address[0], client_address[1]))

    def _handle_server(self):
        server = self._server_socket
        data, r_addr = server.recvfrom(BUF_SIZE)
        ogn_data = data
        if not data:
            logging.debug('UDP handle_server: data is empty')
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))
        if self._is_local:
            frag = common.ord(data[2])
            if frag != 0:
                logging.warn('drop a message since frag is not 0')
                return
            else:
                data = data[3:]
        else:
            data = encrypt.encrypt_all(self._password, self._method, 0, data)
            # decrypt data
            if not data:
                logging.debug('UDP handle_server: data is empty after decrypt')
                return

        #logging.info("UDP data %s" % (binascii.hexlify(data),))
        if not self._is_local:
            data = pre_parse_header(data)

            data = self._pre_parse_udp_header(data)
            if data is None:
                return

            if type(data) is tuple:
                #(cmd, request_id, data)
                #logging.info("UDP data %d %d %s" % (data[0], data[1], binascii.hexlify(data[2])))
                try:
                    if data[0] == 0:
                        if len(data[2]) >= 4:
                            for i in range(64):
                                req_id = random.randint(1, 65535)
                                if req_id not in self._reqid_to_hd:
                                    break
                            if req_id in self._reqid_to_hd:
                                for i in range(64):
                                    req_id = random.randint(1, 65535)
                                    if type(self._reqid_to_hd[req_id]) is tuple:
                                        break
                            # return req id
                            self._reqid_to_hd[req_id] = (data[2][0:4], None)
                            rsp_data = self._pack_rsp_data(CMD_RSP_CONNECT, req_id, RSP_STATE_CONNECTED)
                            data_to_send = encrypt.encrypt_all(self._password, self._method, 1, rsp_data)
                            self.write_to_server_socket(data_to_send, r_addr)
                    elif data[0] == CMD_CONNECT_REMOTE:
                        if len(data[2]) > 4 and data[1] in self._reqid_to_hd:
                            # create
                            if type(self._reqid_to_hd[data[1]]) is tuple:
                                if data[2][0:4] == self._reqid_to_hd[data[1]][0]:
                                    handle = TCPRelayHandler(self, self._reqid_to_hd, self._fd_to_handlers,
                                        self._eventloop, self._server_socket,
                                        self._reqid_to_hd[data[1]][0], self._reqid_to_hd[data[1]][1],
                                        self._config, self._dns_resolver, self._is_local)
                                    self._reqid_to_hd[data[1]] = handle
                                    handle.handle_client(r_addr, CMD_CONNECT, data[1], data[2])
                                    handle.handle_client(r_addr, *data)
                                    self.update_activity(handle)
                                else:
                                    # disconnect
                                    rsp_data = self._pack_rsp_data(CMD_DISCONNECT, data[1], RSP_STATE_EMPTY)
                                    data_to_send = encrypt.encrypt_all(self._password, self._method, 1, rsp_data)
                                    self.write_to_server_socket(data_to_send, r_addr)
                            else:
                                self.update_activity(self._reqid_to_hd[data[1]])
                                self._reqid_to_hd[data[1]].handle_client(r_addr, *data)
                        else:
                            # disconnect
                            rsp_data = self._pack_rsp_data(CMD_DISCONNECT, data[1], RSP_STATE_EMPTY)
                            data_to_send = encrypt.encrypt_all(self._password, self._method, 1, rsp_data)
                            self.write_to_server_socket(data_to_send, r_addr)
                    elif data[0] > CMD_CONNECT_REMOTE and data[0] <= CMD_DISCONNECT:
                        if data[1] in self._reqid_to_hd:
                            if type(self._reqid_to_hd[data[1]]) is tuple:
                                pass
                            else:
                                self.update_activity(self._reqid_to_hd[data[1]])
                                self._reqid_to_hd[data[1]].handle_client(r_addr, *data)
                        else:
                            # disconnect
                            rsp_data = self._pack_rsp_data(CMD_DISCONNECT, data[1], RSP_STATE_EMPTY)
                            data_to_send = encrypt.encrypt_all(self._password, self._method, 1, rsp_data)
                            self.write_to_server_socket(data_to_send, r_addr)
                    return
                except Exception as e:
                    trace = traceback.format_exc()
                    logging.error(trace)
                    return

        try:
            header_result = parse_header(data)
        except:
            self._handel_protocol_error(r_addr, ogn_data)
            return

        if header_result is None:
            self._handel_protocol_error(r_addr, ogn_data)
            return
        connecttype, dest_addr, dest_port, header_length = header_result

        if self._is_local:
            server_addr, server_port = self._get_a_server()
        else:
            server_addr, server_port = dest_addr, dest_port

        addrs = self._dns_cache.get(server_addr, None)
        if addrs is None:
            addrs = socket.getaddrinfo(server_addr, server_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
            if not addrs:
                # drop
                return
            else:
                self._dns_cache[server_addr] = addrs

        af, socktype, proto, canonname, sa = addrs[0]
        key = client_key(r_addr, af)
        client = self._cache.get(key, None)
        if not client:
            # TODO async getaddrinfo
            if self._forbidden_iplist:
                if common.to_str(sa[0]) in self._forbidden_iplist:
                    logging.debug('IP %s is in forbidden list, drop' %
                                  common.to_str(sa[0]))
                    # drop
                    return
            client = socket.socket(af, socktype, proto)
            client.setblocking(False)
            self._cache[key] = client
            self._client_fd_to_server_addr[client.fileno()] = r_addr

            self._sockets.add(client.fileno())
            self._eventloop.add(client, eventloop.POLL_IN, self)

            logging.debug('UDP port %5d sockets %d' % (self._listen_port, len(self._sockets)))

            logging.info('UDP data to %s:%d from %s:%d' %
                        (common.to_str(server_addr), server_port,
                            r_addr[0], r_addr[1]))

        if self._is_local:
            data = encrypt.encrypt_all(self._password, self._method, 1, data)
            if not data:
                return
        else:
            data = data[header_length:]
        if not data:
            return
        try:
            #logging.info('UDP handle_server sendto %s:%d %d bytes' % (common.to_str(server_addr), server_port, len(data)))
            client.sendto(data, (server_addr, server_port))
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            if err in (errno.EINPROGRESS, errno.EAGAIN):
                pass
            else:
                shell.print_exception(e)

    def _handle_client(self, sock):
        data, r_addr = sock.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_client: data is empty')
            return
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))
        if not self._is_local:
            addrlen = len(r_addr[0])
            if addrlen > 255:
                # drop
                return
            data = pack_addr(r_addr[0]) + struct.pack('>H', r_addr[1]) + data
            response = encrypt.encrypt_all(self._password, self._method, 1,
                                           data)
            if not response:
                return
        else:
            data = encrypt.encrypt_all(self._password, self._method, 0,
                                       data)
            if not data:
                return
            header_result = parse_header(data)
            if header_result is None:
                return
            #connecttype, dest_addr, dest_port, header_length = header_result
            #logging.debug('UDP handle_client %s:%d to %s:%d' % (common.to_str(r_addr[0]), r_addr[1], dest_addr, dest_port))

            response = b'\x00\x00\x00' + data
        client_addr = self._client_fd_to_server_addr.get(sock.fileno())
        if client_addr:
            self.write_to_server_socket(response, client_addr)
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    def write_to_server_socket(self, data, addr):
        #self._server_socket.sendto(data, addr)
        #'''
        uncomplete = False
        retry = 0
        try:
            #"""
            #if self._data_to_write_to_server_socket:
            #    self._data_to_write_to_server_socket.append([(data, addr), 0])
            #else:
            self._server_socket.sendto(data, addr)
            data = None
            while self._data_to_write_to_server_socket:
                data_buf = self._data_to_write_to_server_socket[0]
                retry = data_buf[1] + 1
                del self._data_to_write_to_server_socket[0]
                data, addr = data_buf[0]
                self._server_socket.sendto(data, addr)
            #"""
        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            uncomplete = True
            if error_no in (errno.EWOULDBLOCK,):
                pass
            else:
                shell.print_exception(e)
                return False
        #if uncomplete and data is not None and retry < 3:
        #    self._data_to_write_to_server_socket.append([(data, addr), retry])
        #'''

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop

        server_socket = self._server_socket
        self._eventloop.add(server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR, self)
        loop.add_periodic(self.handle_periodic)

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def update_activity(self, handler):
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
                            logging.warn('timed out: %s:%d' %
                                         handler.remote_address)
                        else:
                            logging.warn('timed out')
                        handler.destroy()
                        handler.destroy_local()
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
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                logging.error('UDP server_socket err')
            try:
                self._handle_server()
            except Exception as e:
                shell.print_exception(e)
                if self._config['verbose']:
                    traceback.print_exc()
        elif sock and (fd in self._sockets):
            if event & eventloop.POLL_ERR:
                logging.error('UDP client_socket err')
            try:
                self._handle_client(sock)
            except Exception as e:
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
                self._server_socket.close()
                self._server_socket = None
                for sock in self._sockets:
                    sock.close()
                logging.info('closed UDP port %d', self._listen_port)
        before_sweep_size = len(self._sockets)
        self._cache.sweep()
        self._dns_cache.sweep()
        if before_sweep_size != len(self._sockets):
            logging.debug('UDP port %5d sockets %d' % (self._listen_port, len(self._sockets)))
        self._client_fd_to_server_addr.sweep()
        self._sweep_timeout()

    def close(self, next_tick=False):
        logging.debug('UDP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            for client in list(self._cache.values()):
                client.close()
