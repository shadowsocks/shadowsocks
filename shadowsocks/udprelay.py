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
import threading

from shadowsocks import encrypt, obfs, eventloop, lru_cache, common, shell
from shadowsocks.common import pre_parse_header, parse_header, pack_addr

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

def client_key(source_addr, server_af):
    # notice this is server af, not dest af
    return '%s:%s:%d' % (source_addr[0], source_addr[1], server_af)

class UDPRelay(object):
    def __init__(self, config, dns_resolver, is_local, stat_callback=None, stat_counter=None):
        self._config = config
        if config.get('connect_verbose_info', 0) > 0:
            common.connect_log = logging.info
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
        self._udp_cache_size = config['udp_cache']
        self._cache = lru_cache.LRUCache(timeout=config['udp_timeout'],
                                         close_callback=self._close_client_pair)
        self._cache_dns_client = lru_cache.LRUCache(timeout=10,
                                         close_callback=self._close_client_pair)
        self._client_fd_to_server_addr = {}
        #self._dns_cache = lru_cache.LRUCache(timeout=1800)
        self._eventloop = None
        self._closed = False
        self.server_transfer_ul = 0
        self.server_transfer_dl = 0
        self.server_users = {}
        self.server_user_transfer_ul = {}
        self.server_user_transfer_dl = {}

        if common.to_bytes(config['protocol']) in obfs.mu_protocol():
            self._update_users(None, None)

        self.protocol_data = obfs.obfs(config['protocol']).init_data()
        self._protocol = obfs.obfs(config['protocol'])
        server_info = obfs.server_info(self.protocol_data)
        server_info.host = self._listen_addr
        server_info.port = self._listen_port
        server_info.users = self.server_users
        server_info.protocol_param = config['protocol_param']
        server_info.obfs_param = ''
        server_info.iv = b''
        server_info.recv_iv = b''
        server_info.key_str = common.to_bytes(config['password'])
        server_info.key = encrypt.encrypt_key(self._password, self._method)
        server_info.head_len = 30
        server_info.tcp_mss = 1452
        server_info.buffer_size = BUF_SIZE
        server_info.overhead = 0
        self._protocol.set_server_info(server_info)

        self._sockets = set()
        self._fd_to_handlers = {}
        self._reqid_to_hd = {}
        self._data_to_write_to_server_socket = []

        self._timeout_cache = lru_cache.LRUCache(timeout=self._timeout,
                                         close_callback=self._close_tcp_client)

        self._bind = config.get('out_bind', '')
        self._bindv6 = config.get('out_bindv6', '')
        self._ignore_bind_list = config.get('ignore_bind', [])

        if 'forbidden_ip' in config:
            self._forbidden_iplist = config['forbidden_ip']
        else:
            self._forbidden_iplist = None
        if 'forbidden_port' in config:
            self._forbidden_portset = config['forbidden_port']
        else:
            self._forbidden_portset = None

        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
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

    def get_ud(self):
        return (self.server_transfer_ul, self.server_transfer_dl)

    def get_users_ud(self):
        ret = (self.server_user_transfer_ul.copy(), self.server_user_transfer_dl.copy())
        return ret

    def _update_users(self, protocol_param, acl):
        if protocol_param is None:
            protocol_param = self._config['protocol_param']
        param = common.to_bytes(protocol_param).split(b'#')
        if len(param) == 2:
            user_list = param[1].split(b',')
            if user_list:
                for user in user_list:
                    items = user.split(b':')
                    if len(items) == 2:
                        user_int_id = int(items[0])
                        uid = struct.pack('<I', user_int_id)
                        if acl is not None and user_int_id not in acl:
                            self.del_user(uid)
                        else:
                            passwd = items[1]
                            self.add_user(uid, {'password':passwd})

    def _update_user(self, id, passwd):
        uid = struct.pack('<I', id)
        self.add_user(uid, passwd)

    def update_users(self, users):
        for uid in list(self.server_users.keys()):
            id = struct.unpack('<I', uid)[0]
            if id not in users:
                self.del_user(uid)
        for id in users:
            uid = struct.pack('<I', id)
            self.add_user(uid, users[id])

    def add_user(self, uid, cfg): # user: binstr[4], passwd: str
        passwd = cfg['password']
        self.server_users[uid] = common.to_bytes(passwd)

    def del_user(self, uid):
        if uid in self.server_users:
            del self.server_users[uid]

    def add_transfer_u(self, user, transfer):
        if user is None:
            self.server_transfer_ul += transfer
        else:
            if user not in self.server_user_transfer_ul:
                self.server_user_transfer_ul[user] = 0
            self.server_user_transfer_ul[user] += transfer + self.server_transfer_ul
            self.server_transfer_ul = 0

    def add_transfer_d(self, user, transfer):
        if user is None:
            self.server_transfer_dl += transfer
        else:
            if user not in self.server_user_transfer_dl:
                self.server_user_transfer_dl[user] = 0
            self.server_user_transfer_dl[user] += transfer + self.server_transfer_dl
            self.server_transfer_dl = 0

    def _close_client_pair(self, client_pair):
        client, uid = client_pair
        self._close_client(client)

    def _close_client(self, client):
        if hasattr(client, 'close'):
            if not self._is_local:
                if client.fileno() in self._client_fd_to_server_addr:
                    logging.debug('close_client: %s' %
                                 (self._client_fd_to_server_addr[client.fileno()],))
                else:
                    client.info('close_client')
            self._sockets.remove(client.fileno())
            self._eventloop.remove(client)
            del self._client_fd_to_server_addr[client.fileno()]
            client.close()
        else:
            # just an address
            client.info('close_client pass %s' % client)
            pass

    def _handel_protocol_error(self, client_address, ogn_data):
        #raise Exception('can not parse header')
        logging.warn("Protocol ERROR, UDP ogn data %s from %s:%d" % (binascii.hexlify(ogn_data), client_address[0], client_address[1]))

    def _socket_bind_addr(self, sock, af):
        bind_addr = ''
        if self._bind and af == socket.AF_INET:
            bind_addr = self._bind
        elif self._bindv6 and af == socket.AF_INET6:
            bind_addr = self._bindv6

        bind_addr = bind_addr.replace("::ffff:", "")
        if bind_addr in self._ignore_bind_list:
            bind_addr = None
        if bind_addr:
            local_addrs = socket.getaddrinfo(bind_addr, 0, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
            if local_addrs[0][0] == af:
                logging.debug("bind %s" % (bind_addr,))
                try:
                    sock.bind((bind_addr, 0))
                except Exception as e:
                    logging.warn("bind %s fail" % (bind_addr,))

    def _handle_server(self):
        server = self._server_socket
        data, r_addr = server.recvfrom(BUF_SIZE)
        ogn_data = data
        if not data:
            logging.debug('UDP handle_server: data is empty')
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))
        uid = None
        if self._is_local:
            frag = common.ord(data[2])
            if frag != 0:
                logging.warn('drop a message since frag is not 0')
                return
            else:
                data = data[3:]
        else:
            ref_iv = [0]
            data = encrypt.encrypt_all_iv(self._protocol.obfs.server_info.key, self._method, 0, data, ref_iv)
            # decrypt data
            if not data:
                logging.debug('UDP handle_server: data is empty after decrypt')
                return
            self._protocol.obfs.server_info.recv_iv = ref_iv[0]
            data, uid = self._protocol.server_udp_post_decrypt(data)

        #logging.info("UDP data %s" % (binascii.hexlify(data),))
        if not self._is_local:
            data = pre_parse_header(data)
            if data is None:
                return

        try:
            header_result = parse_header(data)
        except:
            self._handel_protocol_error(r_addr, ogn_data)
            return

        if header_result is None:
            self._handel_protocol_error(r_addr, ogn_data)
            return
        connecttype, addrtype, dest_addr, dest_port, header_length = header_result

        if self._is_local:
            addrtype = 3
            server_addr, server_port = self._get_a_server()
        else:
            server_addr, server_port = dest_addr, dest_port

        if (addrtype & 7) == 3:
            af = common.is_ip(server_addr)
            if af == False:
                handler = common.UDPAsyncDNSHandler((data, r_addr, uid, header_length))
                handler.resolve(self._dns_resolver, (server_addr, server_port), self._handle_server_dns_resolved)
            else:
                self._handle_server_dns_resolved("", (server_addr, server_port), server_addr, (data, r_addr, uid, header_length))
        else:
            self._handle_server_dns_resolved("", (server_addr, server_port), server_addr, (data, r_addr, uid, header_length))

    def _handle_server_dns_resolved(self, error, remote_addr, server_addr, params):
        if error:
            return
        data, r_addr, uid, header_length = params
        user_id = self._listen_port
        try:
            server_port = remote_addr[1]
            addrs = socket.getaddrinfo(server_addr, server_port, 0,
                                        socket.SOCK_DGRAM, socket.SOL_UDP)
            if not addrs: # drop
                return
            af, socktype, proto, canonname, sa = addrs[0]
            server_addr = sa[0]
            key = client_key(r_addr, af)
            client_pair = self._cache.get(key, None)
            if client_pair is None:
                client_pair = self._cache_dns_client.get(key, None)
            if client_pair is None:
                if self._forbidden_iplist:
                    if common.to_str(sa[0]) in self._forbidden_iplist:
                        logging.debug('IP %s is in forbidden list, drop' % common.to_str(sa[0]))
                        # drop
                        return
                if self._forbidden_portset:
                    if sa[1] in self._forbidden_portset:
                        logging.debug('Port %d is in forbidden list, reject' % sa[1])
                        # drop
                        return
                client = socket.socket(af, socktype, proto)
                client_uid = uid
                client.setblocking(False)
                self._socket_bind_addr(client, af)
                is_dns = False
                if len(data) > header_length + 13 and data[header_length + 4 : header_length + 12] == b"\x00\x01\x00\x00\x00\x00\x00\x00":
                    is_dns = True
                else:
                    pass
                if sa[1] == 53 and is_dns: #DNS
                    logging.debug("DNS query %s from %s:%d" % (common.to_str(sa[0]), r_addr[0], r_addr[1]))
                    self._cache_dns_client[key] = (client, uid)
                else:
                    self._cache[key] = (client, uid)
                self._client_fd_to_server_addr[client.fileno()] = (r_addr, af)

                self._sockets.add(client.fileno())
                self._eventloop.add(client, eventloop.POLL_IN, self)

                logging.debug('UDP port %5d sockets %d' % (self._listen_port, len(self._sockets)))

                if uid is not None:
                    user_id = struct.unpack('<I', client_uid)[0]
            else:
                client, client_uid = client_pair
            self._cache.clear(self._udp_cache_size)
            self._cache_dns_client.clear(16)

            if self._is_local:
                ref_iv = [encrypt.encrypt_new_iv(self._method)]
                self._protocol.obfs.server_info.iv = ref_iv[0]
                data = self._protocol.client_udp_pre_encrypt(data)
                #logging.debug("%s" % (binascii.hexlify(data),))
                data = encrypt.encrypt_all_iv(self._protocol.obfs.server_info.key, self._method, 1, data, ref_iv)
                if not data:
                    return
            else:
                data = data[header_length:]
            if not data:
                return
        except Exception as e:
            shell.print_exception(e)
            logging.error("exception from user %d" % (user_id,))

        try:
            client.sendto(data, (server_addr, server_port))
            self.add_transfer_u(client_uid, len(data))
            if client_pair is None: # new request
                addr, port = client.getsockname()[:2]
                common.connect_log('UDP data to %s(%s):%d from %s:%d by user %d' %
                        (common.to_str(remote_addr[0]), common.to_str(server_addr), server_port, addr, port, user_id))
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            logging.warning('IOError sendto %s:%d by user %d' % (server_addr, server_port, user_id))
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

        client_addr = self._client_fd_to_server_addr.get(sock.fileno())
        client_uid = None
        if client_addr:
            key = client_key(client_addr[0], client_addr[1])
            client_pair = self._cache.get(key, None)
            client_dns_pair = self._cache_dns_client.get(key, None)
            if client_pair:
                client, client_uid = client_pair
            elif client_dns_pair:
                client, client_uid = client_dns_pair

        if not self._is_local:
            addrlen = len(r_addr[0])
            if addrlen > 255:
                # drop
                return
            data = pack_addr(r_addr[0]) + struct.pack('>H', r_addr[1]) + data
            ref_iv = [encrypt.encrypt_new_iv(self._method)]
            self._protocol.obfs.server_info.iv = ref_iv[0]
            data = self._protocol.server_udp_pre_encrypt(data, client_uid)
            response = encrypt.encrypt_all_iv(self._protocol.obfs.server_info.key, self._method, 1,
                                           data, ref_iv)
            if not response:
                return
        else:
            ref_iv = [0]
            data = encrypt.encrypt_all_iv(self._protocol.obfs.server_info.key, self._method, 0,
                                       data, ref_iv)
            if not data:
                return
            self._protocol.obfs.server_info.recv_iv = ref_iv[0]
            data = self._protocol.client_udp_post_decrypt(data)
            header_result = parse_header(data)
            if header_result is None:
                return
            #connecttype, dest_addr, dest_port, header_length = header_result
            #logging.debug('UDP handle_client %s:%d to %s:%d' % (common.to_str(r_addr[0]), r_addr[1], dest_addr, dest_port))

            response = b'\x00\x00\x00' + data

        if client_addr:
            if client_uid:
                self.add_transfer_d(client_uid, len(response))
            else:
                self.server_transfer_dl += len(response)
            self.write_to_server_socket(response, client_addr[0])
            if client_dns_pair:
                logging.debug("remove dns client %s:%d" % (client_addr[0][0], client_addr[0][1]))
                del self._cache_dns_client[key]
                self._close_client(client_dns_pair[0])
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    def write_to_server_socket(self, data, addr):
        uncomplete = False
        retry = 0
        try:
            self._server_socket.sendto(data, addr)
            data = None
            while self._data_to_write_to_server_socket:
                data_buf = self._data_to_write_to_server_socket[0]
                retry = data_buf[1] + 1
                del self._data_to_write_to_server_socket[0]
                data, addr = data_buf[0]
                self._server_socket.sendto(data, addr)
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

    def remove_handler(self, client):
        if hash(client) in self._timeout_cache:
            del self._timeout_cache[hash(client)]

    def update_activity(self, client):
        self._timeout_cache[hash(client)] = client

    def _sweep_timeout(self):
        self._timeout_cache.sweep()

    def _close_tcp_client(self, client):
        if client.remote_address:
            logging.debug('timed out: %s:%d' %
                         client.remote_address)
        else:
            logging.debug('timed out')
        client.destroy()
        client.destroy_local()

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
            self._cache.clear(0)
            self._cache_dns_client.clear(0)
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            if self._server_socket:
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed UDP port %d', self._listen_port)
        else:
            before_sweep_size = len(self._sockets)
            self._cache.sweep()
            self._cache_dns_client.sweep()
            if before_sweep_size != len(self._sockets):
                logging.debug('UDP port %5d sockets %d' % (self._listen_port, len(self._sockets)))
            self._sweep_timeout()

    def close(self, next_tick=False):
        logging.debug('UDP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            self._cache.clear(0)
            self._cache_dns_client.clear(0)
