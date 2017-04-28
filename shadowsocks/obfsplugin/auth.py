#!/usr/bin/env python
#
# Copyright 2015-2015 breakwa11
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

import os
import sys
import hashlib
import logging
import binascii
import base64
import time
import datetime
import random
import math
import struct
import zlib
import hmac
import hashlib

import shadowsocks
from shadowsocks import common, lru_cache, encrypt
from shadowsocks.obfsplugin import plain
from shadowsocks.common import to_bytes, to_str, ord, chr

def create_auth_sha1_v4(method):
    return auth_sha1_v4(method)

def create_auth_aes128_md5(method):
    return auth_aes128_sha1(method, hashlib.md5)

def create_auth_aes128_sha1(method):
    return auth_aes128_sha1(method, hashlib.sha1)

obfs_map = {
        'auth_sha1_v4': (create_auth_sha1_v4,),
        'auth_sha1_v4_compatible': (create_auth_sha1_v4,),
        'auth_aes128_md5': (create_auth_aes128_md5,),
        'auth_aes128_sha1': (create_auth_aes128_sha1,),
}

def match_begin(str1, str2):
    if len(str1) >= len(str2):
        if str1[:len(str2)] == str2:
            return True
    return False

class auth_base(plain.plain):
    def __init__(self, method):
        super(auth_base, self).__init__(method)
        self.method = method
        self.no_compatible_method = ''
        self.overhead = 7

    def init_data(self):
        return ''

    def get_overhead(self, direction): # direction: true for c->s false for s->c
        return self.overhead

    def set_server_info(self, server_info):
        self.server_info = server_info

    def client_encode(self, buf):
        return buf

    def client_decode(self, buf):
        return (buf, False)

    def server_encode(self, buf):
        return buf

    def server_decode(self, buf):
        return (buf, True, False)

    def not_match_return(self, buf):
        self.raw_trans = True
        self.overhead = 0
        if self.method == self.no_compatible_method:
            return (b'E'*2048, False)
        return (buf, False)

class client_queue(object):
    def __init__(self, begin_id):
        self.front = begin_id - 64
        self.back = begin_id + 1
        self.alloc = {}
        self.enable = True
        self.last_update = time.time()

    def update(self):
        self.last_update = time.time()

    def is_active(self):
        return time.time() - self.last_update < 60 * 3

    def re_enable(self, connection_id):
        self.enable = True
        self.front = connection_id - 64
        self.back = connection_id + 1
        self.alloc = {}

    def insert(self, connection_id):
        if not self.enable:
            logging.warn('obfs auth: not enable')
            return False
        if not self.is_active():
            self.re_enable(connection_id)
        self.update()
        if connection_id < self.front:
            logging.warn('obfs auth: deprecated id, someone replay attack')
            return False
        if connection_id > self.front + 0x4000:
            logging.warn('obfs auth: wrong id')
            return False
        if connection_id in self.alloc:
            logging.warn('obfs auth: duplicate id, someone replay attack')
            return False
        if self.back <= connection_id:
            self.back = connection_id + 1
        self.alloc[connection_id] = 1
        while (self.front in self.alloc) or self.front + 0x1000 < self.back:
            if self.front in self.alloc:
                del self.alloc[self.front]
            self.front += 1
        return True

class obfs_auth_v2_data(object):
    def __init__(self):
        self.client_id = lru_cache.LRUCache()
        self.local_client_id = b''
        self.connection_id = 0
        self.set_max_client(64) # max active client count

    def update(self, client_id, connection_id):
        if client_id in self.client_id:
            self.client_id[client_id].update()

    def set_max_client(self, max_client):
        self.max_client = max_client
        self.max_buffer = max(self.max_client * 2, 1024)

    def insert(self, client_id, connection_id):
        if self.client_id.get(client_id, None) is None or not self.client_id[client_id].enable:
            if self.client_id.first() is None or len(self.client_id) < self.max_client:
                if client_id not in self.client_id:
                    #TODO: check
                    self.client_id[client_id] = client_queue(connection_id)
                else:
                    self.client_id[client_id].re_enable(connection_id)
                return self.client_id[client_id].insert(connection_id)

            if not self.client_id[self.client_id.first()].is_active():
                del self.client_id[self.client_id.first()]
                if client_id not in self.client_id:
                    #TODO: check
                    self.client_id[client_id] = client_queue(connection_id)
                else:
                    self.client_id[client_id].re_enable(connection_id)
                return self.client_id[client_id].insert(connection_id)

            logging.warn('auth_sha1_v2: no inactive client')
            return False
        else:
            return self.client_id[client_id].insert(connection_id)

class auth_sha1_v4(auth_base):
    def __init__(self, method):
        super(auth_sha1_v4, self).__init__(method)
        self.recv_buf = b''
        self.unit_len = 8100
        self.decrypt_packet_num = 0
        self.raw_trans = False
        self.has_sent_header = False
        self.has_recv_header = False
        self.client_id = 0
        self.connection_id = 0
        self.max_time_dif = 60 * 60 * 24 # time dif (second) setting
        self.salt = b"auth_sha1_v4"
        self.no_compatible_method = 'auth_sha1_v4'

    def init_data(self):
        return obfs_auth_v2_data()

    def set_server_info(self, server_info):
        self.server_info = server_info
        try:
            max_client = int(server_info.protocol_param)
        except:
            max_client = 64
        self.server_info.data.set_max_client(max_client)

    def rnd_data(self, buf_size):
        if buf_size > 1200:
            return b'\x01'

        if buf_size > 400:
            rnd_data = os.urandom(common.ord(os.urandom(1)[0]) % 256)
        else:
            rnd_data = os.urandom(struct.unpack('>H', os.urandom(2))[0] % 512)

        if len(rnd_data) < 128:
            return common.chr(len(rnd_data) + 1) + rnd_data
        else:
            return common.chr(255) + struct.pack('>H', len(rnd_data) + 3) + rnd_data

    def pack_data(self, buf):
        data = self.rnd_data(len(buf)) + buf
        data_len = len(data) + 8
        crc = binascii.crc32(struct.pack('>H', data_len)) & 0xFFFF
        data = struct.pack('<H', crc) + data
        data = struct.pack('>H', data_len) + data
        adler32 = zlib.adler32(data) & 0xFFFFFFFF
        data += struct.pack('<I', adler32)
        return data

    def pack_auth_data(self, buf):
        if len(buf) == 0:
            return b''
        data = self.rnd_data(len(buf)) + buf
        data_len = len(data) + 16
        crc = binascii.crc32(struct.pack('>H', data_len) + self.salt + self.server_info.key) & 0xFFFFFFFF
        data = struct.pack('<I', crc) + data
        data = struct.pack('>H', data_len) + data
        data += hmac.new(self.server_info.iv + self.server_info.key, data, hashlib.sha1).digest()[:10]
        return data

    def auth_data(self):
        utc_time = int(time.time()) & 0xFFFFFFFF
        if self.server_info.data.connection_id > 0xFF000000:
            self.server_info.data.local_client_id = b''
        if not self.server_info.data.local_client_id:
            self.server_info.data.local_client_id = os.urandom(4)
            logging.debug("local_client_id %s" % (binascii.hexlify(self.server_info.data.local_client_id),))
            self.server_info.data.connection_id = struct.unpack('<I', os.urandom(4))[0] & 0xFFFFFF
        self.server_info.data.connection_id += 1
        return b''.join([struct.pack('<I', utc_time),
                self.server_info.data.local_client_id,
                struct.pack('<I', self.server_info.data.connection_id)])

    def client_pre_encrypt(self, buf):
        ret = b''
        if not self.has_sent_header:
            head_size = self.get_head_size(buf, 30)
            datalen = min(len(buf), random.randint(0, 31) + head_size)
            ret += self.pack_auth_data(self.auth_data() + buf[:datalen])
            buf = buf[datalen:]
            self.has_sent_header = True
        while len(buf) > self.unit_len:
            ret += self.pack_data(buf[:self.unit_len])
            buf = buf[self.unit_len:]
        ret += self.pack_data(buf)
        return ret

    def client_post_decrypt(self, buf):
        if self.raw_trans:
            return buf
        self.recv_buf += buf
        out_buf = b''
        while len(self.recv_buf) > 4:
            crc = struct.pack('<H', binascii.crc32(self.recv_buf[:2]) & 0xFFFF)
            if crc != self.recv_buf[2:4]:
                raise Exception('client_post_decrypt data uncorrect crc')
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 8192 or length < 7:
                self.raw_trans = True
                self.recv_buf = b''
                raise Exception('client_post_decrypt data error')
            if length > len(self.recv_buf):
                break

            if struct.pack('<I', zlib.adler32(self.recv_buf[:length - 4]) & 0xFFFFFFFF) != self.recv_buf[length - 4:length]:
                self.raw_trans = True
                self.recv_buf = b''
                raise Exception('client_post_decrypt data uncorrect checksum')

            pos = common.ord(self.recv_buf[4])
            if pos < 255:
                pos += 4
            else:
                pos = struct.unpack('>H', self.recv_buf[5:7])[0] + 4
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]

        if out_buf:
            self.decrypt_packet_num += 1
        return out_buf

    def server_pre_encrypt(self, buf):
        if self.raw_trans:
            return buf
        ret = b''
        while len(buf) > self.unit_len:
            ret += self.pack_data(buf[:self.unit_len])
            buf = buf[self.unit_len:]
        ret += self.pack_data(buf)
        return ret

    def server_post_decrypt(self, buf):
        if self.raw_trans:
            return (buf, False)
        self.recv_buf += buf
        out_buf = b''
        sendback = False

        if not self.has_recv_header:
            if len(self.recv_buf) <= 6:
                return (b'', False)
            crc = struct.pack('<I', binascii.crc32(self.recv_buf[:2] + self.salt + self.server_info.key) & 0xFFFFFFFF)
            if crc != self.recv_buf[2:6]:
                return self.not_match_return(self.recv_buf)
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length > len(self.recv_buf):
                return (b'', False)
            sha1data = hmac.new(self.server_info.recv_iv + self.server_info.key, self.recv_buf[:length - 10], hashlib.sha1).digest()[:10]
            if sha1data != self.recv_buf[length - 10:length]:
                logging.error('auth_sha1_v4 data uncorrect auth HMAC-SHA1')
                return self.not_match_return(self.recv_buf)
            pos = common.ord(self.recv_buf[6])
            if pos < 255:
                pos += 6
            else:
                pos = struct.unpack('>H', self.recv_buf[7:9])[0] + 6
            out_buf = self.recv_buf[pos:length - 10]
            if len(out_buf) < 12:
                logging.info('auth_sha1_v4: too short, data %s' % (binascii.hexlify(self.recv_buf),))
                return self.not_match_return(self.recv_buf)
            utc_time = struct.unpack('<I', out_buf[:4])[0]
            client_id = struct.unpack('<I', out_buf[4:8])[0]
            connection_id = struct.unpack('<I', out_buf[8:12])[0]
            time_dif = common.int32(utc_time - (int(time.time()) & 0xffffffff))
            if time_dif < -self.max_time_dif or time_dif > self.max_time_dif:
                logging.info('auth_sha1_v4: wrong timestamp, time_dif %d, data %s' % (time_dif, binascii.hexlify(out_buf),))
                return self.not_match_return(self.recv_buf)
            elif self.server_info.data.insert(client_id, connection_id):
                self.has_recv_header = True
                out_buf = out_buf[12:]
                self.client_id = client_id
                self.connection_id = connection_id
            else:
                logging.info('auth_sha1_v4: auth fail, data %s' % (binascii.hexlify(out_buf),))
                return self.not_match_return(self.recv_buf)
            self.recv_buf = self.recv_buf[length:]
            self.has_recv_header = True
            sendback = True

        while len(self.recv_buf) > 4:
            crc = struct.pack('<H', binascii.crc32(self.recv_buf[:2]) & 0xFFFF)
            if crc != self.recv_buf[2:4]:
                self.raw_trans = True
                logging.info('auth_sha1_v4: wrong crc')
                if self.decrypt_packet_num == 0:
                    logging.info('auth_sha1_v4: wrong crc')
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data error')
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 8192 or length < 7:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    logging.info('auth_sha1_v4: over size')
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            if struct.pack('<I', zlib.adler32(self.recv_buf[:length - 4]) & 0xFFFFFFFF) != self.recv_buf[length - 4:length]:
                logging.info('auth_sha1_v4: checksum error, data %s' % (binascii.hexlify(self.recv_buf[:length]),))
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data uncorrect checksum')

            pos = common.ord(self.recv_buf[4])
            if pos < 255:
                pos += 4
            else:
                pos = struct.unpack('>H', self.recv_buf[5:7])[0] + 4
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]
            if pos == length - 4:
                sendback = True

        if out_buf:
            self.server_info.data.update(self.client_id, self.connection_id)
            self.decrypt_packet_num += 1
        return (out_buf, sendback)

class obfs_auth_mu_data(object):
    def __init__(self):
        self.user_id = {}
        self.local_client_id = b''
        self.connection_id = 0
        self.set_max_client(64) # max active client count

    def update(self, user_id, client_id, connection_id):
        if user_id not in self.user_id:
            self.user_id[user_id] = lru_cache.LRUCache()
        local_client_id = self.user_id[user_id]

        if client_id in local_client_id:
            local_client_id[client_id].update()

    def set_max_client(self, max_client):
        self.max_client = max_client
        self.max_buffer = max(self.max_client * 2, 1024)

    def insert(self, user_id, client_id, connection_id):
        if user_id not in self.user_id:
            self.user_id[user_id] = lru_cache.LRUCache()
        local_client_id = self.user_id[user_id]

        if local_client_id.get(client_id, None) is None or not local_client_id[client_id].enable:
            if local_client_id.first() is None or len(local_client_id) < self.max_client:
                if client_id not in local_client_id:
                    #TODO: check
                    local_client_id[client_id] = client_queue(connection_id)
                else:
                    local_client_id[client_id].re_enable(connection_id)
                return local_client_id[client_id].insert(connection_id)

            if not local_client_id[local_client_id.first()].is_active():
                del local_client_id[local_client_id.first()]
                if client_id not in local_client_id:
                    #TODO: check
                    local_client_id[client_id] = client_queue(connection_id)
                else:
                    local_client_id[client_id].re_enable(connection_id)
                return local_client_id[client_id].insert(connection_id)

            logging.warn('auth_aes128: no inactive client')
            return False
        else:
            return local_client_id[client_id].insert(connection_id)

class auth_aes128_sha1(auth_base):
    def __init__(self, method, hashfunc):
        super(auth_aes128_sha1, self).__init__(method)
        self.hashfunc = hashfunc
        self.recv_buf = b''
        self.unit_len = 8100
        self.raw_trans = False
        self.has_sent_header = False
        self.has_recv_header = False
        self.client_id = 0
        self.connection_id = 0
        self.max_time_dif = 60 * 60 * 24 # time dif (second) setting
        self.salt = hashfunc == hashlib.md5 and b"auth_aes128_md5" or b"auth_aes128_sha1"
        self.no_compatible_method = hashfunc == hashlib.md5 and "auth_aes128_md5" or 'auth_aes128_sha1'
        self.extra_wait_size = struct.unpack('>H', os.urandom(2))[0] % 1024
        self.pack_id = 1
        self.recv_id = 1
        self.user_id = None
        self.user_key = None
        self.last_rnd_len = 0
        self.overhead = 9

    def init_data(self):
        return obfs_auth_mu_data()

    def get_overhead(self, direction): # direction: true for c->s false for s->c
        return self.overhead

    def set_server_info(self, server_info):
        self.server_info = server_info
        try:
            max_client = int(server_info.protocol_param.split('#')[0])
        except:
            max_client = 64
        self.server_info.data.set_max_client(max_client)

    def trapezoid_random_float(self, d):
        if d == 0:
            return random.random()
        s = random.random()
        a = 1 - d
        return (math.sqrt(a * a + 4 * d * s) - a) / (2 * d)

    def trapezoid_random_int(self, max_val, d):
        v = self.trapezoid_random_float(d)
        return int(v * max_val)

    def rnd_data_len(self, buf_size, full_buf_size):
        if full_buf_size >= self.server_info.buffer_size:
            return 0
        tcp_mss = self.server_info.tcp_mss
        rev_len = tcp_mss - buf_size - 9
        if rev_len == 0:
            return 0
        if rev_len < 0:
            if rev_len > -tcp_mss:
                return self.trapezoid_random_int(rev_len + tcp_mss, -0.3)
            return common.ord(os.urandom(1)[0]) % 32
        if buf_size > 900:
            return struct.unpack('>H', os.urandom(2))[0] % rev_len
        return self.trapezoid_random_int(rev_len, -0.3)

    def rnd_data(self, buf_size, full_buf_size):
        data_len = self.rnd_data_len(buf_size, full_buf_size)

        if data_len < 128:
            return common.chr(data_len + 1) + os.urandom(data_len)

        return common.chr(255) + struct.pack('<H', data_len + 1) + os.urandom(data_len - 2)

    def pack_data(self, buf, full_buf_size):
        data = self.rnd_data(len(buf), full_buf_size) + buf
        data_len = len(data) + 8
        mac_key = self.user_key + struct.pack('<I', self.pack_id)
        mac = hmac.new(mac_key, struct.pack('<H', data_len), self.hashfunc).digest()[:2]
        data = struct.pack('<H', data_len) + mac + data
        data += hmac.new(mac_key, data, self.hashfunc).digest()[:4]
        self.pack_id = (self.pack_id + 1) & 0xFFFFFFFF
        return data

    def pack_auth_data(self, auth_data, buf):
        if len(buf) == 0:
            return b''
        if len(buf) > 400:
            rnd_len = struct.unpack('<H', os.urandom(2))[0] % 512
        else:
            rnd_len = struct.unpack('<H', os.urandom(2))[0] % 1024
        data = auth_data
        data_len = 7 + 4 + 16 + 4 + len(buf) + rnd_len + 4
        data = data + struct.pack('<H', data_len) + struct.pack('<H', rnd_len)
        mac_key = self.server_info.iv + self.server_info.key
        uid = os.urandom(4)
        if b':' in to_bytes(self.server_info.protocol_param):
            try:
                items = to_bytes(self.server_info.protocol_param).split(b':')
                self.user_key = self.hashfunc(items[1]).digest()
                uid = struct.pack('<I', int(items[0]))
            except:
                pass
        if self.user_key is None:
            self.user_key = self.server_info.key
        encryptor = encrypt.Encryptor(to_bytes(base64.b64encode(self.user_key)) + self.salt, 'aes-128-cbc', b'\x00' * 16)
        data = uid + encryptor.encrypt(data)[16:]
        data += hmac.new(mac_key, data, self.hashfunc).digest()[:4]
        check_head = os.urandom(1)
        check_head += hmac.new(mac_key, check_head, self.hashfunc).digest()[:6]
        data = check_head + data + os.urandom(rnd_len) + buf
        data += hmac.new(self.user_key, data, self.hashfunc).digest()[:4]
        return data

    def auth_data(self):
        utc_time = int(time.time()) & 0xFFFFFFFF
        if self.server_info.data.connection_id > 0xFF000000:
            self.server_info.data.local_client_id = b''
        if not self.server_info.data.local_client_id:
            self.server_info.data.local_client_id = os.urandom(4)
            logging.debug("local_client_id %s" % (binascii.hexlify(self.server_info.data.local_client_id),))
            self.server_info.data.connection_id = struct.unpack('<I', os.urandom(4))[0] & 0xFFFFFF
        self.server_info.data.connection_id += 1
        return b''.join([struct.pack('<I', utc_time),
                self.server_info.data.local_client_id,
                struct.pack('<I', self.server_info.data.connection_id)])

    def client_pre_encrypt(self, buf):
        ret = b''
        ogn_data_len = len(buf)
        if not self.has_sent_header:
            head_size = self.get_head_size(buf, 30)
            datalen = min(len(buf), random.randint(0, 31) + head_size)
            ret += self.pack_auth_data(self.auth_data(), buf[:datalen])
            buf = buf[datalen:]
            self.has_sent_header = True
        while len(buf) > self.unit_len:
            ret += self.pack_data(buf[:self.unit_len], ogn_data_len)
            buf = buf[self.unit_len:]
        ret += self.pack_data(buf, ogn_data_len)
        self.last_rnd_len = ogn_data_len
        return ret

    def client_post_decrypt(self, buf):
        if self.raw_trans:
            return buf
        self.recv_buf += buf
        out_buf = b''
        while len(self.recv_buf) > 4:
            mac_key = self.user_key + struct.pack('<I', self.recv_id)
            mac = hmac.new(mac_key, self.recv_buf[:2], self.hashfunc).digest()[:2]
            if mac != self.recv_buf[2:4]:
                raise Exception('client_post_decrypt data uncorrect mac')
            length = struct.unpack('<H', self.recv_buf[:2])[0]
            if length >= 8192 or length < 7:
                self.raw_trans = True
                self.recv_buf = b''
                raise Exception('client_post_decrypt data error')
            if length > len(self.recv_buf):
                break

            if hmac.new(mac_key, self.recv_buf[:length - 4], self.hashfunc).digest()[:4] != self.recv_buf[length - 4:length]:
                self.raw_trans = True
                self.recv_buf = b''
                raise Exception('client_post_decrypt data uncorrect checksum')

            self.recv_id = (self.recv_id + 1) & 0xFFFFFFFF
            pos = common.ord(self.recv_buf[4])
            if pos < 255:
                pos += 4
            else:
                pos = struct.unpack('<H', self.recv_buf[5:7])[0] + 4
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]

        return out_buf

    def server_pre_encrypt(self, buf):
        if self.raw_trans:
            return buf
        ret = b''
        ogn_data_len = len(buf)
        while len(buf) > self.unit_len:
            ret += self.pack_data(buf[:self.unit_len], ogn_data_len)
            buf = buf[self.unit_len:]
        ret += self.pack_data(buf, ogn_data_len)
        self.last_rnd_len = ogn_data_len
        return ret

    def server_post_decrypt(self, buf):
        if self.raw_trans:
            return (buf, False)
        self.recv_buf += buf
        out_buf = b''
        sendback = False

        if not self.has_recv_header:
            if len(self.recv_buf) >= 7 or len(self.recv_buf) in [2, 3]:
                recv_len = min(len(self.recv_buf), 7)
                mac_key = self.server_info.recv_iv + self.server_info.key
                sha1data = hmac.new(mac_key, self.recv_buf[:1], self.hashfunc).digest()[:recv_len - 1]
                if sha1data != self.recv_buf[1:recv_len]:
                    return self.not_match_return(self.recv_buf)

            if len(self.recv_buf) < 31:
                return (b'', False)
            sha1data = hmac.new(mac_key, self.recv_buf[7:27], self.hashfunc).digest()[:4]
            if sha1data != self.recv_buf[27:31]:
                logging.error('%s data uncorrect auth HMAC-SHA1 from %s:%d, data %s' % (self.no_compatible_method, self.server_info.client, self.server_info.client_port, binascii.hexlify(self.recv_buf)))
                if len(self.recv_buf) < 31 + self.extra_wait_size:
                    return (b'', False)
                return self.not_match_return(self.recv_buf)

            uid = self.recv_buf[7:11]
            if uid in self.server_info.users:
                self.user_id = uid
                self.user_key = self.hashfunc(self.server_info.users[uid]).digest()
                self.server_info.update_user_func(uid)
            else:
                if not self.server_info.users:
                    self.user_key = self.server_info.key
                else:
                    self.user_key = self.server_info.recv_iv
            encryptor = encrypt.Encryptor(to_bytes(base64.b64encode(self.user_key)) + self.salt, 'aes-128-cbc')
            head = encryptor.decrypt(b'\x00' * 16 + self.recv_buf[11:27] + b'\x00') # need an extra byte or recv empty
            length = struct.unpack('<H', head[12:14])[0]
            if len(self.recv_buf) < length:
                return (b'', False)

            utc_time = struct.unpack('<I', head[:4])[0]
            client_id = struct.unpack('<I', head[4:8])[0]
            connection_id = struct.unpack('<I', head[8:12])[0]
            rnd_len = struct.unpack('<H', head[14:16])[0]
            if hmac.new(self.user_key, self.recv_buf[:length - 4], self.hashfunc).digest()[:4] != self.recv_buf[length - 4:length]:
                logging.info('%s: checksum error, data %s' % (self.no_compatible_method, binascii.hexlify(self.recv_buf[:length])))
                return self.not_match_return(self.recv_buf)
            time_dif = common.int32(utc_time - (int(time.time()) & 0xffffffff))
            if time_dif < -self.max_time_dif or time_dif > self.max_time_dif:
                logging.info('%s: wrong timestamp, time_dif %d, data %s' % (self.no_compatible_method, time_dif, binascii.hexlify(head)))
                return self.not_match_return(self.recv_buf)
            elif self.server_info.data.insert(self.user_id, client_id, connection_id):
                self.has_recv_header = True
                out_buf = self.recv_buf[31 + rnd_len:length - 4]
                self.client_id = client_id
                self.connection_id = connection_id
            else:
                logging.info('%s: auth fail, data %s' % (self.no_compatible_method, binascii.hexlify(out_buf)))
                return self.not_match_return(self.recv_buf)
            self.recv_buf = self.recv_buf[length:]
            self.has_recv_header = True
            sendback = True

        while len(self.recv_buf) > 4:
            mac_key = self.user_key + struct.pack('<I', self.recv_id)
            mac = hmac.new(mac_key, self.recv_buf[:2], self.hashfunc).digest()[:2]
            if mac != self.recv_buf[2:4]:
                self.raw_trans = True
                logging.info(self.no_compatible_method + ': wrong crc')
                if self.recv_id == 0:
                    logging.info(self.no_compatible_method + ': wrong crc')
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data error')
            length = struct.unpack('<H', self.recv_buf[:2])[0]
            if length >= 8192 or length < 7:
                self.raw_trans = True
                self.recv_buf = b''
                if self.recv_id == 0:
                    logging.info(self.no_compatible_method + ': over size')
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            if hmac.new(mac_key, self.recv_buf[:length - 4], self.hashfunc).digest()[:4] != self.recv_buf[length - 4:length]:
                logging.info('%s: checksum error, data %s' % (self.no_compatible_method, binascii.hexlify(self.recv_buf[:length])))
                self.raw_trans = True
                self.recv_buf = b''
                if self.recv_id == 0:
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data uncorrect checksum')

            self.recv_id = (self.recv_id + 1) & 0xFFFFFFFF
            pos = common.ord(self.recv_buf[4])
            if pos < 255:
                pos += 4
            else:
                pos = struct.unpack('<H', self.recv_buf[5:7])[0] + 4
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]
            if pos == length - 4:
                sendback = True

        if out_buf:
            self.server_info.data.update(self.user_id, self.client_id, self.connection_id)
        return (out_buf, sendback)

    def client_udp_pre_encrypt(self, buf):
        if self.user_key is None:
            if b':' in to_bytes(self.server_info.protocol_param):
                try:
                    items = to_bytes(self.server_info.protocol_param).split(':')
                    self.user_key = self.hashfunc(items[1]).digest()
                    self.user_id = struct.pack('<I', int(items[0]))
                except:
                    pass
            if self.user_key is None:
                self.user_id = os.urandom(4)
                self.user_key = self.server_info.key
        buf += self.user_id
        return buf + hmac.new(self.user_key, buf, self.hashfunc).digest()[:4]

    def client_udp_post_decrypt(self, buf):
        user_key = self.server_info.key
        if hmac.new(user_key, buf[:-4], self.hashfunc).digest()[:4] != buf[-4:]:
            return b''
        return buf[:-4]

    def server_udp_pre_encrypt(self, buf, uid):
        user_key = self.server_info.key
        return buf + hmac.new(user_key, buf, self.hashfunc).digest()[:4]

    def server_udp_post_decrypt(self, buf):
        uid = buf[-8:-4]
        if uid in self.server_info.users:
            user_key = self.hashfunc(self.server_info.users[uid]).digest()
        else:
            uid = None
            if not self.server_info.users:
                user_key = self.server_info.key
            else:
                user_key = self.server_info.recv_iv
        if hmac.new(user_key, buf[:-4], self.hashfunc).digest()[:4] != buf[-4:]:
            return (b'', None)
        return (buf[:-8], uid)

