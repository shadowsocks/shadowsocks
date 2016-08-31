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
import struct
import zlib
import hmac
import hashlib

import shadowsocks
from shadowsocks import common, lru_cache
from shadowsocks.obfsplugin import plain
from shadowsocks.common import to_bytes, to_str, ord, chr

def create_auth_sha1(method):
    return auth_sha1(method)

def create_auth_sha1_v2(method):
    return auth_sha1_v2(method)

def create_auth_sha1_v3(method):
    return auth_sha1_v3(method)

obfs_map = {
        'auth_sha1': (create_auth_sha1,),
        'auth_sha1_compatible': (create_auth_sha1,),
        'auth_sha1_v2': (create_auth_sha1_v2,),
        'auth_sha1_v2_compatible': (create_auth_sha1_v2,),
        'auth_sha1_v3': (create_auth_sha1_v3,),
        'auth_sha1_v3_compatible': (create_auth_sha1_v3,),
}

def match_begin(str1, str2):
    if len(str1) >= len(str2):
        if str1[:len(str2)] == str2:
            return True
    return False

class obfs_verify_data(object):
    def __init__(self):
        pass

class verify_base(plain.plain):
    def __init__(self, method):
        super(verify_base, self).__init__(method)
        self.method = method
        self.no_compatible_method = ''

    def init_data(self):
        return ''

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
        if self.method == self.no_compatible_method:
            return (b'E'*64, False)
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
            logging.warn('obfs auth: duplicate id')
            return False
        if connection_id > self.front + 0x4000:
            logging.warn('obfs auth: wrong id')
            return False
        if connection_id in self.alloc:
            logging.warn('obfs auth: duplicate id 2')
            return False
        if self.back <= connection_id:
            self.back = connection_id + 1
        self.alloc[connection_id] = 1
        while (self.front in self.alloc) or self.front + 0x1000 < self.back:
            if self.front in self.alloc:
                del self.alloc[self.front]
            self.front += 1
        return True

class obfs_auth_data(object):
    def __init__(self):
        self.client_id = {}
        self.startup_time = int(time.time() - 30) & 0xFFFFFFFF
        self.local_client_id = b''
        self.connection_id = 0
        self.set_max_client(64) # max active client count

    def update(self, client_id, connection_id):
        if client_id in self.client_id:
            self.client_id[client_id].update()

    def set_max_client(self, max_client):
        self.max_client = max_client
        self.max_buffer = max(self.max_client * 2, 256)

    def insert(self, client_id, connection_id):
        if client_id not in self.client_id or not self.client_id[client_id].enable:
            active = 0
            for c_id in self.client_id:
                if self.client_id[c_id].is_active():
                    active += 1
            if active >= self.max_client:
                logging.warn('obfs auth: max active clients exceeded')
                return False

            if len(self.client_id) < self.max_client:
                if client_id not in self.client_id:
                    self.client_id[client_id] = client_queue(connection_id)
                else:
                    self.client_id[client_id].re_enable(connection_id)
                return self.client_id[client_id].insert(connection_id)
            keys = self.client_id.keys()
            random.shuffle(keys)
            for c_id in keys:
                if not self.client_id[c_id].is_active() and self.client_id[c_id].enable:
                    if len(self.client_id) >= self.max_buffer:
                        del self.client_id[c_id]
                    else:
                        self.client_id[c_id].enable = False
                    if client_id not in self.client_id:
                        self.client_id[client_id] = client_queue(connection_id)
                    else:
                        self.client_id[client_id].re_enable(connection_id)
                    return self.client_id[client_id].insert(connection_id)
            logging.warn('obfs auth: no inactive client [assert]')
            return False
        else:
            return self.client_id[client_id].insert(connection_id)

class auth_sha1(verify_base):
    def __init__(self, method):
        super(auth_sha1, self).__init__(method)
        self.recv_buf = b''
        self.unit_len = 8000
        self.decrypt_packet_num = 0
        self.raw_trans = False
        self.has_sent_header = False
        self.has_recv_header = False
        self.client_id = 0
        self.connection_id = 0
        self.max_time_dif = 60 * 60 # time dif (second) setting
        self.no_compatible_method = 'auth_sha1'

    def init_data(self):
        return obfs_auth_data()

    def set_server_info(self, server_info):
        self.server_info = server_info
        try:
            max_client = int(server_info.protocol_param)
        except:
            max_client = 64
        self.server_info.data.set_max_client(max_client)

    def pack_data(self, buf):
        rnd_data = os.urandom(common.ord(os.urandom(1)[0]) % 16)
        data = common.chr(len(rnd_data) + 1) + rnd_data + buf
        data = struct.pack('>H', len(data) + 6) + data
        adler32 = zlib.adler32(data) & 0xFFFFFFFF
        data += struct.pack('<I', adler32)
        return data

    def pack_auth_data(self, buf):
        if len(buf) == 0:
            return b''
        rnd_data = os.urandom(common.ord(os.urandom(1)[0]) % 128)
        data = common.chr(len(rnd_data) + 1) + rnd_data + buf
        data = struct.pack('>H', len(data) + 16) + data
        crc = binascii.crc32(self.server_info.key) & 0xFFFFFFFF
        data = struct.pack('<I', crc) + data
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
        while len(self.recv_buf) > 2:
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

            pos = common.ord(self.recv_buf[2]) + 2
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
        if not self.has_recv_header:
            if len(self.recv_buf) < 6:
                return (b'', False)
            crc = struct.pack('<I', binascii.crc32(self.server_info.key) & 0xFFFFFFFF)
            if crc != self.recv_buf[:4]:
                return self.not_match_return(self.recv_buf)
            length = struct.unpack('>H', self.recv_buf[4:6])[0]
            if length > 2048:
                return self.not_match_return(self.recv_buf)
            if length > len(self.recv_buf):
                return (b'', False)
            sha1data = hmac.new(self.server_info.recv_iv + self.server_info.key, self.recv_buf[:length - 10], hashlib.sha1).digest()[:10]
            if sha1data != self.recv_buf[length - 10:length]:
                logging.error('auth_sha1 data uncorrect auth HMAC-SHA1')
                return self.not_match_return(self.recv_buf)
            pos = common.ord(self.recv_buf[6]) + 6
            out_buf = self.recv_buf[pos:length - 10]
            if len(out_buf) < 12:
                logging.info('auth_sha1: too short, data %s' % (binascii.hexlify(self.recv_buf),))
                return self.not_match_return(self.recv_buf)
            utc_time = struct.unpack('<I', out_buf[:4])[0]
            client_id = struct.unpack('<I', out_buf[4:8])[0]
            connection_id = struct.unpack('<I', out_buf[8:12])[0]
            time_dif = common.int32(utc_time - (int(time.time()) & 0xffffffff))
            if time_dif < -self.max_time_dif or time_dif > self.max_time_dif \
                    or common.int32(utc_time - self.server_info.data.startup_time) < -self.max_time_dif / 2:
                logging.info('auth_sha1: wrong timestamp, time_dif %d, data %s' % (time_dif, binascii.hexlify(out_buf),))
                return self.not_match_return(self.recv_buf)
            elif self.server_info.data.insert(client_id, connection_id):
                self.has_recv_header = True
                out_buf = out_buf[12:]
                self.client_id = client_id
                self.connection_id = connection_id
            else:
                logging.info('auth_sha1: auth fail, data %s' % (binascii.hexlify(out_buf),))
                return self.not_match_return(self.recv_buf)
            self.recv_buf = self.recv_buf[length:]
            self.has_recv_header = True

        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 8192 or length < 7:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    logging.info('auth_sha1: over size')
                    return (b'E', False)
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            if struct.pack('<I', zlib.adler32(self.recv_buf[:length - 4]) & 0xFFFFFFFF) != self.recv_buf[length - 4:length]:
                logging.info('auth_sha1: checksum error, data %s' % (binascii.hexlify(self.recv_buf[:length]),))
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return (b'E', False)
                else:
                    raise Exception('server_post_decrype data uncorrect checksum')

            pos = common.ord(self.recv_buf[2]) + 2
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]

        if out_buf:
            self.server_info.data.update(self.client_id, self.connection_id)
            self.decrypt_packet_num += 1
        return (out_buf, False)

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

class auth_sha1_v2(verify_base):
    def __init__(self, method):
        super(auth_sha1_v2, self).__init__(method)
        self.recv_buf = b''
        self.unit_len = 8100
        self.decrypt_packet_num = 0
        self.raw_trans = False
        self.has_sent_header = False
        self.has_recv_header = False
        self.client_id = 0
        self.connection_id = 0
        self.salt = b"auth_sha1_v2"
        self.no_compatible_method = 'auth_sha1_v2'

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
        if buf_size > 1300:
            return b'\x01'

        if buf_size > 400:
            rnd_data = os.urandom(common.ord(os.urandom(1)[0]) % 128)
            return common.chr(len(rnd_data) + 1) + rnd_data

        rnd_data = os.urandom(struct.unpack('>H', os.urandom(2))[0] % 1024)
        return common.chr(255) + struct.pack('>H', len(rnd_data) + 3) + rnd_data

    def pack_data(self, buf):
        data = self.rnd_data(len(buf)) + buf
        data = struct.pack('>H', len(data) + 6) + data
        adler32 = zlib.adler32(data) & 0xFFFFFFFF
        data += struct.pack('<I', adler32)
        return data

    def pack_auth_data(self, buf):
        if len(buf) == 0:
            return b''
        data = self.rnd_data(len(buf)) + buf
        data = struct.pack('>H', len(data) + 16) + data
        crc = binascii.crc32(self.salt + self.server_info.key) & 0xFFFFFFFF
        data = struct.pack('<I', crc) + data
        data += hmac.new(self.server_info.iv + self.server_info.key, data, hashlib.sha1).digest()[:10]
        return data

    def auth_data(self):
        if self.server_info.data.connection_id > 0xFF000000:
            self.server_info.data.local_client_id = b''
        if not self.server_info.data.local_client_id:
            self.server_info.data.local_client_id = os.urandom(8)
            logging.debug("local_client_id %s" % (binascii.hexlify(self.server_info.data.local_client_id),))
            self.server_info.data.connection_id = struct.unpack('<Q', self.server_info.data.local_client_id)[0] % 0xFFFFFD
        self.server_info.data.connection_id += 1
        return b''.join([self.server_info.data.local_client_id,
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
        while len(self.recv_buf) > 2:
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

            pos = common.ord(self.recv_buf[2])
            if pos < 255:
                pos += 2
            else:
                pos = struct.unpack('>H', self.recv_buf[3:5])[0] + 2
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
        if not self.has_recv_header:
            if len(self.recv_buf) < 6:
                return (b'', False)
            crc = struct.pack('<I', binascii.crc32(self.salt + self.server_info.key) & 0xFFFFFFFF)
            if crc != self.recv_buf[:4]:
                return self.not_match_return(self.recv_buf)
            length = struct.unpack('>H', self.recv_buf[4:6])[0]
            if length > 2048:
                return self.not_match_return(self.recv_buf)
            if length > len(self.recv_buf):
                return (b'', False)
            sha1data = hmac.new(self.server_info.recv_iv + self.server_info.key, self.recv_buf[:length - 10], hashlib.sha1).digest()[:10]
            if sha1data != self.recv_buf[length - 10:length]:
                logging.error('auth_sha1_v2 data uncorrect auth HMAC-SHA1')
                return self.not_match_return(self.recv_buf)
            pos = common.ord(self.recv_buf[6])
            if pos < 255:
                pos += 6
            else:
                pos = struct.unpack('>H', self.recv_buf[7:9])[0] + 6
            out_buf = self.recv_buf[pos:length - 10]
            if len(out_buf) < 12:
                logging.info('auth_sha1_v2: too short, data %s' % (binascii.hexlify(self.recv_buf),))
                return self.not_match_return(self.recv_buf)
            client_id = struct.unpack('<Q', out_buf[:8])[0]
            connection_id = struct.unpack('<I', out_buf[8:12])[0]
            if self.server_info.data.insert(client_id, connection_id):
                self.has_recv_header = True
                out_buf = out_buf[12:]
                self.client_id = client_id
                self.connection_id = connection_id
            else:
                logging.info('auth_sha1_v2: auth fail, data %s' % (binascii.hexlify(out_buf),))
                return self.not_match_return(self.recv_buf)
            self.recv_buf = self.recv_buf[length:]
            self.has_recv_header = True

        sendback = False
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 8192 or length < 7:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    logging.info('auth_sha1_v2: over size')
                    return (b'E', False)
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            if struct.pack('<I', zlib.adler32(self.recv_buf[:length - 4]) & 0xFFFFFFFF) != self.recv_buf[length - 4:length]:
                logging.info('auth_sha1_v2: checksum error, data %s' % (binascii.hexlify(self.recv_buf[:length]),))
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return (b'E', False)
                else:
                    raise Exception('server_post_decrype data uncorrect checksum')

            pos = common.ord(self.recv_buf[2])
            if pos < 255:
                pos += 2
            else:
                pos = struct.unpack('>H', self.recv_buf[3:5])[0] + 2
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]
            if pos == length - 4:
                sendback = True

        if out_buf:
            self.server_info.data.update(self.client_id, self.connection_id)
            self.decrypt_packet_num += 1
        return (out_buf, sendback)

class auth_sha1_v3(verify_base):
    def __init__(self, method):
        super(auth_sha1_v3, self).__init__(method)
        self.recv_buf = b''
        self.unit_len = 8100
        self.decrypt_packet_num = 0
        self.raw_trans = False
        self.has_sent_header = False
        self.has_recv_header = False
        self.client_id = 0
        self.connection_id = 0
        self.max_time_dif = 60 * 60 * 24 # time dif (second) setting
        self.salt = b"auth_sha1_v3"
        self.no_compatible_method = 'auth_sha1_v3'

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
        data = struct.pack('>H', len(data) + 6) + data
        adler32 = zlib.adler32(data) & 0xFFFFFFFF
        data += struct.pack('<I', adler32)
        return data

    def pack_auth_data(self, buf):
        if len(buf) == 0:
            return b''
        data = self.rnd_data(len(buf)) + buf
        data_len = len(data) + 16
        crc = binascii.crc32(self.salt + self.server_info.key + struct.pack('>H', data_len)) & 0xFFFFFFFF
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
        while len(self.recv_buf) > 2:
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

            pos = common.ord(self.recv_buf[2])
            if pos < 255:
                pos += 2
            else:
                pos = struct.unpack('>H', self.recv_buf[3:5])[0] + 2
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
        if not self.has_recv_header:
            if len(self.recv_buf) < 6:
                return (b'', False)
            crc = struct.pack('<I', binascii.crc32(self.salt + self.server_info.key + self.recv_buf[:2]) & 0xFFFFFFFF)
            if crc != self.recv_buf[2:6]:
                return self.not_match_return(self.recv_buf)
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length > len(self.recv_buf):
                return (b'', False)
            sha1data = hmac.new(self.server_info.recv_iv + self.server_info.key, self.recv_buf[:length - 10], hashlib.sha1).digest()[:10]
            if sha1data != self.recv_buf[length - 10:length]:
                logging.error('auth_sha1_v3 data uncorrect auth HMAC-SHA1')
                return self.not_match_return(self.recv_buf)
            pos = common.ord(self.recv_buf[6])
            if pos < 255:
                pos += 6
            else:
                pos = struct.unpack('>H', self.recv_buf[7:9])[0] + 6
            out_buf = self.recv_buf[pos:length - 10]
            if len(out_buf) < 12:
                logging.info('auth_sha1_v3: too short, data %s' % (binascii.hexlify(self.recv_buf),))
                return self.not_match_return(self.recv_buf)
            utc_time = struct.unpack('<I', out_buf[:4])[0]
            client_id = struct.unpack('<I', out_buf[4:8])[0]
            connection_id = struct.unpack('<I', out_buf[8:12])[0]
            time_dif = common.int32(utc_time - (int(time.time()) & 0xffffffff))
            if time_dif < -self.max_time_dif or time_dif > self.max_time_dif:
                logging.info('auth_sha1_v3: wrong timestamp, time_dif %d, data %s' % (time_dif, binascii.hexlify(out_buf),))
                return self.not_match_return(self.recv_buf)
            elif self.server_info.data.insert(client_id, connection_id):
                self.has_recv_header = True
                out_buf = out_buf[12:]
                self.client_id = client_id
                self.connection_id = connection_id
            else:
                logging.info('auth_sha1_v3: auth fail, data %s' % (binascii.hexlify(out_buf),))
                return self.not_match_return(self.recv_buf)
            self.recv_buf = self.recv_buf[length:]
            self.has_recv_header = True

        sendback = False
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 8192 or length < 7:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    logging.info('auth_sha1_v3: over size')
                    return (b'E', False)
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            if struct.pack('<I', zlib.adler32(self.recv_buf[:length - 4]) & 0xFFFFFFFF) != self.recv_buf[length - 4:length]:
                logging.info('auth_sha1_v3: checksum error, data %s' % (binascii.hexlify(self.recv_buf[:length]),))
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return (b'E', False)
                else:
                    raise Exception('server_post_decrype data uncorrect checksum')

            pos = common.ord(self.recv_buf[2])
            if pos < 255:
                pos += 2
            else:
                pos = struct.unpack('>H', self.recv_buf[3:5])[0] + 2
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]
            if pos == length - 4:
                sendback = True

        if out_buf:
            self.server_info.data.update(self.client_id, self.connection_id)
            self.decrypt_packet_num += 1
        return (out_buf, sendback)

