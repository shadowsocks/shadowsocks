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
from shadowsocks import common
from shadowsocks.obfsplugin import plain
from shadowsocks.common import to_bytes, to_str, ord, chr

def create_verify_obfs(method):
    return verify_simple(method)

def create_verify_deflate(method):
    return verify_deflate(method)

def create_verify_sha1(method):
    return verify_sha1(method)

def create_auth_obfs(method):
    return auth_simple(method)

obfs_map = {
        'verify_simple': (create_verify_obfs,),
        'verify_deflate': (create_verify_deflate,),
        'verify_sha1': (create_verify_sha1,),
        'verify_sha1_compatible': (create_verify_sha1,),
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

    def init_data(self):
        return obfs_verify_data()

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

class verify_simple(verify_base):
    def __init__(self, method):
        super(verify_simple, self).__init__(method)
        self.recv_buf = b''
        self.unit_len = 8100
        self.decrypt_packet_num = 0
        self.raw_trans = False

    def pack_data(self, buf):
        if len(buf) == 0:
            return b''
        rnd_data = os.urandom(common.ord(os.urandom(1)[0]) % 16)
        data = common.chr(len(rnd_data) + 1) + rnd_data + buf
        data = struct.pack('>H', len(data) + 6) + data
        crc = (0xffffffff - binascii.crc32(data)) & 0xffffffff
        data += struct.pack('<I', crc)
        return data

    def client_pre_encrypt(self, buf):
        ret = b''
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

            if (binascii.crc32(self.recv_buf[:length]) & 0xffffffff) != 0xffffffff:
                self.raw_trans = True
                self.recv_buf = b''
                raise Exception('client_post_decrypt data uncorrect CRC32')

            pos = common.ord(self.recv_buf[2]) + 2
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]

        if out_buf:
            self.decrypt_packet_num += 1
        return out_buf

    def server_pre_encrypt(self, buf):
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
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 8192 or length < 7:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            if (binascii.crc32(self.recv_buf[:length]) & 0xffffffff) != 0xffffffff:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data uncorrect CRC32')

            pos = common.ord(self.recv_buf[2]) + 2
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]

        if out_buf:
            self.decrypt_packet_num += 1
        return (out_buf, False)

class verify_deflate(verify_base):
    def __init__(self, method):
        super(verify_deflate, self).__init__(method)
        self.recv_buf = b''
        self.unit_len = 32700
        self.decrypt_packet_num = 0
        self.raw_trans = False

    def pack_data(self, buf):
        if len(buf) == 0:
            return b''
        data = zlib.compress(buf)
        data = struct.pack('>H', len(data)) + data[2:]
        return data

    def client_pre_encrypt(self, buf):
        ret = b''
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
            if length >= 32768 or length < 6:
                self.raw_trans = True
                self.recv_buf = b''
                raise Exception('client_post_decrypt data error')
            if length > len(self.recv_buf):
                break

            out_buf += zlib.decompress(b'x\x9c' + self.recv_buf[2:length])
            self.recv_buf = self.recv_buf[length:]

        if out_buf:
            self.decrypt_packet_num += 1
        return out_buf

    def server_pre_encrypt(self, buf):
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
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 32768 or length < 6:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return (b'E'*2048, False)
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            out_buf += zlib.decompress(b'\x78\x9c' + self.recv_buf[2:length])
            self.recv_buf = self.recv_buf[length:]

        if out_buf:
            self.decrypt_packet_num += 1
        return (out_buf, False)

class verify_sha1(verify_base):
    def __init__(self, method):
        super(verify_sha1, self).__init__(method)
        self.recv_buf = b''
        self.unit_len = 8100
        self.raw_trans = False
        self.pack_id = 0
        self.recv_id = 0
        self.has_sent_header = False
        self.has_recv_header = False

    def pack_data(self, buf):
        if len(buf) == 0:
            return b''
        sha1data = hmac.new(self.server_info.iv + struct.pack('>I', self.pack_id), buf, hashlib.sha1).digest()
        data = struct.pack('>H', len(buf)) + sha1data[:10] + buf
        self.pack_id += 1
        return data

    def pack_auth_data(self, buf):
        data = chr(ord(buf[0]) | 0x10) + buf[1:]
        data += hmac.new(self.server_info.iv + self.server_info.key, data, hashlib.sha1).digest()[:10]
        return data

    def client_pre_encrypt(self, buf):
        ret = b''
        if not self.has_sent_header:
            datalen = self.get_head_size(buf, 30)
            ret += self.pack_auth_data(buf[:datalen])
            buf = buf[datalen:]
            self.has_sent_header = True
        while len(buf) > self.unit_len:
            ret += self.pack_data(buf[:self.unit_len])
            buf = buf[self.unit_len:]
        ret += self.pack_data(buf)
        return ret

    def client_post_decrypt(self, buf):
        return buf

    def server_pre_encrypt(self, buf):
        return buf

    def not_match_return(self, buf):
        self.raw_trans = True
        if self.method == 'verify_sha1':
            return (b'E'*2048, False)
        return (buf, False)

    def server_post_decrypt(self, buf):
        if self.raw_trans:
            return (buf, False)
        self.recv_buf += buf
        out_buf = b''
        if not self.has_recv_header:
            if len(self.recv_buf) < 2:
                return (b'', False)
            if (ord(self.recv_buf[0]) & 0x10) != 0x10:
                return self.not_match_return(self.recv_buf)
            head_size = self.get_head_size(self.recv_buf, 65536)
            if len(self.recv_buf) < head_size + 10:
                return self.not_match_return(self.recv_buf)
            sha1data = hmac.new(self.server_info.recv_iv + self.server_info.key, self.recv_buf[:head_size], hashlib.sha1).digest()[:10]
            if sha1data != self.recv_buf[head_size:head_size + 10]:
                logging.error('server_post_decrype data uncorrect auth HMAC-SHA1')
                return self.not_match_return(self.recv_buf)
            out_buf = to_bytes(chr(ord(self.recv_buf[0]) & 0xEF)) + self.recv_buf[1:head_size]
            self.recv_buf = self.recv_buf[head_size + 10:]
            self.has_recv_header = True
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0] + 12
            if length > len(self.recv_buf):
                break

            data = self.recv_buf[12:length]
            sha1data = hmac.new(self.server_info.recv_iv + struct.pack('>I', self.recv_id), data, hashlib.sha1).digest()[:10]
            if sha1data != self.recv_buf[2:12]:
                raise Exception('server_post_decrype data uncorrect chunk HMAC-SHA1')

            self.recv_id = (self.recv_id + 1) & 0xFFFFFFFF
            out_buf += data
            self.recv_buf = self.recv_buf[length:]

        return (out_buf, False)

    def client_udp_pre_encrypt(self, buf):
        ret = self.pack_auth_data(buf)
        return chr(ord(buf[0]) | 0x10) + buf[1:]

    def server_udp_post_decrypt(self, buf):
        if buf and ((ord(buf[0]) & 0x10) == 0x10):
            if len(buf) <= 11:
                return b''
            sha1data = hmac.new(self.server_info.recv_iv + self.server_info.key, buf[:-10], hashlib.sha1).digest()[:10]
            if sha1data != buf[-10:]:
                return b''
            return to_bytes(chr(ord(buf[0]) & 0xEF)) + buf[1:-10]
        else:
            return buf

