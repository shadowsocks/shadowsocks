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
import datetime
import struct
import zlib

from shadowsocks.obfsplugin import plain
from shadowsocks import common
from shadowsocks.common import to_bytes, to_str, ord

def create_verify_obfs(method):
    return verify_simple(method)

def create_verify_deflate(method):
    return verify_deflate(method)

obfs = {
        'verify_simple': (create_verify_obfs,),
        'verify_deflate': (create_verify_deflate,),
}

def match_begin(str1, str2):
    if len(str1) >= len(str2):
        if str1[:len(str2)] == str2:
            return True
    return False

class verify_simple(plain.plain):
    def __init__(self, method):
        self.method = method
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

    def client_encode(self, buf):
        return buf

    def client_decode(self, buf):
        # (buffer_to_recv, is_need_to_encode_and_send_back)
        return (buf, False)

    def client_post_decrypt(self, buf):
        if self.raw_trans:
            return buf
        self.recv_buf += buf
        out_buf = b''
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 8192:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return None
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            if (binascii.crc32(self.recv_buf[:length]) & 0xffffffff) != 0xffffffff:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return None
                else:
                    raise Exception('server_post_decrype data uncorrect CRC32')

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

    def server_encode(self, buf):
        return buf

    def server_decode(self, buf):
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (buf, True, False)

    def server_post_decrypt(self, buf):
        if self.raw_trans:
            return buf
        self.recv_buf += buf
        out_buf = b''
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 8192:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return b'E'
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            if (binascii.crc32(self.recv_buf[:length]) & 0xffffffff) != 0xffffffff:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return b'E'
                else:
                    raise Exception('server_post_decrype data uncorrect CRC32')

            pos = common.ord(self.recv_buf[2]) + 2
            out_buf += self.recv_buf[pos:length - 4]
            self.recv_buf = self.recv_buf[length:]

        if out_buf:
            self.decrypt_packet_num += 1
        return out_buf

class verify_deflate(plain.plain):
    def __init__(self, method):
        self.method = method
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

    def client_encode(self, buf):
        return buf

    def client_decode(self, buf):
        # (buffer_to_recv, is_need_to_encode_and_send_back)
        return (buf, False)

    def client_post_decrypt(self, buf):
        if self.raw_trans:
            return buf
        self.recv_buf += buf
        out_buf = b''
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 32768:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return None
                else:
                    raise Exception('server_post_decrype data error')
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

    def server_encode(self, buf):
        return buf

    def server_decode(self, buf):
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (buf, True, False)

    def server_post_decrypt(self, buf):
        if self.raw_trans:
            return buf
        self.recv_buf += buf
        out_buf = b''
        while len(self.recv_buf) > 2:
            length = struct.unpack('>H', self.recv_buf[:2])[0]
            if length >= 32768:
                self.raw_trans = True
                self.recv_buf = b''
                if self.decrypt_packet_num == 0:
                    return None
                else:
                    raise Exception('server_post_decrype data error')
            if length > len(self.recv_buf):
                break

            out_buf += zlib.decompress(b'x\x9c' + self.recv_buf[2:length])
            self.recv_buf = self.recv_buf[length:]

        if out_buf:
            self.decrypt_packet_num += 1
        return out_buf

