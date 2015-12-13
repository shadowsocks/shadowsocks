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
import struct
import base64
import time
import random
import hmac
import hashlib

from shadowsocks import common
from shadowsocks.obfsplugin import plain
from shadowsocks.common import to_bytes, to_str, ord
from shadowsocks import lru_cache

def create_tls_obfs(method):
    return tls_simple(method)

def create_tls_auth_obfs(method):
    return tls_auth(method)

obfs_map = {
        'tls_simple': (create_tls_obfs,),
        'tls_simple_compatible': (create_tls_obfs,),
        'tls1.0_session_auth': (create_tls_auth_obfs,),
        'tls1.0_session_auth_compatible': (create_tls_auth_obfs,),
}

def match_begin(str1, str2):
    if len(str1) >= len(str2):
        if str1[:len(str2)] == str2:
            return True
    return False

class tls_simple(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False
        self.raw_trans_sent = False
        self.send_buffer = b''
        self.tls_version = b'\x03\x01'

    def client_encode(self, buf):
        if self.raw_trans_sent:
            return buf
        self.send_buffer += buf
        if not self.has_sent_header:
            self.has_sent_header = True
            data = self.tls_version + os.urandom(32) + binascii.unhexlify(b"000016c02bc02fc00ac009c013c01400330039002f0035000a0100006fff01000100000a00080006001700180019000b0002010000230000337400000010002900270568322d31360568322d31350568322d313402683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202")
            data = b"\x01\x00" + struct.pack('>H', len(data)) + data
            data = b"\x16" + self.tls_version + struct.pack('>H', len(data)) + data
            return data
        if self.has_recv_header:
            ret = self.send_buffer
            self.send_buffer = b''
            self.raw_trans_sent = True
            return ret
        return b''

    def client_decode(self, buf):
        if self.has_recv_header:
            return (buf, False)
        self.has_recv_header = True
        return (b'', True)

    def server_encode(self, buf):
        if self.has_sent_header:
            return buf
        self.has_sent_header = True
        # TODO
        data = self.tls_version + os.urandom(32)
        data = b"\x02\x00" + struct.pack('>H', len(data)) + data
        data = b"\x16" + self.tls_version + struct.pack('>H', len(data)) + data
        return data

    def decode_error_return(self, buf):
        self.has_sent_header = True
        if self.method == 'tls_simple':
            return (b'E', False, False)
        return (buf, True, False)

    def server_decode(self, buf):
        if self.has_recv_header:
            return (buf, True, False)

        self.has_recv_header = True
        if not match_begin(buf, b'\x16' + self.tls_version):
            return self.decode_error_return(buf)
        buf = buf[3:]
        if struct.unpack('>H', buf[:2])[0] != len(buf) - 2:
            return self.decode_error_return(buf)
        buf = buf[2:]
        if not match_begin(buf, b'\x01\x00'): #client hello
            return self.decode_error_return(buf)
        buf = buf[2:]
        if struct.unpack('>H', buf[:2])[0] != len(buf) - 2:
            return self.decode_error_return(buf)
        buf = buf[2:]
        if not match_begin(buf, self.tls_version):
            return self.decode_error_return(buf)
        buf = buf[2:]
        verifyid = buf[:32]
        buf = buf[32:]
        sessionid_len = ord(buf[1])
        sessionid = buf[1:sessionid_len + 1]
        buf = buf[sessionid_len+1:]
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (b'', False, True)

class obfs_client_data(object):
    def __init__(self, cid):
        self.client_id = cid
        self.auth_code = {}

class obfs_auth_data(object):
    def __init__(self):
        self.client_data = lru_cache.LRUCache(60 * 5)
        self.client_id = os.urandom(32)
        self.startup_time = int(time.time() - 60 * 30) & 0xFFFFFFFF

class tls_auth(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False
        self.raw_trans_sent = False
        self.raw_trans_recv = False
        self.send_buffer = b''
        self.client_id = b''
        self.max_time_dif = 60 * 60 # time dif (second) setting
        self.tls_version = b'\x03\x01'

    def init_data(self):
        return obfs_auth_data()

    def pack_auth_data(self, client_id):
        utc_time = int(time.time()) & 0xFFFFFFFF
        data = struct.pack('>I', utc_time) + os.urandom(18)
        data += hmac.new(self.server_info.key + client_id, data, hashlib.sha1).digest()[:10]
        return data

    def client_encode(self, buf):
        if self.raw_trans_sent:
            return buf
        self.send_buffer += buf
        if not self.has_sent_header:
            self.has_sent_header = True
            data = self.tls_version + self.pack_auth_data(self.server_info.data.client_id) + b"\x20" + self.server_info.data.client_id + binascii.unhexlify(b"0016c02bc02fc00ac009c013c01400330039002f0035000a0100006fff01000100000a00080006001700180019000b0002010000230000337400000010002900270568322d31360568322d31350568322d313402683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202")
            data = b"\x01\x00" + struct.pack('>H', len(data)) + data
            data = b"\x16" + self.tls_version + struct.pack('>H', len(data)) + data
            return data
        if self.has_recv_header:
            data = b"\x14" + self.tls_version + "\x00\x01\x01" #ChangeCipherSpec
            data += b"\x16" + self.tls_version + "\x00\x01\x20" + os.urandom(22) #Finished
            data += hmac.new(self.server_info.key + self.server_info.data.client_id, data, hashlib.sha1).digest()[:10]
            ret = data + self.send_buffer
            self.send_buffer = b''
            self.raw_trans_sent = True
            return ret
        return b''

    def client_decode(self, buf):
        if self.has_recv_header:
            return (buf, False)
        self.has_recv_header = True
        return (b'', True)

    def server_encode(self, buf):
        if self.has_sent_header:
            return buf
        self.has_sent_header = True
        data = self.tls_version + self.pack_auth_data(self.client_id) + b"\x20" + self.client_id + binascii.unhexlify(b"0016c02bc02fc00ac009c013c01400330039002f0035000a0100006fff01000100000a00080006001700180019000b0002010000230000337400000010002900270568322d31360568322d31350568322d313402683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202")
        data = b"\x02\x00" + struct.pack('>H', len(data)) + data #server hello
        data = b"\x16" + self.tls_version + struct.pack('>H', len(data)) + data
        data += b"\x14" + self.tls_version + "\x00\x01\x01" #ChangeCipherSpec
        data += b"\x16" + self.tls_version + "\x00\x01\x20" + os.urandom(22) #Finished
        data += hmac.new(self.server_info.key + self.client_id, data, hashlib.sha1).digest()[:10]
        return data

    def decode_error_return(self, buf):
        self.raw_trans_recv = True
        if self.method == 'tls_simple':
            return (b'E', False, False)
        return (buf, True, False)

    def server_decode(self, buf):
        if self.raw_trans_recv:
            return (buf, True, False)

        if self.has_recv_header:
            verify = buf
            verify_len = 44 - 10
            if len(buf) < 44:
                logging.error('server_decode data error')
                return decode_error_return(b'')
            if not match_begin(buf, b"\x14" + self.tls_version + "\x00\x01\x01"): #ChangeCipherSpec
                logging.error('server_decode data error')
                return decode_error_return(b'')
            buf = buf[6:]
            if not match_begin(buf, b"\x16" + self.tls_version + "\x00\x01\x20"): #Finished
                logging.error('server_decode data error')
                return decode_error_return(b'')
            if hmac.new(self.server_info.key + self.client_id, verify[:verify_len], hashlib.sha1).digest()[:10] != verify[verify_len:verify_len+10]:
                logging.error('server_decode data error')
                return decode_error_return(b'')
            if len(buf) < 38:
                logging.error('server_decode data error')
                return decode_error_return(b'')
            buf = buf[38:]
            self.raw_trans_recv = True
            return (buf, True, False)

        self.has_recv_header = True
        ogn_buf = buf
        if not match_begin(buf, b'\x16' + self.tls_version):
            return self.decode_error_return(ogn_buf)
        buf = buf[3:]
        if struct.unpack('>H', buf[:2])[0] != len(buf) - 2:
            return self.decode_error_return(ogn_buf)
        buf = buf[2:]
        if not match_begin(buf, b'\x01\x00'): #client hello
            return self.decode_error_return(ogn_buf)
        buf = buf[2:]
        if struct.unpack('>H', buf[:2])[0] != len(buf) - 2:
            return self.decode_error_return(ogn_buf)
        buf = buf[2:]
        if not match_begin(buf, self.tls_version):
            return self.decode_error_return(ogn_buf)
        buf = buf[2:]
        verifyid = buf[:32]
        buf = buf[32:]
        sessionid_len = ord(buf[0])
        if sessionid_len < 32:
            logging.error("tls_auth wrong sessionid_len")
            return self.decode_error_return(ogn_buf)
        sessionid = buf[1:sessionid_len + 1]
        buf = buf[sessionid_len+1:]
        self.client_id = sessionid
        sha1 = hmac.new(self.server_info.key + sessionid, verifyid[:22], hashlib.sha1).digest()[:10]
        utc_time = struct.unpack('>I', verifyid[:4])[0]
        time_dif = common.int32((int(time.time()) & 0xffffffff) - utc_time)
        if time_dif < -self.max_time_dif or time_dif > self.max_time_dif \
                or common.int32(utc_time - self.server_info.data.startup_time) < -self.max_time_dif / 2:
            logging.debug("tls_auth wrong time")
            return self.decode_error_return(ogn_buf)
        if sha1 != verifyid[22:]:
            logging.debug("tls_auth wrong sha1")
            return self.decode_error_return(ogn_buf)
        if self.server_info.data.client_data.get(verifyid[:22]):
            logging.error("replay attack detect, id = %s" % (binascii.hexlify(verifyid)))
            return self.decode_error_return(ogn_buf)
        self.server_info.data.client_data.sweep()
        self.server_info.data.client_data[verifyid[:22]] = sessionid
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (b'', False, True)

