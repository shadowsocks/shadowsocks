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

from shadowsocks.obfsplugin import plain
from shadowsocks import common
from shadowsocks.common import to_bytes, to_str, ord

def create_http_obfs(method):
    return http_simple(method)

def create_http2_obfs(method):
    return http2_simple(method)

def create_tls_obfs(method):
    return tls_simple(method)

def create_random_head_obfs(method):
    return random_head(method)

obfs = {
        'http_simple': (create_http_obfs,),
        'http_simple_compatible': (create_http_obfs,),
        'http2_simple': (create_http2_obfs,),
        'http2_simple_compatible': (create_http2_obfs,),
        'tls_simple': (create_tls_obfs,),
        'tls_simple_compatible': (create_tls_obfs,),
        'random_head': (create_random_head_obfs,),
        'random_head_compatible': (create_random_head_obfs,),
}

def match_begin(str1, str2):
    if len(str1) >= len(str2):
        if str1[:len(str2)] == str2:
            return True
    return False

class http_simple(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False
        self.host = None
        self.port = 0
        self.recv_buffer = b''

    def client_encode(self, buf):
        # TODO
        return buf

    def client_decode(self, buf):
        # TODO
        return (buf, False)

    def server_encode(self, buf):
        if self.has_sent_header:
            return buf

        header = b'HTTP/1.1 200 OK\r\nServer: openresty\r\nDate: '
        header += to_bytes(datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'))
        header += b'\r\nContent-Type: text/plain; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nKeep-Alive: timeout=20\r\nVary: Accept-Encoding\r\nContent-Encoding: gzip\r\n\r\n'
        self.has_sent_header = True
        return header + buf

    def get_data_from_http_header(self, buf):
        ret_buf = b''
        lines = buf.split(b'\r\n')
        if lines and len(lines) > 4:
            hex_items = lines[0].split(b'%')
            if hex_items and len(hex_items) > 1:
                for index in range(1, len(hex_items)):
                    if len(hex_items[index]) != 2:
                        ret_buf += binascii.unhexlify(hex_items[index][:2])
                        break
                    ret_buf += binascii.unhexlify(hex_items[index])
                return ret_buf
        return b''

    def not_match_return(self, buf):
        self.has_sent_header = True
        self.has_recv_header = True
        if self.method == 'http_simple':
            return (b'E', False, False)
        return (buf, True, False)

    def server_decode(self, buf):
        if self.has_recv_header:
            return (buf, True, False)

        buf = self.recv_buffer + buf
        if len(buf) > 10:
            if match_begin(buf, b'GET /') or match_begin(buf, b'POST /'):
                if len(buf) > 65536:
                    self.recv_buffer = None
                    return self.not_match_return(buf)
            else: #not http header, run on original protocol
                self.recv_buffer = None
                return self.not_match_return(buf)
        else:
            self.recv_buffer = buf
            return (b'', True, False)

        datas = buf.split(b'\r\n\r\n', 1)
        if datas and len(datas) > 1:
            ret_buf = self.get_data_from_http_header(buf)
            ret_buf += datas[1]
            if len(ret_buf) >= 15:
                self.has_recv_header = True
                return (ret_buf, True, False)
            self.recv_buffer = buf
            return (b'', True, False)
        else:
            self.recv_buffer = buf
            return (b'', True, False)
        return self.not_match_return(buf)

class http2_simple(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False
        self.host = None
        self.port = 0
        self.recv_buffer = b''

    def client_encode(self, buf):
        # TODO
        return buf

    def client_decode(self, buf):
        # TODO
        return (buf, False)

    def server_encode(self, buf):
        if self.has_sent_header:
            return buf

        header = b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n'
        self.has_sent_header = True
        return header + buf

    def not_match_return(self, buf):
        self.has_sent_header = True
        self.has_recv_header = True
        if self.method == 'http2_simple':
            return (b'E', False, False)
        return (buf, True, False)

    def server_decode(self, buf):
        if self.has_recv_header:
            return (buf, True, False)

        buf = self.recv_buffer + buf
        if len(buf) > 10:
            if match_begin(buf, b'GET /'):
                pass
            else: #not http header, run on original protocol
                self.recv_buffer = None
                return self.not_match_return(buf)
        else:
            self.recv_buffer = buf
            return (b'', True, False)

        datas = buf.split(b'\r\n\r\n', 1)
        if datas and len(datas) > 1 and len(datas[0]) >= 4:
            lines = buf.split(b'\r\n')
            if lines and len(lines) >= 4:
                if match_begin(lines[4], b'HTTP2-Settings: '):
                    ret_buf = base64.urlsafe_b64decode(lines[4][16:])
                    ret_buf += datas[1]
                    self.has_recv_header = True
                    return (ret_buf, True, False)
            self.recv_buffer = buf
            return (b'', True, False)
        else:
            self.recv_buffer = buf
            return (b'', True, False)
        return self.not_match_return(buf)

class tls_simple(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False

    def client_encode(self, buf):
        return buf

    def client_decode(self, buf):
        # (buffer_to_recv, is_need_to_encode_and_send_back)
        return (buf, False)

    def server_encode(self, buf):
        if self.has_sent_header:
            return buf
        self.has_sent_header = True
        # TODO
        #server_hello = b''
        return b'\x16\x03\x01'

    def server_decode(self, buf):
        if self.has_recv_header:
            return (buf, True, False)

        self.has_recv_header = True
        if not match_begin(buf, b'\x16\x03\x01'):
            self.has_sent_header = True
            if self.method == 'tls_simple':
                return (b'E', False, False)
            return (buf, True, False)
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (b'', False, True)

class random_head(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False

    def client_encode(self, buf):
        return buf

    def client_decode(self, buf):
        # (buffer_to_recv, is_need_to_encode_and_send_back)
        return (buf, False)

    def server_encode(self, buf):
        if self.has_sent_header:
            return buf
        self.has_sent_header = True
        return os.urandom(common.ord(os.urandom(1)[0]) % 96 + 4)

    def server_decode(self, buf):
        if self.has_recv_header:
            return (buf, True, False)

        self.has_recv_header = True
        crc = binascii.crc32(buf) & 0xffffffff
        if crc != 0xffffffff:
            self.has_sent_header = True
            if self.method == 'random_head':
                return (b'E', False, False)
            return (buf, True, False)
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (b'', False, True)

