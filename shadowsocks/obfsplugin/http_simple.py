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
import datetime
import random

from shadowsocks import common
from shadowsocks.obfsplugin import plain
from shadowsocks.common import to_bytes, to_str, ord

def create_http_obfs(method):
    return http_simple(method)

def create_http2_obfs(method):
    return http2_simple(method)

def create_tls_obfs(method):
    return tls_simple(method)

def create_random_head_obfs(method):
    return random_head(method)

obfs_map = {
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
        self.user_agent = [b"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
            b"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
            b"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
            b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
            b"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
            b"Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
            b"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            b"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
            b"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
            b"Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
            b"Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
            b"Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3"]

    def encode_head(self, buf):
        ret = b''
        for ch in buf:
            ret += '%' + binascii.hexlify(ch)
        return ret

    def client_encode(self, buf):
        if self.has_sent_header:
            return buf
        if len(buf) > 64:
            headlen = random.randint(1, 64)
        else:
            headlen = len(buf)
        headdata = buf[:headlen]
        buf = buf[headlen:]
        port = b''
        if self.server_info.port != 80:
            port = b':' + common.to_bytes(str(self.server_info.port))
        http_head = b"GET /" + self.encode_head(headdata) + b" HTTP/1.1\r\n"
        http_head += b"Host: " + (self.server_info.param or self.server_info.host) + port + b"\r\n"
        http_head += b"User-Agent: " + random.choice(self.user_agent) + b"\r\n"
        http_head += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\n\r\n"
        self.has_sent_header = True
        return http_head + buf

    def client_decode(self, buf):
        if self.has_recv_header:
            return (buf, False)
        pos = buf.find(b'\r\n\r\n')
        if pos >= 0:
            self.has_recv_header = True
            return (buf[pos + 4:], False)
        else:
            return (b'', False)

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

        self.recv_buffer += buf
        buf = self.recv_buffer
        if len(buf) > 10:
            if match_begin(buf, b'GET /') or match_begin(buf, b'POST /'):
                if len(buf) > 65536:
                    self.recv_buffer = None
                    logging.warn('http_simple: over size')
                    return self.not_match_return(buf)
            else: #not http header, run on original protocol
                self.recv_buffer = None
                logging.debug('http_simple: not match begin')
                return self.not_match_return(buf)
        else:
            return (b'', True, False)

        datas = buf.split(b'\r\n\r\n', 1)
        if datas and len(datas) > 1:
            ret_buf = self.get_data_from_http_header(buf)
            ret_buf += datas[1]
            if len(ret_buf) >= 15:
                self.has_recv_header = True
                return (ret_buf, True, False)
            return (b'', True, False)
        else:
            return (b'', True, False)

class http2_simple(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False
        self.raw_trans_sent = False
        self.host = None
        self.port = 0
        self.recv_buffer = b''

    def client_encode(self, buf):
        if self.raw_trans_sent:
            return buf
        self.send_buffer += buf
        if not self.has_sent_header:
            port = b''
            if self.server_info.port != 80:
                port = b':' + common.to_bytes(str(self.server_info.port))
            self.has_sent_header = True
            http_head = b"GET / HTTP/1.1\r\n"
            http_head += b"Host: " + (self.server_info.param or self.server_info.host) + port + b"\r\n"
            http_head += b"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"
            http_head += b"HTTP2-Settings: " + base64.urlsafe_b64encode(buf) + b"\r\n"
            return http_head + b"\r\n"
        if self.has_recv_header:
            ret = self.send_buffer
            self.send_buffer = b''
            self.raw_trans_sent = True
            return ret
        return b''

    def client_decode(self, buf):
        if self.has_recv_header:
            return (buf, False)
        pos = buf.find(b'\r\n\r\n')
        if pos >= 0:
            self.has_recv_header = True
            return (buf[pos + 4:], False)
        else:
            return (b'', False)

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

        self.recv_buffer += buf
        buf = self.recv_buffer
        if len(buf) > 10:
            if match_begin(buf, b'GET /'):
                pass
            else: #not http header, run on original protocol
                self.recv_buffer = None
                return self.not_match_return(buf)
        else:
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
            return (b'', True, False)
        else:
            return (b'', True, False)
        return self.not_match_return(buf)

class tls_simple(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False
        self.raw_trans_sent = False

    def client_encode(self, buf):
        if self.raw_trans_sent:
            return buf
        self.send_buffer += buf
        if not self.has_sent_header:
            self.has_sent_header = True
            data = b"\x03\x03" + os.urandom(32) + binascii.unhexlify(b"000016c02bc02fc00ac009c013c01400330039002f0035000a0100006fff01000100000a00080006001700180019000b0002010000230000337400000010002900270568322d31360568322d31350568322d313402683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202")
            data = b"\x01\x00" + struct.pack('>H', len(data)) + data
            data = b"\x16\x03\x01" + struct.pack('>H', len(data)) + data
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
        self.raw_trans_sent = False
        self.raw_trans_recv = False
        self.send_buffer = b''

    def client_encode(self, buf):
        if self.raw_trans_sent:
            return buf
        self.send_buffer += buf
        if not self.has_sent_header:
            self.has_sent_header = True
            data = os.urandom(common.ord(os.urandom(1)[0]) % 96 + 4)
            crc = (0xffffffff - binascii.crc32(data)) & 0xffffffff
            return data + struct.pack('<I', crc)
        if self.raw_trans_recv:
            ret = self.send_buffer
            self.send_buffer = b''
            self.raw_trans_sent = True
            return ret
        return b''

    def client_decode(self, buf):
        if self.raw_trans_recv:
            return (buf, False)
        self.raw_trans_recv = True
        return (b'', True)

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

