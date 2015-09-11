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
import datetime

def create_obfs(method):
    return http_simple(method)

obfs = {
        'http_simple': (create_obfs,),
}

class http_simple(object):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False
        self.host = ""
        self.port = 0
        self.recv_buffer = ""

    def encode(self, buf):
        if self.has_sent_header:
            return buf
        else:
            header = "HTTP/1.1 200 OK\r\nServer: openresty\r\nDate: "
            header += datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')
            header += '''\r\nContent-Type: text/plain; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nKeep-Alive: timeout=20\r\nVary: Accept-Encoding\r\nContent-Encoding: gzip\r\n\r\n'''
            self.has_sent_header = True
            return header + buf

    def decode(self, buf):
        if self.has_recv_header:
            return (buf, True, False)
        else:
            buf = self.recv_buffer + buf
            if len(buf) > 10:
                if buf[:5] == "GET /" or buf[:6] == "POST /":
                    pass
                else: #not http header, run on original protocol
                    self.has_sent_header = True
                    self.has_recv_header = True
                    self.recv_buffer = None
                    return (buf, True, False)
            else:
                self.recv_buffer = buf
                return ("", True, False)

            datas = buf.split('\r\n\r\n', 1)
            if datas and len(datas) > 1 and len(datas[1]) >= 7:
                lines = buf.split('\r\n')
                if lines and len(lines) > 4:
                    hex_items = lines[0].split('%')
                    if hex_items and len(hex_items) > 1:
                        ret_buf = ""
                        for index in xrange(1, len(hex_items)):
                            if len(hex_items[index]) != 2:
                                ret_buf += binascii.unhexlify(hex_items[index][:2])
                                break
                            ret_buf += binascii.unhexlify(hex_items[index])
                        ret_buf += datas[1]
                        self.has_recv_header = True
                        return (ret_buf, True, False)
            else:
                self.recv_buffer = buf
                return ("", True, False)
            self.has_sent_header = True
            self.has_recv_header = True
            return (buf, True, False)

