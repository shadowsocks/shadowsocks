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

def create_obfs(method):
    return plain(method)

obfs_map = {
        'plain': (create_obfs,),
        'origin': (create_obfs,),
}

class plain(object):
    def __init__(self, method):
        self.method = method
        self.server_info = None

    def init_data(self):
        return b''

    def set_server_info(self, server_info):
        self.server_info = server_info

    def client_pre_encrypt(self, buf):
        return buf

    def client_encode(self, buf):
        return buf

    def client_decode(self, buf):
        # (buffer_to_recv, is_need_to_encode_and_send_back)
        return (buf, False)

    def client_post_decrypt(self, buf):
        return buf

    def server_pre_encrypt(self, buf):
        return buf

    def server_encode(self, buf):
        return buf

    def server_decode(self, buf):
        # (buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back)
        return (buf, True, False)

    def server_post_decrypt(self, buf):
        return buf

    def dispose(self):
        pass

