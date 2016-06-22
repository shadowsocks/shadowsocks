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

from shadowsocks import common
from shadowsocks.obfsplugin import plain, http_simple, obfs_tls, verify, auth


method_supported = {}
method_supported.update(plain.obfs_map)
method_supported.update(http_simple.obfs_map)
method_supported.update(obfs_tls.obfs_map)
method_supported.update(verify.obfs_map)
method_supported.update(auth.obfs_map)

class server_info(object):
    def __init__(self, data):
        self.data = data

class obfs(object):
    def __init__(self, method):
        method = common.to_str(method)
        self.method = method
        self._method_info = self.get_method_info(method)
        if self._method_info:
            self.obfs = self.get_obfs(method)
        else:
            raise Exception('obfs plugin [%s] not supported' % method)

    def init_data(self):
        return self.obfs.init_data()

    def set_server_info(self, server_info):
        return self.obfs.set_server_info(server_info)

    def get_method_info(self, method):
        method = method.lower()
        m = method_supported.get(method)
        return m

    def get_obfs(self, method):
        m = self._method_info
        return m[0](method)

    def client_pre_encrypt(self, buf):
        return self.obfs.client_pre_encrypt(buf)

    def client_encode(self, buf):
        return self.obfs.client_encode(buf)

    def client_decode(self, buf):
        return self.obfs.client_decode(buf)

    def client_post_decrypt(self, buf):
        return self.obfs.client_post_decrypt(buf)

    def server_pre_encrypt(self, buf):
        return self.obfs.server_pre_encrypt(buf)

    def server_encode(self, buf):
        return self.obfs.server_encode(buf)

    def server_decode(self, buf):
        return self.obfs.server_decode(buf)

    def server_post_decrypt(self, buf):
        return self.obfs.server_post_decrypt(buf)

    def client_udp_pre_encrypt(self, buf):
        return self.obfs.client_udp_pre_encrypt(buf)

    def client_udp_post_decrypt(self, buf):
        return self.obfs.client_udp_post_decrypt(buf)

    def server_udp_pre_encrypt(self, buf):
        return self.obfs.server_udp_pre_encrypt(buf)

    def server_udp_post_decrypt(self, buf):
        return self.obfs.server_udp_post_decrypt(buf)

    def dispose(self):
        self.obfs.dispose()
        del self.obfs

