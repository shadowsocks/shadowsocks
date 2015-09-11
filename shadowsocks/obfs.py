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
from shadowsocks.obfsplugin import plain, http_simple


method_supported = {}
method_supported.update(plain.obfs)
method_supported.update(http_simple.obfs)

class Obfs(object):
    def __init__(self, method):
        self.method = method
        self._method_info = self.get_method_info(method)
        if self._method_info:
            self.obfs = self.get_obfs(method)
        else:
            logging.error('method %s not supported' % method)
            sys.exit(1)

    def get_method_info(self, method):
        method = method.lower()
        m = method_supported.get(method)
        return m

    def get_obfs(self, method):
        m = self._method_info
        return m[0](method)

    def encode(self, buf):
        #if len(buf) == 0:
        #    return buf
        return self.obfs.encode(buf)

    def decode(self, buf):
        #if len(buf) == 0:
        #    return (buf, True, False)
        return self.obfs.decode(buf)

