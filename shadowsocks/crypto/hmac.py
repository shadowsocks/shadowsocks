#!/usr/bin/env python

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function, \
    with_statement

import hmac

from shadowsocks import common

__all__ = ['auths']


class HMAC(object):
    @staticmethod
    def auth(method, key, data):
        digest = common.to_str(method.replace(b'hmac-', b''))
        return hmac.new(key, data, digest).digest()

    @staticmethod
    def verify(method, key, data, tag):
        digest = common.to_str(method.replace(b'hmac-', b''))
        t = hmac.new(key, data, digest).digest()
        return hmac.compare_digest(t, tag)


auths = {
    b'hmac-md5': (32, 16, HMAC),
    b'hmac-sha256': (32, 32, HMAC),
}
