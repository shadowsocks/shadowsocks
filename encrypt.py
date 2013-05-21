#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
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

import sys
import hashlib
import string
import struct
import logging


def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table

encrypt_table = None
decrypt_table = None


def init_table(key, method=None):
    if method == 'table':
        method = None
    if method:
        try:
            __import__('M2Crypto')
        except ImportError:
            logging.error('M2Crypto is required to use encryption other than default method')
            sys.exit(1)
    if not method:
        global encrypt_table, decrypt_table
        encrypt_table = ''.join(get_table(key))
        decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    else:
        get_cipher(key, method, 1)


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    # TODO: cache the results
    m = []
    i = 0
    while len(''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = ''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    return (key, iv)


method_supported = {
    'aes-128-cfb': (16, 16),
    'aes-192-cfb': (24, 16),
    'aes-256-cfb': (32, 16),
    'bf-cfb': (16, 8),
    'cast5-cfb': (16, 8),
    'des-cfb': (8, 8),
    'rc4': (16, 0),
}


def get_cipher(password, method, op):
    import M2Crypto.EVP
    password = password.encode('utf-8')
    method = method.lower()
    m = method_supported.get(method, None)
    if m:
        key, iv = EVP_BytesToKey(password, m[0], m[1])
        return M2Crypto.EVP.Cipher(method.replace('-', '_'), key, iv, op, key_as_bytes=0, d='md5', salt=None, i=1, padding=1)

    logging.error('method %s not supported' % method)
    sys.exit(1)


class Encryptor(object):
    def __init__(self, key, method=None):
        if method == 'table':
            method = None
        self.method = method
        if method is not None:
            self.cipher = get_cipher(key, method, 1)
            self.decipher = get_cipher(key, method, 0)
        else:
            self.cipher = None
            self.decipher = None

    def encrypt(self, buf):
        if self.cipher is None:
            return string.translate(buf, encrypt_table)
        else:
            return self.cipher.update(buf)

    def decrypt(self, buf):
        if self.cipher is None:
            return string.translate(buf, decrypt_table)
        else:
            return self.decipher.update(buf)
