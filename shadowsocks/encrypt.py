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

import os
import sys
import hashlib
import string
import struct
import logging
import encrypt_salsa20
import encrypt_rc4_md5


def random_string(length):
    try:
        import M2Crypto.Rand
        return M2Crypto.Rand.rand_bytes(length)
    except ImportError:
        # TODO really strong enough on Linux?
        return os.urandom(length)


cached_tables = {}
cached_keys = {}


def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table


def init_table(key, method=None):
    if method is not None and method == 'table':
        method = None
    if method:
        try:
            __import__('M2Crypto')
        except ImportError:
            logging.error(('M2Crypto is required to use %s, please run'
                           ' `apt-get install python-m2crypto`') % method)
            sys.exit(1)
    if not method:
        if key in cached_tables:
            return cached_tables[key]
        encrypt_table = ''.join(get_table(key))
        decrypt_table = string.maketrans(encrypt_table,
                                         string.maketrans('', ''))
        cached_tables[key] = [encrypt_table, decrypt_table]
    else:
        try:
            Encryptor(key, method)  # test if the settings if OK
        except Exception as e:
            logging.error(e)
            sys.exit(1)


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    password = str(password)
    r = cached_keys.get(password, None)
    if r:
        return r
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
    cached_keys[password] = (key, iv)
    return (key, iv)


method_supported = {
    'aes-128-cfb': (16, 16),
    'aes-192-cfb': (24, 16),
    'aes-256-cfb': (32, 16),
    'bf-cfb': (16, 8),
    'camellia-128-cfb': (16, 16),
    'camellia-192-cfb': (24, 16),
    'camellia-256-cfb': (32, 16),
    'cast5-cfb': (16, 8),
    'des-cfb': (8, 8),
    'idea-cfb': (16, 8),
    'rc2-cfb': (16, 8),
    'rc4': (16, 0),
    'rc4-md5': (16, 16),
    'seed-cfb': (16, 16),
    'salsa20-ctr': (32, 8),
}


class Encryptor(object):
    def __init__(self, key, method=None):
        if method == 'table':
            method = None
        self.key = key
        self.method = method
        self.iv = None
        self.iv_sent = False
        self.cipher_iv = ''
        self.decipher = None
        if method:
            self.cipher = self.get_cipher(key, method, 1, iv=random_string(32))
        else:
            self.encrypt_table, self.decrypt_table = init_table(key)
            self.cipher = None

    def get_cipher_len(self, method):
        method = method.lower()
        m = method_supported.get(method, None)
        return m

    def iv_len(self):
        return len(self.cipher_iv)

    def get_cipher(self, password, method, op, iv=None):
        password = password.encode('utf-8')
        method = method.lower()
        m = self.get_cipher_len(method)
        if m:
            key, iv_ = EVP_BytesToKey(password, m[0], m[1])
            if iv is None:
                iv = iv_
            iv = iv[:m[1]]
            if op == 1:
                # this iv is for cipher not decipher
                self.cipher_iv = iv[:m[1]]
            if method == 'salsa20-ctr':
                return encrypt_salsa20.Salsa20Cipher(method, key, iv, op)
            elif method == 'rc4-md5':
                return encrypt_rc4_md5.create_cipher(method, key, iv, op)
            else:
                import M2Crypto.EVP
                return M2Crypto.EVP.Cipher(method.replace('-', '_'), key, iv,
                                           op, key_as_bytes=0, d='md5',
                                           salt=None, i=1, padding=1)

        logging.error('method %s not supported' % method)
        sys.exit(1)

    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        if not self.method:
            return string.translate(buf, self.encrypt_table)
        else:
            if self.iv_sent:
                return self.cipher.update(buf)
            else:
                self.iv_sent = True
                return self.cipher_iv + self.cipher.update(buf)

    def decrypt(self, buf):
        if len(buf) == 0:
            return buf
        if not self.method:
            return string.translate(buf, self.decrypt_table)
        else:
            if self.decipher is None:
                decipher_iv_len = self.get_cipher_len(self.method)[1]
                decipher_iv = buf[:decipher_iv_len]
                self.decipher = self.get_cipher(self.key, self.method, 0,
                                                iv=decipher_iv)
                buf = buf[decipher_iv_len:]
                if len(buf) == 0:
                    return buf
            return self.decipher.update(buf)


def encrypt_all(password, method, op, data):
    if method is not None and method.lower() == 'table':
        method = None
    if not method:
        [encrypt_table, decrypt_table] = init_table(password)
        if op:
            return string.translate(data, encrypt_table)
        else:
            return string.translate(data, decrypt_table)
    else:
        import M2Crypto.EVP
        result = []
        method = method.lower()
        (key_len, iv_len) = method_supported[method]
        (key, _) = EVP_BytesToKey(password, key_len, iv_len)
        if op:
            iv = random_string(iv_len)
            result.append(iv)
        else:
            iv = data[:iv_len]
            data = data[iv_len:]
        if method == 'salsa20-ctr':
            cipher = encrypt_salsa20.Salsa20Cipher(method, key, iv, op)
        elif method == 'rc4-md5':
            cipher = encrypt_rc4_md5.create_cipher(method, key, iv, op)
        else:
            cipher = M2Crypto.EVP.Cipher(method.replace('-', '_'), key, iv,
                                         op, key_as_bytes=0, d='md5',
                                         salt=None, i=1, padding=1)
        result.append(cipher.update(data))
        return ''.join(result)
