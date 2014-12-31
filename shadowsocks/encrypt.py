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

import os
import sys
import hashlib
import logging

from shadowsocks.crypto import m2, rc4_md5, salsa20_ctr,\
    ctypes_openssl, ctypes_libsodium, table, hmac
from shadowsocks import common


ciphers_supported = {}
ciphers_supported.update(rc4_md5.ciphers)
ciphers_supported.update(salsa20_ctr.ciphers)
ciphers_supported.update(ctypes_openssl.ciphers)
ciphers_supported.update(ctypes_libsodium.ciphers)
# let M2Crypto override ctypes_openssl
ciphers_supported.update(m2.ciphers)
ciphers_supported.update(table.ciphers)


auths_supported = {}
auths_supported.update(hmac.auths)
auths_supported.update(ctypes_libsodium.auths)


def random_string(length):
    try:
        import M2Crypto.Rand
        return M2Crypto.Rand.rand_bytes(length)
    except ImportError:
        return os.urandom(length)


def try_cipher(key, method=None, auth=None):
    Encryptor(key, method)
    auth_create(b'test', key, b'test', auth)


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    return key, iv


class Encryptor(object):
    def __init__(self, key, method):
        self.key = key
        self.method = method
        self.iv = None
        self.iv_sent = False
        self.cipher_iv = b''
        self.decipher = None
        method = method.lower()
        self._method_info = self.get_method_info(method)
        if self._method_info:
            self.cipher = self.get_cipher(key, method, 1,
                                          random_string(self._method_info[1]))
        else:
            logging.error('method %s not supported' % method)
            sys.exit(1)

    def get_method_info(self, method):
        method = method.lower()
        m = ciphers_supported.get(method)
        return m

    def iv_len(self):
        return len(self.cipher_iv)

    def get_cipher(self, password, method, op, iv):
        password = common.to_bytes(password)
        m = self._method_info
        if m[0] > 0:
            key, iv_ = EVP_BytesToKey(password, m[0], m[1])
        else:
            # key_length == 0 indicates we should use the key directly
            key, iv = password, b''

        iv = iv[:m[1]]
        if op == 1:
            # this iv is for cipher not decipher
            self.cipher_iv = iv[:m[1]]
        return m[2](method, key, iv, op)

    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.iv_sent:
            return self.cipher.update(buf)
        else:
            self.iv_sent = True
            return self.cipher_iv + self.cipher.update(buf)

    def decrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.decipher is None:
            decipher_iv_len = self._method_info[1]
            decipher_iv = buf[:decipher_iv_len]
            self.decipher = self.get_cipher(self.key, self.method, 0,
                                            iv=decipher_iv)
            buf = buf[decipher_iv_len:]
            if len(buf) == 0:
                return buf
        return self.decipher.update(buf)


def encrypt_all(password, method, op, data):
    result = []
    method = method.lower()
    password = common.to_bytes(password)
    (key_len, iv_len, m) = ciphers_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    if op:
        iv = random_string(iv_len)
        result.append(iv)
    else:
        iv = data[:iv_len]
        data = data[iv_len:]
    cipher = m(method, key, iv, op)
    result.append(cipher.update(data))
    return b''.join(result)


def auth_create(data, password, iv, method):
    if method is None:
        return data
    # prepend hmac to data
    password = common.to_bytes(password)
    method = method.lower()
    method_info = auths_supported.get(method)
    if not method_info:
        logging.error('method %s not supported' % method)
        sys.exit(1)
    key_len, tag_len, m = method_info
    key, _ = EVP_BytesToKey(password + iv, key_len, 0)
    tag = m.auth(method, key, data)
    return tag + data


def auth_open(data, password, iv, method):
    if method is None:
        return data
    # verify hmac and remove the hmac or return None
    password = common.to_bytes(password)
    method = method.lower()
    method_info = auths_supported.get(method)
    if not method_info:
        logging.error('method %s not supported' % method)
        sys.exit(1)
    key_len, tag_len, m = method_info
    key, _ = EVP_BytesToKey(password + iv, key_len, 0)
    if len(data) <= tag_len:
        return None
    result = data[tag_len:]
    if not m.verify(method, key, result, data[:tag_len]):
        return None
    return result


CIPHERS_TO_TEST = [
    b'aes-128-cfb',
    b'aes-256-cfb',
    b'rc4-md5',
    b'salsa20',
    b'chacha20',
    b'table',
]

AUTHS_TO_TEST = [
    None,
    b'hmac-md5',
    b'hmac-sha256',
    b'poly1305',
]


def test_encryptor():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        encryptor = Encryptor(b'key', method)
        decryptor = Encryptor(b'key', method)
        cipher = encryptor.encrypt(plain)
        plain2 = decryptor.decrypt(cipher)
        assert plain == plain2


def test_encrypt_all():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        cipher = encrypt_all(b'key', method, 1, plain)
        plain2 = encrypt_all(b'key', method, 0, cipher)
        assert plain == plain2


def test_auth():
    from os import urandom
    plain = urandom(10240)
    for method in AUTHS_TO_TEST:
        logging.warn(method)
        boxed = auth_create(plain, b'key', b'iv', method)
        unboxed = auth_open(boxed, b'key', b'iv', method)
        assert plain == unboxed
        if method is not None:
            b = common.ord(boxed[0])
            b ^= 1
            attack = common.chr(b) + boxed[1:]
            assert auth_open(attack, b'key', b'iv', method) is None


if __name__ == '__main__':
    test_encrypt_all()
    test_encryptor()
    test_auth()
