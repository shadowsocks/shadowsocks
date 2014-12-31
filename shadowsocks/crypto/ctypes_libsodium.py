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

import logging
from ctypes import CDLL, c_char_p, c_int, c_ulonglong, byref, \
    create_string_buffer, c_void_p

__all__ = ['ciphers', 'auths']

libsodium = None
loaded = False

buf_size = 2048

# for salsa20 and chacha20
BLOCK_SIZE = 64


def load_libsodium():
    global loaded, libsodium, buf, tag_buf

    from ctypes.util import find_library
    for p in ('sodium', 'libsodium'):
        libsodium_path = find_library(p)
        if libsodium_path:
            break
    else:
        raise Exception('libsodium not found')
    logging.info('loading libsodium from %s', libsodium_path)
    libsodium = CDLL(libsodium_path)
    libsodium.sodium_init.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                       c_ulonglong,
                                                       c_char_p, c_ulonglong,
                                                       c_char_p)
    libsodium.crypto_stream_chacha20_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                        c_ulonglong,
                                                        c_char_p, c_ulonglong,
                                                        c_char_p)

    libsodium.crypto_onetimeauth.restype = c_int
    libsodium.crypto_onetimeauth.argtypes = (c_void_p, c_char_p,
                                             c_ulonglong, c_char_p)

    libsodium.crypto_onetimeauth_verify.restype = c_int
    libsodium.crypto_onetimeauth_verify.argtypes = (c_char_p, c_char_p,
                                                    c_ulonglong, c_char_p)

    libsodium.sodium_init()

    buf = create_string_buffer(buf_size)
    tag_buf = create_string_buffer(16)
    loaded = True


class Salsa20Crypto(object):
    def __init__(self, cipher_name, key, iv, op):
        if not loaded:
            load_libsodium()
        self.key = key
        self.iv = iv
        self.key_ptr = c_char_p(key)
        self.iv_ptr = c_char_p(iv)
        if cipher_name == b'salsa20':
            self.cipher = libsodium.crypto_stream_salsa20_xor_ic
        elif cipher_name == b'chacha20':
            self.cipher = libsodium.crypto_stream_chacha20_xor_ic
        else:
            raise Exception('Unknown cipher')
        # byte counter, not block counter
        self.counter = 0

    def update(self, data):
        global buf_size, buf
        l = len(data)

        # we can only prepend some padding to make the encryption align to
        # blocks
        padding = self.counter % BLOCK_SIZE
        if buf_size < padding + l:
            buf_size = (padding + l) * 2
            buf = create_string_buffer(buf_size)

        if padding:
            data = (b'\0' * padding) + data
        self.cipher(byref(buf), c_char_p(data), padding + l,
                    self.iv_ptr, int(self.counter / BLOCK_SIZE), self.key_ptr)
        self.counter += l
        # buf is copied to a str object when we access buf.raw
        # strip off the padding
        return buf.raw[padding:padding + l]


class Poly1305(object):
    @staticmethod
    def auth(method, key, data):
        global tag_buf
        if not loaded:
            load_libsodium()
        libsodium.crypto_onetimeauth(byref(tag_buf), data, len(data), key)
        return tag_buf.raw

    @staticmethod
    def verify(method, key, data, tag):
        if not loaded:
            load_libsodium()
        r = libsodium.crypto_onetimeauth_verify(tag, data, len(data), key)
        return r == 0


ciphers = {
    b'salsa20': (32, 8, Salsa20Crypto),
    b'chacha20': (32, 8, Salsa20Crypto),
}

auths = {
    b'poly1305': (32, 16, Poly1305)
}


def test_salsa20():
    from shadowsocks.crypto import util

    cipher = Salsa20Crypto(b'salsa20', b'k' * 32, b'i' * 16, 1)
    decipher = Salsa20Crypto(b'salsa20', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def test_chacha20():
    from shadowsocks.crypto import util

    cipher = Salsa20Crypto(b'chacha20', b'k' * 32, b'i' * 16, 1)
    decipher = Salsa20Crypto(b'chacha20', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


if __name__ == '__main__':
    test_chacha20()
    test_salsa20()
