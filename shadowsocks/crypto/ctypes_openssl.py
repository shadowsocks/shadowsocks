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

import logging

__all__ = ['ciphers']

loaded = False


def load_openssl():
    global loaded, libcrypto, CDLL, c_char_p, c_int, c_long, byref,\
        create_string_buffer, c_void_p, buf
    from ctypes import CDLL, c_char_p, c_int, c_long, byref,\
        create_string_buffer, c_void_p
    from ctypes.util import find_library
    libcrypto_path = find_library('crypto')
    logging.info('loading libcrypto from %s', libcrypto_path)
    libcrypto = CDLL(libcrypto_path)
    libcrypto.EVP_get_cipherbyname.restype = c_void_p
    libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p
    libcrypto.EVP_CIPHER_CTX_new.argtypes = (c_void_p, c_void_p, c_char_p,
                                             c_char_p)

    libcrypto.EVP_CipherInit_ex.argtypes = (c_void_p, c_void_p, c_char_p,
                                            c_char_p, c_char_p, c_int)

    libcrypto.EVP_CipherUpdate.argtypes = (c_void_p, c_void_p, c_void_p,
                                           c_char_p, c_int)

    libcrypto.EVP_CIPHER_CTX_cleanup.argtypes = (c_void_p,)
    libcrypto.EVP_CIPHER_CTX_free.argtypes = (c_void_p,)

    buf = create_string_buffer(65536)
    loaded = True


def load_ctr_cipher(cipher_name):
    func_name = 'EVP_' + cipher_name.replace('-', '_')
    cipher = getattr(libcrypto, func_name, None)
    if cipher:
        cipher.restype = c_void_p
        return cipher()
    return None


class CtypesCrypto(object):
    def __init__(self, cipher_name, key, iv, op):
        if not loaded:
            load_openssl()
        self._ctx = None
        if 'ctr' in cipher_name:
            cipher = load_ctr_cipher(cipher_name)
        else:
            cipher = libcrypto.EVP_get_cipherbyname(cipher_name)
        if not cipher:
            raise Exception('cipher %s not found in libcrypto' % cipher_name)
        key_ptr = c_char_p(key)
        iv_ptr = c_char_p(iv)
        self._ctx = libcrypto.EVP_CIPHER_CTX_new(cipher, None,
                                                 key_ptr, iv_ptr)
        if not self._ctx:
            raise Exception('can not create cipher context')
        r = libcrypto.EVP_CipherInit_ex(self._ctx, cipher, None,
                                        key_ptr, iv_ptr, c_int(op))
        if not r:
            self.clean()
            raise Exception('can not initialize cipher context')

    def update(self, data):
        cipher_out_len = c_long(0)
        libcrypto.EVP_CipherUpdate(self._ctx, byref(buf),
                                   byref(cipher_out_len), c_char_p(data),
                                   len(data))
        # buf is copied to a str object when we access buf.raw
        return buf.raw[:cipher_out_len.value]

    def __del__(self):
        self.clean()

    def clean(self):
        if self._ctx:
            libcrypto.EVP_CIPHER_CTX_cleanup(self._ctx)
            libcrypto.EVP_CIPHER_CTX_free(self._ctx)


ciphers = {
    'aes-128-ctr': (16, 16, CtypesCrypto),
    'aes-192-ctr': (24, 16, CtypesCrypto),
    'aes-256-ctr': (32, 16, CtypesCrypto),
    'aes-128-cfb8': (16, 16, CtypesCrypto),
    'aes-192-cfb8': (24, 16, CtypesCrypto),
    'aes-256-cfb8': (32, 16, CtypesCrypto),
    'aes-128-cfb1': (16, 16, CtypesCrypto),
    'aes-192-cfb1': (24, 16, CtypesCrypto),
    'aes-256-cfb1': (32, 16, CtypesCrypto),
}


def test():
    from os import urandom
    import random
    import time

    BLOCK_SIZE = 16384
    rounds = 1 * 1024
    plain = urandom(BLOCK_SIZE * rounds)
    import M2Crypto.EVP
    # cipher = M2Crypto.EVP.Cipher('aes_128_cfb', 'k' * 32, 'i' * 16, 1,
    #                key_as_bytes=0, d='md5', salt=None, i=1,
    #                padding=1)
    # decipher = M2Crypto.EVP.Cipher('aes_128_cfb', 'k' * 32, 'i' * 16, 0,
    #                key_as_bytes=0, d='md5', salt=None, i=1,
    #                padding=1)
    cipher = CtypesCrypto('aes-128-cfb', 'k' * 32, 'i' * 16, 1)
    decipher = CtypesCrypto('aes-128-cfb', 'k' * 32, 'i' * 16, 0)

    # cipher = Salsa20Cipher('salsa20-ctr', 'k' * 32, 'i' * 8, 1)
    # decipher = Salsa20Cipher('salsa20-ctr', 'k' * 32, 'i' * 8, 1)
    results = []
    pos = 0
    print 'salsa20 test start'
    start = time.time()
    while pos < len(plain):
        l = random.randint(100, 32768)
        c = cipher.update(plain[pos:pos + l])
        results.append(c)
        pos += l
    pos = 0
    c = ''.join(results)
    results = []
    while pos < len(plain):
        l = random.randint(100, 32768)
        results.append(decipher.update(c[pos:pos + l]))
        pos += l
    end = time.time()
    print 'speed: %d bytes/s' % (BLOCK_SIZE * rounds / (end - start))
    assert ''.join(results) == plain


if __name__ == '__main__':
    test()