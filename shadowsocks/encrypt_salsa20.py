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

import time
import struct
import logging
import sys

slow_xor = False
imported = False

BLOCK_SIZE = 16384


def run_imports():
    global imported, slow_xor, salsa20, numpy
    if not imported:
        imported = True
        try:
            import numpy
        except ImportError:
            logging.error('can not import numpy, using SLOW XOR')
            logging.error('please install numpy if you use salsa20')
            slow_xor = True
        try:
            import salsa20
        except ImportError:
            logging.error('you have to install salsa20 before you use salsa20')
            sys.exit(1)


def numpy_xor(a, b):
    if slow_xor:
        return py_xor_str(a, b)
    dtype = numpy.byte
    if len(a) % 4 == 0:
        dtype = numpy.uint32
    elif len(a) % 2 == 0:
        dtype = numpy.uint16

    ab = numpy.frombuffer(a, dtype=dtype)
    bb = numpy.frombuffer(b, dtype=dtype)
    c = numpy.bitwise_xor(ab, bb)
    r = c.tostring()
    return r


def py_xor_str(a, b):
    c = []
    for i in xrange(0, len(a)):
        c.append(chr(ord(a[i]) ^ ord(b[i])))
    return ''.join(c)


class Salsa20Cipher(object):
    """a salsa20 CTR implemetation, provides m2crypto like cipher API"""

    def __init__(self, alg, key, iv, op, key_as_bytes=0, d=None, salt=None,
                 i=1, padding=1):
        run_imports()
        if alg != 'salsa20-ctr':
            raise Exception('unknown algorithm')
        self._key = key
        self._nonce = struct.unpack('<Q', iv)[0]
        self._pos = 0
        self._next_stream()

    def _next_stream(self):
        self._nonce &= 0xFFFFFFFFFFFFFFFF
        self._stream = salsa20.Salsa20_keystream(BLOCK_SIZE,
                                                 struct.pack('<Q',
                                                             self._nonce),
                                                 self._key)
        self._nonce += 1

    def update(self, data):
        results = []
        while True:
            remain = BLOCK_SIZE - self._pos
            cur_data = data[:remain]
            cur_data_len = len(cur_data)
            cur_stream = self._stream[self._pos:self._pos + cur_data_len]
            self._pos = self._pos + cur_data_len
            data = data[remain:]

            results.append(numpy_xor(cur_data, cur_stream))

            if self._pos >= BLOCK_SIZE:
                self._next_stream()
                self._pos = 0
            if not data:
                break
        return ''.join(results)


def test():
    from os import urandom
    import random

    rounds = 1 * 1024
    plain = urandom(BLOCK_SIZE * rounds)
    import M2Crypto.EVP
    # cipher = M2Crypto.EVP.Cipher('aes_128_cfb', 'k' * 32, 'i' * 16, 1,
    #                key_as_bytes=0, d='md5', salt=None, i=1,
    #                padding=1)
    # decipher = M2Crypto.EVP.Cipher('aes_128_cfb', 'k' * 32, 'i' * 16, 0,
    #                key_as_bytes=0, d='md5', salt=None, i=1,
    #                padding=1)

    cipher = Salsa20Cipher('salsa20-ctr', 'k' * 32, 'i' * 8, 1)
    decipher = Salsa20Cipher('salsa20-ctr', 'k' * 32, 'i' * 8, 1)
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
