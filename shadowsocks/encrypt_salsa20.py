#!/usr/bin/python

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
    ab = numpy.frombuffer(a, dtype=numpy.byte)
    bb = numpy.frombuffer(b, dtype=numpy.byte)
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
                                                 struct.pack('<Q', self._nonce),
                                                 self._key)
        self._nonce += 1

    def update(self, data):
        results = []
        while True:
            remain = BLOCK_SIZE - self._pos
            cur_data = data[:remain]
            cur_data_len = len(cur_data)
            cur_stream = self._stream[self._pos:self._pos + cur_data_len]
            self._pos = (self._pos + cur_data_len) % BLOCK_SIZE
            data = data[remain:]

            results.append(numpy_xor(cur_data, cur_stream))

            if not data:
                break
            self._next_stream()
        return ''.join(results)


def test():
    from os import urandom
    import random

    rounds = 1 * 10
    plain = urandom(BLOCK_SIZE * rounds)
    cipher = Salsa20Cipher('salsa20-ctr', 'k' * 32, 'i' * 8, 1)
    decipher = Salsa20Cipher('salsa20-ctr', 'k' * 32, 'i' * 8, 1)
    results = []
    pos = 0
    print 'start'
    start = time.time()
    while pos < len(plain):
        l = random.randint(10000, 32768)
        c = cipher.update(plain[pos:pos + l])
        results.append(decipher.update(c))
        pos += l
    assert ''.join(results) == plain
    end = time.time()
    print BLOCK_SIZE * rounds / (end - start)


if __name__ == '__main__':
    test()