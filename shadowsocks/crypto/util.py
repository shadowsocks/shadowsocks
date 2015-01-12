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


def find_library(possible_lib_names, search_symbol, library_name):
    from ctypes.util import find_library
    from ctypes import CDLL

    paths = []

    if type(possible_lib_names) not in (list, tuple):
        possible_lib_names = [possible_lib_names]

    for name in possible_lib_names:
        path = find_library(name)
        if path:
            paths.append(path)

    if not paths:
        # We may get here when find_library fails because, for example,
        # the user does not have sufficient privileges to access those
        # tools underlying find_library on linux.
        import glob

        for name in possible_lib_names:
            patterns = [
                '/usr/local/lib*/lib%s.*' % name,
                '/usr/lib*/lib%s.*' % name,
                'lib%s.*' % name,
                '%s.dll' % name,
                'lib%s.dll' % name]

            for pat in patterns:
                files = glob.glob(pat)
                if files:
                    paths.extend(files)
    for path in paths:
        try:
            lib = CDLL(path)
            if hasattr(lib, search_symbol):
                logging.info('loading %s from %s', library_name, path)
                return lib
            else:
                logging.warn('can\'t find symbol %s in %s', search_symbol,
                             path)
        except Exception:
            pass
    return None


def run_cipher(cipher, decipher):
    from os import urandom
    import random
    import time

    BLOCK_SIZE = 16384
    rounds = 1 * 1024
    plain = urandom(BLOCK_SIZE * rounds)

    results = []
    pos = 0
    print('test start')
    start = time.time()
    while pos < len(plain):
        l = random.randint(100, 32768)
        c = cipher.update(plain[pos:pos + l])
        results.append(c)
        pos += l
    pos = 0
    c = b''.join(results)
    results = []
    while pos < len(plain):
        l = random.randint(100, 32768)
        results.append(decipher.update(c[pos:pos + l]))
        pos += l
    end = time.time()
    print('speed: %d bytes/s' % (BLOCK_SIZE * rounds / (end - start)))
    assert b''.join(results) == plain


def test_find_library():
    assert find_library('c', 'strcpy', 'libc') is not None
    assert find_library(['c'], 'strcpy', 'libc') is not None
    assert find_library(('c',), 'strcpy', 'libc') is not None
    assert find_library('crypto', 'EVP_CipherUpdate', 'libcrypto') is not None
    assert find_library('notexist', 'strcpy', 'libnotexist') is None
    assert find_library('c', 'symbol_not_exist', 'c') is None
    assert find_library(('notexist', 'c', 'crypto'),
                        'EVP_CipherUpdate', 'libc') is not None


if __name__ == '__main__':
    test_find_library()
