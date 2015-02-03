#!/usr/bin/env python
#
# Copyright 2015 clowwindy
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
import logging


def find_library_nt(name):
    # modified from ctypes.util
    # ctypes.util.find_library just returns first result he found
    # but we want to try them all
    # because on Windows, users may have both 32bit and 64bit version installed
    results = []
    for directory in os.environ['PATH'].split(os.pathsep):
        fname = os.path.join(directory, name)
        if os.path.isfile(fname):
            results.append(fname)
        if fname.lower().endswith(".dll"):
            continue
        fname = fname + ".dll"
        if os.path.isfile(fname):
            results.append(fname)
    return results


def find_library(possible_lib_names, search_symbol, library_name):
    import ctypes.util
    from ctypes import CDLL

    paths = []

    if type(possible_lib_names) not in (list, tuple):
        possible_lib_names = [possible_lib_names]

    lib_names = []
    for lib_name in possible_lib_names:
        lib_names.append(lib_name)
        lib_names.append('lib' + lib_name)

    for name in lib_names:
        if os.name == "nt":
            paths.extend(find_library_nt(name))
        else:
            path = ctypes.util.find_library(name)
            if path:
                paths.append(path)

    if not paths:
        # We may get here when find_library fails because, for example,
        # the user does not have sufficient privileges to access those
        # tools underlying find_library on linux.
        import glob

        for name in lib_names:
            patterns = [
                '/usr/local/lib*/lib%s.*' % name,
                '/usr/lib*/lib%s.*' % name,
                'lib%s.*' % name,
                '%s.dll' % name]

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
    assert find_library(('crypto', 'eay32'), 'EVP_CipherUpdate',
                        'libcrypto') is not None
    assert find_library('notexist', 'strcpy', 'libnotexist') is None
    assert find_library('c', 'symbol_not_exist', 'c') is None
    assert find_library(('notexist', 'c', 'crypto', 'eay32'),
                        'EVP_CipherUpdate', 'libc') is not None


if __name__ == '__main__':
    test_find_library()
