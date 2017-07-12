#!/usr/bin/python
# -*- coding: utf-8 -*-
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

import collections
import logging
import time

if __name__ == '__main__':
    import os, sys, inspect
    file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
    sys.path.insert(0, os.path.join(file_path, '../'))

try:
    from collections import OrderedDict
except:
    from shadowsocks.ordereddict import OrderedDict

# this LRUCache is optimized for concurrency, not QPS
# n: concurrency, keys stored in the cache
# m: visits not timed out, proportional to QPS * timeout
# get & set is O(1), not O(n). thus we can support very large n
# sweep is O((n - m)) or O(1024) at most,
# no metter how large the cache or timeout value is

SWEEP_MAX_ITEMS = 1024

class LRUCache(collections.MutableMapping):
    """This class is not thread safe"""

    def __init__(self, timeout=60, close_callback=None, *args, **kwargs):
        self.timeout = timeout
        self.close_callback = close_callback
        self._store = {}
        self._keys_to_last_time = OrderedDict()
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        # O(1)
        t = time.time()
        last_t = self._keys_to_last_time[key]
        del self._keys_to_last_time[key]
        self._keys_to_last_time[key] = t
        return self._store[key]

    def __setitem__(self, key, value):
        # O(1)
        t = time.time()
        if key in self._keys_to_last_time:
            del self._keys_to_last_time[key]
        self._keys_to_last_time[key] = t
        self._store[key] = value

    def __delitem__(self, key):
        # O(1)
        last_t = self._keys_to_last_time[key]
        del self._store[key]
        del self._keys_to_last_time[key]

    def __contains__(self, key):
        return key in self._store

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)

    def first(self):
        if len(self._keys_to_last_time) > 0:
            for key in self._keys_to_last_time:
                return key

    def sweep(self, sweep_item_cnt = SWEEP_MAX_ITEMS):
        # O(n - m)
        now = time.time()
        c = 0
        while c < sweep_item_cnt:
            if len(self._keys_to_last_time) == 0:
                break
            for key in self._keys_to_last_time:
                break
            last_t = self._keys_to_last_time[key]
            if now - last_t <= self.timeout:
                break
            value = self._store[key]
            del self._store[key]
            del self._keys_to_last_time[key]
            if self.close_callback is not None:
                self.close_callback(value)
            c += 1
        if c:
            logging.debug('%d keys swept' % c)
        return c < SWEEP_MAX_ITEMS

    def clear(self, keep):
        now = time.time()
        c = 0
        while len(self._keys_to_last_time) > keep:
            if len(self._keys_to_last_time) == 0:
                break
            for key in self._keys_to_last_time:
                break
            last_t = self._keys_to_last_time[key]
            value = self._store[key]
            if self.close_callback is not None:
                self.close_callback(value)
            del self._store[key]
            del self._keys_to_last_time[key]
            c += 1
        if c:
            logging.debug('%d keys swept' % c)
        return c < SWEEP_MAX_ITEMS

def test():
    c = LRUCache(timeout=0.3)

    c['a'] = 1
    assert c['a'] == 1
    c['a'] = 1

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c

    c['a'] = 2
    c['b'] = 3
    time.sleep(0.2)
    c.sweep()
    assert c['a'] == 2
    assert c['b'] == 3

    time.sleep(0.2)
    c.sweep()
    c['b']
    time.sleep(0.2)
    c.sweep()
    assert 'a' not in c
    assert c['b'] == 3

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c
    assert 'b' not in c

    global close_cb_called
    close_cb_called = False

    def close_cb(t):
        global close_cb_called
        assert not close_cb_called
        close_cb_called = True

    c = LRUCache(timeout=0.1, close_callback=close_cb)
    c['s'] = 1
    c['s']
    time.sleep(0.1)
    c['s']
    time.sleep(0.3)
    c.sweep()

if __name__ == '__main__':
    test()
