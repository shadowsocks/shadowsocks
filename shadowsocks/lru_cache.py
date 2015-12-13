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

# this LRUCache is optimized for concurrency, not QPS
# n: concurrency, keys stored in the cache
# m: visits not timed out, proportional to QPS * timeout
# get & set is O(log(n)), not O(n). thus we can support very large n
# sweep is O((n - m)*log(n)) or O(1024*log(n)) at most,
# no metter how large the cache or timeout value is

SWEEP_MAX_ITEMS = 1024

class LRUCache(collections.MutableMapping):
    """This class is not thread safe"""

    def __init__(self, timeout=60, close_callback=None, *args, **kwargs):
        self.timeout = timeout
        self.close_callback = close_callback
        self._store = {}
        self._time_to_keys = collections.OrderedDict()
        self._keys_to_last_time = {}
        self._visit_id = 0
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        # O(log(n))
        t = time.time()
        last_t, vid = self._keys_to_last_time[key]
        self._keys_to_last_time[key] = (t, vid)
        if last_t != t:
            del self._time_to_keys[(last_t, vid)]
            self._time_to_keys[(t, vid)] = key
        return self._store[key]

    def __setitem__(self, key, value):
        # O(log(n))
        t = time.time()
        if key in self._keys_to_last_time:
            last_t, vid = self._keys_to_last_time[key]
            del self._time_to_keys[(last_t, vid)]
        vid = self._visit_id
        self._visit_id += 1
        self._keys_to_last_time[key] = (t, vid)
        self._store[key] = value
        self._time_to_keys[(t, vid)] = key

    def __delitem__(self, key):
        # O(log(n))
        last_t, vid = self._keys_to_last_time[key]
        del self._store[key]
        del self._keys_to_last_time[key]
        del self._time_to_keys[(last_t, vid)]

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)

    def sweep(self):
        # O(n - m)
        now = time.time()
        c = 0
        while c < SWEEP_MAX_ITEMS:
            if len(self._time_to_keys) == 0:
                break
            last_t, vid = iter(self._time_to_keys).next()
            if now - last_t <= self.timeout:
                break
            key = self._time_to_keys[(last_t, vid)]
            value = self._store[key]
            if self.close_callback is not None:
                self.close_callback(value)
            del self._store[key]
            del self._keys_to_last_time[key]
            del self._time_to_keys[(last_t, vid)]
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
