#!/usr/bin/python
# -*- coding: utf-8 -*-

import collections
import logging
import heapq
import time


class LRUCache(collections.MutableMapping):
    """This class is not thread safe"""

    def __init__(self, timeout=60, close_callback=None, *args, **kwargs):
        self.timeout = timeout
        self.close_callback = close_callback
        self._store = {}
        self._time_to_keys = collections.defaultdict(list)
        self._last_visits = []
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        # O(logm)
        t = time.time()
        self._time_to_keys[t].append(key)
        heapq.heappush(self._last_visits, t)
        return self._store[key]

    def __setitem__(self, key, value):
        # O(logm)
        t = time.time()
        self._store[key] = value
        self._time_to_keys[t].append(key)
        heapq.heappush(self._last_visits, t)

    def __delitem__(self, key):
        # O(1)
        del self._store[key]

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)

    def sweep(self):
        # O(m)
        now = time.time()
        c = 0
        while len(self._last_visits) > 0:
            least = self._last_visits[0]
            if now - least <= self.timeout:
                break
            if self.close_callback is not None:
                for key in self._time_to_keys[least]:
                    if self._store.__contains__(key):
                        value = self._store[key]
                        self.close_callback(value)
            for key in self._time_to_keys[least]:
                heapq.heappop(self._last_visits)
                if self._store.__contains__(key):
                    del self._store[key]
                    c += 1
            del self._time_to_keys[least]
        if c:
            logging.debug('%d keys swept' % c)