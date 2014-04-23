#!/usr/bin/python
# -*- coding: utf-8 -*-

import collections
import logging
import heapq
import time


class LRUCache(collections.MutableMapping):
    """This class is not thread safe"""

    def __init__(self, timeout=60, *args, **kwargs):
        self.timeout = timeout
        self.store = {}
        self.time_to_keys = collections.defaultdict(list)
        self.last_visits = []
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        "O(logm)"
        t = time.time()
        self.time_to_keys[t].append(key)
        heapq.heappush(self.last_visits, t)
        return self.store[key]

    def __setitem__(self, key, value):
        "O(logm)"
        t = time.time()
        self.store[key] = value
        self.time_to_keys[t].append(key)
        heapq.heappush(self.last_visits, t)

    def __delitem__(self, key):
        "O(1)"
        del self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def sweep(self):
        "O(m)"
        now = time.time()
        c = 0
        while len(self.last_visits) > 0:
            least = self.last_visits[0]
            if now - least <= self.timeout:
                break
            for key in self.time_to_keys[least]:
                heapq.heappop(self.last_visits)
                if self.store.__contains__(key):
                    value = self.store[key]
                    if hasattr(value, 'close'):
                        value.close()
                    del self.store[key]
                    c += 1
            del self.time_to_keys[least]
        if c:
            logging.debug('%d keys swept' % c)
