#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import logging
import time
import traceback
import errno
from shadowsocks import selectors
from shadowsocks.selectors import (EVENT_READ, EVENT_WRITE, EVENT_ERROR,
                                   errno_from_exception)


POLL_IN = EVENT_READ
POLL_OUT = EVENT_WRITE
POLL_ERR = EVENT_ERROR

TIMEOUT_PRECISION = 10


class EventLoop:

    def __init__(self):
        self._selector = selectors.DefaultSelector()
        self._stopping = False
        self._last_time = time.time()
        self._periodic_callbacks = []

    def poll(self, timeout=None):
        return self._selector.select(timeout)

    def add(self, sock, events, data):
        events |= selectors.EVENT_ERROR
        return self._selector.register(sock, events, data)

    def remove(self, sock):
        try:
            return self._selector.unregister(sock)
        except KeyError:
            pass

    def modify(self, sock, events, data):
        events |= selectors.EVENT_ERROR
        try:
            key = self._selector.modify(sock, events, data)
        except KeyError:
            key = self.add(sock, events, data)
        return key

    def add_periodic(self, callback):
        self._periodic_callbacks.append(callback)

    def remove_periodic(self, callback):
        self._periodic_callbacks.remove(callback)

    def fd_count(self):
        return len(self._selector.get_map())

    def run(self):
        logging.debug('Starting event loop')

        while not self._stopping:
            asap = False
            try:
                events = self.poll(timeout=TIMEOUT_PRECISION)
            except (OSError, IOError) as e:
                if errno_from_exception(e) in (errno.EPIPE, errno.EINTR):
                    # EPIPE: Happens when the client closes the connection
                    # EINTR: Happens when received a signal
                    # handles them as soon as possible
                    asap = True
                    logging.debug('poll: %s', e)
                else:
                    logging.error('poll: %s', e)
                    traceback.print_exc()
                    continue

            for key, event in events:
                if type(key.data) == tuple:
                    handler = key.data[0]
                    args = key.data[1:]
                else:
                    handler = key.data
                    args = ()

                sock = key.fileobj
                if hasattr(handler, 'handle_event'):
                    handler = handler.handle_event

                try:
                    handler(sock, event, *args)
                except Exception as e:
                    logging.debug(e)
                    traceback.print_exc()
                    raise

            now = time.time()
            if asap or now - self._last_time >= TIMEOUT_PRECISION:
                for callback in self._periodic_callbacks:
                    callback()
                self._last_time = now

            logging.debug('Got {} fds registered'.format(self.fd_count()))

        logging.debug('Stopping event loop')
        self._selector.close()

    def stop(self):
        self._stopping = True
