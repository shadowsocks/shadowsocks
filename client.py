#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import logging
import os
import sys

path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, path)
from shadowsocks.eventloop import EventLoop
from shadowsocks.tcprelay import TcpRelay, TcpRelayClientHanler


FORMATTER = '%(asctime)s - %(levelname)s - %(message)s'
LOGGING_LEVEL = logging.INFO
logging.basicConfig(level=LOGGING_LEVEL, format=FORMATTER)

LISTEN_ADDR = ('127.0.0.1', 1080)
REMOTE_ADDR = ('127.0.0.1', 9000)


def main():
    loop = EventLoop()
    relay = TcpRelay(TcpRelayClientHanler, LISTEN_ADDR, REMOTE_ADDR)
    relay.add_to_loop(loop)
    loop.run()


if __name__ == '__main__':
    main()
