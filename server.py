#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import logging

path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, path)
from shadowsocks.eventloop import EventLoop
from shadowsocks.tcprelay import TcpRelay, TcpRelayServerHandler
from shadowsocks.asyncdns import DNSResolver


FORMATTER = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOGGING_LEVEL = logging.INFO
logging.basicConfig(level=LOGGING_LEVEL, format=FORMATTER)

LISTEN_ADDR = ('0.0.0.0', 9000)


def main():
    loop = EventLoop()
    dns_resolver = DNSResolver()
    relay = TcpRelay(TcpRelayServerHandler, LISTEN_ADDR,
                     dns_resolver=dns_resolver)
    dns_resolver.add_to_loop(loop)
    relay.add_to_loop(loop)
    loop.run()

if __name__ == '__main__':
    main()
