#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy
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

import sys
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, asyncdns


@shell.exception_handle(self_=False, exit_code=1)
def main():
    shell.check_python()

    # fix py2exe
    if hasattr(sys, "frozen") and sys.frozen in \
            ("windows_exe", "console_exe"):
        p = os.path.dirname(os.path.abspath(sys.executable))
        os.chdir(p)

    config = shell.get_config(True)
    daemon.daemon_exec(config)
    dns_resolver = asyncdns.DNSResolver()
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop)
    _config = config.copy()
    _config["local_port"] = _config["tunnel_port"]
    logging.info("starting tcp tunnel at %s:%d forward to %s:%d" %
                 (_config['local_address'], _config['local_port'],
                  _config['tunnel_remote'], _config['tunnel_remote_port']))
    tunnel_tcp_server = tcprelay.TCPRelay(_config, dns_resolver, True)
    tunnel_tcp_server._is_tunnel = True
    tunnel_tcp_server.add_to_loop(loop)
    logging.info("starting udp tunnel at %s:%d forward to %s:%d" %
                 (_config['local_address'], _config['local_port'],
                     _config['tunnel_remote'], _config['tunnel_remote_port']))
    tunnel_udp_server = udprelay.UDPRelay(_config, dns_resolver, True)
    tunnel_udp_server._is_tunnel = True
    tunnel_udp_server.add_to_loop(loop)

    def handler(signum, _):
        logging.warn('received SIGQUIT, doing graceful shutting down..')
        tunnel_tcp_server.close(next_tick=True)
        tunnel_udp_server.close(next_tick=True)
    signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)

    def int_handler(signum, _):
        sys.exit(1)
    signal.signal(signal.SIGINT, int_handler)

    daemon.set_user(config.get('user', None))
    loop.run()

if __name__ == '__main__':
    main()
