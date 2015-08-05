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

import errno
import traceback
import socket
import logging
import json
import collections

from shadowsocks import common, eventloop, tcprelay, udprelay, asyncdns, shell


BUF_SIZE = 1506
STAT_SEND_LIMIT = 100


class Manager(object):

    def __init__(self, config):
        self._config = config
        self._relays = {}  # (tcprelay, udprelay)
        self._loop = eventloop.EventLoop()
        self._dns_resolver = asyncdns.DNSResolver()
        self._dns_resolver.add_to_loop(self._loop)

        self._statistics = collections.defaultdict(int)
        self._control_client_addr = None
        try:
            manager_address = config['manager_address']
            if ':' in manager_address:
                addr = manager_address.split(':')
                addr = addr[0], int(addr[1])
                family = socket.AF_INET
            else:
                addr = manager_address
                family = socket.AF_UNIX
            # TODO use address instead of port
            self._control_socket = socket.socket(family,
                                                 socket.SOCK_DGRAM)
            self._control_socket.bind(addr)
            self._control_socket.setblocking(False)
        except (OSError, IOError) as e:
            logging.error(e)
            logging.error('can not bind to manager address')
            exit(1)
        self._loop.add(self._control_socket,
                       eventloop.POLL_IN, self)
        self._loop.add_periodic(self.handle_periodic)

        port_password = config['port_password']
        del config['port_password']
        for port, password in port_password.items():
            a_config = config.copy()
            a_config['server_port'] = int(port)
            a_config['password'] = password
            self.add_port(a_config)

    def add_port(self, config):
        port = int(config['server_port'])
        servers = self._relays.get(port, None)
        if servers:
            logging.error("server already exists at %s:%d" % (config['server'],
                                                              port))
            return
        logging.info("adding server at %s:%d" % (config['server'], port))
        t = tcprelay.TCPRelay(config, self._dns_resolver, False,
                              self.stat_callback)
        u = udprelay.UDPRelay(config, self._dns_resolver, False,
                              self.stat_callback)
        t.add_to_loop(self._loop)
        u.add_to_loop(self._loop)
        self._relays[port] = (t, u)

    def remove_port(self, config):
        port = int(config['server_port'])
        servers = self._relays.get(port, None)
        if servers:
            logging.info("removing server at %s:%d" % (config['server'], port))
            t, u = servers
            t.close(next_tick=False)
            u.close(next_tick=False)
            del self._relays[port]
        else:
            logging.error("server not exist at %s:%d" % (config['server'],
                                                         port))

    def handle_event(self, sock, fd, event):
        if sock == self._control_socket and event == eventloop.POLL_IN:
            data, self._control_client_addr = sock.recvfrom(BUF_SIZE)
            parsed = self._parse_command(data)
            if parsed:
                command, config = parsed
                a_config = self._config.copy()
                if config:
                    a_config.update(config)
                if 'server_port' not in a_config:
                    logging.error('can not find server_port in config')
                else:
                    if command == 'add':
                        self.add_port(a_config)
                    elif command == 'remove':
                        self.remove_port(a_config)
                    elif command == 'ping':
                        self._send_control_data(b'pong')
                    else:
                        logging.error('unknown command %s', command)

    def _parse_command(self, data):
        # commands:
        # add: {"server_port": 8000, "password": "foobar"}
        # remove: {"server_port": 8000"}
        data = common.to_str(data)
        parts = data.split(':', 1)
        if len(parts) < 2:
            return data, None
        command, config_json = parts
        try:
            config = json.loads(config_json)
            return command, config
        except Exception as e:
            logging.error(e)
            return None

    def stat_callback(self, port, data_len):
        self._statistics[port] += data_len

    def handle_periodic(self):
        r = {}
        i = 0

        def send_data(data_dict):
            if data_dict:
                data = common.to_bytes(json.dumps(data_dict,
                                                  separators=(',', ':')))
                self._send_control_data(b'stat: ' + data)

        for k, v in self._statistics.items():
            r[k] = v
            i += 1
            if i >= STAT_SEND_LIMIT:
                send_data(r)
                r.clear()
        send_data(r)
        self._statistics.clear()

    def _send_control_data(self, data):
        if self._control_client_addr:
            try:
                self._control_socket.sendto(data, self._control_client_addr)
            except (socket.error, OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()

    def run(self):
        self._loop.run()


def run(config):
    Manager(config).run()
