#!/usr/bin/env python
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

import sys
import os
import logging
import signal

if __name__ == '__main__':
    import inspect
    file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
    sys.path.insert(0, os.path.join(file_path, '../'))

from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, \
    asyncdns, manager


def main():
    shell.check_python()

    config = shell.get_config(False)

    shell.log_shadowsocks_version()

    daemon.daemon_exec(config)

    if config['port_password']:
        pass
    else:
        config['port_password'] = {}
        server_port = config['server_port']
        if type(server_port) == list:
            for a_server_port in server_port:
                config['port_password'][a_server_port] = config['password']
        else:
            config['port_password'][str(server_port)] = config['password']

    if not config.get('dns_ipv6', False):
        asyncdns.IPV6_CONNECTION_SUPPORT = False

    if config.get('manager_address', 0):
        logging.info('entering manager mode')
        manager.run(config)
        return

    tcp_servers = []
    udp_servers = []
    dns_resolver = asyncdns.DNSResolver()
    if int(config['workers']) > 1:
        stat_counter_dict = None
    else:
        stat_counter_dict = {}
    port_password = config['port_password']
    config_password = config.get('password', 'm')
    del config['port_password']
    for port, password_obfs in port_password.items():
        method = config["method"]
        protocol = config.get("protocol", 'origin')
        protocol_param = config.get("protocol_param", '')
        obfs = config.get("obfs", 'plain')
        obfs_param = config.get("obfs_param", '')
        bind = config.get("out_bind", '')
        bindv6 = config.get("out_bindv6", '')
        if type(password_obfs) == list:
            password = password_obfs[0]
            obfs = password_obfs[1]
            if len(password_obfs) > 2:
                protocol = password_obfs[2]
        elif type(password_obfs) == dict:
            password = password_obfs.get('password', config_password)
            method = password_obfs.get('method', method)
            protocol = password_obfs.get('protocol', protocol)
            protocol_param = password_obfs.get('protocol_param', protocol_param)
            obfs = password_obfs.get('obfs', obfs)
            obfs_param = password_obfs.get('obfs_param', obfs_param)
            bind = password_obfs.get('bind', bind)
            bindv6 = password_obfs.get('bindv6', bindv6)
        else:
            password = password_obfs
        a_config = config.copy()
        ipv6_ok = False
        logging.info("server start with protocol[%s] password [%s] method [%s] obfs [%s] obfs_param [%s]" %
                (protocol, password, a_config['method'], obfs, obfs_param))
        if 'server_ipv6' in a_config:
            try:
                if len(a_config['server_ipv6']) > 2 and a_config['server_ipv6'][0] == "[" and a_config['server_ipv6'][-1] == "]":
                    a_config['server_ipv6'] = a_config['server_ipv6'][1:-1]
                a_config['server_port'] = int(port)
                a_config['password'] = password
                a_config['method'] = method
                a_config['protocol'] = protocol
                a_config['protocol_param'] = protocol_param
                a_config['obfs'] = obfs
                a_config['obfs_param'] = obfs_param
                a_config['out_bind'] = bind
                a_config['out_bindv6'] = bindv6
                a_config['server'] = a_config['server_ipv6']
                logging.info("starting server at [%s]:%d" %
                             (a_config['server'], int(port)))
                tcp_servers.append(tcprelay.TCPRelay(a_config, dns_resolver, False, stat_counter=stat_counter_dict))
                udp_servers.append(udprelay.UDPRelay(a_config, dns_resolver, False, stat_counter=stat_counter_dict))
                if a_config['server_ipv6'] == b"::":
                    ipv6_ok = True
            except Exception as e:
                shell.print_exception(e)

        try:
            a_config = config.copy()
            a_config['server_port'] = int(port)
            a_config['password'] = password
            a_config['method'] = method
            a_config['protocol'] = protocol
            a_config['protocol_param'] = protocol_param
            a_config['obfs'] = obfs
            a_config['obfs_param'] = obfs_param
            a_config['out_bind'] = bind
            a_config['out_bindv6'] = bindv6
            logging.info("starting server at %s:%d" %
                         (a_config['server'], int(port)))
            tcp_servers.append(tcprelay.TCPRelay(a_config, dns_resolver, False, stat_counter=stat_counter_dict))
            udp_servers.append(udprelay.UDPRelay(a_config, dns_resolver, False, stat_counter=stat_counter_dict))
        except Exception as e:
            if not ipv6_ok:
                shell.print_exception(e)

    def run_server():
        def child_handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            list(map(lambda s: s.close(next_tick=True),
                     tcp_servers + udp_servers))
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM),
                      child_handler)

        def int_handler(signum, _):
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        try:
            loop = eventloop.EventLoop()
            dns_resolver.add_to_loop(loop)
            list(map(lambda s: s.add_to_loop(loop), tcp_servers + udp_servers))

            daemon.set_user(config.get('user', None))
            loop.run()
        except Exception as e:
            shell.print_exception(e)
            sys.exit(1)

    if int(config['workers']) > 1:
        if os.name == 'posix':
            children = []
            is_child = False
            for i in range(0, int(config['workers'])):
                r = os.fork()
                if r == 0:
                    logging.info('worker started')
                    is_child = True
                    run_server()
                    break
                else:
                    children.append(r)
            if not is_child:
                def handler(signum, _):
                    for pid in children:
                        try:
                            os.kill(pid, signum)
                            os.waitpid(pid, 0)
                        except OSError:  # child may already exited
                            pass
                    sys.exit()
                signal.signal(signal.SIGTERM, handler)
                signal.signal(signal.SIGQUIT, handler)
                signal.signal(signal.SIGINT, handler)

                # master
                for a_tcp_server in tcp_servers:
                    a_tcp_server.close()
                for a_udp_server in udp_servers:
                    a_udp_server.close()
                dns_resolver.close()

                for child in children:
                    os.waitpid(child, 0)
        else:
            logging.warn('worker is only available on Unix/Linux')
            run_server()
    else:
        run_server()


if __name__ == '__main__':
    main()
