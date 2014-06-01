#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import socket
import logging
import encrypt
import os
import utils
import tcprelay
import udprelay


def main():
    utils.check_python()

    config = utils.get_config(False)

    utils.print_shadowsocks()

    if config['port_password']:
        if config['server_port'] or config['password']:
            logging.warn('warning: port_password should not be used with '
                         'server_port and password. server_port and password '
                         'will be ignored')
    else:
        config['port_password'] = {}
        config['port_password'][str(config['server_port'])] = config['password']

    encrypt.init_table(config['password'], config['method'])
    tcp_servers = []
    udp_servers = []
    for port, password in config['port_password'].items():
        a_config = config.copy()
        a_config['server_port'] = port
        a_config['password'] = password
        logging.info("starting server at %s:%d" %
                     (a_config['server'], port))
        tcp_server = tcprelay.TCPRelay(config, False)
        tcp_servers.append(tcp_server)
        udp_server = udprelay.UDPRelay(config, False)
        udp_servers.append(udp_server)

    def run_server():
        for tcp_server in tcp_servers:
            tcp_server.start()
        for udp_server in udp_servers:
            udp_server.start()

    if int(config['workers']) > 1:
        if os.name == 'posix':
            children = []
            is_child = False
            for i in xrange(0, int(config['workers'])):
                r = os.fork()
                if r == 0:
                    logging.info('worker started')
                    is_child = True
                    run_server()
                    break
                else:
                    children.append(r)
            if not is_child:
                def handler(signum, frame):
                    for pid in children:
                        os.kill(pid, signum)
                        os.waitpid(pid, 0)
                    sys.exit()
                import signal
                signal.signal(signal.SIGTERM, handler)

                # master
                for tcp_server in tcp_servers:
                    tcp_server.server_close()
                for udp_server in udp_servers:
                    udp_server.close()

                for child in children:
                    os.waitpid(child, 0)
        else:
            logging.warn('worker is only available on Unix/Linux')
            run_server()
    else:
        run_server()


if __name__ == '__main__':
    try:
        main()
    except socket.error, e:
        logging.error(e)
