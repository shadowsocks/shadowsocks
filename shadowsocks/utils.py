#!/usr/bin/python
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

import os
import json
import sys
import getopt
import logging


def check_python():
    info = sys.version_info
    if not (info.major == 2 and info.minor >= 6):
        print 'Python 2.6 or 2.7 required'
        sys.exit(1)


def print_shadowsocks():
    version = ''
    try:
        import pkg_resources
        version = pkg_resources.get_distribution('shadowsocks').version
    except Exception:
        pass
    print 'shadowsocks %s' % version


def find_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        return config_path
    config_path = os.path.join(os.path.dirname(__file__), '../', 'config.json')
    if os.path.exists(config_path):
        return config_path
    return None


def check_config(config):
    if config.get('local_address', '') in ['0.0.0.0']:
        logging.warn('warning: local set to listen 0.0.0.0, which is not safe')
    if config.get('server', '') in ['127.0.0.1', 'localhost']:
        logging.warn('warning: server set to listen %s:%s, are you sure?' %
                     (config['server'], config['server_port']))
    if (config.get('method', '') or '').lower() == 'rc4':
        logging.warn('warning: RC4 is not safe; please use a safer cipher, '
                     'like AES-256-CFB')
    if (int(config.get('timeout', 300)) or 300) < 100:
        logging.warn('warning: your timeout %d seems too short' %
                     int(config.get('timeout')))
    if (int(config.get('timeout', 300)) or 300) > 600:
        logging.warn('warning: your timeout %d seems too long' %
                     int(config.get('timeout')))


def get_config(is_local):
    if is_local:
        shortopts = 's:b:p:k:l:m:c:t:v'
        longopts = ['fast-open']
    else:
        shortopts = 's:p:k:m:c:t:v'
        longopts = ['fast-open', 'workers:']
    try:
        config_path = find_config()
        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
        for key, value in optlist:
            if key == '-c':
                config_path = value

        if config_path:
            logging.info('loading config from %s' % config_path)
            with open(config_path, 'rb') as f:
                try:
                    config = json.load(f)
                except ValueError as e:
                    logging.error('found an error in config.json: %s',
                                  e.message)
                    sys.exit(1)
        else:
            config = {}

        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
        for key, value in optlist:
            if key == '-p':
                config['server_port'] = int(value)
            elif key == '-k':
                config['password'] = value
            elif key == '-l':
                config['local_port'] = int(value)
            elif key == '-s':
                config['server'] = value
            elif key == '-m':
                config['method'] = value
            elif key == '-b':
                config['local_address'] = value
            elif key == '-v':
                config['verbose'] = True
            elif key == '--fast-open':
                config['fast_open'] = True
            elif key == '--workers':
                config['workers'] = value
    except getopt.GetoptError as e:
        print >>sys.stderr, e
        if is_local:
            print_local_help()
        else:
            print_server_help()
        sys.exit(2)

    if not config['password'] and not config_path:
        sys.exit('config not specified, please read '
                 'https://github.com/clowwindy/shadowsocks')

    config['password'] = config.get('password', None)
    config['method'] = config.get('method', None)
    config['port_password'] = config.get('port_password', None)
    config['timeout'] = int(config.get('timeout', 300))
    config['fast_open'] = config.get('fast_open', False)
    config['workers'] = config.get('workers', 1)
    config['verbose'] = config.get('verbose', False)
    config['local_address'] = config.get('local_address', '127.0.0.1')

    if config['verbose']:
        level = logging.DEBUG
    else:
        level = logging.WARNING
    logging.getLogger('').handlers = []
    logging.basicConfig(level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    check_config(config)

    return config


def print_local_help():
    print '''usage: sslocal [-h] -s SERVER_ADDR -p SERVER_PORT [-b LOCAL_ADDR]
                -l LOCAL_PORT -k PASSWORD -m METHOD [-t TIMEOUT] [-c CONFIG]
                [--fast-open] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER_ADDR        server address
  -p SERVER_PORT        server port
  -b LOCAL_ADDR         local binding address, default is 127.0.0.1
  -l LOCAL_PORT         local port
  -k PASSWORD           password
  -m METHOD             encryption method, for example, aes-256-cfb
  -t TIMEOUT            timeout in seconds
  -c CONFIG             path to config file
  --fast-open           use TCP_FASTOPEN, requires Linux 3.7+
  -v                    verbose mode

Online help: <https://github.com/clowwindy/shadowsocks>
'''


def print_server_help():
    print '''usage: ssserver [-h] -s SERVER_ADDR -p SERVER_PORT -k PASSWORD
                -m METHOD [-t TIMEOUT] [-c CONFIG] [--fast-open] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER_ADDR        server address
  -p SERVER_PORT        server port
  -k PASSWORD           password
  -m METHOD             encryption method, for example, aes-256-cfb
  -t TIMEOUT            timeout in seconds
  -c CONFIG             path to config file
  --fast-open           use TCP_FASTOPEN, requires Linux 3.7+
  --workers WORKERS     number of workers, available on Unix/Linux
  -v                    verbose mode

Online help: <https://github.com/clowwindy/shadowsocks>
'''