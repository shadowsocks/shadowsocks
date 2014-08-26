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


VERBOSE_LEVEL = 5


def check_python():
    info = sys.version_info
    if not (info[0] == 2 and info[1] >= 6):
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
    if (config.get('method', '') or '').lower() == '':
        logging.warn('warning: table is not safe; please use a safer cipher, '
                     'like AES-256-CFB')
    if (config.get('method', '') or '').lower() == 'rc4':
        logging.warn('warning: RC4 is not safe; please use a safer cipher, '
                     'like AES-256-CFB')
    if config.get('timeout', 300) < 100:
        logging.warn('warning: your timeout %d seems too short' %
                     int(config.get('timeout')))
    if config.get('timeout', 300) > 600:
        logging.warn('warning: your timeout %d seems too long' %
                     int(config.get('timeout')))
    if config.get('password') in ['mypassword', 'barfoo!']:
        logging.error('DON\'T USE DEFAULT PASSWORD! Please change it in your '
                      'config.json!')
        exit(1)


def get_config(is_local):
    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)-s: %(message)s', filemode='a+')
    if is_local:
        shortopts = 'hs:b:p:k:l:m:c:t:vq'
        longopts = ['fast-open']
    else:
        shortopts = 'hs:p:k:m:c:t:vq'
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
                    config = json.load(f, object_hook=_decode_dict)
                except ValueError as e:
                    logging.error('found an error in config.json: %s',
                                  e.message)
                    sys.exit(1)
        else:
            config = {}

        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
        v_count = 0
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
                v_count += 1
                # '-vv' turns on more verbose mode
                config['verbose'] = v_count
            elif key == '-t':
                config['timeout'] = int(value)
            elif key == '--fast-open':
                config['fast_open'] = True
            elif key == '--workers':
                config['workers'] = value
            elif key == '-h':
                if is_local:
                    print_local_help()
                else:
                    print_server_help()
                sys.exit(0)
            elif key == '-q':
                v_count -= 1
                config['verbose'] = v_count
    except getopt.GetoptError as e:
        print >>sys.stderr, e
        print_help(is_local)
        sys.exit(2)

    if not config:
        logging.error('config not specified')
        print_help(is_local)
        sys.exit(2)

    config['password'] = config.get('password', None)
    config['method'] = config.get('method', 'aes-256-cfb')
    config['port_password'] = config.get('port_password', None)
    config['timeout'] = int(config.get('timeout', 300))
    config['fast_open'] = config.get('fast_open', False)
    config['workers'] = config.get('workers', 1)
    config['verbose'] = config.get('verbose', False)
    config['local_address'] = config.get('local_address', '127.0.0.1')
    config['local_port'] = config.get('local_port', 1080)
    if is_local:
        if config.get('server', None) is None:
            logging.error('server addr not specified')
            print_local_help()
            sys.exit(2)
    else:
        config['server'] = config.get('server', '0.0.0.0')
    config['server_port'] = config.get('server_port', 8388)

    if not ('password' in config and config['password']):
        logging.error('password not specified')
        print_help(is_local)
        sys.exit(2)

    logging.getLogger('').handlers = []
    logging.addLevelName(VERBOSE_LEVEL, 'VERBOSE')
    if config['verbose'] >= 2:
        level = VERBOSE_LEVEL
    elif config['verbose'] == 1:
        level = logging.DEBUG
    elif config['verbose'] == -1:
        level = logging.WARN
    elif config['verbose'] <= -2:
        level = logging.ERROR
    else:
        level = logging.INFO
    logging.basicConfig(level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    check_config(config)

    return config


def print_help(is_local):
    if is_local:
        print_local_help()
    else:
        print_server_help()


def print_local_help():
    print '''usage: sslocal [-h] -s SERVER_ADDR [-p SERVER_PORT]
               [-b LOCAL_ADDR] [-l LOCAL_PORT] -k PASSWORD [-m METHOD]
               [-t TIMEOUT] [-c CONFIG] [--fast-open] [-v] [-q]

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER_ADDR        server address
  -p SERVER_PORT        server port, default: 8388
  -b LOCAL_ADDR         local binding address, default: 127.0.0.1
  -l LOCAL_PORT         local port, default: 1080
  -k PASSWORD           password
  -m METHOD             encryption method, default: aes-256-cfb
  -t TIMEOUT            timeout in seconds, default: 300
  -c CONFIG             path to config file
  --fast-open           use TCP_FASTOPEN, requires Linux 3.7+
  -v, -vv               verbose mode
  -q, -qq               quiet mode, only show warnings/errors

Online help: <https://github.com/clowwindy/shadowsocks>
'''


def print_server_help():
    print '''usage: ssserver [-h] [-s SERVER_ADDR] [-p SERVER_PORT] -k PASSWORD
                -m METHOD [-t TIMEOUT] [-c CONFIG] [--fast-open]
                [--workers WORKERS] [-v] [-q]

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER_ADDR        server address, default: 0.0.0.0
  -p SERVER_PORT        server port, default: 8388
  -k PASSWORD           password
  -m METHOD             encryption method, default: aes-256-cfb
  -t TIMEOUT            timeout in seconds, default: 300
  -c CONFIG             path to config file
  --fast-open           use TCP_FASTOPEN, requires Linux 3.7+
  --workers WORKERS     number of workers, available on Unix/Linux
  -v, -vv               verbose mode
  -q, -qq               quiet mode, only show warnings/errors

Online help: <https://github.com/clowwindy/shadowsocks>
'''


def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv
