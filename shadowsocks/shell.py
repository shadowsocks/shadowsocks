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

import os
import json
import sys
import getopt
import logging
import traceback

from functools import wraps

from shadowsocks.common import to_bytes, to_str, IPNetwork
from shadowsocks import cryptor


VERBOSE_LEVEL = 5

verbose = 0


def check_python():
    info = sys.version_info
    if info[0] == 2 and not info[1] >= 6:
        print('Python 2.6+ required')
        sys.exit(1)
    elif info[0] == 3 and not info[1] >= 3:
        print('Python 3.3+ required')
        sys.exit(1)
    elif info[0] not in [2, 3]:
        print('Python version not supported')
        sys.exit(1)


def print_exception(e):
    global verbose
    logging.error(e)
    if verbose > 0:
        import traceback
        traceback.print_exc()


def exception_handle(self_, err_msg=None, exit_code=None,
                     destroy=False, conn_err=False):
    # self_: if function passes self as first arg

    def process_exception(e, self=None):
        print_exception(e)
        if err_msg:
            logging.error(err_msg)
        if exit_code:
            sys.exit(1)

        if not self_:
            return

        if conn_err:
            addr, port = self._client_address[0], self._client_address[1]
            logging.error('%s when handling connection from %s:%d' %
                          (e, addr, port))
        if self._config['verbose']:
            traceback.print_exc()
        if destroy:
            self.destroy()

    def decorator(func):
        if self_:
            @wraps(func)
            def wrapper(self, *args, **kwargs):
                try:
                    func(self, *args, **kwargs)
                except Exception as e:
                    process_exception(e, self)
        else:
            @wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    func(*args, **kwargs)
                except Exception as e:
                    process_exception(e)

        return wrapper
    return decorator


def print_shadowsocks():
    version = ''
    try:
        import pkg_resources
        version = pkg_resources.get_distribution('shadowsocks').version
    except Exception:
        pass
    print('Shadowsocks %s' % version)


def find_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        return config_path
    config_path = os.path.join(os.path.dirname(__file__), '../', 'config.json')
    if os.path.exists(config_path):
        return config_path
    return None


def check_config(config, is_local):
    if config.get('daemon', None) == 'stop':
        # no need to specify configuration for daemon stop
        return

    if is_local:
        if config.get('server', None) is None:
            logging.error('server addr not specified')
            print_local_help()
            sys.exit(2)
        else:
            config['server'] = to_str(config['server'])

        if config.get('tunnel_remote', None) is None:
            logging.error('tunnel_remote addr not specified')
            print_local_help()
            sys.exit(2)
        else:
            config['tunnel_remote'] = to_str(config['tunnel_remote'])
    else:
        config['server'] = to_str(config.get('server', '0.0.0.0'))
        try:
            config['forbidden_ip'] = \
                IPNetwork(config.get('forbidden_ip', '127.0.0.0/8,::1/128'))
        except Exception as e:
            logging.error(e)
            sys.exit(2)

    if is_local and not config.get('password', None):
        logging.error('password not specified')
        print_help(is_local)
        sys.exit(2)

    if not is_local and not config.get('password', None) \
            and not config.get('port_password', None) \
            and not config.get('manager_address'):
        logging.error('password or port_password not specified')
        print_help(is_local)
        sys.exit(2)

    if 'local_port' in config:
        config['local_port'] = int(config['local_port'])

    if 'server_port' in config and type(config['server_port']) != list:
        config['server_port'] = int(config['server_port'])

    if 'tunnel_remote_port' in config:
        config['tunnel_remote_port'] = int(config['tunnel_remote_port'])
    if 'tunnel_port' in config:
        config['tunnel_port'] = int(config['tunnel_port'])

    if config.get('local_address', '') in [b'0.0.0.0']:
        logging.warn('warning: local set to listen on 0.0.0.0, it\'s not safe')
    if config.get('server', '') in ['127.0.0.1', 'localhost']:
        logging.warn('warning: server set to listen on %s:%s, are you sure?' %
                     (to_str(config['server']), config['server_port']))
    if (config.get('method', '') or '').lower() == 'table':
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
    if config.get('password') in [b'mypassword']:
        logging.error('DON\'T USE DEFAULT PASSWORD! Please change it in your '
                      'config.json!')
        sys.exit(1)
    if config.get('user', None) is not None:
        if os.name != 'posix':
            logging.error('user can be used only on Unix')
            sys.exit(1)
    if config.get('dns_server', None) is not None:
        if type(config['dns_server']) != list:
            config['dns_server'] = to_str(config['dns_server'])
        else:
            config['dns_server'] = [to_str(ds) for ds in config['dns_server']]
        logging.info('Specified DNS server: %s' % config['dns_server'])

    config['crypto_path'] = {'openssl': config['libopenssl'],
                             'mbedtls': config['libmbedtls'],
                             'sodium': config['libsodium']}

    cryptor.try_cipher(config['password'], config['method'],
                       config['crypto_path'])


def get_config(is_local):
    global verbose

    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)-s: %(message)s')
    if is_local:
        shortopts = 'hd:s:b:p:k:l:m:c:t:vqa'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'user=',
                    'libopenssl=', 'libmbedtls=', 'libsodium=', 'version']
    else:
        shortopts = 'hd:s:p:k:m:c:t:vqa'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'workers=',
                    'forbidden-ip=', 'user=', 'manager-address=', 'version',
                    'libopenssl=', 'libmbedtls=', 'libsodium=', 'prefer-ipv6']
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
                    config = parse_json_in_str(f.read().decode('utf8'))
                except ValueError as e:
                    logging.error('found an error in config.json: %s',
                                  e.message)
                    sys.exit(1)
        else:
            config = {}

        v_count = 0
        for key, value in optlist:
            if key == '-p':
                config['server_port'] = int(value)
            elif key == '-k':
                config['password'] = to_bytes(value)
            elif key == '-l':
                config['local_port'] = int(value)
            elif key == '-s':
                config['server'] = to_str(value)
            elif key == '-m':
                config['method'] = to_str(value)
            elif key == '-b':
                config['local_address'] = to_str(value)
            elif key == '-v':
                v_count += 1
                # '-vv' turns on more verbose mode
                config['verbose'] = v_count
            elif key == '-a':
                config['one_time_auth'] = True
            elif key == '-t':
                config['timeout'] = int(value)
            elif key == '--fast-open':
                config['fast_open'] = True
            elif key == '--libopenssl':
                config['libopenssl'] = to_str(value)
            elif key == '--libmbedtls':
                config['libmbedtls'] = to_str(value)
            elif key == '--libsodium':
                config['libsodium'] = to_str(value)
            elif key == '--workers':
                config['workers'] = int(value)
            elif key == '--manager-address':
                config['manager_address'] = to_str(value)
            elif key == '--user':
                config['user'] = to_str(value)
            elif key == '--forbidden-ip':
                config['forbidden_ip'] = to_str(value).split(',')
            elif key in ('-h', '--help'):
                if is_local:
                    print_local_help()
                else:
                    print_server_help()
                sys.exit(0)
            elif key == '--version':
                print_shadowsocks()
                sys.exit(0)
            elif key == '-d':
                config['daemon'] = to_str(value)
            elif key == '--pid-file':
                config['pid-file'] = to_str(value)
            elif key == '--log-file':
                config['log-file'] = to_str(value)
            elif key == '-q':
                v_count -= 1
                config['verbose'] = v_count
            elif key == '--prefer-ipv6':
                config['prefer_ipv6'] = True
    except getopt.GetoptError as e:
        print(e, file=sys.stderr)
        print_help(is_local)
        sys.exit(2)

    if not config:
        logging.error('config not specified')
        print_help(is_local)
        sys.exit(2)

    config['password'] = to_bytes(config.get('password', b''))
    config['method'] = to_str(config.get('method', 'aes-256-cfb'))
    config['port_password'] = config.get('port_password', None)
    config['timeout'] = int(config.get('timeout', 300))
    config['fast_open'] = config.get('fast_open', False)
    config['workers'] = config.get('workers', 1)
    config['pid-file'] = config.get('pid-file', '/var/run/shadowsocks.pid')
    config['log-file'] = config.get('log-file', '/var/log/shadowsocks.log')
    config['verbose'] = config.get('verbose', False)
    config['local_address'] = to_str(config.get('local_address', '127.0.0.1'))
    config['local_port'] = config.get('local_port', 1080)
    config['one_time_auth'] = config.get('one_time_auth', False)
    config['prefer_ipv6'] = config.get('prefer_ipv6', False)
    config['server_port'] = config.get('server_port', 8388)
    config['dns_server'] = config.get('dns_server', None)
    config['libopenssl'] = config.get('libopenssl', None)
    config['libmbedtls'] = config.get('libmbedtls', None)
    config['libsodium'] = config.get('libsodium', None)

    config['tunnel_remote'] = to_str(config.get('tunnel_remote', '8.8.8.8'))
    config['tunnel_remote_port'] = config.get('tunnel_remote_port', 53)
    config['tunnel_port'] = config.get('tunnel_port', 53)

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
    verbose = config['verbose']
    logging.basicConfig(level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    check_config(config, is_local)

    return config


def print_help(is_local):
    if is_local:
        print_local_help()
    else:
        print_server_help()


def print_local_help():
    print('''usage: sslocal [OPTION]...
A fast tunnel proxy that helps you bypass firewalls.

You can supply configurations via either config file or command line arguments.

Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address
  -p SERVER_PORT         server port, default: 8388
  -b LOCAL_ADDR          local binding address, default: 127.0.0.1
  -l LOCAL_PORT          local port, default: 1080
  -k PASSWORD            password
  -m METHOD              encryption method, default: aes-256-cfb
                         Sodium:
                            chacha20-poly1305, chacha20-ietf-poly1305,
                            xchacha20-ietf-poly1305,
                            sodium:aes-256-gcm,
                            salsa20, chacha20, chacha20-ietf.
                         Sodium 1.0.12:
                            xchacha20
                         OpenSSL:
                            aes-{128|192|256}-gcm, aes-{128|192|256}-cfb,
                            aes-{128|192|256}-ofb, aes-{128|192|256}-ctr,
                            camellia-{128|192|256}-cfb,
                            bf-cfb, cast5-cfb, des-cfb, idea-cfb,
                            rc2-cfb, seed-cfb,
                            rc4, rc4-md5, table.
                         OpenSSL 1.1:
                            aes-{128|192|256}-ocb
                         mbedTLS:
                            mbedtls:aes-{128|192|256}-cfb128,
                            mbedtls:aes-{128|192|256}-ctr,
                            mbedtls:camellia-{128|192|256}-cfb128,
                            mbedtls:aes-{128|192|256}-gcm
  -t TIMEOUT             timeout in seconds, default: 300
  -a ONE_TIME_AUTH       one time auth
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+
  --libopenssl=PATH      custom openssl crypto lib path
  --libmbedtls=PATH      custom mbedtls crypto lib path
  --libsodium=PATH       custom sodium crypto lib path

General options:
  -h, --help             show this help message and exit
  -d start/stop/restart  daemon mode
  --pid-file=PID_FILE    pid file for daemon mode
  --log-file=LOG_FILE    log file for daemon mode
  --user=USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information

Online help: <https://github.com/shadowsocks/shadowsocks>
''')


def print_server_help():
    print('''usage: ssserver [OPTION]...
A fast tunnel proxy that helps you bypass firewalls.

You can supply configurations via either config file or command line arguments.

Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address, default: 0.0.0.0
  -p SERVER_PORT         server port, default: 8388
  -k PASSWORD            password
  -m METHOD              encryption method, default: aes-256-cfb
                         Sodium:
                            chacha20-poly1305, chacha20-ietf-poly1305,
                            xchacha20-ietf-poly1305,
                            sodium:aes-256-gcm,
                            salsa20, chacha20, chacha20-ietf.
                         Sodium 1.0.12:
                            xchacha20
                         OpenSSL:
                            aes-{128|192|256}-gcm, aes-{128|192|256}-cfb,
                            aes-{128|192|256}-ofb, aes-{128|192|256}-ctr,
                            camellia-{128|192|256}-cfb,
                            bf-cfb, cast5-cfb, des-cfb, idea-cfb,
                            rc2-cfb, seed-cfb,
                            rc4, rc4-md5, table.
                         OpenSSL 1.1:
                            aes-{128|192|256}-ocb
                         mbedTLS:
                            mbedtls:aes-{128|192|256}-cfb128,
                            mbedtls:aes-{128|192|256}-ctr,
                            mbedtls:camellia-{128|192|256}-cfb128,
                            mbedtls:aes-{128|192|256}-gcm
  -t TIMEOUT             timeout in seconds, default: 300
  -a ONE_TIME_AUTH       one time auth
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+
  --workers=WORKERS      number of workers, available on Unix/Linux
  --forbidden-ip=IPLIST  comma seperated IP list forbidden to connect
  --manager-address=ADDR optional server manager UDP address, see wiki
  --prefer-ipv6          resolve ipv6 address first
  --libopenssl=PATH      custom openssl crypto lib path
  --libmbedtls=PATH      custom mbedtls crypto lib path
  --libsodium=PATH       custom sodium crypto lib path

General options:
  -h, --help             show this help message and exit
  -d start/stop/restart  daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information

Online help: <https://github.com/shadowsocks/shadowsocks>
''')


def _decode_list(data):
    rv = []
    for item in data:
        if hasattr(item, 'encode'):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.items():
        if hasattr(value, 'encode'):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


def parse_json_in_str(data):
    # parse json and convert everything from unicode to str
    return json.loads(data, object_hook=_decode_dict)
