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
import socket
import logging


def inet_ntop(family, ipstr):
    if family == socket.AF_INET:
        return socket.inet_ntoa(ipstr)
    elif family == socket.AF_INET6:
        v6addr = ':'.join(('%02X%02X' % (ord(i), ord(j)))
                          for i, j in zip(ipstr[::2], ipstr[1::2]))
        return v6addr


def inet_pton(family, addr):
    if family == socket.AF_INET:
        return socket.inet_aton(addr)
    elif family == socket.AF_INET6:
        if '.' in addr:  # a v4 addr
            v4addr = addr[addr.rindex(':') + 1:]
            v4addr = socket.inet_aton(v4addr)
            v4addr = map(lambda x: ('%02X' % ord(x)), v4addr)
            v4addr.insert(2, ':')
            newaddr = addr[:addr.rindex(':') + 1] + ''.join(v4addr)
            return inet_pton(family, newaddr)
        dbyts = [0] * 8  # 8 groups
        grps = addr.split(':')
        for i, v in enumerate(grps):
            if v:
                dbyts[i] = int(v, 16)
            else:
                for j, w in enumerate(grps[::-1]):
                    if w:
                        dbyts[7 - j] = int(w, 16)
                    else:
                        break
                break
        return ''.join((chr(i // 256) + chr(i % 256)) for i in dbyts)
    else:
        raise RuntimeError("What family?")


if not hasattr(socket, 'inet_pton'):
    socket.inet_pton = inet_pton

if not hasattr(socket, 'inet_ntop'):
    socket.inet_ntop = inet_ntop

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
    if (config.get('timeout', 600) or 600) < 100:
        logging.warn('warning: your timeout %d seems too short' %
                     config.get('timeout'))
    if (config.get('timeout', 600) or 600) > 600:
        logging.warn('warning: your timeout %d seems too long' %
                     config.get('timeout'))


def print_local_help():
    print '''usage: sslocal [-h] -s SERVER_ADDR -p SERVER_PORT [-b LOCAL_ADDR]
                -l LOCAL_PORT -k PASSWORD -m METHOD [-c config] [--fast-open]

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER_ADDR        server address
  -p SERVER_PORT        server port
  -b LOCAL_ADDR         local binding address, default is 127.0.0.1
  -l LOCAL_PORT         local port
  -k PASSWORD           password
  -m METHOD             encryption method, for example, aes-256-cfb
  -c CONFIG             path to config file
  --fast-open           use TCP_FASTOPEN, requires Linux 3.7+
'''


def print_server_help():
    print '''usage: ssserver [-h] -s SERVER_ADDR -p SERVER_PORT -k PASSWORD
                -m METHOD [-c config] [--fast-open]

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER_ADDR        server address
  -p SERVER_PORT        server port
  -k PASSWORD           password
  -m METHOD             encryption method, for example, aes-256-cfb
  -c CONFIG             path to config file
  --fast-open           use TCP_FASTOPEN, requires Linux 3.7+
'''