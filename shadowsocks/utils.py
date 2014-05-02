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
import logging


def find_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        return config_path
    config_path = os.path.join(os.path.dirname(__file__), '../', 'config.json')
    if os.path.exists(config_path):
        return config_path
    return None


def check_config(config):
    if config.get('server', '') in ['127.0.0.1', 'localhost']:
        logging.warn('Server is set to "%s", maybe it\'s not correct' %
                     config['server'])
        logging.warn('Notice server will listen at %s:%s' %
                     (config['server'], config['server_port']))
    if (config.get('method', '') or '').lower() == 'rc4':
        logging.warn('RC4 is not safe; please use a safer cipher, '
                     'like AES-256-CFB')


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