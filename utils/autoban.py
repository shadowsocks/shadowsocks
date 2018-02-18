#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 clowwindy
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

from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import socket
import argparse
import subprocess


def inet_pton(str_ip):
    try:
        return socket.inet_pton(socket.AF_INET, str_ip)
    except socket.error:
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='See README')
    parser.add_argument('-c', '--count', default=3, type=int,
                        help='with how many failure times it should be '
                             'considered as an attack')
    config = parser.parse_args()
    ips = {}
    banned = set()
    for line in sys.stdin:
        if 'can not parse header when' not in line:
            continue
        ip_str = line.split()[-1].rsplit(':', 1)[0]
        ip = inet_pton(ip_str)
        if ip is None:
            continue
        if ip not in ips:
            ips[ip] = 1
            sys.stdout.flush()
        else:
            ips[ip] += 1
        if ip not in banned and ips[ip] >= config.count:
            banned.add(ip)
            print('ban ip %s' % ip_str)
            cmd = ['iptables', '-A', 'INPUT', '-s', ip_str, '-j', 'DROP',
                   '-m', 'comment', '--comment', 'autoban']
            print(' '.join(cmd), file=sys.stderr)
            sys.stderr.flush()
            subprocess.call(cmd)
