#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2013-2015 clowwindy
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

import socket
import struct
import logging
import binascii
import re

from shadowsocks import lru_cache

def compat_ord(s):
    if type(s) == int:
        return s
    return _ord(s)


def compat_chr(d):
    if bytes == str:
        return _chr(d)
    return bytes([d])


_ord = ord
_chr = chr
ord = compat_ord
chr = compat_chr

connect_log = logging.debug

def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s


def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s

def int32(x):
    if x > 0xFFFFFFFF or x < 0:
        x &= 0xFFFFFFFF
    if x > 0x7FFFFFFF:
        x = int(0x100000000 - x)
        if x < 0x80000000:
            return -x
        else:
            return -2147483648
    return x

def inet_ntop(family, ipstr):
    if family == socket.AF_INET:
        return to_bytes(socket.inet_ntoa(ipstr))
    elif family == socket.AF_INET6:
        import re
        v6addr = ':'.join(('%02X%02X' % (ord(i), ord(j))).lstrip('0')
                          for i, j in zip(ipstr[::2], ipstr[1::2]))
        v6addr = re.sub('::+', '::', v6addr, count=1)
        return to_bytes(v6addr)


def inet_pton(family, addr):
    addr = to_str(addr)
    if family == socket.AF_INET:
        return socket.inet_aton(addr)
    elif family == socket.AF_INET6:
        if '.' in addr:  # a v4 addr
            v4addr = addr[addr.rindex(':') + 1:]
            v4addr = socket.inet_aton(v4addr)
            v4addr = ['%02X' % ord(x) for x in v4addr]
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
        return b''.join((chr(i // 256) + chr(i % 256)) for i in dbyts)
    else:
        raise RuntimeError("What family?")


def is_ip(address):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            if type(address) != str:
                address = address.decode('utf8')
            inet_pton(family, address)
            return family
        except (TypeError, ValueError, OSError, IOError):
            pass
    return False


def match_regex(regex, text):
    regex = re.compile(regex)
    for item in regex.findall(text):
        return True
    return False


def patch_socket():
    if not hasattr(socket, 'inet_pton'):
        socket.inet_pton = inet_pton

    if not hasattr(socket, 'inet_ntop'):
        socket.inet_ntop = inet_ntop


patch_socket()


ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3


def pack_addr(address):
    address_str = to_str(address)
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            r = socket.inet_pton(family, address_str)
            if family == socket.AF_INET6:
                return b'\x04' + r
            else:
                return b'\x01' + r
        except (TypeError, ValueError, OSError, IOError):
            pass
    if len(address) > 255:
        address = address[:255]  # TODO
    return b'\x03' + chr(len(address)) + address

def pre_parse_header(data):
    if not data:
        return None
    datatype = ord(data[0])
    if datatype == 0x80:
        if len(data) <= 2:
            return None
        rand_data_size = ord(data[1])
        if rand_data_size + 2 >= len(data):
            logging.warn('header too short, maybe wrong password or '
                         'encryption method')
            return None
        data = data[rand_data_size + 2:]
    elif datatype == 0x81:
        data = data[1:]
    elif datatype == 0x82:
        if len(data) <= 3:
            return None
        rand_data_size = struct.unpack('>H', data[1:3])[0]
        if rand_data_size + 3 >= len(data):
            logging.warn('header too short, maybe wrong password or '
                         'encryption method')
            return None
        data = data[rand_data_size + 3:]
    elif datatype == 0x88 or (~datatype & 0xff) == 0x88:
        if len(data) <= 7 + 7:
            return None
        data_size = struct.unpack('>H', data[1:3])[0]
        ogn_data = data
        data = data[:data_size]
        crc = binascii.crc32(data) & 0xffffffff
        if crc != 0xffffffff:
            logging.warn('uncorrect CRC32, maybe wrong password or '
                         'encryption method')
            return None
        start_pos = 3 + ord(data[3])
        data = data[start_pos:-4]
        if data_size < len(ogn_data):
            data += ogn_data[data_size:]
    return data

def parse_header(data):
    addrtype = ord(data[0])
    dest_addr = None
    dest_port = None
    header_length = 0
    connecttype = (addrtype & 0x8) and 1 or 0
    addrtype &= ~0x8
    if addrtype == ADDRTYPE_IPV4:
        if len(data) >= 7:
            dest_addr = socket.inet_ntoa(data[1:5])
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1])
            if len(data) >= 4 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                                     addrlen])[0]
                header_length = 4 + addrlen
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_IPV6:
        if len(data) >= 19:
            dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            dest_port = struct.unpack('>H', data[17:19])[0]
            header_length = 19
        else:
            logging.warn('header is too short')
    else:
        logging.warn('unsupported addrtype %d, maybe wrong password or '
                     'encryption method' % addrtype)
    if dest_addr is None:
        return None
    return connecttype, addrtype, to_bytes(dest_addr), dest_port, header_length


class IPNetwork(object):
    ADDRLENGTH = {socket.AF_INET: 32, socket.AF_INET6: 128, False: 0}

    def __init__(self, addrs):
        self.addrs_str = addrs
        self._network_list_v4 = []
        self._network_list_v6 = []
        if type(addrs) == str:
            addrs = addrs.split(',')
        list(map(self.add_network, addrs))

    def add_network(self, addr):
        if addr is "":
            return
        block = addr.split('/')
        addr_family = is_ip(block[0])
        addr_len = IPNetwork.ADDRLENGTH[addr_family]
        if addr_family is socket.AF_INET:
            ip, = struct.unpack("!I", socket.inet_aton(block[0]))
        elif addr_family is socket.AF_INET6:
            hi, lo = struct.unpack("!QQ", inet_pton(addr_family, block[0]))
            ip = (hi << 64) | lo
        else:
            raise Exception("Not a valid CIDR notation: %s" % addr)
        if len(block) is 1:
            prefix_size = 0
            while (ip & 1) == 0 and ip is not 0:
                ip >>= 1
                prefix_size += 1
            logging.warn("You did't specify CIDR routing prefix size for %s, "
                         "implicit treated as %s/%d" % (addr, addr, addr_len))
        elif block[1].isdigit() and int(block[1]) <= addr_len:
            prefix_size = addr_len - int(block[1])
            ip >>= prefix_size
        else:
            raise Exception("Not a valid CIDR notation: %s" % addr)
        if addr_family is socket.AF_INET:
            self._network_list_v4.append((ip, prefix_size))
        else:
            self._network_list_v6.append((ip, prefix_size))

    def __contains__(self, addr):
        addr_family = is_ip(addr)
        if addr_family is socket.AF_INET:
            ip, = struct.unpack("!I", socket.inet_aton(addr))
            return any(map(lambda n_ps: n_ps[0] == ip >> n_ps[1],
                           self._network_list_v4))
        elif addr_family is socket.AF_INET6:
            hi, lo = struct.unpack("!QQ", inet_pton(addr_family, addr))
            ip = (hi << 64) | lo
            return any(map(lambda n_ps: n_ps[0] == ip >> n_ps[1],
                           self._network_list_v6))
        else:
            return False

    def __cmp__(self, other):
        return cmp(self.addrs_str, other.addrs_str)

    def __eq__(self, other):
        return self.addrs_str == other.addrs_str

    def __ne__(self, other):
        return self.addrs_str != other.addrs_str

class PortRange(object):
    def __init__(self, range_str):
        self.range_str = to_str(range_str)
        self.range = set()
        range_str = to_str(range_str).split(',')
        for item in range_str:
            try:
                int_range = item.split('-')
                if len(int_range) == 1:
                    if item:
                        self.range.add(int(item))
                elif len(int_range) == 2:
                    int_range[0] = int(int_range[0])
                    int_range[1] = int(int_range[1])
                    if int_range[0] < 0:
                        int_range[0] = 0
                    if int_range[1] > 65535:
                        int_range[1] = 65535
                    i = int_range[0]
                    while i <= int_range[1]:
                        self.range.add(i)
                        i += 1
            except Exception as e:
                logging.error(e)

    def __contains__(self, val):
        return val in self.range

    def __cmp__(self, other):
        return cmp(self.range_str, other.range_str)

    def __eq__(self, other):
        return self.range_str == other.range_str

    def __ne__(self, other):
        return self.range_str != other.range_str

class UDPAsyncDNSHandler(object):
    dns_cache = lru_cache.LRUCache(timeout=1800)
    def __init__(self, params):
        self.params = params
        self.remote_addr = None
        self.call_back = None

    def resolve(self, dns_resolver, remote_addr, call_back):
        if remote_addr in UDPAsyncDNSHandler.dns_cache:
            if call_back:
                call_back("", remote_addr, UDPAsyncDNSHandler.dns_cache[remote_addr], self.params)
        else:
            self.call_back = call_back
            self.remote_addr = remote_addr
            dns_resolver.resolve(remote_addr[0], self._handle_dns_resolved)
            UDPAsyncDNSHandler.dns_cache.sweep()

    def _handle_dns_resolved(self, result, error):
        if error:
            logging.error("%s when resolve DNS" % (error,)) #drop
            return self.call_back(error, self.remote_addr, None, self.params)
        if result:
            ip = result[1]
            if ip:
                return self.call_back("", self.remote_addr, ip, self.params)
        logging.warning("can't resolve %s" % (self.remote_addr,))
        return self.call_back("fail to resolve", self.remote_addr, None, self.params)

def test_inet_conv():
    ipv4 = b'8.8.4.4'
    b = inet_pton(socket.AF_INET, ipv4)
    assert inet_ntop(socket.AF_INET, b) == ipv4
    ipv6 = b'2404:6800:4005:805::1011'
    b = inet_pton(socket.AF_INET6, ipv6)
    assert inet_ntop(socket.AF_INET6, b) == ipv6


def test_parse_header():
    assert parse_header(b'\x03\x0ewww.google.com\x00\x50') == \
        (0, b'www.google.com', 80, 18)
    assert parse_header(b'\x01\x08\x08\x08\x08\x00\x35') == \
        (0, b'8.8.8.8', 53, 7)
    assert parse_header((b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00'
                         b'\x00\x10\x11\x00\x50')) == \
        (0, b'2404:6800:4005:805::1011', 80, 19)


def test_pack_header():
    assert pack_addr(b'8.8.8.8') == b'\x01\x08\x08\x08\x08'
    assert pack_addr(b'2404:6800:4005:805::1011') == \
        b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00\x00\x10\x11'
    assert pack_addr(b'www.google.com') == b'\x03\x0ewww.google.com'


def test_ip_network():
    ip_network = IPNetwork('127.0.0.0/24,::ff:1/112,::1,192.168.1.1,192.0.2.0')
    assert '127.0.0.1' in ip_network
    assert '127.0.1.1' not in ip_network
    assert ':ff:ffff' in ip_network
    assert '::ffff:1' not in ip_network
    assert '::1' in ip_network
    assert '::2' not in ip_network
    assert '192.168.1.1' in ip_network
    assert '192.168.1.2' not in ip_network
    assert '192.0.2.1' in ip_network
    assert '192.0.3.1' in ip_network  # 192.0.2.0 is treated as 192.0.2.0/23
    assert 'www.google.com' not in ip_network


if __name__ == '__main__':
    test_inet_conv()
    test_parse_header()
    test_pack_header()
    test_ip_network()
