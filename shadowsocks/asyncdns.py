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

import socket
import struct
import logging
import common
import eventloop


_request_count = 1

# rfc1035
# format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QCLASS_IN = 1


def build_address(address):
    address = address.strip('.')
    labels = address.split('.')
    results = []
    for label in labels:
        l = len(label)
        if l > 63:
            return None
        results.append(chr(l))
        results.append(label)
    results.append('\0')
    return ''.join(results)


def build_request(address, qtype):
    global _request_count
    header = struct.pack('!HBBHHHH', _request_count, 1, 0, 1, 0, 0, 0)
    addr = build_address(address)
    qtype_qclass = struct.pack('!HH', qtype, QCLASS_IN)
    _request_count += 1
    if _request_count > 65535:
        _request_count = 1
    return header + addr + qtype_qclass


def parse_ip(addrtype, data, length, offset):
    if addrtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype == QTYPE_CNAME:
        return parse_name(data, offset, length)[1]
    else:
        return data


def parse_name(data, offset, length=512):
    p = offset
    if (ord(data[offset]) & (128 + 64)) == (128 + 64):
        # pointer
        pointer = struct.unpack('!H', data[offset:offset + 2])[0]
        pointer = pointer & 0x3FFF
        if pointer == offset:
            return (0, None)
        return (2, parse_name(data, pointer)[1])
    else:
        labels = []
        l = ord(data[p])
        while l > 0 and p < offset + length:
            if (l & (128 + 64)) == (128 + 64):
                # pointer
                pointer = struct.unpack('!H', data[p:p + 2])[0]
                pointer = pointer & 0x3FFF
                # if pointer == offset:
                #     return (0, None)
                r = parse_name(data, pointer)
                labels.append(r[1])
                p += 2
                # pointer is the end
                return (p - offset + 1, '.'.join(labels))
            else:
                labels.append(data[p + 1:p + 1 + l])
                p += 1 + l
            l = ord(data[p])
        return (p - offset + 1, '.'.join(labels))


# rfc1035
# record
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
def parse_record(data, offset, question=False):
    len, name = parse_name(data, offset)
    # TODO
    assert len
    if not question:
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + len:offset + len + 10]
        )
        ip = parse_ip(record_type, data, record_rdlength, offset + len + 10)
        return len + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)
    else:
        record_type, record_class = struct.unpack(
            '!HH', data[offset + len:offset + len + 4]
        )
        return len + 4, (name, None, record_type, record_class, None, None)


def parse_response(data):
    try:
        if len(data) >= 12:
            header = struct.unpack('!HBBHHHH', data[:12])
            res_id = header[0]
            res_qr = header[1] & 128
            res_tc = header[1] & 2
            res_ra = header[2] & 128
            res_rcode = header[2] & 15
            # TODO check tc and rcode
            assert res_tc == 0
            assert res_rcode == 0
            res_qdcount = header[3]
            res_ancount = header[4]
            res_nscount = header[5]
            res_arcount = header[6]
            qds = []
            ans = []
            nss = []
            ars = []
            offset = 12
            for i in xrange(0, res_qdcount):
                l, r = parse_record(data, offset, True)
                offset += l
                if r:
                    qds.append(r)
            for i in xrange(0, res_ancount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    ans.append(r)
            for i in xrange(0, res_nscount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    nss.append(r)
            for i in xrange(0, res_arcount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    ars.append(r)
            response = DNSResponse()
            if qds:
                response.hostname = qds[0][0]
            for an in ans:
                response.answers.append((an[1], an[2], an[3]))
            return response
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None


def is_ip(address):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, address)
            return True
        except (OSError, IOError):
            pass
    return False


class DNSResponse(object):
    def __init__(self):
        self.hostname = None
        self.answers = []  # each: (addr, type, class)

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


STATUS_IPV4 = 0
STATUS_IPV6 = 1


class DNSResolver(object):

    def __init__(self):
        self._loop = None
        self._hostname_status = {}
        self._hostname_to_cb = {}
        self._cb_to_hostname = {}
        # TODO add caching
        # TODO try ipv4 and ipv6 sequencely
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        self._sock.setblocking(False)
        self._parse_config()

    def _parse_config(self):
        try:
            with open('/etc/resolv.conf', 'rb') as f:
                servers = []
                content = f.readlines()
                for line in content:
                    line = line.strip()
                    if line:
                        if line.startswith('nameserver'):
                            parts = line.split(' ')
                            if len(parts) >= 2:
                                server = parts[1]
                                if is_ip(server):
                                    servers.append(server)
                # TODO support more servers
                if servers:
                    self._dns_server = (servers[0], 53)
                    return
        except IOError:
            pass
        self._dns_server = ('8.8.8.8', 53)

    def add_to_loop(self, loop):
        self._loop = loop
        loop.add(self._sock, eventloop.POLL_IN)
        loop.add_handler(self.handle_events)

    def _handle_data(self, data):
        response = parse_response(data)
        if response and response.hostname:
            hostname = response.hostname
            callbacks = self._hostname_to_cb.get(hostname, [])
            ip = None
            for answer in response.answers:
                if answer[1] in (QTYPE_A, QTYPE_AAAA) and \
                        answer[2] == QCLASS_IN:
                    ip = answer[0]
                    break
            if not ip and self._hostname_status.get(hostname, STATUS_IPV6) \
                    == STATUS_IPV4:
                self._hostname_status[hostname] = STATUS_IPV6
                self._send_req(hostname, QTYPE_AAAA)
                return
            for callback in callbacks:
                if self._cb_to_hostname.__contains__(callback):
                    del self._cb_to_hostname[callback]
                callback((hostname, ip), None)
            if self._hostname_to_cb.__contains__(hostname):
                del self._hostname_to_cb[hostname]

    def handle_events(self, events):
        for sock, fd, event in events:
            if sock != self._sock:
                continue
            if event & eventloop.POLL_ERR:
                logging.error('dns socket err')
                self._loop.remove(self._sock)
                self._sock.close()
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                           socket.SOL_UDP)
                self._sock.setblocking(False)
                self._loop.add(self._sock, eventloop.POLL_IN)
            else:
                data, addr = sock.recvfrom(1024)
                if addr != self._dns_server:
                    logging.warn('received a packet other than our dns')
                    break
                self._handle_data(data)
            break

    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]
            arr = self._hostname_to_cb.get(hostname, None)
            if arr:
                arr.remove(callback)
                if not arr:
                    del self._hostname_to_cb[hostname]

    def _send_req(self, hostname, qtype):
        logging.debug('resolving %s with type %d using server %s', hostname,
                      qtype, self._dns_server)
        req = build_request(hostname, qtype)
        self._sock.sendto(req, self._dns_server)

    def resolve(self, hostname, callback):
        if not hostname:
            callback(None, Exception('empty hostname'))
        elif is_ip(hostname):
            callback(hostname, None)
        else:
            arr = self._hostname_to_cb.get(hostname, None)
            if not arr:
                self._hostname_status[hostname] = STATUS_IPV4
                self._send_req(hostname, QTYPE_A)
                self._hostname_to_cb[hostname] = [callback]
                self._cb_to_hostname[callback] = hostname
            else:
                arr.append(callback)


def test():
    logging.getLogger('').handlers = []
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    def _callback(address, error):
        print error, address

    loop = eventloop.EventLoop()
    resolver = DNSResolver()
    resolver.add_to_loop(loop)

    resolver.resolve('8.8.8.8', _callback)
    resolver.resolve('www.twitter.com', _callback)
    resolver.resolve('www.google.com', _callback)
    resolver.resolve('ipv6.google.com', _callback)
    resolver.resolve('ipv6.l.google.com', _callback)
    resolver.resolve('www.gmail.com', _callback)
    resolver.resolve('r4---sn-3qqp-ioql.googlevideo.com', _callback)
    resolver.resolve('www.baidu.com', _callback)
    resolver.resolve('www.a.shifen.com', _callback)
    resolver.resolve('m.baidu.jp', _callback)
    resolver.resolve('www.youku.com', _callback)
    resolver.resolve('www.twitter.com', _callback)
    resolver.resolve('ipv6.google.com', _callback)

    loop.run()


if __name__ == '__main__':
    test()
