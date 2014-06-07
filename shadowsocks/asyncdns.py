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
import common


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


def parse_ip(addrtype, data, length, offset):
    if addrtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype == QTYPE_CNAME:
        return parse_name(data, offset, length)[1]
    else:
        return data


def pack_address(address):
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


def pack_request(address):
    global _request_count
    header = struct.pack('!HBBHHHH', _request_count, 1, 0, 1, 0, 0, 0)
    addr = pack_address(address)
    qtype_qclass = struct.pack('!HH', QTYPE_ANY, QCLASS_IN)
    _request_count += 1
    if _request_count > 65535:
        _request_count = 1
    return header + addr + qtype_qclass


def parse_name(data, offset, length=512):
    p = offset
    if (ord(data[offset]) & (128 + 64)) == (128 + 64):
        # pointer
        pointer = struct.unpack('!H', data[offset:offset + 2])[0]
        pointer = pointer & 0x3FFF
        if pointer == offset:
            return (0, None)
        return (2, parse_name(data, pointer))
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


def unpack_response(data):
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

            return ans

    except Exception as e:
        import traceback
        traceback.print_exc()
        return None


def resolve(address, callback):
    # TODO async
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.SOL_UDP)
    req = pack_request(address)
    if req is None:
        # TODO
        return
    sock.sendto(req, ('8.8.8.8', 53))
    res, addr = sock.recvfrom(1024)
    parsed_res = unpack_response(res)
    callback(parsed_res)


def test():
    def _callback(address):
        print address

    resolve('www.twitter.com', _callback)
    resolve('www.google.com', _callback)
    resolve('ipv6.google.com', _callback)
    resolve('ipv6.l.google.com', _callback)
    resolve('www.baidu.com', _callback)
    resolve('www.a.shifen.com', _callback)
    resolve('m.baidu.jp', _callback)


if __name__ == '__main__':
    test()
