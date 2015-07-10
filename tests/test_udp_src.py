#!/usr/bin/python

import socket
import socks

if __name__ == '__main__':
    sock_out = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM,
                                socket.SOL_UDP)
    sock_out.set_proxy(socks.SOCKS5, '127.0.0.1', 1081)
    sock_out.bind(('127.0.0.1', 9000))

    sock_in1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.SOL_UDP)
    sock_in2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.SOL_UDP)

    sock_in1.bind(('127.0.0.1', 9001))
    sock_in2.bind(('127.0.0.1', 9002))

    sock_out.sendto('data', ('127.0.0.1', 9001))
    result1 = sock_in1.recvfrom(8)

    sock_out.sendto('data', ('127.0.0.1', 9002))
    result2 = sock_in2.recvfrom(8)

    sock_out.close()
    sock_in1.close()
    sock_in2.close()

    # make sure they're from the same source port
    assert result1 == result2
