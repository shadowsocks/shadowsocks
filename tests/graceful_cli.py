#!/usr/bin/python

import socks
import time


SERVER_IP = '127.0.0.1'
SERVER_PORT = 8001


if __name__ == '__main__':
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, SERVER_IP, 1081)
    s.connect((SERVER_IP, SERVER_PORT))
    s.send(b'test')
    time.sleep(30)
    s.close()
