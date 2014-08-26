#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os
import signal
import select
import time
from subprocess import Popen, PIPE

sys.path.insert(0, './')

if 'salsa20' in sys.argv[-1]:
    from shadowsocks import encrypt_salsa20
    encrypt_salsa20.test()
    print 'encryption test passed'

p1 = Popen(['python', 'shadowsocks/server.py', '-c', sys.argv[-1]], stdin=PIPE,
           stdout=PIPE, stderr=PIPE, close_fds=True)
p2 = Popen(['python', 'shadowsocks/local.py', '-c', sys.argv[-1]], stdin=PIPE,
           stdout=PIPE, stderr=PIPE, close_fds=True)
p3 = None

try:
    local_ready = False
    server_ready = False
    fdset = [p1.stdout, p2.stdout, p1.stderr, p2.stderr]
    while True:
        r, w, e = select.select(fdset, [], fdset)
        if e:
            break

        for fd in r:
            line = fd.readline()
            sys.stdout.write(line)
            if line.find('starting local') >= 0:
                local_ready = True
            if line.find('starting server') >= 0:
                server_ready = True

        if local_ready and server_ready and p3 is None:
            time.sleep(1)

            break

    p3 = Popen(['curl', 'http://www.example.com/', '-v', '-L',
               '--socks5-hostname', '127.0.0.1:1081'], close_fds=True)
    if p3 is not None:
        r = p3.wait()
        if r != 0:
            sys.exit(r)
    else:
        sys.exit(1)

    p4 = Popen(['socksify', 'dig', '@8.8.8.8', 'www.google.com'],
               close_fds=True)
    if p4 is not None:
        r = p4.wait()
        if r != 0:
            sys.exit(r)
    else:
        sys.exit(1)
    print 'test passed'

finally:
    for p in [p1, p2]:
        try:
            os.kill(p.pid, signal.SIGTERM)
        except OSError:
            pass
