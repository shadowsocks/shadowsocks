#!/usr/bin/python

import json

with open('server-multi-passwd-performance.json', 'wb') as f:
    r = {
        'server': '127.0.0.1',
        'local_port': 1081,
        'timeout': 60,
        'method': 'aes-256-cfb'
    }
    ports = {}
    for i in range(7000, 9000):
        ports[str(i)] = 'aes_password'

    r['port_password'] = ports
    print(r)
    f.write(json.dumps(r, indent=4).encode('utf-8'))
