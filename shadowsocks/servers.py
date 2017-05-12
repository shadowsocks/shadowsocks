#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import thread
import time
import manager
import config
from dbtransfer import DbTransfer
if config.LOG_ENABLE:
    logging.basicConfig(
        filename=config.LOG_FILE,
        level=config.LOG_LEVEL,
        datefmt='%Y-%m-%d %H:%M:%S',
        format='%(asctime)s %(levelname)s %(filename)s[%(lineno)d] %(message)s'
    )
def main():
    configer = {
        'server': '%s' % config.SS_BIND_IP,
        'local_port': 1081,
        'port_password': {
        },
        'method': '%s' % config.SS_METHOD,
        'manager_address': '%s:%s' % (config.MANAGE_BIND_IP, config.MANAGE_PORT),
        'timeout': 60, # some protocol keepalive packet 3 min Eg bt
        'fast_open': False,
        'verbose': 1
    }
    start_shadowsock = thread.start_new_thread(manager.run, (configer,))
    time.sleep(1)
    sync_users = thread.start_new_thread(DbTransfer.thread_db, ())
    time.sleep(1)
    sysc_transfer = thread.start_new_thread(DbTransfer.thread_push, ())
    while True:
        time.sleep(3600)
if __name__ == '__main__':
    main()
