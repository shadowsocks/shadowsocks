#!/usr/bin/python
import time
import sys
import thread
import os
os.chdir(os.path.split(os.path.realpath(__file__))[0])

import server_pool
import db_transfer

#def test():
#	 thread.start_new_thread(DbTransfer.thread_db, ())
#	 Api.web_server()

if __name__ == '__main__':
	#server_pool.ServerPool.get_instance()
	#server_pool.ServerPool.get_instance().new_server(2333, '2333')
	thread.start_new_thread(db_transfer.DbTransfer.thread_db, ())
	while True:
		time.sleep(99999)
