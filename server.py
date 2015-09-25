#!/usr/bin/python
import time
import sys
import threading
import os
os.chdir(os.path.split(os.path.realpath(__file__))[0])

import server_pool
import db_transfer

#def test():
#	 thread.start_new_thread(DbTransfer.thread_db, ())
#	 Api.web_server()

class MainThread(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		db_transfer.DbTransfer.thread_db()

if __name__ == '__main__':
	#server_pool.ServerPool.get_instance()
	#server_pool.ServerPool.get_instance().new_server(2333, '2333')
	thread = MainThread()
	thread.start()
	while True:
		time.sleep(99999)
