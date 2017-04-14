#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 breakwall
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

import time
import sys
import threading
import os

if __name__ == '__main__':
	import inspect
	os.chdir(os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe()))))

import server_pool
import db_transfer
from shadowsocks import shell
from configloader import load_config, get_config

class MainThread(threading.Thread):
	def __init__(self, obj):
		super(MainThread, self).__init__()
		self.daemon = True
		self.obj = obj

	def run(self):
		self.obj.thread_db(self.obj)

	def stop(self):
		self.obj.thread_db_stop()

def main():
	shell.check_python()
	if False:
		db_transfer.DbTransfer.thread_db()
	else:
		if get_config().API_INTERFACE == 'mudbjson':
			thread = MainThread(db_transfer.MuJsonTransfer)
		elif get_config().API_INTERFACE == 'sspanelv2':
			thread = MainThread(db_transfer.DbTransfer)
		else:
			thread = MainThread(db_transfer.Dbv3Transfer)
		thread.start()
		try:
			while thread.is_alive():
				thread.join(10.0)
		except (KeyboardInterrupt, IOError, OSError) as e:
			import traceback
			traceback.print_exc()
			thread.stop()

if __name__ == '__main__':
	main()

