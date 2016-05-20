#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import cymysql
import time
import sys
from server_pool import ServerPool
import Config
import traceback
from shadowsocks import common

class DbTransfer(object):

	instance = None

	def __init__(self):
		import threading
		self.last_get_transfer = {}
		self.event = threading.Event()

	@staticmethod
	def get_instance():
		if DbTransfer.instance is None:
			DbTransfer.instance = DbTransfer()
		return DbTransfer.instance

	def push_db_all_user(self):
		#更新用户流量到数据库
		last_transfer = self.last_get_transfer
		curr_transfer = ServerPool.get_instance().get_servers_transfer()
		#上次和本次的增量
		dt_transfer = {}
		for id in curr_transfer.keys():
			if id in last_transfer:
				if last_transfer[id][0] == curr_transfer[id][0] and last_transfer[id][1] == curr_transfer[id][1]:
					continue
				elif curr_transfer[id][0] == 0 and curr_transfer[id][1] == 0:
					continue
				elif last_transfer[id][0] <= curr_transfer[id][0] and \
				last_transfer[id][1] <= curr_transfer[id][1]:
					dt_transfer[id] = [int((curr_transfer[id][0] - last_transfer[id][0]) * Config.MYSQL_TRANSFER_MUL),
										int((curr_transfer[id][1] - last_transfer[id][1]) * Config.MYSQL_TRANSFER_MUL)]
				else:
					dt_transfer[id] = [int(curr_transfer[id][0] * Config.MYSQL_TRANSFER_MUL),
										int(curr_transfer[id][1] * Config.MYSQL_TRANSFER_MUL)]
			else:
				if curr_transfer[id][0] == 0 and curr_transfer[id][1] == 0:
					continue
				dt_transfer[id] = [int(curr_transfer[id][0] * Config.MYSQL_TRANSFER_MUL),
									int(curr_transfer[id][1] * Config.MYSQL_TRANSFER_MUL)]

		query_head = 'UPDATE user'
		query_sub_when = ''
		query_sub_when2 = ''
		query_sub_in = None
		last_time = time.time()
		for id in dt_transfer.keys():
			if dt_transfer[id][0] == 0 and dt_transfer[id][1] == 0:
				continue
			query_sub_when += ' WHEN %s THEN u+%s' % (id, dt_transfer[id][0])
			query_sub_when2 += ' WHEN %s THEN d+%s' % (id, dt_transfer[id][1])
			if query_sub_in is not None:
				query_sub_in += ',%s' % id
			else:
				query_sub_in = '%s' % id
		if query_sub_when == '':
			return
		query_sql = query_head + ' SET u = CASE port' + query_sub_when + \
					' END, d = CASE port' + query_sub_when2 + \
					' END, t = ' + str(int(last_time)) + \
					' WHERE port IN (%s)' % query_sub_in
		#print query_sql
		conn = cymysql.connect(host=Config.MYSQL_HOST, port=Config.MYSQL_PORT, user=Config.MYSQL_USER,
								passwd=Config.MYSQL_PASS, db=Config.MYSQL_DB, charset='utf8')
		cur = conn.cursor()
		cur.execute(query_sql)
		cur.close()
		conn.commit()
		conn.close()
		self.last_get_transfer = curr_transfer

	@staticmethod
	def pull_db_all_user():
		#数据库所有用户信息
		try:
			import switchrule
			reload(switchrule)
			keys = switchrule.getKeys()
		except Exception as e:
			keys = ['port', 'u', 'd', 'transfer_enable', 'passwd', 'enable' ]
		reload(cymysql)
		conn = cymysql.connect(host=Config.MYSQL_HOST, port=Config.MYSQL_PORT, user=Config.MYSQL_USER,
								passwd=Config.MYSQL_PASS, db=Config.MYSQL_DB, charset='utf8')
		cur = conn.cursor()
		cur.execute("SELECT " + ','.join(keys) + " FROM user")
		rows = []
		for r in cur.fetchall():
			d = {}
			for column in range(len(keys)):
				d[keys[column]] = r[column]
			rows.append(d)
		cur.close()
		conn.close()
		return rows

	@staticmethod
	def del_server_out_of_bound_safe(last_rows, rows):
		#停止超流量的服务
		#启动没超流量的服务
		#需要动态载入switchrule，以便实时修改规则
		try:
			import switchrule
			reload(switchrule)
		except Exception as e:
			logging.error('load switchrule.py fail')
		cur_servers = {}
		new_servers = {}
		for row in rows:
			try:
				allow = switchrule.isTurnOn(row) and row['enable'] == 1 and row['u'] + row['d'] < row['transfer_enable']
			except Exception as e:
				allow = False

			port = row['port']
			passwd = common.to_bytes(row['passwd'])

			if port not in cur_servers:
				cur_servers[port] = passwd
			else:
				logging.error('more than one user use the same port [%s]' % (port,))
				continue

			if ServerPool.get_instance().server_is_run(port) > 0:
				if not allow:
					logging.info('db stop server at port [%s]' % (port,))
					ServerPool.get_instance().cb_del_server(port)
				elif (port in ServerPool.get_instance().tcp_servers_pool and ServerPool.get_instance().tcp_servers_pool[port]._config['password'] != passwd) \
					or (port in ServerPool.get_instance().tcp_ipv6_servers_pool and ServerPool.get_instance().tcp_ipv6_servers_pool[port]._config['password'] != passwd):
					#password changed
					logging.info('db stop server at port [%s] reason: password changed' % (port,))
					ServerPool.get_instance().cb_del_server(port)
					new_servers[port] = passwd

			elif allow and ServerPool.get_instance().server_run_status(port) is False:
				#new_servers[port] = passwd
				logging.info('db start server at port [%s] pass [%s]' % (port, passwd))
				ServerPool.get_instance().new_server(port, passwd)

		for row in last_rows:
			if row['port'] in cur_servers:
				pass
			else:
				logging.info('db stop server at port [%s] reason: port not exist' % (row['port']))
				ServerPool.get_instance().cb_del_server(row['port'])

		if len(new_servers) > 0:
			from shadowsocks import eventloop
			DbTransfer.get_instance().event.wait(eventloop.TIMEOUT_PRECISION)
			for port in new_servers.keys():
				passwd = new_servers[port]
				logging.info('db start server at port [%s] pass [%s]' % (port, passwd))
				ServerPool.get_instance().new_server(port, passwd)

	@staticmethod
	def del_servers():
		for port in ServerPool.get_instance().tcp_servers_pool.keys():
			if ServerPool.get_instance().server_is_run(port) > 0:
					ServerPool.get_instance().cb_del_server(port)
		for port in ServerPool.get_instance().tcp_ipv6_servers_pool.keys():
			if ServerPool.get_instance().server_is_run(port) > 0:
					ServerPool.get_instance().cb_del_server(port)

	@staticmethod
	def thread_db():
		import socket
		import time
		timeout = 60
		socket.setdefaulttimeout(timeout)
		last_rows = []
		try:
			while True:
				reload(Config)
				try:
					DbTransfer.get_instance().push_db_all_user()
					rows = DbTransfer.get_instance().pull_db_all_user()
					DbTransfer.del_server_out_of_bound_safe(last_rows, rows)
					last_rows = rows
				except Exception as e:
					trace = traceback.format_exc()
					logging.error(trace)
					#logging.warn('db thread except:%s' % e)
				if DbTransfer.get_instance().event.wait(Config.MYSQL_UPDATE_TIME):
					break
		except KeyboardInterrupt as e:
			pass
		DbTransfer.del_servers()
		ServerPool.get_instance().stop()

	@staticmethod
	def thread_db_stop():
		DbTransfer.get_instance().event.set()

