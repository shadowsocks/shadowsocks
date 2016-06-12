#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import cymysql
import time
import sys
from server_pool import ServerPool
import traceback
from shadowsocks import common
from configloader import load_config, get_config

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
					dt_transfer[id] = [int((curr_transfer[id][0] - last_transfer[id][0]) * get_config().TRANSFER_MUL),
										int((curr_transfer[id][1] - last_transfer[id][1]) * get_config().TRANSFER_MUL)]
				else:
					dt_transfer[id] = [int(curr_transfer[id][0] * get_config().TRANSFER_MUL),
										int(curr_transfer[id][1] * get_config().TRANSFER_MUL)]
			else:
				if curr_transfer[id][0] == 0 and curr_transfer[id][1] == 0:
					continue
				dt_transfer[id] = [int(curr_transfer[id][0] * get_config().TRANSFER_MUL),
									int(curr_transfer[id][1] * get_config().TRANSFER_MUL)]

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
		conn = cymysql.connect(host=get_config().MYSQL_HOST, port=get_config().MYSQL_PORT, user=get_config().MYSQL_USER,
								passwd=get_config().MYSQL_PASS, db=get_config().MYSQL_DB, charset='utf8')
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
		conn = cymysql.connect(host=get_config().MYSQL_HOST, port=get_config().MYSQL_PORT, user=get_config().MYSQL_USER,
								passwd=get_config().MYSQL_PASS, db=get_config().MYSQL_DB, charset='utf8')
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
			cfg = {'password': passwd}
			for name in ['method', 'obfs', 'protocol']:
				if name in row:
					cfg[name] = row[name]

			for name in cfg.keys():
				if hasattr(cfg[name], 'encode'):
					cfg[name] = cfg[name].encode('utf-8')

			if port not in cur_servers:
				cur_servers[port] = passwd
			else:
				logging.error('more than one user use the same port [%s]' % (port,))
				continue

			if ServerPool.get_instance().server_is_run(port) > 0:
				if not allow:
					logging.info('db stop server at port [%s]' % (port,))
					ServerPool.get_instance().cb_del_server(port)
				else:
					cfgchange = False
					if port in ServerPool.get_instance().tcp_servers_pool:
						relay = ServerPool.get_instance().tcp_servers_pool[port]
						for name in ['password', 'method', 'obfs', 'protocol']:
							if name in cfg and cfg[name] != relay._config[name]:
								cfgchange = True
								break;
					if not cfgchange and port in ServerPool.get_instance().tcp_ipv6_servers_pool:
						relay = ServerPool.get_instance().tcp_ipv6_servers_pool[port]
						for name in ['password', 'method', 'obfs', 'protocol']:
							if name in cfg and cfg[name] != relay._config[name]:
								cfgchange = True
								break;
					#config changed
					if cfgchange:
						logging.info('db stop server at port [%s] reason: config changed: %s' % (port, cfg))
						ServerPool.get_instance().cb_del_server(port)
						new_servers[port] = (passwd, cfg)

			elif allow and ServerPool.get_instance().server_run_status(port) is False:
				#new_servers[port] = passwd
				logging.info('db start server at port [%s] pass [%s]' % (port, passwd))
				ServerPool.get_instance().new_server(port, cfg)

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
				passwd, cfg = new_servers[port]
				logging.info('db start server at port [%s] pass [%s]' % (port, passwd))
				ServerPool.get_instance().new_server(port, cfg)

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
				load_config()
				try:
					DbTransfer.get_instance().push_db_all_user()
					rows = DbTransfer.get_instance().pull_db_all_user()
					DbTransfer.del_server_out_of_bound_safe(last_rows, rows)
					last_rows = rows
				except Exception as e:
					trace = traceback.format_exc()
					logging.error(trace)
					#logging.warn('db thread except:%s' % e)
				if DbTransfer.get_instance().event.wait(get_config().MYSQL_UPDATE_TIME) or not ServerPool.get_instance().thread.is_alive():
					break
		except KeyboardInterrupt as e:
			pass
		DbTransfer.del_servers()
		ServerPool.get_instance().stop()

	@staticmethod
	def thread_db_stop():
		DbTransfer.get_instance().event.set()

