#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
from server_pool import ServerPool
import traceback
from shadowsocks import common, shell
from configloader import load_config, get_config

db_instance = None

class DbTransfer(object):
	def __init__(self):
		import threading
		self.last_get_transfer = {}
		self.event = threading.Event()

	def update_all_user(self, dt_transfer):
		import cymysql
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

		self.update_all_user(dt_transfer)
		self.last_get_transfer = curr_transfer

	def pull_db_all_user(self):
		import cymysql
		#数据库所有用户信息
		try:
			import switchrule
			reload(switchrule)
			keys = switchrule.getKeys()
		except Exception as e:
			keys = ['port', 'u', 'd', 'transfer_enable', 'passwd', 'enable' ]
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

	def del_server_out_of_bound_safe(self, last_rows, rows):
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

			read_config_keys = ['method', 'obfs', 'protocol', 'forbidden_ip', 'forbidden_port']
			for name in read_config_keys:
				if name in row and row[name]:
					cfg[name] = row[name]

			merge_config_keys = ['password'] + read_config_keys
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
						for name in merge_config_keys:
							if name in cfg and cfg[name] != relay._config[name]:
								cfgchange = True
								break;
					if not cfgchange and port in ServerPool.get_instance().tcp_ipv6_servers_pool:
						relay = ServerPool.get_instance().tcp_ipv6_servers_pool[port]
						for name in merge_config_keys:
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
			self.event.wait(eventloop.TIMEOUT_PRECISION)
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
	def thread_db(obj):
		import socket
		import time
		global db_instance
		timeout = 60
		socket.setdefaulttimeout(timeout)
		last_rows = []
		db_instance = obj()
		try:
			while True:
				load_config()
				try:
					db_instance.push_db_all_user()
					rows = db_instance.pull_db_all_user()
					db_instance.del_server_out_of_bound_safe(last_rows, rows)
					last_rows = rows
				except Exception as e:
					trace = traceback.format_exc()
					logging.error(trace)
					#logging.warn('db thread except:%s' % e)
				if db_instance.event.wait(get_config().MYSQL_UPDATE_TIME) or not ServerPool.get_instance().thread.is_alive():
					break
		except KeyboardInterrupt as e:
			pass
		db_instance.del_servers()
		ServerPool.get_instance().stop()
		db_instance = None

	@staticmethod
	def thread_db_stop():
		global db_instance
		db_instance.event.set()

class MuJsonTransfer(DbTransfer):
	def __init__(self):
		super(MuJsonTransfer, self).__init__()

	def update_all_user(self, dt_transfer):
		import json
		rows = None

		config_path = "mudb.json"
		with open(config_path, 'r+') as f:
			rows = shell.parse_json_in_str(f.read().decode('utf8'))
			for row in rows:
				if "port" in row:
					port = row["port"]
					if port in dt_transfer:
						row["u"] += dt_transfer[port][0]
						row["d"] += dt_transfer[port][1]

		if rows:
			output = json.dumps(rows, sort_keys=True, indent=4, separators=(',', ': '))
			with open(config_path, 'w') as f:
				f.write(output)

	def pull_db_all_user(self):
		rows = None

		config_path = "mudb.json"
		with open(config_path, 'r+') as f:
			rows = shell.parse_json_in_str(f.read().decode('utf8'))
			for row in rows:
				try:
					if 'forbidden_ip' in row:
						row['forbidden_ip'] = common.IPNetwork(row['forbidden_ip'])
				except Exception as e:
					logging.error(e)
				try:
					if 'forbidden_port' in row:
						row['forbidden_port'] = common.PortRange(row['forbidden_port'])
				except Exception as e:
					logging.error(e)

		return rows

