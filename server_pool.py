#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import logging
import time
from shadowsocks import shell
from shadowsocks import eventloop
from shadowsocks import tcprelay
from shadowsocks import udprelay
from shadowsocks import asyncdns
import thread
import threading
import sys
import asyncmgr
import Config
from socket import *

class ServerPool(object):

	instance = None

	def __init__(self):
		shell.check_python()
		self.config = shell.get_config(False)
		shell.print_shadowsocks()
		self.dns_resolver = asyncdns.DNSResolver()
		self.mgr = asyncmgr.ServerMgr()

		self.tcp_servers_pool = {}
		self.tcp_ipv6_servers_pool = {}
		self.udp_servers_pool = {}
		self.udp_ipv6_servers_pool = {}

		self.loop = eventloop.EventLoop()
		thread.start_new_thread(ServerPool._loop, (self.loop, self.dns_resolver, self.mgr))

	@staticmethod
	def get_instance():
		if ServerPool.instance is None:
			ServerPool.instance = ServerPool()
		return ServerPool.instance

	@staticmethod
	def _loop(loop, dns_resolver, mgr):
		try:
			mgr.add_to_loop(loop)
			dns_resolver.add_to_loop(loop)
			loop.run()
		except (KeyboardInterrupt, IOError, OSError) as e:
			logging.error(e)
			import traceback
			traceback.print_exc()
			os.exit(0)

	def server_is_run(self, port):
		port = int(port)
		ret = 0
		if port in self.tcp_servers_pool:
			ret = 1
		if port in self.tcp_ipv6_servers_pool:
			ret |= 2
		return ret

	def server_run_status(self, port):
		if 'server' in self.config:
			if port not in self.tcp_servers_pool:
				return False
		if 'server_ipv6' in self.config:
			if port not in self.tcp_ipv6_servers_pool:
				return False
		return True

	def new_server(self, port, password):
		ret = True
		port = int(port)
		ipv6_ok = False

		if 'server_ipv6' in self.config:
			if port in self.tcp_ipv6_servers_pool:
				logging.info("server already at %s:%d" % (self.config['server_ipv6'], port))
				return 'this port server is already running'
			else:
				a_config = self.config.copy()
				if len(a_config['server_ipv6']) > 2 and a_config['server_ipv6'][0] == "[" and a_config['server_ipv6'][-1] == "]":
					a_config['server_ipv6'] = a_config['server_ipv6'][1:-1]
				a_config['server'] = a_config['server_ipv6']
				a_config['server_port'] = port
				a_config['password'] = password
				try:
					logging.info("starting server at [%s]:%d" % (a_config['server'], port))

					tcp_server = tcprelay.TCPRelay(a_config, self.dns_resolver, False)
					tcp_server.add_to_loop(self.loop)
					self.tcp_ipv6_servers_pool.update({port: tcp_server})

					udp_server = udprelay.UDPRelay(a_config, self.dns_resolver, False)
					udp_server.add_to_loop(self.loop)
					self.udp_ipv6_servers_pool.update({port: udp_server})

					if a_config['server_ipv6'] == "::":
						ipv6_ok = True
				except Exception, e:
					logging.warn("IPV6 %s " % (e,))

		if 'server' in self.config:
			if port in self.tcp_servers_pool:
				logging.info("server already at %s:%d" % (self.config['server'], port))
				return 'this port server is already running'
			else:
				a_config = self.config.copy()
				a_config['server_port'] = port
				a_config['password'] = password
				try:
					logging.info("starting server at %s:%d" % (a_config['server'], port))

					tcp_server = tcprelay.TCPRelay(a_config, self.dns_resolver, False)
					tcp_server.add_to_loop(self.loop)
					self.tcp_servers_pool.update({port: tcp_server})

					udp_server = udprelay.UDPRelay(a_config, self.dns_resolver, False)
					udp_server.add_to_loop(self.loop)
					self.udp_servers_pool.update({port: udp_server})

				except Exception, e:
					if not ipv6_ok:
						logging.warn("IPV4 %s " % (e,))

		return True

	def del_server(self, port):
		port = int(port)
		logging.info("del server at %d" % port)
		try:
			udpsock = socket(AF_INET, SOCK_DGRAM)
			udpsock.sendto('%s:%s:0:0' % (Config.MANAGE_PASS, port), (Config.MANAGE_BIND_IP, Config.MANAGE_PORT))
			udpsock.close()
		except Exception, e:
			logging.warn(e)
		return True

	def cb_del_server(self, port):
		port = int(port)

		if port not in self.tcp_servers_pool:
			logging.info("stopped server at %s:%d already stop" % (self.config['server'], port))
		else:
			logging.info("stopped server at %s:%d" % (self.config['server'], port))
			try:
				self.tcp_servers_pool[port].close(True)
				del self.tcp_servers_pool[port]
			except Exception, e:
				logging.warn(e)
			try:
				self.udp_servers_pool[port].close(True)
				del self.udp_servers_pool[port]
			except Exception, e:
				logging.warn(e)

		if 'server_ipv6' in self.config:
			if port not in self.tcp_ipv6_servers_pool:
				logging.info("stopped server at %s:%d already stop" % (self.config['server_ipv6'], port))
			else:
				logging.info("stopped server at %s:%d" % (self.config['server_ipv6'], port))
				try:
					self.tcp_ipv6_servers_pool[port].close(True)
					del self.tcp_ipv6_servers_pool[port]
				except Exception, e:
					logging.warn(e)
				try:
					self.udp_ipv6_servers_pool[port].close(True)
					del self.udp_ipv6_servers_pool[port]
				except Exception, e:
					logging.warn(e)

			return True

	def get_server_transfer(self, port):
		port = int(port)
		ret = [0, 0]
		if port in self.tcp_servers_pool:
			ret[0] = self.tcp_servers_pool[port].server_transfer_ul
			ret[1] = self.tcp_servers_pool[port].server_transfer_dl
		if port in self.tcp_ipv6_servers_pool:
			ret[0] += self.tcp_ipv6_servers_pool[port].server_transfer_ul
			ret[1] += self.tcp_ipv6_servers_pool[port].server_transfer_dl
		return ret

	def get_servers_transfer(self):
		servers = self.tcp_servers_pool.copy()
		servers.update(self.tcp_ipv6_servers_pool)
		ret = {}
		for port in servers.keys():
			ret[port] = self.get_server_transfer(port)
		return ret

