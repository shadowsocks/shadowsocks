#!/usr/bin/python
# -*- coding: UTF-8 -*-

config = None

def load_config():
	global config
	try:
		import userapiconfig
		reload(userapiconfig)
		config = userapiconfig
		return
	except:
		pass
	try:
		import apiconfig
		reload(apiconfig)
		config = apiconfig
	except:
		pass

def get_config():
	global config
	return config

load_config()

