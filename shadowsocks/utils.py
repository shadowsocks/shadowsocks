#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import logging


def find_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        return config_path
    config_path = os.path.join(os.path.dirname(__file__), '../', 'config.json')
    if os.path.exists(config_path):
        return config_path
    return None

def check_config(config):
    if config.get('server', '') in ['127.0.0.1', 'localhost']:
        logging.warn('Server is set to "%s", maybe it\'s not correct' % config['server'])
        logging.warn('Notice server will listen at %s:%s' % (config['server'], config['server_port']))
    if (config.get('method', '') or '').lower() == 'rc4':
        logging.warn('RC4 is not safe; please use a safer cipher, like AES-256-CFB')
