import logging

#Config
MYSQL_HOST = '127.0.0.1'
MYSQL_PORT = 3306
MYSQL_USER = 'root'
MYSQL_PASS = ''
MYSQL_DB = 'shadowsocks'

SS_BIND_IP = '0.0.0.0'
SS_METHOD = 'rc4-md5'
MANAGE_BIND_IP = '127.0.0.1'
MANAGE_PORT = 3333

NODE = 'node1'
CHECKTIME = 15
SYNCTIME = 600

#LOG CONFIG
LOG_ENABLE = False
LOG_LEVEL = logging.INFO
LOG_FILE = '/var/log/shadowsocks.log'

