#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import cymysql
import time
import socket
import config
import json


class DbTransfer(object):
    instance = None

    def __init__(self):
        self.last_get_transfer = {}

    @staticmethod
    def get_instance():
        if DbTransfer.instance is None:
            DbTransfer.instance = DbTransfer()
        return DbTransfer.instance
    @staticmethod
    def get_mysql_conn():
        conn = cymysql.connect(host=config.MYSQL_HOST, port=config.MYSQL_PORT, user=config.MYSQL_USER,
                        passwd=config.MYSQL_PASS, db=config.MYSQL_DB, charset='utf8')
        return conn;
    @staticmethod
    def send_command(cmd):
        data = ''
        try:
            cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cli.settimeout(1)
            cli.sendto(cmd, ('%s' % (config.MANAGE_BIND_IP), config.MANAGE_PORT))
            data, addr = cli.recvfrom(1500)
            cli.close()
            # TODO: bad way solve timed out
            # time.sleep(0.05)
        except:
            logging.warn('send_command response')
        return data

    @staticmethod
    def get_servers_transfer():
        dt_transfer = {}
        cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cli.settimeout(2)
        cli.sendto('transfer: {}', ('%s' % (config.MANAGE_BIND_IP), config.MANAGE_PORT))
        while True:
            data, addr = cli.recvfrom(1500)
            if data == 'e':
                break
            data = json.loads(data)
            dt_transfer.update(data)
        cli.close()
        return dt_transfer

    def push_db_all_user(self):
        logging.info("push_db_all_user")
        dt_transfer = self.get_servers_transfer()
        last_time = time.time()
        conn = DbTransfer.get_mysql_conn()
        cur = conn.cursor()
        for port in dt_transfer.keys():
            update_sql='UPDATE user '+\
                       'set b_usage=b_usage+'+str(dt_transfer[port])+\
                       ' where ss_port = '+str(port)
            insert_sql='insert bandwidth_log value(null,"node1",'+str(port)+','+str(dt_transfer[port])+','+str(int(last_time))+')'
            logging.info(update_sql)
            cur.execute(update_sql)
            cur.execute(insert_sql)
        cur.close()
        conn.commit()
        conn.close()

    @staticmethod
    def pull_db_all_user():
        conn = DbTransfer.get_mysql_conn()
        cur = conn.cursor()
        cur.execute("SELECT ss_port, ss_pwd, b_usage, b_max, u_status FROM user")
        rows = []
        for r in cur.fetchall():
            rows.append(list(r))
        cur.close()
        conn.close()
        return rows

    @staticmethod
    def del_server_out_of_bound_safe(rows):
        for row in rows:
            server = json.loads(DbTransfer.get_instance().send_command('stat: {"server_port":%s}' % row[0]))
            if server['stat'] != 'ko':
                if row[4] < 0:
                    # stop disable or switch off user
                    logging.info('db stop server at port [%s] reason: disable' % (row[0]))
                    DbTransfer.send_command('remove: {"server_port":%s}' % row[0])
                elif row[2] >= row[3]:
                    # stop out bandwidth user
                    logging.info('db stop server at port [%s] reason: out bandwidth' % (row[0]))
                    DbTransfer.send_command('remove: {"server_port":%s}' % row[0])
                if server['password'] != row[1]:
                    # password changed
                    logging.info('db stop server at port [%s] reason: password changed' % (row[0]))
                    DbTransfer.send_command('remove: {"server_port":%s}' % row[0])
            else:
                if row[4] > 0 and row[2] < row[3]:
                    logging.info('db start server at port [%s] pass [%s]' % (row[0], row[1]))
                    DbTransfer.send_command('add: {"server_port": %s, "password":"%s"}' % (row[0], row[1]))

    @staticmethod
    def thread_db():
        import socket
        import time
        timeout = 30
        socket.setdefaulttimeout(timeout)
        while True:
            logging.info('db thread_db')
            try:
                rows = DbTransfer.get_instance().pull_db_all_user()
                DbTransfer.del_server_out_of_bound_safe(rows)
            except Exception as e:
                import traceback
                traceback.print_exc()
                logging.warn('db thread except:%s' % e)
            finally:
                time.sleep(config.CHECKTIME)

    @staticmethod
    def thread_push():
        import socket
        import time
        timeout = 30
        socket.setdefaulttimeout(timeout)
        while True:
            logging.info('db thread_push')
            try:
                DbTransfer.get_instance().push_db_all_user()
            except Exception as e:
                import traceback
                traceback.print_exc()
                logging.warn('db thread except:%s' % e)
            finally:
                time.sleep(config.SYNCTIME)
