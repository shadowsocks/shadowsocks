import time
import sys
import thread
import server_pool
import db_transfer

#def test():
#    thread.start_new_thread(DbTransfer.thread_db, ())
#    Api.web_server()

if __name__ == '__main__':
    #server_pool.ServerPool.get_instance()
    thread.start_new_thread(db_transfer.DbTransfer.thread_db, ())
    while True:
        time.sleep(99999)
