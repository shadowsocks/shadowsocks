#coding:utf8
"""
Created on Oct 24, 2013

@author: xing
@
"""

import sys
import os
import select
import logging
import socket
import errno
import binascii
import time

try:
    from cStringIO import StringIO
except ImportError, e:
    from StringIO import StringIO

try:
    from select import epoll as pollerFact
    MY_POLLEV_IN = select.EPOLLIN
    MY_POLLEV_PRI = select.EPOLLPRI
    MY_POLLEV_OUT = select.EPOLLOUT
    MY_POLLEV_ERR = select.EPOLLERR
except ImportError, e:
    print >> sys.stderr, e
    pollerFact = select.poll
    MY_POLLEV_IN = select.POLLIN
    MY_POLLEV_PRI = select.POLLPRI
    MY_POLLEV_OUT = select.POLLOUT
    MY_POLLEV_ERR = select.POLLERR


class IOLoopError(Exception):
    pass


class IOLoop(object):
    _instance = None

    @classmethod
    def instance(cls):
        if not cls._instance:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        logging.debug('IOLoop.__init__()')
        self._fd_map = {}
        self._poller = pollerFact()

    def add_handler(self, fd, handler, m_read=False, m_write=False):
        if fd in self._fd_map:
            raise IOLoopError(u'fd(%s) handler is %s' % (fd, self._fd_map[fd]))

        flags = MY_POLLEV_ERR
    	if m_read:
	    flags |= MY_POLLEV_IN | MY_POLLEV_PRI 
    	if m_write:
	    flags |= MY_POLLEV_OUT

        self._poller.register(fd, flags)
        #self._set_nonblocking(fd)
        self._fd_map[fd] = handler
        logging.debug('len(ioloop._fd_map) = %d', len(self._fd_map))

    def remove_handler(self, fd):
        handler = self._fd_map.pop(fd)
        del handler
        self._poller.unregister(fd)
        logging.debug('unregister %d,current len(ioloop._fd_map) = %d', fd, len(self._fd_map))


    def modify_handler(self, fd, handler, m_read=False, m_write=False):
		self.remove_handler(fd)
		self.add_handler(fd, handler, m_read=False, m_write=False)

    def wait_events(self, timeout):
        events_list = self._poller.poll(timeout)
        for fd, events in events_list:
            if fd not in self._fd_map:
                logging.warn('fd %d not in fd_map', fd)
                self._poller.unregister(fd)
                continue
            # logging.info('fd %d, events %d', fd, events)
            handler = self._fd_map[fd]
            if events & MY_POLLEV_ERR:
                # logging.debug("fd[%s] events MY_POLLEV_ERR | MY_POLLEV_HUP", fd)
                handler.handle_error(fd, events)
            elif events & MY_POLLEV_IN or events & MY_POLLEV_PRI:
                # logging.debug("fd[%s] events MY_POLLEV_IN | MY_POLLEV_PRI", fd)
                handler.handle_read()
            elif events & MY_POLLEV_OUT:
                # logging.debug("fd[%s] events MY_POLLEV_OUT", fd)
                handler.handle_write()
            else:
                logging.error("unknow events %d", events)

    #@staticmethod
    #def _set_nonblocking(fd):
    #    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    #    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


class IOStream(object):
    def __init__(self, obj):
        self._wbuf = StringIO()
        self._fd = obj.fileno()
        self._obj = obj

    def read(self, *args, **kwargs):
        # logging.debug("IOStream[%s].read()", self._obj.fileno())
        return self._obj.read(*args, **kwargs)

    def write(self, s):
        """write to buffer, unit IOHandler.handle_write() call real_write() to write it"""
        self._wbuf.write(s)

    def real_write(self):
        if self._wbuf.tell() > 0:
            self._obj.write(self._wbuf.getvalue())
            self._wbuf.truncate(0)

    def close(self):
        return self._obj.close()

    def fileno(self):
        return self._fd


class SocketStream(IOStream):
    def read(self, size):
        return self._obj.recv(size)

    def real_write(self):
        if self._wbuf.tell() > 0:
            data = self._wbuf.getvalue()
            try:
                self._obj.sendall(data)
            except socket.error, _e:
                if _e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                    return 

            self._wbuf.truncate(0)
    
    def close(self):
        if isinstance(self._obj, socket._socketobject):
            self._obj.shutdown(socket.SHUT_RDWR)
        self._obj.close()


class BaseHandler(object):
    monitor_read = True
    monitor_write = True
    def __init__(self):
        raise

    def handle_read(self):
        raise

    def handle_write(self):
        raise

    def handle_error(self, fd, events):
        logging.warn("socket error, fd: %d, events: %d", fd, events)


class IOHandler(BaseHandler):
    monitor_read = True
    monitor_write = True
    def __init__(self, ioloop, iostream):
        self._ioloop = ioloop
        self._ios = iostream
        self._fd = self._ios.fileno()

    def handle_read(self):
        """fd 可读事件出现"""
        # logging.debug("read from fd %s", self._fd)
        try:
            s = self.do_stream_read()
            if len(s) == 0:
                logging.debug('iostream[%s].read() return len(s) == 0, close it', self._fd)
                self._ioloop.remove_handler(self._fd)
                self._ios.close()
            return s
        except socket.error, _e:
            if _e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                logging.debug('socket error, %s', _e)
                return
            else:
                raise

    def do_stream_read(self, size=None):
        # 定义这个方法是为了方便重载
        if size:
            return self._ios.read(size)
        else:
            return self._ios.read()

    def handle_write(self):
        """fd 可写事件出现"""
        self._ios.real_write()

    def handle_error(self, fd, events):
        logging.error("handle_error fd(%s), events: %r", fd, events)
        try:
            self._ios.close()
        except Exception, e:
            loggin.error("handle_error() close() exception: %s", e)


class SimpleCopyFileHandler(IOHandler):
    monitor_read = True
    monitor_write = True
    def __init__(self, outfile, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self._outfile = outfile
        self._outfp = open(self._outfile, 'wb')
        self.last_len = 0

    def handle_read(self):
        s = super(self.__class__, self).handle_read()
        if s:
            self._outfp.write(s)
            curr_len = self._outfp.tell()
            if curr_len - self.last_len >= 1024*1024:
                self._ios.write(str(curr_len/1024/1024)+'M\n')
                self.last_len = curr_len

    def do_stream_read(self, size=4096):
        # 定义这个方法是为了方便重载
        return self._ios.read(size)


class SimpleAcceptHandler(BaseHandler):
    monitor_read = True
    monitor_write = False
    def __init__(self, ioloop, srv_socket):
        self._ioloop = ioloop
        self._srv_socket = srv_socket

    def handle_read(self):
        cli_socket, cli_addr = self._srv_socket.accept()
        logging.debug("accept connect[%s] from %s:%s" % (
            cli_socket.fileno(), cli_addr[0], cli_addr[1]))
        cli_socket.setblocking(0)
        #handler = SimpleCopyFileHandler('/dev/null', self._ioloop, SocketStream(cli_socket))
        handler = SimpleCopyFileHandler('/data/SimpleCopyFileHandler.fd%s.out.txt' % (
            cli_socket.fileno()), self._ioloop, SocketStream(cli_socket))
        self._ioloop.add_handler(cli_socket.fileno(), handler, m_read=True, m_write=False)


def test_pipe():
    ioloop = IOLoop()
    io_stdin = IOStream(sys.stdin)

    import random
    fifo_filename = ''.join([chr(random.randint(0, 25)+ord('A')) for _ in range(10)])
    fifo_filepath = os.path.join('/tmp', fifo_filename)
    if not os.path.exists(fifo_filepath):
        os.mkfifo(fifo_filepath)
    io_pipe = IOStream(open(fifo_filepath, 'rb+'))
    import atexit
    atexit.register(lambda: os.unlink(fifo_filepath))

    ioloop.add_handler(io_pipe.fileno(), IOHandler(ioloop, io_pipe), m_read=True, m_write=True)
    ioloop.add_handler(io_stdin.fileno(), IOHandler(ioloop, io_stdin), m_read=True, m_write=True)
    while True:
        ioloop.wait_events(0.1)


def test_copyfilehandler():
    ioloop = IOLoop()
    import socket
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(0)
    sock.bind(("0.0.0.0", 64433))
    logging.info("listing on %s", str(sock.getsockname()))
    sock.listen(1024)
    ioloop.add_handler(sock.fileno(), SimpleAcceptHandler(ioloop, sock), m_read=True)
    while True:
        ioloop.wait_events(0.1)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    #logging.basicConfig(level=logging.INFO)
    test_copyfilehandler()
