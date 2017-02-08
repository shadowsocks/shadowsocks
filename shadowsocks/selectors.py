"""Selectors module.

This module allows high-level and efficient I/O multiplexing, built upon the
`select` module primitives.
"""


from abc import ABCMeta, abstractmethod
from collections import namedtuple, Mapping
import errno
import math
import os
import select
import socket
import sys


# generic events, that must be mapped to implementation-specific ones
EVENT_READ = 0x001
EVENT_WRITE = 0x004
EVENT_ERROR = 0x018


def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None


def get_sock_error(sock):
    if not sock:
        return
    error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    return socket.error(error_number, os.strerror(error_number))


def _fileobj_to_fd(fileobj):
    """Return a file descriptor from a file object.

    Parameters:
    fileobj -- file object or file descriptor

    Returns:
    corresponding file descriptor

    Raises:
    ValueError if the object is invalid
    """
    if isinstance(fileobj, int):
        fd = fileobj
    else:
        try:
            fd = int(fileobj.fileno())
        except (AttributeError, TypeError, ValueError):
            raise ValueError("Invalid file object: "
                             "{!r}".format(fileobj))
    if fd < 0:
        raise ValueError("Invalid file descriptor: {}".format(fd))
    return fd


SelectorKey = namedtuple('SelectorKey', ['fileobj', 'fd', 'events', 'data'])
"""Object used to associate a file object to its backing file descriptor,
selected event mask and attached data."""


class _SelectorMapping(Mapping):
    """Mapping of file objects to selector keys."""

    def __init__(self, selector):
        self._selector = selector

    def __len__(self):
        return len(self._selector._fd_to_key)

    def __getitem__(self, fileobj):
        try:
            fd = self._selector._fileobj_lookup(fileobj)
            return self._selector._fd_to_key[fd]
        except KeyError:
            raise KeyError("{!r} is not registered".format(fileobj))

    def __iter__(self):
        return iter(self._selector._fd_to_key)


class BaseSelector(object):
    __metaclass__ = ABCMeta
    """Selector abstract base class.

    A selector supports registering file objects to be monitored for specific
    I/O events.

    A file object is a file descriptor or any object with a `fileno()` method.
    An arbitrary object can be attached to the file object, which can be used
    for example to store context information, a callback, etc.

    A selector can use various implementations (select(), poll(), epoll()...)
    depending on the platform. The default `Selector` class uses the most
    efficient implementation on the current platform.
    """

    @abstractmethod
    def register(self, fileobj, events, data=None):
        """Register a file object.

        Parameters:
        fileobj -- file object or file descriptor
        events  -- events to monitor (bitwise mask of EVENT_READ|EVENT_WRITE)
        data    -- attached data

        Returns:
        SelectorKey instance

        Raises:
        ValueError if events is invalid
        KeyError if fileobj is already registered
        OSError if fileobj is closed or otherwise is unacceptable to
                the underlying system call (if a system call is made)

        Note:
        OSError may or may not be raised
        """
        raise NotImplementedError

    @abstractmethod
    def unregister(self, fileobj):
        """Unregister a file object.

        Parameters:
        fileobj -- file object or file descriptor

        Returns:
        SelectorKey instance

        Raises:
        KeyError if fileobj is not registered

        Note:
        If fileobj is registered but has since been closed this does
        *not* raise OSError (even if the wrapped syscall does)
        """
        raise NotImplementedError

    def modify(self, fileobj, events, data=None):
        """Change a registered file object monitored events or attached data.

        Parameters:
        fileobj -- file object or file descriptor
        events  -- events to monitor (bitwise mask of EVENT_READ|EVENT_WRITE)
        data    -- attached data

        Returns:
        SelectorKey instance

        Raises:
        Anything that unregister() or register() raises
        """
        self.unregister(fileobj)
        return self.register(fileobj, events, data)

    @abstractmethod
    def select(self, timeout=None):
        """Perform the actual selection, until some monitored file objects are
        ready or a timeout expires.

        Parameters:
        timeout -- if timeout > 0, this specifies the maximum wait time, in
                   seconds
                   if timeout <= 0, the select() call won't block, and will
                   report the currently ready file objects
                   if timeout is None, select() will block until a monitored
                   file object becomes ready

        Returns:
        list of (key, events) for ready file objects
        `events` is a bitwise mask of EVENT_READ|EVENT_WRITE
        """
        raise NotImplementedError

    def close(self):
        """Close the selector.

        This must be called to make sure that any underlying resource is freed.
        """
        pass

    def get_key(self, fileobj):
        """Return the key associated to a registered file object.

        Returns:
        SelectorKey for this file object
        """
        mapping = self.get_map()
        try:
            if mapping is None:
                raise KeyError
            return mapping[fileobj]
        except KeyError:
            raise KeyError("{!r} is not registered".format(fileobj))

    @abstractmethod
    def get_map(self):
        """Return a mapping of file objects to selector keys."""
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class _BaseSelectorImpl(BaseSelector):
    """Base selector implementation."""

    def __init__(self):
        # this maps file descriptors to keys
        self._fd_to_key = {}
        # read-only mapping returned by get_map()
        self._map = _SelectorMapping(self)

    def _fileobj_lookup(self, fileobj):
        """Return a file descriptor from a file object.

        This wraps _fileobj_to_fd() to do an exhaustive search in case
        the object is invalid but we still have it in our map.  This
        is used by unregister() so we can unregister an object that
        was previously registered even if it is closed.  It is also
        used by _SelectorMapping.
        """
        try:
            return _fileobj_to_fd(fileobj)
        except ValueError:
            # Do an exhaustive search.
            for key in self._fd_to_key.values():
                if key.fileobj is fileobj:
                    return key.fd
            # Raise ValueError after all.
            raise

    def register(self, fileobj, events, data=None):
        if (not events) or (events & ~(EVENT_READ | EVENT_WRITE |
                            EVENT_ERROR)):
            raise ValueError("Invalid events: {!r}".format(events))

        key = SelectorKey(fileobj, self._fileobj_lookup(fileobj), events, data)

        if key.fd in self._fd_to_key:
            raise KeyError("{!r} (FD {}) is already registered"
                           .format(fileobj, key.fd))

        self._fd_to_key[key.fd] = key
        return key

    def unregister(self, fileobj):
        try:
            key = self._fd_to_key.pop(self._fileobj_lookup(fileobj))
        except KeyError:
            raise KeyError("{!r} is not registered".format(fileobj))
        return key

    def modify(self, fileobj, events, data=None):
        # TODO: Subclasses can probably optimize this even further.
        try:
            key = self._fd_to_key[self._fileobj_lookup(fileobj)]
        except KeyError:
            raise KeyError("{!r} is not registered".format(fileobj))
        if events != key.events:
            self.unregister(fileobj)
            key = self.register(fileobj, events, data)
        elif data != key.data:
            # Use a shortcut to update the data.
            key = key._replace(data=data)
            self._fd_to_key[key.fd] = key
        return key

    def close(self):
        self._fd_to_key.clear()
        self._map = None

    def get_map(self):
        return self._map

    def _key_from_fd(self, fd):
        """Return the key associated to a given file descriptor.

        Parameters:
        fd -- file descriptor

        Returns:
        corresponding key, or None if not found
        """
        try:
            return self._fd_to_key[fd]
        except KeyError:
            return None


class SelectSelector(_BaseSelectorImpl):
    """Select-based selector."""

    def __init__(self):
        super(self.__class__, self).__init__()
        self._readers = set()
        self._writers = set()
        self._errors = set()

    def register(self, fileobj, events, data=None):
        key = super(self.__class__, self).register(fileobj, events, data)
        if events & EVENT_READ:
            self._readers.add(key.fd)
        if events & EVENT_WRITE:
            self._writers.add(key.fd)
        if events & EVENT_ERROR:
            self._errors.add(key.fd)
        return key

    def unregister(self, fileobj):
        key = super(self.__class__, self).unregister(fileobj)
        self._readers.discard(key.fd)
        self._writers.discard(key.fd)
        self._errors.discard(key.fd)
        return key

    if sys.platform == 'win32':
        def _select(self, r, w, x, timeout=None):
            r, w, x = select.select(r, w, x, timeout)
            return r, w, x
    else:
        _select = select.select

    def select(self, timeout=None):
        timeout = None if timeout is None else max(timeout, 0)
        ready = []
        try:
            r, w, x = self._select(self._readers, self._writers, self._errors,
                                   timeout)
        except OSError as e:
            if errno_from_exception(e) == errno.EAGAIN:
                return ready
        r = set(r)
        w = set(w)
        x = set(x)
        for fd in r | w | x:
            events = 0
            if fd in r:
                events |= EVENT_READ
            if fd in w:
                events |= EVENT_WRITE
            if fd in x:
                events |= EVENT_ERROR

            key = self._key_from_fd(fd)
            if key:
                ready.append((key, events & key.events))
        return ready


if hasattr(select, 'poll'):

    class PollSelector(_BaseSelectorImpl):
        """Poll-based selector."""

        def __init__(self):
            super(self.__class__, self).__init__()
            self._poll = select.poll()

        def register(self, fileobj, events, data=None):
            key = super(self.__class__, self).register(fileobj, events, data)
            poll_events = 0
            if events & EVENT_READ:
                poll_events |= select.POLLIN
            if events & EVENT_WRITE:
                poll_events |= select.POLLOUT
            if events & EVENT_ERROR:
                poll_events |= select.POLLERR | select.POLLHUP
            self._poll.register(key.fd, poll_events)
            return key

        def unregister(self, fileobj):
            key = super(self.__class__, self).unregister(fileobj)
            self._poll.unregister(key.fd)
            return key

        def select(self, timeout=None):
            if timeout is None:
                timeout = None
            elif timeout <= 0:
                timeout = 0
            else:
                # poll() has a resolution of 1 millisecond, round away from
                # zero to wait *at least* timeout seconds.
                timeout = math.ceil(timeout * 1e3)
            ready = []
            try:
                fd_event_list = self._poll.poll(timeout)
            except OSError as e:
                if errno_from_exception(e) == errno.EAGAIN:
                    return ready
            for fd, event in fd_event_list:
                events = 0
                if event & select.POLLIN:
                    events |= EVENT_READ
                if event & select.POLLOUT:
                    events |= EVENT_WRITE
                if event & (select.POLLERR | select.POLLHUP):
                    events |= EVENT_ERROR

                key = self._key_from_fd(fd)
                if key:
                    ready.append((key, events & key.events))
            return ready


if hasattr(select, 'epoll'):

    class EpollSelector(_BaseSelectorImpl):
        """Epoll-based selector."""

        def __init__(self):
            super(self.__class__, self).__init__()
            self._epoll = select.epoll()

        def fileno(self):
            return self._epoll.fileno()

        def register(self, fileobj, events, data=None):
            key = super(self.__class__, self).register(fileobj, events, data)
            epoll_events = 0
            if events & EVENT_READ:
                epoll_events |= select.EPOLLIN
            if events & EVENT_WRITE:
                epoll_events |= select.EPOLLOUT
            if events & EVENT_ERROR:
                epoll_events |= select.EPOLLERR | select.EPOLLHUP
            self._epoll.register(key.fd, epoll_events)
            return key

        def unregister(self, fileobj):
            key = super(self.__class__, self).unregister(fileobj)
            try:
                self._epoll.unregister(key.fd)
            except OSError:
                # This can happen if the FD was closed since it
                # was registered.
                pass
            return key

        def select(self, timeout=None):
            if timeout is None:
                timeout = -1
            elif timeout <= 0:
                timeout = 0
            else:
                # epoll_wait() has a resolution of 1 millisecond, round away
                # from zero to wait *at least* timeout seconds.
                timeout = math.ceil(timeout * 1e3) * 1e-3

            # epoll_wait() expects `maxevents` to be greater than zero;
            # we want to make sure that `select()` can be called when no
            # FD is registered.
            max_ev = max(len(self._fd_to_key), 1)

            ready = []
            try:
                fd_event_list = self._epoll.poll(timeout, max_ev)
            except OSError as e:
                if errno_from_exception(e) == errno.EAGAIN:
                    return ready
            for fd, event in fd_event_list:
                events = 0
                if event & select.EPOLLIN:
                    events |= EVENT_READ
                if event & select.EPOLLOUT:
                    events |= EVENT_WRITE
                if event & (select.EPOLLERR | select.EPOLLHUP):
                    events |= EVENT_ERROR

                key = self._key_from_fd(fd)
                if key:
                    ready.append((key, events & key.events))
            return ready

        def close(self):
            try:
                self._epoll.close()
            finally:
                super(self.__class__, self).close()


if hasattr(select, 'devpoll'):

    class DevpollSelector(_BaseSelectorImpl):
        """Solaris /dev/poll selector."""

        def __init__(self):
            super().__init__()
            self._devpoll = select.devpoll()

        def fileno(self):
            return self._devpoll.fileno()

        def register(self, fileobj, events, data=None):
            key = super().register(fileobj, events, data)
            poll_events = 0
            if events & EVENT_READ:
                poll_events |= select.POLLIN
            if events & EVENT_WRITE:
                poll_events |= select.POLLOUT
            if events & EVENT_ERROR:
                poll_events |= select.POLLERR | select.POLLHUP
            self._devpoll.register(key.fd, poll_events)
            return key

        def unregister(self, fileobj):
            key = super().unregister(fileobj)
            self._devpoll.unregister(key.fd)
            return key

        def select(self, timeout=None):
            if timeout is None:
                timeout = None
            elif timeout <= 0:
                timeout = 0
            else:
                # devpoll() has a resolution of 1 millisecond, round away from
                # zero to wait *at least* timeout seconds.
                timeout = math.ceil(timeout * 1e3)
            ready = []
            try:
                fd_event_list = self._devpoll.poll(timeout)
            except InterruptedError:
                return ready
            for fd, event in fd_event_list:
                events = 0
                if event & select.POLLIN:
                    events |= EVENT_READ
                if event & select.POLLOUT:
                    events |= EVENT_WRITE
                if event & (select.POLLERR | select.POLLHUP):
                    events |= EVENT_ERROR

                key = self._key_from_fd(fd)
                if key:
                    ready.append((key, events & key.events))
            return ready

        def close(self):
            self._devpoll.close()
            super().close()


if hasattr(select, 'kqueue'):

    class KqueueSelector(_BaseSelectorImpl):
        """Kqueue-based selector."""

        def __init__(self):
            super(self.__class__, self).__init__()
            self._kqueue = select.kqueue()

        def fileno(self):
            return self._kqueue.fileno()

        def register(self, fileobj, events, data=None):
            key = super(self.__class__, self).register(fileobj, events, data)
            if events & EVENT_READ:
                kev = select.kevent(key.fd, select.KQ_FILTER_READ,
                                    select.KQ_EV_ADD)
                self._kqueue.control([kev], 0, 0)
            if events & EVENT_WRITE:
                kev = select.kevent(key.fd, select.KQ_FILTER_WRITE,
                                    select.KQ_EV_ADD)
                self._kqueue.control([kev], 0, 0)
            return key

        def unregister(self, fileobj):
            key = super(self.__class__, self).unregister(fileobj)
            if key.events & EVENT_READ:
                kev = select.kevent(key.fd, select.KQ_FILTER_READ,
                                    select.KQ_EV_DELETE)
                try:
                    self._kqueue.control([kev], 0, 0)
                except OSError:
                    # This can happen if the FD was closed since it
                    # was registered.
                    pass
            if key.events & EVENT_WRITE:
                kev = select.kevent(key.fd, select.KQ_FILTER_WRITE,
                                    select.KQ_EV_DELETE)
                try:
                    self._kqueue.control([kev], 0, 0)
                except OSError:
                    # See comment above.
                    pass
            return key

        def select(self, timeout=None):
            timeout = None if timeout is None else max(timeout, 0)
            max_ev = len(self._fd_to_key)
            ready = []
            try:
                kev_list = self._kqueue.control(None, max_ev, timeout)
            except OSError as e:
                if errno_from_exception(e) == errno.EAGAIN:
                    return ready
            for kev in kev_list:
                fd = kev.ident
                flag = kev.filter
                events = 0
                if flag == select.KQ_FILTER_READ:
                    events |= EVENT_READ
                if flag == select.KQ_FILTER_WRITE:
                    events |= EVENT_WRITE

                key = self._key_from_fd(fd)
                if key:
                    ready.append((key, events & key.events))
            return ready

        def close(self):
            try:
                self._kqueue.close()
            finally:
                super(self.__class__, self).close()


# Choose the best implementation: roughly, epoll|kqueue > poll > select.
# select() also can't accept a FD > FD_SETSIZE (usually around 1024)
if 'KqueueSelector' in globals():
    DefaultSelector = KqueueSelector
elif 'EpollSelector' in globals():
    DefaultSelector = EpollSelector
elif 'DevpollSelector' in globals():
    DefaultSelector = DevpollSelector
elif 'PollSelector' in globals():
    DefaultSelector = PollSelector
else:
    DefaultSelector = SelectSelector
