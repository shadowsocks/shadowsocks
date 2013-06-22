shadowsocks
===========

|Build Status| Current version: 1.3.0

shadowsocks is a lightweight tunnel proxy which can help you get through
firewalls

Other ports and clients can be found
`here <https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients>`__.

Usage
-----

First, make sure you have Python 2.6 or 2.7.

::

    $ python --version
    Python 2.6.8

Install Shadowsocks.

::

    pip install shadowsocks

Create a file named ``config.json``, with the following content.

::

    {
        "server":"my_server_ip",
        "server_port":8388,
        "local_port":1080,
        "password":"barfoo!",
        "timeout":600,
        "method":null
    }

Explaination of the fields:

::

    server          your server IP (IPv4/IPv6), notice that your server will listen to this IP
    server_port     server port
    local_port      local port
    password        a password used to encrypt transfer
    timeout         in seconds
    method          encryption method, "bf-cfb", "aes-256-cfb", "des-cfb", "rc4", etc. Default is table

``cd`` into the directory of ``config.json``. Run ``ssserver`` on your
server. To run it in the background, run ``nohup ssserver > log &``.

On your client machine, run ``sslocal``.

Change the proxy setting in your browser into

::

    protocol: socks5
    hostname: 127.0.0.1
    port:     your local_port

Command line args
-----------------

You can use args to override settings from ``config.json``.

::

    sslocal -s server_name -p server_port -l local_port -k password -m bf-cfb
    ssserver -p server_port -k password -m bf-cfb
    ssserver -c /etc/shadowsocks/config.json

Encryption
----------

If you want to use non-default encryption method like "bf-cfb", please
install `M2Crypto <http://chandlerproject.org/Projects/MeTooCrypto>`__.

Ubuntu:

::

    sudo apt-get install python-m2crypto

Others:

::

    pip install M2Crypto

Performance
-----------

You may want to install gevent for better performance.

::

    $ sudo apt-get install python-gevent

Or:

::

    $ sudo apt-get install libevent-dev python-pip
    $ sudo pip install gevent

License
-------

MIT

Bugs and Issues
---------------

Please visit `issue
tracker <https://github.com/clowwindy/shadowsocks/issues?state=open>`__

.. |Build Status| image:: https://travis-ci.org/clowwindy/shadowsocks.png
   :target: https://travis-ci.org/clowwindy/shadowsocks
