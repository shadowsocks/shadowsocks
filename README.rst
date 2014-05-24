shadowsocks
===========

shadowsocks is a lightweight tunnel proxy which can help you get through
firewalls.

Both TCP CONNECT and UDP ASSOCIATE are implemented.

`中文说明 <https://github.com/clowwindy/shadowsocks/wiki/Shadowsocks-%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E>`__

Install
-------

First, make sure you have Python 2.6 or 2.7.

::

    $ python --version
    Python 2.6.8

Install Shadowsocks.

Debian / Ubuntu:
^^^^^^^^^^^^^^^^

::

    apt-get install python-pip python-gevent python-m2crypto
    pip install shadowsocks

CentOS:
^^^^^^^

::

    yum install m2crypto python-setuptools
    easy_install pip
    pip install shadowsocks

OS X:
^^^^^

::

    git clone https://github.com/clowwindy/M2Crypto.git
    cd M2Crypto
    pip install .
    pip install shadowsocks

Windows:
^^^^^^^^

Choose a `GUI
client <https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients>`__

Usage
-----

Create a config file ``/etc/shadowsocks.json`` (or put it in other
path). Example:

::

    {
        "server":"my_server_ip",
        "server_port":8388,
        "local_address": "127.0.0.1",
        "local_port":1080,
        "password":"mypassword",
        "timeout":300,
        "method":"aes-256-cfb",
        "fast_open": false,
        "workers": 1
    }

Explanation of the fields:

+------------------+-----------------------------------------------------------------------------------------------------+
| Name             | Explanation                                                                                         |
+==================+=====================================================================================================+
| server           | the address your server listens                                                                     |
+------------------+-----------------------------------------------------------------------------------------------------+
| server\_port     | server port                                                                                         |
+------------------+-----------------------------------------------------------------------------------------------------+
| local\_address   | the address your local listens                                                                      |
+------------------+-----------------------------------------------------------------------------------------------------+
| local\_port      | local port                                                                                          |
+------------------+-----------------------------------------------------------------------------------------------------+
| password         | password used for encryption                                                                        |
+------------------+-----------------------------------------------------------------------------------------------------+
| timeout          | in seconds                                                                                          |
+------------------+-----------------------------------------------------------------------------------------------------+
| method           | encryption method, "aes-256-cfb" is recommended                                                     |
+------------------+-----------------------------------------------------------------------------------------------------+
| fast\_open       | use `TCP\_FASTOPEN <https://github.com/clowwindy/shadowsocks/wiki/TCP-Fast-Open>`__, true / false   |
+------------------+-----------------------------------------------------------------------------------------------------+
| workers          | number of workers, available on Unix/Linux                                                          |
+------------------+-----------------------------------------------------------------------------------------------------+

Run ``ssserver -c /etc/shadowsocks.json`` on your server. To run it in
the background, `use
supervisor <https://github.com/clowwindy/shadowsocks/wiki/Configure-Shadowsocks-with-Supervisor>`__.

On your client machine, run ``sslocal -c /etc/shadowsocks.json``.

Change the proxy settings in your browser to

::

    protocol: socks5
    hostname: 127.0.0.1
    port:     your local_port

**Notice: If you want to use encryption methods other than "table",
please install M2Crypto (See Encryption Section).**

It's recommended to use shadowsocks with AutoProxy or Proxy
SwitchySharp.

Command line args
-----------------

You can use args to override settings from ``config.json``.

::

    sslocal -s server_name -p server_port -l local_port -k password -m bf-cfb
    ssserver -p server_port -k password -m bf-cfb --workers 2
    ssserver -c /etc/shadowsocks/config.json

Salsa20
-------

Salsa20 is a fast stream cipher.

Use "salsa20-ctr" in shadowsocks.json.

And install these packages:

Debian / Ubuntu:
^^^^^^^^^^^^^^^^

::

    apt-get install python-numpy
    pip install salsa20

Wiki
----

https://github.com/clowwindy/shadowsocks/wiki

License
-------

MIT

Bugs and Issues
---------------

Please visit `issue
tracker <https://github.com/clowwindy/shadowsocks/issues?state=open>`__

Mailing list: http://groups.google.com/group/shadowsocks

Also see
`troubleshooting <https://github.com/clowwindy/shadowsocks/wiki/Troubleshooting>`__

.. |Build Status| image:: https://travis-ci.org/clowwindy/shadowsocks.png?branch=master
   :target: https://travis-ci.org/clowwindy/shadowsocks
