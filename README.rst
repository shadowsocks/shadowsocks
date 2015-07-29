shadowsocks
===========

|PyPI version| |Build Status| |Coverage Status|

A fast tunnel proxy that helps you bypass firewalls.

`中文说明 <https://github.com/shadowsocks/shadowsocks/wiki/Shadowsocks-%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E>`__

Install
-------

You'll have a client on your local side, and setup a server on a remote
server.

Client
~~~~~~

-  `Windows <https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#windows>`__
   / `OS
   X <https://github.com/shadowsocks/shadowsocks-iOS/wiki/Shadowsocks-for-OSX-Help>`__
-  `Android <https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#android>`__
   / `iOS <https://github.com/shadowsocks/shadowsocks-iOS/wiki/Help>`__
-  `OpenWRT <https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#openwrt>`__

Server
~~~~~~

Debian / Ubuntu:
^^^^^^^^^^^^^^^^

::

    apt-get install python-pip
    pip install shadowsocks

Or simply ``apt-get install shadowsocks`` if you have `Debian
sid <https://packages.debian.org/unstable/python/shadowsocks>`__ in your
source list.

CentOS:
^^^^^^^

::

    yum install python-setuptools
    easy_install pip
    pip install shadowsocks

Windows:
^^^^^^^^

Download `OpenSSL for
Windows <http://slproweb.com/products/Win32OpenSSL.html>`__ and install.
Then install shadowsocks via easy\_install and pip as Linux. If you
don't know how to use them, you can directly download `the
package <https://pypi.python.org/pypi/shadowsocks>`__, and use
``python shadowsocks/server.py`` instead of ``ssserver`` command below.

Configuration
-------------

On your server create a config file ``/etc/shadowsocks.json``. Example:

::

    {
        "server":"my_server_ip",
        "server_port":8388,
        "local_address": "127.0.0.1",
        "local_port":1080,
        "password":"mypassword",
        "timeout":300,
        "method":"aes-256-cfb",
        "fast_open": false
    }

Explanation of the fields:

+------------------+-----------------------------------------------------------------------------------------------------------+
| Name             | Explanation                                                                                               |
+==================+===========================================================================================================+
| server           | the address your server listens                                                                           |
+------------------+-----------------------------------------------------------------------------------------------------------+
| server\_port     | server port                                                                                               |
+------------------+-----------------------------------------------------------------------------------------------------------+
| local\_address   | the address your local listens                                                                            |
+------------------+-----------------------------------------------------------------------------------------------------------+
| local\_port      | local port                                                                                                |
+------------------+-----------------------------------------------------------------------------------------------------------+
| password         | password used for encryption                                                                              |
+------------------+-----------------------------------------------------------------------------------------------------------+
| timeout          | in seconds                                                                                                |
+------------------+-----------------------------------------------------------------------------------------------------------+
| method           | default: "aes-256-cfb", see `Encryption <https://github.com/shadowsocks/shadowsocks/wiki/Encryption>`__   |
+------------------+-----------------------------------------------------------------------------------------------------------+
| fast\_open       | use `TCP\_FASTOPEN <https://github.com/shadowsocks/shadowsocks/wiki/TCP-Fast-Open>`__, true / false       |
+------------------+-----------------------------------------------------------------------------------------------------------+
| workers          | number of workers, available on Unix/Linux                                                                |
+------------------+-----------------------------------------------------------------------------------------------------------+

On your server:

To run in the foreground:

::

    ssserver -c /etc/shadowsocks.json

To run in the background:

::

    ssserver -c /etc/shadowsocks.json -d start
    ssserver -c /etc/shadowsocks.json -d stop

On your client machine, use the same configuration as your server. Check
the README of your client for more information.

Command Line Options
--------------------

Check the options via ``-h``.You can use args to override settings from
``config.json``.

::

    sslocal -s server_name -p server_port -l local_port -k password -m bf-cfb
    ssserver -p server_port -k password -m bf-cfb --workers 2
    ssserver -c /etc/shadowsocks/config.json -d start --pid-file=/tmp/shadowsocks.pid
    ssserver -c /etc/shadowsocks/config.json -d stop --pid-file=/tmp/shadowsocks.pid

Documentation
-------------

You can find all the documentation in the wiki:
https://github.com/shadowsocks/shadowsocks/wiki

License
-------

MIT

Bugs and Issues
---------------

-  `Troubleshooting <https://github.com/shadowsocks/shadowsocks/wiki/Troubleshooting>`__
-  `Issue
   Tracker <https://github.com/shadowsocks/shadowsocks/issues?state=open>`__
-  `Mailing list <http://groups.google.com/group/shadowsocks>`__

.. |PyPI version| image:: https://img.shields.io/pypi/v/shadowsocks.svg?style=flat
   :target: https://pypi.python.org/pypi/shadowsocks
.. |Build Status| image:: https://img.shields.io/travis/shadowsocks/shadowsocks/master.svg?style=flat
   :target: https://travis-ci.org/shadowsocks/shadowsocks
.. |Coverage Status| image:: http://192.81.132.184/result/shadowsocks
   :target: http://192.81.132.184/job/Shadowsocks/ws/htmlcov/index.html
