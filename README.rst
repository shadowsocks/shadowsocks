shadowsocks
===========

|PyPI version| |Build Status| |Coverage Status|

A fast tunnel proxy that helps you bypass firewalls.

Server
------

Install
~~~~~~~

Debian / Ubuntu:

::

    apt-get install python-pip
    pip install shadowsocks

CentOS:

::

    yum install python-setuptools && easy_install pip
    pip install shadowsocks

Windows:

See `Install Server on
Windows <https://github.com/shadowsocks/shadowsocks/wiki/Install-Shadowsocks-Server-on-Windows>`__

Usage
~~~~~

::

    ssserver -p 443 -k password -m rc4-md5

To run in the background:

::

    sudo ssserver -p 443 -k password -m rc4-md5 --user nobody -d start

To stop:

::

    sudo ssserver -d stop

To check the log:

::

    sudo less /var/log/shadowsocks.log

Check all the options via ``-h``. You can also use a
`Configuration <https://github.com/shadowsocks/shadowsocks/wiki/Configuration-via-Config-File>`__
file instead.

Client
------

-  `Windows <https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#windows>`__
   / `OS
   X <https://github.com/shadowsocks/shadowsocks-iOS/wiki/Shadowsocks-for-OSX-Help>`__
-  `Android <https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#android>`__
   / `iOS <https://github.com/shadowsocks/shadowsocks-iOS/wiki/Help>`__
-  `OpenWRT <https://github.com/shadowsocks/openwrt-shadowsocks>`__

Use GUI clients on your local PC/phones. Check the README of your client
for more information.

Documentation
-------------

You can find all the documentation in the
`Wiki <https://github.com/shadowsocks/shadowsocks/wiki>`__.

License
-------

MIT

Bugs and Issues
---------------

-  `Troubleshooting <https://github.com/shadowsocks/shadowsocks/wiki/Troubleshooting>`__
-  `Issue
   Tracker <https://github.com/shadowsocks/shadowsocks/issues?state=open>`__
-  `Mailing list <https://groups.google.com/group/shadowsocks>`__

.. |PyPI version| image:: https://img.shields.io/pypi/v/shadowsocks.svg?style=flat
   :target: https://pypi.python.org/pypi/shadowsocks
.. |Build Status| image:: https://img.shields.io/travis/shadowsocks/shadowsocks/master.svg?style=flat
   :target: https://travis-ci.org/shadowsocks/shadowsocks
.. |Coverage Status| image:: https://jenkins.shadowvpn.org/result/shadowsocks
   :target: https://jenkins.shadowvpn.org/job/Shadowsocks/ws/PYENV/py34/label/linux/htmlcov/index.html
