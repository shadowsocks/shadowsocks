shadowsocks
===========

[![PyPI version]][PyPI]
[![Build Status]][Travis CI]
[![Coverage Status]][Coverage]

A fast tunnel proxy that helps you bypass firewalls.

[中文说明][Chinese Readme]

Install
-------

You'll have a client on your local side, and setup a server on a
remote server.

### Client

* [Windows] / [OS X]
* [Android] / [iOS]
* [OpenWRT]

### Server

#### Debian / Ubuntu:

    apt-get install python-pip
    pip install shadowsocks

Or simply `apt-get install shadowsocks` if you have [Debian sid] in your
source list.

#### CentOS:

    yum install python-setuptools
    easy_install pip
    pip install shadowsocks

#### Windows:

Install [OpenSSL for Windows]. Download [the package].
Use `python shadowsocks/server.py` instead of `ssserver` command below.

Usage
-----

On your server:

    ssserver -p 8000 -k password -m rc4-md5

To run in the background:

    ssserver -p 8000 -k password -m rc4-md5 -d start
    ssserver -p 8000 -k password -m rc4-md5 -d stop

On your client machine, use the same configuration as your server. Check the
README of your client for more information.

Check the options via `-h`. You can also use a [Configuration] file instead.

Documentation
-------------

You can find all the documentation in the wiki:
https://github.com/shadowsocks/shadowsocks/wiki

License
-------
MIT

Bugs and Issues
----------------

* [Troubleshooting]
* [Issue Tracker]
* [Mailing list]


[Android]:           https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#android
[Build Status]:      https://img.shields.io/travis/shadowsocks/shadowsocks/master.svg?style=flat
[Chinese Readme]:    https://github.com/shadowsocks/shadowsocks/wiki/Shadowsocks-%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E
[Configuration]:     https://github.com/shadowsocks/shadowsocks/wiki/Configuration-via-Config-File
[Coverage Status]:   https://jenkins.shadowvpn.org/result/shadowsocks
[Coverage]:          https://jenkins.shadowvpn.org/job/Shadowsocks/ws/htmlcov/index.html
[Debian sid]:        https://packages.debian.org/unstable/python/shadowsocks
[the package]:       https://pypi.python.org/pypi/shadowsocks
[Encryption]:        https://github.com/shadowsocks/shadowsocks/wiki/Encryption
[iOS]:               https://github.com/shadowsocks/shadowsocks-iOS/wiki/Help
[Issue Tracker]:     https://github.com/shadowsocks/shadowsocks/issues?state=open
[Mailing list]:      https://groups.google.com/group/shadowsocks
[OpenSSL for Windows]: https://slproweb.com/products/Win32OpenSSL.html
[OpenWRT]:           https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#openwrt
[OS X]:              https://github.com/shadowsocks/shadowsocks-iOS/wiki/Shadowsocks-for-OSX-Help
[PyPI]:              https://pypi.python.org/pypi/shadowsocks
[PyPI version]:      https://img.shields.io/pypi/v/shadowsocks.svg?style=flat
[TCP_FASTOPEN]:      https://github.com/shadowsocks/shadowsocks/wiki/TCP-Fast-Open
[Travis CI]:         https://travis-ci.org/shadowsocks/shadowsocks
[Troubleshooting]:   https://github.com/shadowsocks/shadowsocks/wiki/Troubleshooting
[Windows]:           https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#windows
