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

Download [OpenSSL for Windows] and install. Then install shadowsocks via
easy_install and pip as Linux. If you don't know how to use them, you can
directly download [the package], and use `python shadowsocks/server.py`
instead of `ssserver` command below.

Configuration
-------------

On your server create a config file `/etc/shadowsocks.json`.
Example:

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

| Name          | Explanation                                     |
| ------------- | ----------------------------------------------- |
| server        | the address your server listens                 |
| server_port   | server port                                     |
| local_address | the address your local listens                  |
| local_port    | local port                                      |
| password      | password used for encryption                    |
| timeout       | in seconds                                      |
| method        | default: "aes-256-cfb", see [Encryption]        |
| fast_open     | use [TCP_FASTOPEN], true / false                |
| workers       | number of workers, available on Unix/Linux      |

On your server:

To run in the foreground:

    ssserver -c /etc/shadowsocks.json

To run in the background:

    ssserver -c /etc/shadowsocks.json -d start
    ssserver -c /etc/shadowsocks.json -d stop

On your client machine, use the same configuration as your server. Check the
README of your client for more information.

Command Line Options
--------------------

Check the options via `-h`.You can use args to override settings from
`config.json`.

    sslocal -s server_name -p server_port -l local_port -k password -m bf-cfb
    ssserver -p server_port -k password -m bf-cfb --workers 2
    ssserver -c /etc/shadowsocks/config.json -d start --pid-file=/tmp/shadowsocks.pid
    ssserver -c /etc/shadowsocks/config.json -d stop --pid-file=/tmp/shadowsocks.pid

Documentation
-------------

You can find all the documentation in the wiki:
https://github.com/clowwindy/shadowsocks/wiki

License
-------
MIT

Bugs and Issues
----------------

* [Troubleshooting]
* [Issue Tracker]
* [Mailing list]


[Android]:           https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients#android
[Build Status]:      https://img.shields.io/travis/clowwindy/shadowsocks/master.svg?style=flat
[Chinese Readme]:    https://github.com/clowwindy/shadowsocks/wiki/Shadowsocks-%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E
[Coverage Status]:   http://192.81.132.184/result/shadowsocks
[Coverage]:          http://192.81.132.184/job/Shadowsocks/ws/htmlcov/index.html
[Debian sid]:        https://packages.debian.org/unstable/python/shadowsocks
[the package]:       https://pypi.python.org/pypi/shadowsocks
[Encryption]:        https://github.com/clowwindy/shadowsocks/wiki/Encryption
[iOS]:               https://github.com/shadowsocks/shadowsocks-iOS/wiki/Help
[Issue Tracker]:     https://github.com/clowwindy/shadowsocks/issues?state=open
[Mailing list]:      http://groups.google.com/group/shadowsocks
[OpenSSL for Windows]: http://slproweb.com/products/Win32OpenSSL.html
[OpenWRT]:           https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients#openwrt
[OS X]:              https://github.com/shadowsocks/shadowsocks-iOS/wiki/Shadowsocks-for-OSX-Help
[PyPI]:              https://pypi.python.org/pypi/shadowsocks
[PyPI version]:      https://img.shields.io/pypi/v/shadowsocks.svg?style=flat
[TCP_FASTOPEN]:      https://github.com/clowwindy/shadowsocks/wiki/TCP-Fast-Open
[Travis CI]:         https://travis-ci.org/clowwindy/shadowsocks
[Troubleshooting]:   https://github.com/clowwindy/shadowsocks/wiki/Troubleshooting
[Windows]:           https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients#windows
