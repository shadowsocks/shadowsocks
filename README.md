shadowsocks
===========

[![PyPI version]][PyPI] [![Build Status]][Travis CI] 

A fast tunnel proxy that help you get through firewalls.

[中文说明][Chinese Readme]

Install
-------

You'll have a client on your local machine, and install a server on a
remote server.

### Client

* [Windows] / [OS X]
* [Android] / [iOS]
* [OpenWRT]

### Server

#### Debian / Ubuntu:

    apt-get install python-pip python-m2crypto
    pip install shadowsocks

#### CentOS:

    yum install m2crypto python-setuptools
    easy_install pip
    pip install shadowsocks

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
        "fast_open": false,
        "workers": 1
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
| method        | encryption method, "aes-256-cfb" is recommended |
| fast_open     | use [TCP_FASTOPEN], true / false                |
| workers       | number of workers, available on Unix/Linux      |

Run `ssserver -c /etc/shadowsocks.json` on your server. To run it in the
background, use [Supervisor].

On your client machine, use the same configuration as your server, and
start your client.

If you use Chrome, it's recommended to use [SwitchySharp]. Change the proxy 
settings to

    protocol: socks5
    hostname: 127.0.0.1
    port:     your local_port

If you can't install [SwitchySharp], you can launch Chrome with the following
arguments to force Chrome to use the proxy:

    Chrome.exe --proxy-server="socks5://127.0.0.1:1080" --host-resolver-rules="MAP * 0.0.0.0 , EXCLUDE localhost"

If you can't even download Chrome, find a friend to download a
[Chrome Standalone] installer for you.

Command line args
------------------

You can use args to override settings from `config.json`.

    sslocal -s server_name -p server_port -l local_port -k password -m bf-cfb
    ssserver -p server_port -k password -m bf-cfb --workers 2
    ssserver -c /etc/shadowsocks/config.json

List all available args with `-h`.

Wiki
----

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
[Chrome Standalone]: https://support.google.com/installer/answer/126299
[GUI client]:        https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients
[iOS]:               https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients#ios
[Issue Tracker]:     https://github.com/clowwindy/shadowsocks/issues?state=open
[Mailing list]:      http://groups.google.com/group/shadowsocks
[OpenWRT]:           https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients#openwrt
[OS X]:              https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients#os-x
[PyPI]:              https://pypi.python.org/pypi/shadowsocks
[PyPI version]:      https://img.shields.io/pypi/v/shadowsocks.svg?style=flat
[Supervisor]:        https://github.com/clowwindy/shadowsocks/wiki/Configure-Shadowsocks-with-Supervisor
[TCP_FASTOPEN]:      https://github.com/clowwindy/shadowsocks/wiki/TCP-Fast-Open
[Travis CI]:         https://travis-ci.org/clowwindy/shadowsocks
[Troubleshooting]:   https://github.com/clowwindy/shadowsocks/wiki/Troubleshooting
[SwitchySharp]:      https://chrome.google.com/webstore/detail/proxy-switchysharp/dpplabbmogkhghncfbfdeeokoefdjegm
[Windows]:           https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients#windows
