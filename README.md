shadowsocks
===========

Current version: 1.4.1 [![Build Status][1]][0]

shadowsocks is a lightweight tunnel proxy which can help you get through firewalls.

Both TCP CONNECT and UDP ASSOCIATE are implemented.

[中文说明][3]

Install
-------

First, make sure you have Python 2.6 or 2.7.

    $ python --version
    Python 2.6.8

Install Shadowsocks.

#### Debian / Ubuntu:

    apt-get install python-gevent python-m2crypto
    pip install shadowsocks

#### CentOS:

    yum install m2crypto python-setuptools
    easy_install pip
    pip install shadowsocks

#### Windows / OS X:

Choose a [GUI client][7]

Usage
-----

Create a config file `/etc/shadowsocks.json` (or put it in other path).
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
| method        | encryption method, "aes-256-cfb" is recommended |
| fast_open     | use [TCP_FASTOPEN][2], true / false             |

Run `ssserver -c /etc/shadowsocks.json` on your server. To run it in the background, [use supervisor][8].

On your client machine, run `sslocal -c /etc/shadowsocks.json`.

Change the proxy settings in your browser to

    protocol: socks5
    hostname: 127.0.0.1
    port:     your local_port

**Notice: If you want to use encryption methods other than "table", please install M2Crypto (See Encryption Section).**

It's recommended to use shadowsocks with AutoProxy or Proxy SwitchySharp.

Command line args
------------------

You can use args to override settings from `config.json`.

    sslocal -s server_name -p server_port -l local_port -k password -m bf-cfb
    ssserver -p server_port -k password -m bf-cfb
    ssserver -c /etc/shadowsocks/config.json

Wiki
----

https://github.com/clowwindy/shadowsocks/wiki

License
-------
MIT

Bugs and Issues
----------------
Please visit [issue tracker][5]

Mailing list: http://groups.google.com/group/shadowsocks

Also see [troubleshooting][6]

[0]: https://travis-ci.org/clowwindy/shadowsocks
[1]: https://travis-ci.org/clowwindy/shadowsocks.png?branch=master
[2]: https://github.com/clowwindy/shadowsocks/wiki/TCP-Fast-Open
[3]: https://github.com/clowwindy/shadowsocks/wiki/Shadowsocks-%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E
[4]: http://chandlerproject.org/Projects/MeTooCrypto
[5]: https://github.com/clowwindy/shadowsocks/issues?state=open
[6]: https://github.com/clowwindy/shadowsocks/wiki/Troubleshooting
[7]: https://github.com/clowwindy/shadowsocks/wiki/Ports-and-Clients
[8]: https://github.com/clowwindy/shadowsocks/wiki/Configure-Shadowsocks-with-Supervisor
