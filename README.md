shadowsocks
===========

shadowsocks is a lightweight tunnel proxy which can help you get through firewalls

usage
-----------

Put `server.py` on your server. Edit `server.py`, change the following values:

    PORT          server port
    KEY           a password to identify clients

Run `python server.py` on your server. To run it in the background, run `setsid python server.py`.

Put `local.py` on your client machine. Edit `local.py`, change these values:

    SERVER  your  your server ip or hostname
    REMOTE_PORT   server port
    PORT          local port
    KEY           a password, it must be the same as the password of your server

Run `python local.py` on your client machine.

Change proxy settings of your browser into

    SOCKS5 127.0.0.1:PORT

