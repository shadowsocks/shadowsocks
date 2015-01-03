Useful Tools
===========

autoban.py
----------

Automatically ban IPs that try to brute force crack the server.

    python autoban.py < /var/log/shadowsocks.log

Use `-c` to specify with how many failure times it should be considered an
attack. Default is 3.
