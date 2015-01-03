Useful Tools
===========

autoban.py
----------

Automatically ban IPs that try to brute force crack the server.

    python autoban.py < /var/log/shadowsocks.log

Use `-c` to specify with how many failure times it should be considered as an
attack. Default is 3.

To continue watching for the log file:

    nohup tail -f /var/log/shadowsocks.log | python autoban.py >log 2>log &

Use with caution. Avoid to ban yourself.
