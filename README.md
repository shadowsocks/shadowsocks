shadowsocks
===========

shadowsocks is a lightweight tunnel proxy which can help you get through firewalls

usage
-----------

Edit `config.json`, change the following values:

    server          your server ip or hostname
    server_port     server port
    local_port      local port
    password        a password used to encrypt transfer

Put all the files on your server. Run `python server.py` on your server. To run it in the background, run `nohup python server.py > log &`.

Put all the files on your client machine. Run `python local.py` on your client machine.

Change proxy settings of your browser into

    SOCKS5 127.0.0.1:local_port

