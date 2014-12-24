#!/bin/bash

. tests/assert.sh

PYTHON="coverage run -a -p"
LOCAL="$PYTHON shadowsocks/local.py"
SERVER="$PYTHON shadowsocks/server.py"

assert "$LOCAL 2>&1 | grep ERROR" "ERROR: config not specified"
assert "$LOCAL 2>&1 | grep usage | cut -d: -f1" "usage"

assert "$SERVER 2>&1 | grep ERROR" "ERROR: config not specified"
assert "$SERVER 2>&1 | grep usage | cut -d: -f1" "usage"

assert "$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d start | grep WARNING |  awk -F\"WARNING\" '{print \$2}'" "  warning: server set to listen on 127.0.0.1:8388, are you sure?"
$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d stop

assert "$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 0.0.0.0 -p 8388 -t10 -d start | grep WARNING |  awk -F\"WARNING\" '{print \$2}'" "  warning: your timeout 10 seems too short"
$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d stop

assert "$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 0.0.0.0 -p 8388 -t1000 -d start | grep WARNING |  awk -F\"WARNING\" '{print \$2}'" "  warning: your timeout 1000 seems too long"
$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d stop

assert "$LOCAL 2>&1 -m rc4 -k testrc4 -s 0.0.0.0 -p 8388 -d start | grep WARNING |  awk -F\"WARNING\" '{print \$2}'" "  warning: RC4 is not safe; please use a safer cipher, like AES-256-CFB"
$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d stop

assert "$LOCAL 2>&1 -m rc4-md5 -k mypassword -s 0.0.0.0 -p 8388 -d start | grep ERROR |  awk -F\"ERROR\" '{print \$2}'" "    DON'T USE DEFAULT PASSWORD! Please change it in your config.json!"
$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d stop

assert "$LOCAL 2>&1 -m rc4-md5 -p 8388 -k testrc4 -d start | grep ERROR |  awk -F\"ERROR\" '{print \$2}'" ": server addr not specified"
$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d stop

assert "$LOCAL 2>&1 -m rc4-md5 -p 8388 -s 0.0.0.0 -d start | grep ERROR |  awk -F\"ERROR\" '{print \$2}'" ": password not specified"
$LOCAL 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d stop

assert "$SERVER 2>&1 -m rc4-md5 -p 8388 -s 0.0.0.0 -d start | grep ERROR |  awk -F\"ERROR\" '{print \$2}'" ": password or port_password not specified"
$SERVER 2>&1 -m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -d stop


assert_end command
