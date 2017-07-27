#!/bin/bash

PYTHON="coverage run -a"
URL=http://127.0.0.1/file

mkdir -p tmp

$PYTHON shadowsocks/local.py -c tests/aes.json &
LOCAL=$!

$PYTHON shadowsocks/server.py -c tests/aes.json --forbidden-ip "" &
SERVER=$!

sleep 3

time curl -o tmp/expected $URL
time curl -o tmp/result --socks5-hostname 127.0.0.1:1081 $URL

kill -s SIGINT $LOCAL
kill -s SIGINT $SERVER

sleep 2

diff tmp/expected tmp/result || exit 1
