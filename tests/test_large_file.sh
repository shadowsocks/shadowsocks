#!/bin/bash

DEV=lo
PORT=8388
DELAY=100ms

PYTHON="coverage run -p -a"
URL=http://127.0.0.1/file

mkdir -p tmp

type tc 2> /dev/null && (
    tc qdisc add dev $DEV root handle 1: prio
    tc qdisc add dev $DEV parent 1:3 handle 30: netem delay $DELAY
    tc filter add dev $DEV parent 1:0 protocol ip u32 match ip dport $PORT 0xffff flowid 1:3
    tc filter add dev $DEV parent 1:0 protocol ip u32 match ip sport $PORT 0xffff flowid 1:3
    tc qdisc show dev lo
)

$PYTHON shadowsocks/local.py -c tests/aes.json &
LOCAL=$!

$PYTHON shadowsocks/server.py -c tests/aes.json &
SERVER=$!

sleep 3

time curl -o tmp/expected $URL
time curl -o tmp/result --socks5-hostname 127.0.0.1:1081 $URL

kill $LOCAL
kill $SERVER

type tc 2> /dev/null && tc qdisc del dev lo root

sleep 2

diff tmp/expected tmp/result || exit 1
