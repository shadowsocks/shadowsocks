#!/bin/bash

DEV=lo
PORT=8388
DELAY=100ms

PYTHON="coverage run -p -a"
URL=http://127.0.0.1/file

mkdir -p tmp

type tc 2> /dev/null && (
    tc qdisc add dev $DEV root handle 1: htb
    tc class add dev $DEV parent 1: classid 1:1 htb rate 2mbps
    tc class add dev $DEV parent 1:1 classid 1:6 htb rate 2mbps ceil 1mbps prio 0
    tc filter add dev $DEV parent 1:0 prio 0 protocol ip handle 6 fw flowid 1:6

    tc filter add dev $DEV parent 1:0 protocol ip u32 match ip dport $PORT 0xffff flowid 1:6
    tc filter add dev $DEV parent 1:0 protocol ip u32 match ip sport $PORT 0xffff flowid 1:6

#    iptables -D OUTPUT -t mangle -p tcp --sport 8388 -j MARK --set-mark 6
#    iptables -A OUTPUT -t mangle -p tcp --sport 8388 -j MARK --set-mark 6

    tc qdisc show dev lo
)

$PYTHON shadowsocks/local.py -c tests/aes.json &
LOCAL=$!

$PYTHON shadowsocks/server.py -c tests/aes.json &
SERVER=$!

sleep 3

time curl -o tmp/expected $URL
time curl -o tmp/result --socks5-hostname 127.0.0.1:1081 $URL

kill -s SIGINT $LOCAL
kill -s SIGINT $SERVER

type tc 2> /dev/null && tc qdisc del dev lo root

sleep 2

diff tmp/expected tmp/result || exit 1
