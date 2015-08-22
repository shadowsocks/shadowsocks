#!/bin/bash

DEV=lo
PORT=8388
DELAY=100ms

type tc 2> /dev/null && (
    tc qdisc add dev $DEV root handle 1: htb
    tc class add dev $DEV parent 1: classid 1:1 htb rate 2mbps
    tc class add dev $DEV parent 1:1 classid 1:6 htb rate 2mbps ceil 1mbps prio 0
    tc filter add dev $DEV parent 1:0 prio 0 protocol ip handle 6 fw flowid 1:6

    tc filter add dev $DEV parent 1:0 protocol ip u32 match ip dport $PORT 0xffff flowid 1:6
    tc filter add dev $DEV parent 1:0 protocol ip u32 match ip sport $PORT 0xffff flowid 1:6

    tc qdisc show dev lo
)

