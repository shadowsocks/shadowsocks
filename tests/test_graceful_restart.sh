#!/bin/bash

PYTHON="coverage run -p -a"
URL=http://127.0.0.1/file


# setup processes
$PYTHON shadowsocks/local.py -c tests/graceful.json &
LOCAL=$!

$PYTHON shadowsocks/server.py -c tests/graceful.json --forbidden-ip "" &
SERVER=$!

python tests/graceful_server.py &
GSERVER=$!

sleep 1

python tests/graceful_cli.py &
GCLI=$!

sleep 1

# graceful restart server: send SIGQUIT to old process and start a new one
kill -s SIGQUIT $SERVER
sleep 0.5
$PYTHON shadowsocks/server.py -c tests/graceful.json --forbidden-ip "" &
NEWSERVER=$!

sleep 1

# check old server
ps x | grep -v grep | grep $SERVER
OLD_SERVER_RUNNING1=$?
# old server should not quit at this moment
echo old server running: $OLD_SERVER_RUNNING1

sleep 1

# close connections on old server
kill -s SIGKILL $GCLI
kill -s SIGKILL $GSERVER
kill -s SIGINT $LOCAL

sleep 11

# check old server
ps x | grep -v grep | grep $SERVER
OLD_SERVER_RUNNING2=$?
# old server should quit at this moment
echo old server running: $OLD_SERVER_RUNNING2

kill -s SIGINT $SERVER
# new server is expected running
kill -s SIGINT $NEWSERVER || exit 1

if [ $OLD_SERVER_RUNNING1 -ne 0 ]; then
    exit 1
fi

if [ $OLD_SERVER_RUNNING2 -ne 1 ]; then
    sleep 1
    exit 1
fi
