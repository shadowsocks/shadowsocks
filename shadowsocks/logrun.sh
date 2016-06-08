#!/bin/bash
cd `dirname $0`
eval $(ps -ef | grep "[0-9] python server\\.py a" | awk '{print "kill "$2}')
ulimit -n 4096
nohup python server.py a >> ssserver.log 2>&1 &

