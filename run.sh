#!/bin/bash

eval $(ps -ef | grep "[0-9] python server\\.py" | awk '{print "kill "$2}')
nohup python server.py >> ssserver.log 2>&1 &

