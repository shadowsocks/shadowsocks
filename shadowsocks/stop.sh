#!/bin/bash

eval $(ps -ef | grep "[0-9] python server\\.py a" | awk '{print "kill "$2}')
