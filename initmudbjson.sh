#!/bin/bash

bash initcfg.sh
sed -i "s/API_INTERFACE = .\+\?\#/API_INTERFACE = \'mudbjson\' \#/g" userapiconfig.py
ip_addr=`ifconfig -a|grep inet|grep -v inet6|grep -v "127.0.0."|grep -v -e "192\.168\..[0-9]\+\.[0-9]\+"|grep -v -e "10\.[0-9]\+\.[0-9]\+\.[0-9]\+"|awk '{print $2}'|tr -d "addr:"`
ip_count=`echo $ip_addr|grep -e "^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$" -c`

if [[ $ip_count == 1 ]]; then
	ip_addr=`ip a|grep inet|grep -v inet6|grep -v "127.0.0."|grep -v -e "192\.168\..[0-9]\+\.[0-9]\+"|grep -v -e "10\.[0-9]\+\.[0-9]\+\.[0-9]\+"|awk '{print $2}'`
	ip_addr=${ip_addr%/*}
	ip_count=`echo $ip_addr|grep -e "^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$" -c`
fi
if [[ $ip_count == 1 ]]; then
	echo "server IP is "${ip_addr}
	sed -i "s/SERVER_PUB_ADDR = .\+/SERVER_PUB_ADDR = \'"${ip_addr}"\'/g" userapiconfig.py
	user_count=`python mujson_mgr.py -l|grep -c -e "[0-9]"`
	if [[ $user_count == 0 ]]; then
		port=`python -c 'import random;print(random.randint(10000, 65536))'`
		python mujson_mgr.py -a -p ${port}
	fi
else
	echo "unable to detect server IP"
fi

