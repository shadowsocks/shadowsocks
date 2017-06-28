#!/bin/bash

bash initcfg.sh
sed -i 's/sspanelv2/mudbjson/g' userapiconfig.py
ip_addr=`ifconfig -a|grep inet|grep -v inet6|grep -v "127.0.0."|grep -v -e "192\.168\..[0-9]\+\.[0-9]\+"|grep -v -e "10\.[0-9]\+\.[0-9]\+\.[0-9]\+"|awk '{print $2}'|tr -d "addr:"`
ip_count=`echo $ip_addr|grep -e "^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$" -c`
if [[ $ip_count == 1 ]]; then
	echo "server IP is "${ip_addr}
	sed -i 's/127\.0\.0\.1/'${ip_addr}'/g' userapiconfig.py
	port=`python -c 'import random;print(random.randint(10000, 65536))'`
	python mujson_mgr.py -a -p ${port}
else
	echo "unable to detect server IP"
fi

