FROM ubuntu:14.04

RUN apt-get update
RUN apt-get -y install python-software-properties software-properties-common
RUN add-apt-repository ppa:chris-lea/libsodium
RUN echo "deb http://ppa.launchpad.net/chris-lea/libsodium/ubuntu trusty main" >> /etc/apt/sources.list
RUN echo "deb-src http://ppa.launchpad.net/chris-lea/libsodium/ubuntu trusty main" >> /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y libsodium-dev python-pip

RUN pip install shadowsocks

ENTRYPOINT ["/usr/local/bin/ssserver"]

# usage:
# docker run -d --restart=always -p 1314:1314 ficapy/shadowsocks -s 0.0.0.0 -p 1314 -k $PD -m chacha20