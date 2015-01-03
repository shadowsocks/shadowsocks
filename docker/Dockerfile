FROM ubuntu:latest
MAINTAINER Sah Lee <contact@leesah.name>

ENV PORT 8388
EXPOSE $PORT

ENV CONF /etc/shadowsocks.json
VOLUME ["/etc/shadowsocks.json"]

CMD ssserver -p $PORT -c $CONF

RUN apt-get update
RUN apt-get install -y python-pip
RUN pip install shadowsocks
