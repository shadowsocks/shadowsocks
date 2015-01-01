FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y python-pip
RUN pip install shadowsocks

EXPOSE 8388

ADD shadowsocks.json /etc/

VOLUME ["/etc/shadowsocks.json"]

CMD ssserver -c /etc/shadowsocks.json
