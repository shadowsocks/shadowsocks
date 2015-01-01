FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y python-pip
RUN pip install shadowsocks

EXPOSE 8388

CMD ssserver -p 8388 -m "aes-256-cfb"
