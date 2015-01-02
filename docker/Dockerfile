FROM ubuntu:latest

ENV PORT "8388"
ENV METHOD "aes-256-cfb"
ENV KEY "changeme"

EXPOSE "$PORT"

CMD ssserver -p "$PORT" -m "$METHOD" -k "$KEY"

RUN apt-get update
RUN apt-get install -y python-pip
RUN pip install shadowsocks
