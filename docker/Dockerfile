FROM ubuntu:latest

ENV METHOD aes-256-cfb
ENV KEY Change Me!

ENV PORT 8388
EXPOSE $PORT

CMD ssserver -p "$PORT" -m "$METHOD" -k "$KEY"

RUN apt-get update
RUN apt-get install -y python-pip
RUN pip install shadowsocks
