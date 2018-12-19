FROM alpine:3.4

RUN if [ $(wget -qO- ipinfo.io/country) == CN ]; then echo "http://mirrors.ustc.edu.cn/alpine/v3.4/main/" > /etc/apk/repositories ;fi  \
    &&  apk update && apk upgrade \
    && apk add python py-pip libsodium

COPY . /shadowsocks
WORKDIR /shadowsocks
RUN python setup.py install

ENTRYPOINT ["/usr/bin/ssserver"]
# usage:
# docker build -t shadowsocks .
# server:
# docker run -d --restart=always -p 1314:1314 -v /etc/shadowsocks.json:/config shadowsocks -s 0.0.0.0 -c /config
# or docker run -d --restart=always -p 1314
# client:
# docker run -d --entrypoint=/usr/bin/sslocal --restart=always -p 1080:1080 -v /etc/shadowsocks.json:/config shadowsocks -c /config

