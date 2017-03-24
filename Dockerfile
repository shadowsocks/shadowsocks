FROM alpine

ENV SERVER_ADDR 0.0.0.0
ENV SERVER_PORT 51348
ENV PASSWORD=
ENV METHOD      aes-128-ctr
ENV PROTOCOL    auth_aes128_md5
ENV OBFS        tls1.2_ticket_auth_compatible
ENV TIMEOUT     300
ENV DNS_ADDR    8.8.8.8
ENV DNS_ADDR_2  8.8.4.4


RUN apk update \
    && apk add python \
    libsodium \
    unzip \
    wget \
  && rm -rf /var/cache/apk/*



RUN wget --no-check-certificate https://github.com/breakwa11/shadowsocks/archive/manyuser.zip -O /tmp/manyuser.zip \
    && unzip -d /tmp /tmp/manyuser.zip \
    && mv /tmp/shadowsocksr-manyuser/shadowsocks ~/shadowsocks \
    && rm -rf /tmp/*


WORKDIR ~/shadowsocks


CMD python ~/shadowsocks/server.py -p $SERVER_PORT -k $PASSWORD -m $METHOD -O $PROTOCOL -o $OBFS
