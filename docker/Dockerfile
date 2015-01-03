FROM ubuntu:latest

MAINTAINER Sah Lee <contact@leesah.name>

ENV BASEDIR /

# Set up building environment
RUN apt-get update
RUN apt-get install -y git-core python python-setuptools

# Get the latest code, build and install
RUN git clone https://github.com/shadowsocks/shadowsocks.git $BASEDIR
WORKDIR $BASEDIR/shadowsocks
RUN pwd
RUN python setup.py build
RUN python setup.py install

# Tear down building environment and delete git repository
RUN apt-get --purge autoremove -y git-core python python-setuptools
RUN rm -rf $BASEDIR/shadowsocks

# Config file can be in a separated container
ENV CONF /etc/shadowsocks.json
VOLUME ["$CONF"]

# Port in the config file won't take affect. Instead we'll use 8388.
ENV PORT 8388
EXPOSE $PORT

CMD ssserver -c $CONF -p $PORT
