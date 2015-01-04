FROM ubuntu:latest

MAINTAINER Sah Lee <contact@leesah.name>

ENV BASEDIR /tmp

# Install dependencies
RUN apt-get update
RUN apt-get install -y python python-pkg-resources

# Set up building environment
RUN apt-get install -y git-core python-setuptools

# Get the latest code, build and install
WORKDIR $BASEDIR
RUN git clone https://github.com/shadowsocks/shadowsocks.git
WORKDIR $BASEDIR/shadowsocks
RUN pwd
RUN python setup.py build
RUN python setup.py install

# Tear down building environment and delete git repository
WORKDIR $BASEDIR
RUN apt-get --purge autoremove -y git-core python-setuptools
RUN rm -rf $BASEDIR/shadowsocks

# Config file can be in a separated container
ENV CONFIG_DIR /etc/shadowsocks
ENV CONFIG_FILE $CONFIG_DIR/shadowsocks.json
VOLUME ["$CONFIG_DIR"]

# Port in the config file won't take affect. Instead we'll use 8388.
ENV PORT 8388
EXPOSE $PORT

# Override the host and port in the config file.
CMD ssserver --fast-open -c $CONFIG_FILE -s 0.0.0.0 -p $PORT
