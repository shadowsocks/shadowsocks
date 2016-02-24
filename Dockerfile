FROM stackbrew/debian:jessie
RUN apt-get update
RUN apt-get install -y python python-setuptools

ADD . /shadowsocks

WORKDIR /shadowsocks
RUN python setup.py install
CMD ssserver
