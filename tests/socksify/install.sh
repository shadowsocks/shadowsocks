#!/bin/bash

if [ ! -d dante-1.4.0 ] || [ ! -d dante-1.4.0/configure ]; then
    rm dante-1.4.0 -rf
    #wget http://www.inet.no/dante/files/dante-1.4.0.tar.gz || exit 1
    wget https://codeload.github.com/notpeter/dante/tar.gz/dante-1.4.0 -O dante-1.4.0.tar.gz || exit 1
    tar xf dante-1.4.0.tar.gz || exit 1
    #
    mv dante-dante-1.4.0 dante-1.4.0
fi
pushd dante-1.4.0
./configure && make -j4 && make install || exit 1
popd
cp tests/socksify/socks.conf /etc/ || exit 1
