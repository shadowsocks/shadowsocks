#!/bin/bash

if [ ! -d dante-1.4.0 ]; then
    wget http://www.inet.no/dante/files/dante-1.4.0.tar.gz || exit 1
    tar xf dante-1.4.0.tar.gz || exit 1
fi
pushd dante-1.4.0
./configure && make -j4 && make install || exit 1
popd
cp tests/socksify/socks.conf /etc/ || exit 1
