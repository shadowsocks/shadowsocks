#!/bin/bash

if [ ! -d libsodium-1.0.12 ]; then
    wget https://github.com/jedisct1/libsodium/releases/download/1.0.12/libsodium-1.0.12.tar.gz || exit 1
    tar xf libsodium-1.0.12.tar.gz || exit 1
fi
pushd libsodium-1.0.12
./configure && make -j2 && make install || exit 1
sudo ldconfig
popd
rm -rf libsodium-1.0.12 || exit 1
