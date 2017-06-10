#!/bin/bash

OPENSSL_VER=1.1.0e
if [ ! -d openssl-$OPENSSL_VER ]; then
    wget https://www.openssl.org/source/openssl-$OPENSSL_VER.tar.gz || exit 1
    tar xf openssl-$OPENSSL_VER.tar.gz || exit 1
fi
pushd openssl-$OPENSSL_VER
./config && make && sudo make install || exit 1
# sudo ldconfig  # test multiple libcrypto
popd
rm -rf openssl-$OPENSSL_VER || exit 1
