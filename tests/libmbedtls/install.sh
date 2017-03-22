#!/bin/bash

MBEDTLS_VER=2.4.2
if [ ! -d mbedtls-$MBEDTLS_VER ]; then
    wget https://tls.mbed.org/download/mbedtls-$MBEDTLS_VER-gpl.tgz || exit 1
    tar xf mbedtls-$MBEDTLS_VER-gpl.tgz || exit 1
fi
pushd mbedtls-$MBEDTLS_VER
make SHARED=1 CFLAGS=-fPIC && sudo make install || exit 1
sudo ldconfig
popd
rm -rf mbedtls-$MBEDTLS_VER || exit 1
