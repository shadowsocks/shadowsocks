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

rm /usr/bin/openssl || exit 1
rm -r /usr/include/openssl || exit 1
ln -s /usr/local/bin/openssl /usr/bin/openssl || exit 1
ln -s /usr/local/include/openssl /usr/include/openssl || exit 1
echo /usr/local/lib >> /etc/ld.so.conf || exit 1
ldconfig -v || exit 1
