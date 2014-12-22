#!/bin/bash

result=0

function run_test {
    printf '\e[0;36m'
    echo "running test: $command $@"
    printf '\e[0m'

    $command "$@"
    status=$?
    if [ $status -ne 0 ]; then
        printf '\e[0;31m'
        echo "test failed: $command $@"
        printf '\e[0m'
        echo
        result=1
    else
        printf '\e[0;32m'
        echo OK
        printf '\e[0m'
        echo
    fi
    return 0
}

coverage erase
mkdir tmp
run_test pep8 .
run_test pyflakes .
run_test coverage run tests/nose_plugin.py -v
run_test python setup.py sdist
run_test tests/test_daemon.sh
run_test python tests/test.py --with-coverage -c tests/aes.json
run_test python tests/test.py --with-coverage -c tests/aes-ctr.json
run_test python tests/test.py --with-coverage -c tests/aes-cfb1.json
run_test python tests/test.py --with-coverage -c tests/aes-cfb8.json
run_test python tests/test.py --with-coverage -c tests/rc4-md5.json
run_test python tests/test.py --with-coverage -c tests/salsa20.json
run_test python tests/test.py --with-coverage -c tests/chacha20.json
run_test python tests/test.py --with-coverage -c tests/salsa20-ctr.json
run_test python tests/test.py --with-coverage -c tests/table.json
run_test python tests/test.py --with-coverage -c tests/server-multi-ports.json
run_test python tests/test.py --with-coverage -s tests/server-multi-passwd.json -c tests/server-multi-passwd-client-side.json
run_test python tests/test.py --with-coverage -c tests/workers.json
run_test python tests/test.py --with-coverage -s tests/ipv6.json -c tests/ipv6-client-side.json
run_test python tests/test.py --with-coverage -b "-m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388" -a "-m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -l 1081"
run_test python tests/test.py --with-coverage -b "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388" -a "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388 -l 1081"
coverage combine && coverage report --include=shadowsocks/*
rm -rf htmlcov
rm -rf tmp
coverage html --include=shadowsocks/*

exit $result
