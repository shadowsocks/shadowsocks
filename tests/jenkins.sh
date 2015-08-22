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

python --version
coverage erase
mkdir tmp
run_test pep8 --ignore=E402 .
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
run_test python tests/test.py --with-coverage -c tests/table.json
run_test python tests/test.py --with-coverage -c tests/server-multi-ports.json
run_test python tests/test.py --with-coverage -s tests/aes.json -c tests/client-multi-server-ip.json
run_test python tests/test.py --with-coverage -s tests/server-multi-passwd.json -c tests/server-multi-passwd-client-side.json
run_test python tests/test.py --with-coverage -c tests/workers.json
run_test python tests/test.py --with-coverage -s tests/ipv6.json -c tests/ipv6-client-side.json
run_test python tests/test.py --with-coverage -b "-m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -q" -a "-m rc4-md5 -k testrc4 -s 127.0.0.1 -p 8388 -l 1081 -vv"
run_test python tests/test.py --with-coverage -b "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388 --workers 1" -a "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388 -l 1081 -t 30 -qq -b 127.0.0.1"
run_test python tests/test.py --with-coverage --should-fail --url="http://127.0.0.1/" -b "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388 --forbidden-ip=127.0.0.1,::1,8.8.8.8" -a "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388 -l 1081 -t 30 -b 127.0.0.1"

# test if DNS works
run_test python tests/test.py --with-coverage -c tests/aes.json --url="https://clients1.google.com/generate_204"

# test localhost is in the forbidden list by default
run_test python tests/test.py --with-coverage --should-fail --tcp-only --url="http://127.0.0.1/" -b "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388" -a "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388 -l 1081 -t 30 -b 127.0.0.1"

# test localhost is available when forbidden list is empty
run_test python tests/test.py --with-coverage --tcp-only --url="http://127.0.0.1/" -b "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388 --forbidden-ip=" -a "-m aes-256-cfb -k testrc4 -s 127.0.0.1 -p 8388 -l 1081 -t 30 -b 127.0.0.1"

if [ -f /proc/sys/net/ipv4/tcp_fastopen ] ; then
    if [ 3 -eq `cat /proc/sys/net/ipv4/tcp_fastopen` ] ; then
        # we have to run it twice:
        # the first time there's no syn cookie
        # the second time there is syn cookie
        run_test python tests/test.py --with-coverage -c tests/fastopen.json
        run_test python tests/test.py --with-coverage -c tests/fastopen.json
    fi
fi

run_test tests/test_large_file.sh

if [ "a$JENKINS" != "a1" ] ; then
    # jenkins blocked SIGQUIT with sigprocmask(), we have to skip this test on Jenkins
    run_test tests/test_graceful_restart.sh
fi
run_test tests/test_udp_src.sh
run_test tests/test_command.sh

coverage combine && coverage report --include=shadowsocks/*
rm -rf htmlcov
rm -rf tmp
coverage html --include=shadowsocks/*

coverage report --include=shadowsocks/* | tail -n1 | rev | cut -d' ' -f 1 | rev > /tmp/shadowsocks-coverage

exit $result
