How to Contribute
=================

Pull Requests
-------------

1. Pull requests are welcome. If you would like to add a large feature
or make a significant change, make sure to open an issue to discuss with
people first.
2. Follow PEP8.
3. Make sure to pass the unit tests. Write unit tests for new modules if
needed.

Issues
------

1. Only bugs and feature requests are accepted here.
2. We'll only work on important features. If the feature you're asking only
benefits a few people, you'd better implement the feature yourself and send us
a pull request, or ask some of your friends to do so.
3. We don't answer questions of any other types here. Since very few people
are watching the issue tracker here, you'll probably get no help from here.
Read [Troubleshooting] and get help from forums or [mailing lists].

How To Run Unittests Locally
----

Since `ss` is written in python, you probably can develop it on your own
favorate platform. The following instructions are based on debian wheezy.

### Prerequisites

1. Debian packages

        # apt-get install python-pip swig libssl-dev python-dev curl

2. Python packages

        # pip install coverage pep8 pyflakes nose M2Crypto numpy salsa20

3. libsodium and socksify

   You must issue the `install.sh` for `socksify` from your local repo root:

        # pwd
        /path/to/your/shadowsocks

   Run the script:

        # tests/socksify/install.sh

   The `install.sh` for `libsodium` is location free. 
   To be simple, we invoke it from the same location:

        # tests/libsodium/install.sh

### Running unittests

You must issue it from your local repo root:

    $ pwd
    /path/to/your/shadowsocks

The command is `.jenkins.sh`. Invoke like this:

    $ ./.jenkins.sh

Note that we are running `.jenkins.sh` as normal user.

Be aware that `.jenkins.sh` does not stop when the first failure occurs. 
Instead, it runs through all tests and reports all failures.

### Special tests

* For me, the following test in `.jenkins.sh` does not get passed by default:

          run_test python tests/test.py --with-coverage -c tests/table.json

  I have to modify `tests/test.py:104`

        time.sleep(2)

  and increase the delay.

* `tests/test_large_file.sh` requires an http server to host a downloadable
file at http://127.0.0.1/file . If you do not have a local httpd server running,
  here is an easy way to do that:

      # pwd
      /path/to/your/shadowsocks
      # echo "TEST" > file
      # python -m SimpleHTTPServer 80

  Note that to bind SimpleHTTPServer to `80`, you need super user privilege.
Alternatively, you can modify `tests/test_large_file.sh` to use a different
port.

[Troubleshooting]: https://github.com/clowwindy/shadowsocks/wiki/Troubleshooting
[mailing lists]:   https://groups.google.com/forum/#!forum/shadowsocks

