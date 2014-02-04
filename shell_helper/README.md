INTRO
-----

bash function to manage sslocal session and mac osx system proxy settings.

- single bash function, minimum footprint
- enable/disable system proxy easily
- tab completion support

INSTALL
-----

copy `shadowsocks_helper.sh` to anywhere you like.

edit the shell variables to reflect you configuration.

    NAME="shadowsocks"
    VENVPATH="$HOME/.virtualenvs/sandbox/bin"
    CONFFILE="$HOME/bin/lib/$NAME.config.json"
    LOGFILE="/tmp/$NAME.log"
    PIDFILE="/tmp/$NAME.pid"

    NETWORK_INTERFACE="Wi-Fi"
    PROXY_HOST="127.0.0.1"
    PROXY_PORT="3131"

    COMMAND=($VENVPATH/python $VENVPATH/sslocal -c $CONFFILE)

if you don't use virtualenv, leave `VENVPATH` blank and change `COMMAND` to call sslocal directly.

then add the following lines to .bashrc or .zshrc

    if [ -x ~/bin/lib/shadowsocks_helper.sh ]; then
        eval "$(~/bin/lib/shadowsocks_helper.sh)"
    fi

USAGE
-----

    $ shadowsocks [status|start|stop|restart|system_proxy_(status|enable|disable)]
