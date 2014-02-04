#!/bin/sh

## TODO: completion

## add following lines to .bashrc or .zshrc
## =-=
## shadowsocks proxy helper functions
#if [ -x ~/bin/lib/shadowsocks_helper.sh ]; then
#    eval "$(~/bin/lib/shadowsocks_helper.sh)"
#fi
## =-=

## CONFIG START ## 
NAME="shadowsocks"
VENVPATH="$HOME/.virtualenvs/sandbox/bin"
CONFFILE="$HOME/bin/lib/$NAME.config.json"
LOGFILE="/tmp/$NAME.log"
PIDFILE="/tmp/$NAME.pid"

NETWORK_INTERFACE="Wi-Fi"
PROXY_HOST="127.0.0.1"
PROXY_PORT="3131"

COMMAND=($VENVPATH/python $VENVPATH/sslocal -c $CONFFILE)
## CONFIG END ##

cat <<EOF
shadowsocks(){
  case \$1 in
  status)
    shadowsocks system_proxy_status

    local PID=\$(shadowsocks _pid)
    local ARG="-f"
    [ \$2 ] && [ "-s" = \$2 ] && ARG=""
    if [ \$PID -eq 0 ]; then
      echo "[INFO] $NAME is not running."
    else
      echo "[INFO] $NAME is running with pid \$PID."
      [ \$ARG ] && echo "(press Ctrl-C to exit)"
      tail -n 5 \$ARG $LOGFILE
    fi
  ;;
  start)
    [ -r $CONFFILE ] || {
      echo "[ERR] conf file not found ($CONFFILE)."
      return 1
    }
    local PID=\$(shadowsocks _pid)
    [ \$PID -ne 0 ] && {
      echo "[WARN] $NAME is already running with pid \$PID." >&2
      return
    }
    nohup ${COMMAND[@]} > $LOGFILE &
    PID=\$!
    echo \$PID > $PIDFILE
    if [ \$? -eq 0 ]; then
      echo "[INFO] $NAME is running with pid \$PID."
      sleep 3
      cat $LOGFILE
    else
      echo "[ERR] failed to start $NAME." >&2
      return 1
    fi
  ;;
  stop)
    local PID=\$(shadowsocks _pid)
    if [ \$PID -eq 0 ]; then
      echo "[INFO] $NAME is not running."
    else
      kill \$PID
      echo "[INFO] stopped $NAME running with pid \$PID."
      #tail -n 5 $LOGFILE
    fi
  ;;
  restart)
    shadowsocks stop
    shadowsocks start
  ;;
  system_proxy_status)
    echo "[INFO] System Proxy Setting:"
    networksetup -getsocksfirewallproxy $NETWORK_INTERFACE | awk '{print "  " \$0}'
  ;;
  system_proxy_enable)
    sudo networksetup -setsocksfirewallproxy $NETWORK_INTERFACE $PROXY_HOST $PROXY_PORT
    sudo networksetup -setsocksfirewallproxystate $NETWORK_INTERFACE on
    shadowsocks system_proxy_status
  ;;
  system_proxy_disable)
    sudo networksetup -setsocksfirewallproxystate $NETWORK_INTERFACE off
    shadowsocks system_proxy_status | head -n 2
  ;;
  _pid)
    if [ ! -r $PIDFILE ]; then
      echo 0
      return
    fi
    local PID=\$(cat $PIDFILE)
    ps -p \$PID | grep -q $NAME
    if [ \$? -ne 0 ]; then
      echo 0
      return
    fi
    echo \$PID
  ;;
  *)
    shadowsocks status -s
    echo "Usage: shadowsocks status|start|stop|restart"
    echo "       shadowsocks system_proxy_(status|enable|disable)"
  ;;
  esac
}
EOF

SUBCOMMANDS="restart start status stop system_proxy_disable system_proxy_enable system_proxy_status"

case $(basename $SHELL) in
  bash)
    cat <<EOF
_shadowsocks(){
  local cur
  COMPREPLY=()
  cur=\${COMP_WORDS[COMP_CWORD]}

  if [ \$COMP_CWORD -eq 1 ] ; then
    COMPREPLY=( \$( compgen -W "$SUBCOMMANDS" -- \$cur ) )
  fi
}
complete -F _shadowsocks shadowsocks
EOF
  ;;
  zsh)
    cat <<EOF
_shadowsocks(){ compadd restart start status stop system_proxy_disable system_proxy_enable system_proxy_status; }
compdef _shadowsocks shadowsocks
EOF
  ;;
  *)
    # echo "[WARN] shell completion is not supported for $(basename $SHELL)" >&2
  ;;
esac


