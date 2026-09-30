#!/bin/sh
# Installed by install.sh to /usr/local/etc/rc.d/ - runs the unprivileged web
# app watchdog at boot (owned by root here, but it immediately re-execs itself
# as __APP_USER__ - see watchdog.sh).
case "$1" in
  start)
    su __APP_USER__ -c '__APP_DIR__/watchdog.sh'
    ;;
  stop)
    if [ -f __APP_DIR__/server.pid ]; then
      kill "$(cat __APP_DIR__/server.pid)" 2>/dev/null
      rm -f __APP_DIR__/server.pid
    fi
    ;;
esac
exit 0
