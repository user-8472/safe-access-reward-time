#!/bin/sh
# Installed by install.sh to /usr/local/etc/rc.d/ - runs the unprivileged web
# app at boot. Both actions run as __APP_USER__: server.pid is the app user's
# file, so a kill driven by it must not run as root (root would kill whatever
# pid the file names).
case "$1" in
  start)
    su __APP_USER__ -c '__APP_DIR__/watchdog.sh'
    ;;
  stop)
    su __APP_USER__ -c 'cd __APP_DIR__ && [ -f server.pid ] && kill "$(cat server.pid)" 2>/dev/null; rm -f server.pid'
    ;;
esac
exit 0
