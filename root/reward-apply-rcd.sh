#!/bin/sh
# Installed by install.sh to /usr/local/etc/rc.d/ - runs the privileged apply
# daemon at boot (must stay root; it calls synowebapi, which is root-only).
case "$1" in
  start)
    __ROOT_DIR__/apply_watchdog.sh
    ;;
  stop)
    if [ -f __ROOT_DIR__/apply_daemon.pid ]; then
      kill "$(cat __ROOT_DIR__/apply_daemon.pid)" 2>/dev/null
      rm -f __ROOT_DIR__/apply_daemon.pid
    fi
    ;;
esac
exit 0
