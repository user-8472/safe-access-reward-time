#!/bin/sh
# Runs as root from /etc/crontab (apply_daemon.py calls synowebapi, which is
# root-only). Lives in the root-owned __ROOT_DIR__ with the daemon itself, so
# the app user can't edit what root runs or the pid file root acts on.
cd __ROOT_DIR__ || exit 1

if [ -f apply_daemon.pid ] && kill -0 "$(cat apply_daemon.pid)" 2>/dev/null; then
  exit 0
fi

nohup python apply_daemon.py > /dev/null 2>&1 &
echo $! > apply_daemon.pid
