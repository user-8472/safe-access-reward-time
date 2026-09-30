#!/bin/sh
# Must run as root (apply_daemon.py calls synowebapi, which is root-only).
cd "$(dirname "$0")" || exit 1

if [ -f apply_daemon.pid ] && kill -0 "$(cat apply_daemon.pid)" 2>/dev/null; then
  exit 0
fi

nohup python apply_daemon.py > /dev/null 2>&1 &
echo $! > apply_daemon.pid
