#!/bin/sh
# Runs the unit tests on the router itself (its Python 2.7 is what the app
# actually runs on), from a throwaway directory, as whatever user SSH logs in
# as. Usage: tests/run_on_router.sh [ssh-host]   (default: synology)
set -e
HOST=${1:-synology}
cd "$(dirname "$0")/.."
DIR=/tmp/reward-time-tests-$$
tar cf - schedule.py tests/*.py | ssh "$HOST" "mkdir -m 700 $DIR && cd $DIR && tar xf - &&
  TZ='EST5EDT,M3.2.0,M11.1.0' python -m unittest discover -s tests -t . ; rc=\$?; cd / && rm -rf $DIR; exit \$rc"
