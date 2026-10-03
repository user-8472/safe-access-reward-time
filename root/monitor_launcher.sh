#!/bin/sh
# Runs as root from /etc/crontab (SRM strips non-root cron entries on reboot).
# Like app_watchdog.sh, this root-owned launcher only hands off: monitor.py
# needs no root, so it runs as __APP_USER__ from the app directory.
exec su __APP_USER__ -c 'cd __APP_DIR__ && python monitor.py'
