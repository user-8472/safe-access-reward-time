#!/bin/sh
# Runs as root from /etc/crontab - the router's reboot strips any crontab
# entry whose "who" column isn't root (confirmed with a controlled test), so
# the entry has to be root. This root-owned launcher is the only thing root
# runs for the web app: it hands off to the app's own watchdog.sh as
# __APP_USER__, never running anything from the app directory as root.
exec su __APP_USER__ -c '__APP_DIR__/watchdog.sh'
