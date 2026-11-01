#!/bin/sh
# Reward Time's block page for Safe Access's "blocked by schedule" ports
# (5032 http / 5033 https), in place of Synology's blocked.cgi. That one
# starts a fresh root process (~0.5 s of CPU) for every request a blocked
# device makes, and a TV left on an app makes about one a second; it printed
# the same text every time anyway.
#
# This prints a ready-made page for the requesting device from
# blockpage-cache/<ip>.html (a file read, a few milliseconds), rebuilding it
# first with build_page.py when it's missing, over a minute old, or older
# than the last Safe Access settings change. Installed and kept in place by
# blockpage_patch.py, which points the block page's .htaccess here.
ROOT=__ROOT_DIR__
CACHE=$ROOT/blockpage-cache
SA_DB=/usr/syno/etc/packages/SafeAccess/synoaccesscontrol/database.db
[ -n "$TZ" ] || TZ=$(cat /etc/TZ 2>/dev/null)
export TZ

ip=${REMOTE_ADDR#::ffff:}
case "$ip" in ''|*[!0-9.]*) ip=unknown ;; esac
page=$CACHE/$ip.html

if [ ! -f "$page" ] || [ "$SA_DB" -nt "$page" ] || [ -z "$(find "$page" -mmin -1 2>/dev/null)" ]; then
  lock=$CACHE/.lock-$ip
  # A lock left behind by a killed build is cleared after a minute.
  [ -d "$lock" ] && [ -z "$(find "$lock" -prune -mmin -1 2>/dev/null)" ] && rmdir "$lock" 2>/dev/null
  if mkdir "$lock" 2>/dev/null; then
    /usr/bin/python -E -s "$ROOT/blockpage/build_page.py" "$ip" >/dev/null 2>&1
    rmdir "$lock"
  fi
fi

printf 'Content-Type: text/html; charset=utf-8\r\n'
printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\nPragma: no-cache\r\nExpires: 0\r\n\r\n'
if [ -f "$page" ]; then
  cat "$page"
else
  # Another request is building it, or the build failed: plain details only.
  mac=$(awk -v ip="$ip" '$1 == ip { print $4 }' /proc/net/arp 2>/dev/null)
  case "$mac" in *[!0-9a-fA-F:]*|'') mac=unknown ;; esac
  printf '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>No internet right now</title></head>'
  printf '<body style="font-family:sans-serif;padding:24px"><h1>No internet right now</h1><p>IP address: %s<br>MAC address: %s</p></body></html>\n' "$ip" "$mac"
fi
