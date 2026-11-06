#!/usr/bin/env python
# Builds the Reward Time block page for one device, by IP, into
# blockpage-cache/<ip>.html. Run on demand by rt-blocked.cgi (as the web
# server's user, "system") when that device's page is missing, over a minute
# old, or older than the last Safe Access settings change - so only devices
# actually hitting the block page cost anything, about 0.1 s once a minute.
#
# Shows what you need to find the device in the DS router app (name, IP, MAC)
# and when it next gets access. Everything read here is world-readable; it
# needs no root. Device names come from DHCP, so everything is HTML-escaped.
import datetime
import json
import os
import re
import sqlite3
import sys
import time

from schedule import get_schedule_window   # root-owned copy beside this file
try:
    from html import escape
except ImportError:  # Python 2
    from cgi import escape

ROOT_DIR = '__ROOT_DIR__'
# The Reward Time app's address; its tokenless /me page shows this device's
# schedule and reward time (if a blocked device can reach it).
PUBLIC_URL = '__PUBLIC_URL__'
CACHE_DIR = os.path.join(ROOT_DIR, 'blockpage-cache')
PAUSES_PATH = os.path.join(ROOT_DIR, 'pauses.json')
SA_DB = '/usr/syno/etc/packages/SafeAccess/synoaccesscontrol/database.db'
DEVICE_DB = '/usr/syno/etc/device.db'
LEASES = '/etc/dhcpd/dhcpd.conf.leases'
ARP = '/proc/net/arp'
IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
# Reward Time's icon, inline, so the page needs no second request (which a
# blocked device would send to the blocked site, not here).
ICON_URI = 'data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%20128%20128%22%3E%0A%20%20%3Crect%20width%3D%22128%22%20height%3D%22128%22%20rx%3D%2228%22%20fill%3D%22%230a84ff%22/%3E%0A%20%20%3Crect%20x%3D%2252%22%20y%3D%2216%22%20width%3D%2224%22%20height%3D%2210%22%20rx%3D%225%22%20fill%3D%22%23eaf3ff%22/%3E%0A%20%20%3Ccircle%20cx%3D%2264%22%20cy%3D%2268%22%20r%3D%2240%22%20fill%3D%22none%22%20stroke%3D%22%23eaf3ff%22%20stroke-width%3D%228%22/%3E%0A%20%20%3Cline%20x1%3D%2264%22%20y1%3D%2268%22%20x2%3D%2264%22%20y2%3D%2244%22%20stroke%3D%22%23eaf3ff%22%20stroke-width%3D%227%22%20stroke-linecap%3D%22round%22/%3E%0A%20%20%3Cline%20x1%3D%2264%22%20y1%3D%2268%22%20x2%3D%2282%22%20y2%3D%2268%22%20stroke%3D%22%23eaf3ff%22%20stroke-width%3D%227%22%20stroke-linecap%3D%22round%22/%3E%0A%20%20%3Ccircle%20cx%3D%2298%22%20cy%3D%2294%22%20r%3D%2222%22%20fill%3D%22%2330d158%22/%3E%0A%20%20%3Cline%20x1%3D%2298%22%20y1%3D%2284%22%20x2%3D%2298%22%20y2%3D%22104%22%20stroke%3D%22%23052e13%22%20stroke-width%3D%226%22%20stroke-linecap%3D%22round%22/%3E%0A%20%20%3Cline%20x1%3D%2288%22%20y1%3D%2294%22%20x2%3D%22108%22%20y2%3D%2294%22%20stroke%3D%22%23052e13%22%20stroke-width%3D%226%22%20stroke-linecap%3D%22round%22/%3E%0A%3C/svg%3E'
# The DS router app's device type icons, as words; others (e.g. "default") are left out.
DEVICE_TYPES = {'tv': 'TV', 'nb': 'Laptop', 'pc': 'Computer', 'cellphone': 'Phone', 'ipad': 'Tablet',
                'game': 'Game console', 'watch': 'Watch', 'printer': 'Printer', 'cam': 'Camera'}


def h(value):
    return escape(u'%s' % value if not isinstance(value, bytes) else value.decode('utf-8', 'replace'), True)


def mac_for(ip):
    # The address table is the live answer; leases cover a device the router
    # hasn't talked to lately. Lease lines: "<expiry> <mac> <ip> <hostname> <id>".
    try:
        for line in open(ARP):
            f = line.split()
            if len(f) >= 4 and f[0] == ip and MAC_RE.match(f[3].lower()) and f[3] != '00:00:00:00:00:00':
                return f[3].lower()
    except IOError:
        pass
    lease = lease_for(ip)
    return lease[0] if lease else None


def lease_for(ip):
    try:
        for line in open(LEASES):
            f = line.split()
            if len(f) >= 4 and f[2] == ip and MAC_RE.match(f[1].lower()):
                return f[1].lower(), (f[3] if f[3] != '*' else '')
    except IOError:
        pass
    return None


def query(db, sql, args):
    try:
        conn = sqlite3.connect(db, timeout=3)
        try:
            return conn.execute(sql, args).fetchone(), conn
        except Exception:
            conn.close()
            raise
    except Exception:
        return None, None


def clock(ts):
    lt = time.localtime(ts)
    return '%d:%02d %s' % (lt.tm_hour % 12 or 12, lt.tm_min, 'AM' if lt.tm_hour < 12 else 'PM')


def day(ts, now):
    days = (datetime.date.fromtimestamp(ts) - datetime.date.fromtimestamp(now)).days
    if days == 0:
        return 'today'
    if days == 1:
        return 'tomorrow'
    return time.strftime('%A', time.localtime(ts))


def when(ts, now):
    return '%s %s' % (day(ts, now), clock(ts))


def status_lines(profile_id, now):
    # (headline, detail) for why the device is blocked and when that ends.
    row, conn = query(SA_DB, 'SELECT pause_expired FROM config_group WHERE id = ?', (profile_id,))
    if conn is None:
        return 'Blocked right now', ''
    try:
        if row and row[0] is not None:
            until = None
            try:
                until = json.load(open(PAUSES_PATH)).get(str(profile_id))
            except (IOError, ValueError):
                pass
            if until and until > now:
                return 'Internet is paused', 'The pause ends %s.' % when(until, now)
            return 'Internet is paused', 'A parent paused it, with no end time set.'
        state, start, end = get_schedule_window(conn, profile_id, now)
    finally:
        conn.close()
    if state == 'off':
        return ('Outside scheduled time',
                'Next scheduled time: %s to %s.' % (when(start, now),
                                                     clock(end) if day(end, now) == day(start, now) else when(end, now)))
    if state == 'always_off':
        return 'No scheduled time', 'This device only gets internet when a parent adds reward time.'
    if state == 'on':
        return 'Scheduled time now', 'Its schedule allows internet until %s - if this page stays, try again in a minute.' % when(end, now)
    return 'Blocked right now', ''


def build(ip):
    now = int(time.time())
    mac = mac_for(ip) if ip != 'unknown' else None
    lease = lease_for(ip) if ip != 'unknown' else None
    name, dev_type, profile = None, None, None
    if mac:
        row, conn = query(DEVICE_DB, 'SELECT hostname, dev_type FROM devices WHERE mac = ?', (mac,))
        if conn:
            conn.close()
        if row:
            name, dev_type = row[0], row[1]
        row, conn = query(SA_DB, 'SELECT c.id, c.name FROM device d JOIN config_group c ON c.id = d.config_group_id '
                                 'WHERE d.mac = ?', (mac,))
        if conn:
            conn.close()
        profile = row
    name = name or (lease[1] if lease else '') or 'Unknown device'

    if profile:
        headline, detail = status_lines(profile[0], now)
        ask = 'Ask a parent if you need more time - they can add it in Reward Time.'
    else:
        headline, detail = 'Not in a profile', ''
        ask = ('Ask a parent to add this device to a profile in the DS router app '
               '(Safe Access). The name and MAC address below identify it.')

    rows = [('Device', name), ('Profile', profile[1] if profile else 'none'),
            ('IP address', ip), ('MAC address', mac or 'unknown')]
    if dev_type in DEVICE_TYPES:
        rows.append(('Type', DEVICE_TYPES[dev_type]))
    table = ''.join('<tr><th>%s</th><td>%s</td></tr>' % (h(k), h(v)) for k, v in rows)
    page = PAGE % {'headline': h(headline), 'detail': '<p>%s</p>' % h(detail) if detail else '', 'ask': h(ask), 'name': h(name),
                   'table': table, 'updated': h(clock(now)), 'icon': ICON_URI,
                   'me_link': ('<p><a class="me" href="%s/me">See your schedule and reward time &rsaquo;</a></p>'
                               % h(PUBLIC_URL)) if PUBLIC_URL.startswith('https://') else ''}

    if not os.path.isdir(CACHE_DIR):
        return
    path = os.path.join(CACHE_DIR, ip + '.html')
    tmp = '%s.%d.tmp' % (path, os.getpid())
    with open(tmp, 'w') as f:
        f.write(page.encode('utf-8'))
    os.rename(tmp, path)


PAGE = u"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>No internet right now</title>
<link rel="icon" href="%(icon)s">
<style>
:root { --bg: #f2f2f7; --card: #fff; --text: #1c1c1e; --muted: #6e6e73; --line: #d1d1d6; --accent: #0a84ff; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #000; --card: #1c1c1e; --text: #f2f2f7; --muted: #98989f; --line: #38383a; }
}
body { margin: 0; background: var(--bg); color: var(--text);
       font: 16px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 480px; margin: 0 auto; padding: 32px 16px; }
.card { background: var(--card); border: 3px solid var(--accent); border-radius: 14px; padding: 20px; }
h1 { font-size: 22px; margin: 0 0 4px; }
.headline { color: var(--accent); font-weight: 600; margin: 0 0 6px; }
p { margin: 0 0 12px; }
table { width: 100%%; border-collapse: collapse; margin-top: 8px; }
th, td { text-align: left; padding: 8px 0; border-top: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: normal; width: 40%%; padding-right: 12px; }
td { word-break: break-all; }
.muted { color: var(--muted); font-size: 13px; margin-top: 16px; }
a.me { color: var(--accent); font-weight: 600; text-decoration: none; }
</style></head>
<body><main><div class="card">
<h1>No internet right now</h1>
<p class="headline">%(headline)s</p>
%(detail)s
<p>%(ask)s</p>
%(me_link)s
<table>%(table)s</table>
<p class="muted">Reward Time &middot; updated %(updated)s</p>
</div></main></body></html>
"""

if __name__ == '__main__':
    ip = sys.argv[1] if len(sys.argv) > 1 else 'unknown'
    if ip != 'unknown' and not IP_RE.match(ip):
        sys.exit('bad ip')
    build(ip)
