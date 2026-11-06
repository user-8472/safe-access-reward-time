# Which device is asking? Maps a LAN client's IP address to its MAC, the name
# and type the DS router app shows for it, and its Safe Access profile. Used by
# the tokenless "My device" page (/me). Everything read here is world-readable.
#
# The router keeps the client's own address even for requests made through the
# public DDNS name from inside the LAN, so the request's source IP is enough.
import re
import sqlite3

ARP = '/proc/net/arp'
LEASES = '/etc/dhcpd/dhcpd.conf.leases'
DEVICE_DB = '/usr/syno/etc/device.db'
MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
# The DS router app's device type icons, as words; others (e.g. "default") are left out.
DEVICE_TYPES = {'tv': 'TV', 'nb': 'Laptop', 'pc': 'Computer', 'cellphone': 'Phone', 'ipad': 'Tablet',
                'game': 'Game console', 'watch': 'Watch', 'printer': 'Printer', 'cam': 'Camera'}


def lan_ipv4(addr):
    # The client's IPv4 address if it's a private (home network) one, else None.
    addr = (addr or '').replace('::ffff:', '')
    m = IPV4_RE.match(addr)
    if not m:
        return None
    a, b = int(m.group(1)), int(m.group(2))
    if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return addr
    return None


def _lease(ip):
    try:
        with open(LEASES) as f:
            for line in f:
                p = line.split()   # "<expiry> <mac> <ip> <hostname> <client id>"
                if len(p) >= 4 and p[2] == ip and MAC_RE.match(p[1].lower()):
                    return p[1].lower(), (p[3] if p[3] != '*' else '')
    except IOError:
        pass
    return None, ''


def mac_for(ip):
    # The address table is the live answer; leases cover a device the router
    # hasn't talked to lately.
    try:
        with open(ARP) as f:
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[0] == ip and MAC_RE.match(p[3].lower()) \
                        and p[3] != '00:00:00:00:00:00':
                    return p[3].lower()
    except IOError:
        pass
    return _lease(ip)[0]


def identify(ip, sa_conn):
    # {'ip', 'mac', 'name', 'type', 'profile_id', 'profile_name'} - any of the
    # later ones may be None. sa_conn: an open Safe Access database connection.
    info = {'ip': ip, 'mac': mac_for(ip), 'name': None, 'type': None,
            'profile_id': None, 'profile_name': None}
    if not info['mac']:
        return info
    try:
        conn = sqlite3.connect(DEVICE_DB, timeout=3)
        try:
            row = conn.execute("SELECT hostname, dev_type FROM devices WHERE mac = ?",
                               (info['mac'],)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        row = None
    if row:
        info['name'] = row[0] or None
        info['type'] = DEVICE_TYPES.get(row[1])
    if not info['name']:
        info['name'] = _lease(ip)[1] or None
    row = sa_conn.execute(
        "SELECT c.id, c.name FROM device d JOIN config_group c ON c.id = d.config_group_id "
        "WHERE d.mac = ?", (info['mac'],)).fetchone()
    if row:
        info['profile_id'], info['profile_name'] = row
    return info
