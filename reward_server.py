#!/usr/bin/env python
# Reward-time web app for Synology Safe Access. Python 2.7, stdlib only.
import BaseHTTPServer
import SocketServer
import base64
import binascii
import cgi
import hmac
import json
import logging
import logging.handlers
import os
import re
import socket
import sqlite3
import ssl
import time
import urllib
import urlparse

from schedule import (get_schedule_window, on_windows_from_blocks, blocks_from_on_windows,
                      validate_on_windows)

REQUEST_TIMEOUT_SECONDS = 20

# Anything this process creates from here on (tokens.db, pending/*.json request
# files) defaults to owner-only. Files apply_daemon.py (root) creates are a
# separate process with its own umask - unaffected, and must stay readable by
# this user, so this is deliberately not touched there.
os.umask(0o077)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, 'config.json')

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

DB_PATH = CONFIG['db_path']
TOKEN = str(CONFIG['token'])  # plain str/bytes, not unicode - hmac.compare_digest requires matching types
PORT = CONFIG['port']

log = logging.getLogger('reward_server')
log.setLevel(logging.INFO)
_handler = logging.handlers.RotatingFileHandler(
    os.path.join(APP_DIR, 'server.log'), maxBytes=5 * 1024 * 1024, backupCount=1)
_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
log.addHandler(_handler)
CERT_FILE = CONFIG['cert_file']
KEY_FILE = CONFIG['key_file']

PRESETS = [5, 15, 30, 60]
DURATION_PRESETS_HOURS = [4, 8, 24, 48, 72]

TOKENS_DB_PATH = os.path.join(APP_DIR, 'tokens.db')


MONITOR_STATE_PATH = os.path.join(APP_DIR, 'monitor.state')
# Timed pauses are tracked by apply_daemon (Safe Access itself only pauses
# indefinitely): {config_group_id: unpause_at}, world-readable.
PAUSES_PATH = os.path.join(CONFIG.get('root_dir', APP_DIR + '-root'), 'pauses.json')


def load_pauses():
    try:
        with open(PAUSES_PATH) as f:
            return dict((int(k), int(v)) for k, v in json.load(f).items())
    except (IOError, ValueError):
        return {}
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def get_tokens_db():
    conn = sqlite3.connect(TOKENS_DB_PATH, timeout=10)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS guest_tokens ("
        "token TEXT PRIMARY KEY, label TEXT NOT NULL, "
        "created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)"
    )
    # Admin links, each with a name (so activity can say who did what) and an
    # optional email that monitor.py sends alerts to. The token in config.json
    # only seeds the first row; from then on this table is the source of truth,
    # so revoking that original link really revokes it.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS admin_tokens ("
        "token TEXT PRIMARY KEY, label TEXT NOT NULL, email TEXT, "
        "created_at INTEGER NOT NULL)"
    )
    # Babysitter links can be limited to some profiles: a JSON list of profile
    # ids, or NULL for all of them (the default, and every link made before
    # this column existed).
    guest_columns = [row[1] for row in conn.execute("PRAGMA table_info(guest_tokens)")]
    if 'profile_ids' not in guest_columns:
        conn.execute("ALTER TABLE guest_tokens ADD COLUMN profile_ids TEXT")
    # Who did what: one row per action, kept for ACTIVITY_KEEP_DAYS. minutes is
    # the reward time actually added (negative when shortened or revoked).
    conn.execute(
        "CREATE TABLE IF NOT EXISTS activity ("
        "id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL, "
        "actor_kind TEXT NOT NULL, action TEXT NOT NULL, profile_id INTEGER, "
        "profile_name TEXT, minutes INTEGER, until INTEGER, ok INTEGER NOT NULL, detail TEXT)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS activity_ts ON activity (ts)")
    if conn.execute("SELECT COUNT(*) FROM admin_tokens").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO admin_tokens (token, label, email, created_at) VALUES (?, ?, NULL, ?)",
            (TOKEN, CONFIG.get('admin_label', 'Admin'), int(time.time()))
        )
        conn.commit()
    return conn


def get_admin(supplied):
    # Returns {'label', 'email'} for a valid admin token, else None.
    if not supplied:
        return None
    conn = get_tokens_db()
    try:
        row = conn.execute(
            "SELECT token, label, email FROM admin_tokens WHERE token = ?", (supplied,)
        ).fetchone()
    finally:
        conn.close()
    if row is None or not hmac.compare_digest(str(row[0]), str(supplied)):
        return None
    return {'label': row[1], 'email': row[2]}


def is_admin_token(supplied):
    return get_admin(supplied) is not None


def list_admin_tokens():
    conn = get_tokens_db()
    try:
        rows = conn.execute(
            "SELECT token, label, email FROM admin_tokens ORDER BY created_at"
        ).fetchall()
        return [{'token': t, 'label': label, 'email': email or ''} for t, label, email in rows]
    finally:
        conn.close()


def create_admin_token(label, email):
    token = binascii.hexlify(os.urandom(24))
    conn = get_tokens_db()
    try:
        conn.execute(
            "INSERT INTO admin_tokens (token, label, email, created_at) VALUES (?, ?, ?, ?)",
            (token, label, email or None, int(time.time()))
        )
        conn.commit()
    finally:
        conn.close()
    return token


def set_admin_email(token, email):
    conn = get_tokens_db()
    try:
        conn.execute("UPDATE admin_tokens SET email = ? WHERE token = ?", (email or None, token))
        conn.commit()
    finally:
        conn.close()


def revoke_admin_token(token):
    # Never leaves zero admin links - that would lock everyone out.
    conn = get_tokens_db()
    try:
        if conn.execute("SELECT COUNT(*) FROM admin_tokens").fetchone()[0] <= 1:
            raise ValueError("Can't revoke the last admin link")
        conn.execute("DELETE FROM admin_tokens WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()


def get_health():
    # Problems monitor.py currently sees, for the admin warning banner. A stale
    # state file means the monitor itself isn't running.
    try:
        age = time.time() - os.stat(MONITOR_STATE_PATH).st_mtime
        with open(MONITOR_STATE_PATH) as f:
            state = json.load(f)
    except (OSError, IOError, ValueError):
        return ['Health monitor has not run yet']
    problems = ['%s: %s' % (name, text) for name, text in sorted(state.get('problems', {}).items())]
    if age > 300:
        problems.insert(0, 'Health monitor last ran %d minutes ago' % (age // 60))
    return problems


def get_actor(supplied):
    # Who a token belongs to: {'kind': 'admin'|'guest', 'label', 'profile_ids'}
    # (profile_ids is None for "all profiles"), or None if it isn't valid.
    admin = get_admin(supplied)
    if admin:
        return {'kind': 'admin', 'label': admin['label'], 'profile_ids': None}
    if not supplied:
        return None
    conn = get_tokens_db()
    try:
        row = conn.execute(
            "SELECT label, profile_ids FROM guest_tokens WHERE token = ? AND expires_at > ?",
            (supplied, int(time.time()))
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {'kind': 'guest', 'label': row[0],
            'profile_ids': json.loads(row[1]) if row[1] else None}


def can_change(actor, profile_id):
    return actor['profile_ids'] is None or profile_id in actor['profile_ids']


def is_token_valid(supplied):
    return get_actor(supplied) is not None


ACTIVITY_KEEP_DAYS = 365


def record_activity(actor, action, profile_id=None, minutes=None, until=None, ok=True, detail=None):
    # Never lets a logging problem break the action itself.
    try:
        profile_name = None
        if profile_id is not None:
            profile_name = profile_reward_state(profile_id)[0]
        now = int(time.time())
        conn = get_tokens_db()
        try:
            conn.execute(
                "INSERT INTO activity (ts, actor, actor_kind, action, profile_id, profile_name, "
                "minutes, until, ok, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now, actor['label'], actor['kind'], action, profile_id, profile_name,
                 minutes, until, 1 if ok else 0, detail))
            conn.execute("DELETE FROM activity WHERE ts < ?", (now - ACTIVITY_KEEP_DAYS * 86400,))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        log.exception('could not record activity %s by %s', action, actor.get('label'))


def list_activity(who=None, limit=100):
    conn = get_tokens_db()
    try:
        query = ("SELECT ts, actor, actor_kind, action, profile_name, minutes, until, ok, detail, "
                 "profile_id FROM activity")
        args = []
        if who:
            query += " WHERE actor = ?"
            args.append(who)
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit)
        rows = conn.execute(query, args).fetchall()
        people = [r[0] for r in conn.execute(
            "SELECT actor FROM activity GROUP BY actor ORDER BY MAX(ts) DESC").fetchall()]
        now = int(time.time())
        summary = {}
        for period, days in (('week', 7), ('month', 30)):
            for actor, actor_kind, grants, custom, revokes, pauses, minutes in conn.execute(
                    "SELECT actor, actor_kind, "
                    "SUM(action = 'grant'), SUM(action = 'set_until'), SUM(action = 'revoke'), "
                    "SUM(action = 'pause'), "
                    "SUM(CASE WHEN action IN ('grant', 'set_until') AND minutes > 0 THEN minutes ELSE 0 END) "
                    "FROM activity WHERE ok = 1 AND ts >= ? GROUP BY actor", (now - days * 86400,)):
                summary.setdefault(actor, {'kind': actor_kind})[period] = {
                    'grants': grants or 0, 'custom': custom or 0, 'revokes': revokes or 0,
                    'pauses': pauses or 0, 'minutes': minutes or 0}
    finally:
        conn.close()
    events = [{'ts': r[0], 'actor': r[1], 'actor_kind': r[2], 'action': r[3], 'profile': r[4],
               'minutes': r[5], 'until': r[6], 'ok': bool(r[7]), 'detail': r[8],
               'profile_id': r[9]} for r in rows]
    return {'events': events, 'people': people, 'summary': summary}


def list_guest_tokens():
    conn = get_tokens_db()
    try:
        now = int(time.time())
        conn.execute("DELETE FROM guest_tokens WHERE expires_at <= ?", (now,))
        conn.commit()
        rows = conn.execute(
            "SELECT token, label, expires_at, profile_ids FROM guest_tokens ORDER BY expires_at"
        ).fetchall()
        return [{'token': t, 'label': label, 'expires_at': exp,
                 'profile_ids': json.loads(ids) if ids else None} for t, label, exp, ids in rows]
    finally:
        conn.close()


def create_guest_token(label, expires_at, profile_ids=None):
    token = binascii.hexlify(os.urandom(24))
    now = int(time.time())
    conn = get_tokens_db()
    try:
        conn.execute(
            "INSERT INTO guest_tokens (token, label, created_at, expires_at, profile_ids) "
            "VALUES (?, ?, ?, ?, ?)",
            (token, label, now, expires_at, json.dumps(profile_ids) if profile_ids is not None else None)
        )
        conn.commit()
    finally:
        conn.close()
    return token


def revoke_guest_token(token):
    # Returns the revoked link's label (None if it didn't exist).
    conn = get_tokens_db()
    try:
        row = conn.execute("SELECT label FROM guest_tokens WHERE token = ?", (token,)).fetchone()
        conn.execute("DELETE FROM guest_tokens WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()
    return row[0] if row else None


def get_db():
    # DB is written concurrently by SRM's own daemons (WAL mode); short busy timeout avoids
    # SQLITE_BUSY errors when both sides touch it at nearly the same moment.
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA busy_timeout = 10000')
    return conn


def profile_reward_state(profile_id):
    # (name, current reward expiry or None) - used to log how much time an
    # action actually added or removed.
    conn = get_db()
    try:
        row = conn.execute("SELECT name FROM profile WHERE id = ?", (profile_id,)).fetchone()
        expiry = conn.execute(
            "SELECT MAX(expired) FROM ultra_reward WHERE config_group_id = ? AND expired > ?",
            (profile_id, int(time.time()))).fetchone()[0]
    finally:
        conn.close()
    return (row[0] if row else None), expiry


def get_profiles():
    conn = get_db()
    try:
        now = int(time.time())
        # Safe Access records time spent per hour (in minutes), in buckets
        # starting on the hour; today = since local midnight.
        lt = time.localtime(now)
        today_start = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))
        pauses = load_pauses()
        rows = conn.execute(
            "SELECT profile.id, profile.name "
            "FROM profile JOIN config_group ON config_group.profile_id = profile.id "
            "WHERE profile.visible = 1 AND profile.enable_blocktime = 1 "
            "AND profile.name NOT LIKE '$%' "
            "ORDER BY profile.name"
        ).fetchall()
        profiles = []
        for profile_id, name in rows:
            remaining_row = conn.execute(
                "SELECT MAX(expired) FROM ultra_reward WHERE config_group_id = ? AND expired > ?",
                (profile_id, now)
            ).fetchone()
            remaining = remaining_row[0]
            remaining_minutes = int((remaining - now) / 60) if remaining else 0
            schedule_state, window_start, window_end = get_schedule_window(conn, profile_id, now)
            paused = conn.execute(
                "SELECT pause_expired IS NOT NULL FROM config_group WHERE id = ?", (profile_id,)
            ).fetchone()
            normal_used, reward_used = conn.execute(
                "SELECT SUM(normal_spent), SUM(reward_spent) FROM config_group_hour_timespent "
                "WHERE parent_id = ? AND timestamp >= ?", (profile_id, today_start)
            ).fetchone()
            profiles.append({
                'id': profile_id,
                'name': name,
                'remaining_minutes': remaining_minutes,
                'expires_at': remaining if remaining else None,
                'schedule_state': schedule_state,
                'schedule_window_start': window_start,
                'schedule_window_end': window_end,
                'used_today_minutes': (normal_used or 0) + (reward_used or 0),
                'reward_used_today_minutes': reward_used or 0,
                'paused': bool(paused and paused[0]),
                # None while paused = no end time (e.g. paused from the DS router app)
                'paused_until': pauses.get(profile_id),
            })
        return profiles
    finally:
        conn.close()


PENDING_DIR = os.path.join(APP_DIR, 'pending')
# apply_daemon batches same-profile requests picked up in one poll cycle into
# a single synowebapi get/set pair, but concurrent requests against
# *different* profiles still queue up as separate pairs processed one after
# another - this leaves some headroom for that case rather than the bare
# minimum for a single request.
APPLY_TIMEOUT_SECONDS = 10
REQUEST_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
TOKEN_REDACT_RE = re.compile(r'(token=)[^&\s"]+')


def safe_request_id(request_id):
    # Used directly as a filename, so validate strictly.
    if not request_id or not REQUEST_ID_RE.match(request_id):
        raise ValueError('bad request_id')
    return request_id


def enqueue_and_wait(action, config_group_id, request_id, timeout=APPLY_TIMEOUT_SECONDS, **params):
    # Writes are applied by the root-owned apply_daemon via the real Safe Access API
    # (a direct SQLite write here does NOT reliably trigger live enforcement - confirmed
    # the hard way). This app can't call that API itself (root-only), so it hands off
    # the request and waits briefly for the daemon to confirm it actually took effect.
    # request_id is client-supplied so the client can separately poll /api/request_status
    # for progress while this call is blocked waiting.
    base = safe_request_id(request_id)
    if not os.path.isdir(PENDING_DIR):
        os.makedirs(PENDING_DIR)
    req = {'action': action, 'config_group_id': config_group_id}
    req.update(params)
    tmp_path = os.path.join(PENDING_DIR, '.' + base + '.json')
    final_path = os.path.join(PENDING_DIR, base + '.json')
    with open(tmp_path, 'w') as f:
        json.dump(req, f)
    os.rename(tmp_path, final_path)

    done_path = os.path.join(PENDING_DIR, base + '.done')
    error_path = os.path.join(PENDING_DIR, base + '.error')
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(done_path):
            os.remove(done_path)
            return
        if os.path.exists(error_path):
            with open(error_path) as f:
                msg = f.read()
            os.remove(error_path)
            raise RuntimeError(msg or 'apply failed')
        time.sleep(0.1)
    raise RuntimeError('timed out waiting for apply_daemon - is it running?')


PENDING_CLEANUP_INTERVAL = 3600
PENDING_MAX_AGE = 24 * 3600
_last_pending_cleanup = [0]


def cleanup_pending():
    # Status files whose browser gave up waiting are never read, so they'd
    # pile up forever. At most once an hour, drop any older than a day.
    # Request .json files are left alone - apply_daemon owns those.
    now = time.time()
    if now - _last_pending_cleanup[0] < PENDING_CLEANUP_INTERVAL:
        return
    _last_pending_cleanup[0] = now
    try:
        names = os.listdir(PENDING_DIR)
    except OSError:
        return
    for name in names:
        if not (name.endswith(('.done', '.error', '.status')) or name.endswith('.tmp')):
            continue
        path = os.path.join(PENDING_DIR, name)
        try:
            if now - os.lstat(path).st_mtime > PENDING_MAX_AGE:
                os.remove(path)
        except OSError:
            pass


def get_request_stage(request_id):
    base = safe_request_id(request_id)
    if os.path.exists(os.path.join(PENDING_DIR, base + '.done')):
        return 'done'
    error_path = os.path.join(PENDING_DIR, base + '.error')
    if os.path.exists(error_path):
        with open(error_path) as f:
            return 'error: ' + f.read()
    status_path = os.path.join(PENDING_DIR, base + '.status')
    if os.path.exists(status_path):
        with open(status_path) as f:
            return f.read().strip() or 'queued'
    if os.path.exists(os.path.join(PENDING_DIR, base + '.json')):
        return 'queued'
    return 'unknown'


def grant_time(profile_id, minutes, request_id):
    enqueue_and_wait('grant', profile_id, request_id, minutes=minutes)


def set_expiry(profile_id, expires_at, request_id):
    enqueue_and_wait('set_until', profile_id, request_id, until=expires_at)


def revoke_time(profile_id, request_id):
    enqueue_and_wait('revoke', profile_id, request_id)


def get_on_windows(profile_id):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT begin_weekday, begin_clock, end_weekday, end_clock "
            "FROM schedule WHERE profile_id = ? AND type = 3", (profile_id,)).fetchall()
    finally:
        conn.close()
    return on_windows_from_blocks(rows)


def set_schedule(profile_id, days, request_id):
    enqueue_and_wait('set_schedule', profile_id, request_id, blocktimes=blocks_from_on_windows(days))


def profile_pause_state(profile_id):
    # (paused, timed_until): timed_until is None for a pause with no end time
    # (e.g. set from the DS router app) or when not paused.
    conn = get_db()
    try:
        row = conn.execute("SELECT pause_expired FROM config_group WHERE id = ?", (profile_id,)).fetchone()
    finally:
        conn.close()
    paused = bool(row and row[0] is not None)
    return paused, (load_pauses().get(profile_id) if paused else None)


def pause_profile(profile_id, until, request_id):
    enqueue_and_wait('pause', profile_id, request_id, until=until)


def unpause_profile(profile_id, request_id):
    enqueue_and_wait('unpause', profile_id, request_id)


ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="28" fill="#0a84ff"/>
  <rect x="52" y="16" width="24" height="10" rx="5" fill="#eaf3ff"/>
  <circle cx="64" cy="68" r="40" fill="none" stroke="#eaf3ff" stroke-width="8"/>
  <line x1="64" y1="68" x2="64" y2="44" stroke="#eaf3ff" stroke-width="7" stroke-linecap="round"/>
  <line x1="64" y1="68" x2="82" y2="68" stroke="#eaf3ff" stroke-width="7" stroke-linecap="round"/>
  <circle cx="98" cy="94" r="22" fill="#30d158"/>
  <line x1="98" y1="84" x2="98" y2="104" stroke="#052e13" stroke-width="6" stroke-linecap="round"/>
  <line x1="88" y1="94" x2="108" y2="94" stroke="#052e13" stroke-width="6" stroke-linecap="round"/>
</svg>
"""

ICON_PNG_192_B64 = (
    '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'
)

ICON_PNG_512_B64 = (
    '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'
)

ICON_PNG_192 = base64.b64decode(ICON_PNG_192_B64)
ICON_PNG_512 = base64.b64decode(ICON_PNG_512_B64)

def build_manifest_json(token):
    # start_url has to carry the token: this app has no cookies/sessions, so
    # the very first request for "/" (made by the OS launching the installed
    # app, before any of the page's own JS runs) needs the token right in the
    # URL or the server 403s it before anything else gets a chance to run.
    start_url = '/?token=' + urllib.quote(token) if token else '/'
    return json.dumps({
        "name": "Reward Time",
        "short_name": "Reward Time",
        "start_url": start_url,
        "display": "standalone",
        "background_color": "#111111",
        "theme_color": "#0a84ff",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
            {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"},
        ],
    })

# No caching here - this app has no offline functionality (every action needs
# the live backend), so the service worker only exists to satisfy the
# browser's installability check. It just passes every request straight
# through to the network.
SERVICE_WORKER_JS = """
self.addEventListener('install', function(e) { self.skipWaiting(); });
self.addEventListener('activate', function(e) { self.clients.claim(); });
self.addEventListener('fetch', function(e) { e.respondWith(fetch(e.request)); });
"""

PAGE_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="theme-color" content="#0a84ff">
<title>Reward Time</title>
<link rel="icon" type="image/svg+xml" href="/icon.svg">
<link rel="apple-touch-icon" href="/icon.svg">
<link rel="manifest" href="__MANIFEST_HREF__">
<style>
  /* Desktop/default sizing. Anything narrower than 700px (phones, in either
     orientation) gets the larger touch-friendly sizing in the media query
     below instead - a hard threshold switch, not continuous scaling, so it
     also follows a mobile browser's "Request desktop site" toggle for free
     (that mostly works by widening the browser's effective layout viewport,
     which is exactly what this threshold reacts to). */
  body { font-family: -apple-system, sans-serif; background: #111; color: #eee; margin: 0;
         padding: 16px; font-size: 17px; max-width: 480px; margin-left: auto; margin-right: auto; }
  h1 { font-size: 24px; font-weight: 700; margin: 0 0 18px; padding: 10px 0;
       display: flex; align-items: center; gap: 0.4em;
       position: sticky; top: 0; z-index: 20; background: #111;
       box-shadow: 0 4px 10px rgba(0,0,0,0.35); }
  .app-icon { width: 1.2em; height: 1.2em; flex: none; }
  .card { background: #1c1c1e; border-radius: 14px; padding: 16px; margin-bottom: 14px; }
  .card-head { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
  .move-btns { display: flex; gap: 6px; flex: none; }
  .move { flex: none; width: 48px; height: 48px; padding: 0; font-size: 18px;
          background: #2c2c2e; color: #b0b0b5; border-radius: 8px; }
  .move:disabled { opacity: 0.3; }
  .name { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
  .remaining { font-size: 18px; color: #b8b8bd; margin-bottom: 14px; }
  .card.collapsed .remaining { margin-bottom: 0; }
  .schedule { font-size: 15px; color: #8e8e93; margin: -10px 0 14px; }
  .card.collapsed .schedule { margin: 2px 0 0; }
  .card.collapsed .btns { display: none; }
  .card.collapsed .add-token-body { display: none; }
  .add-token-body { margin-top: 14px; }
  .btns { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
  .btns button { padding: 14px 0; font-size: 17px; }
  button { padding: 18px 0; border: none; border-radius: 10px; background: #0a84ff;
           color: white; font-size: 19px; font-weight: 700; }
  button:active { background: #0060df; }
  /* inset shadow rather than a border, so it lines up with the pause buttons beside it */
  .btns .revoke { grid-column: span 2; background: transparent; box-shadow: inset 0 0 0 1px #ff453a;
                  color: #ff453a; font-size: 15px; }
  .revoke:active { background: rgba(255, 69, 58, 0.15); }
  .card.collapsed .custom-btn { display: none; }
  .btns .custom-btn { grid-column: span 2; background: #2c2c2e; font-size: 15px; }
  .btns .custom-btn.wide { grid-column: 1 / -1; }
  .btns .pause-btn { background: #3a2a10; color: #ffb340; font-size: 15px; }
  /* two bars drawn in the text colour - the Unicode pause symbol shows as a coloured emoji on some phones */
  .pause-icon { display: inline-block; width: 0.6em; height: 0.75em; border-left: 0.2em solid currentColor;
                border-right: 0.2em solid currentColor; box-sizing: border-box; margin-right: 0.3em; vertical-align: -0.05em; }
  .paused-line { color: #ffb340; font-weight: 600; margin: -8px 0 12px; }
  .card.collapsed .paused-line { margin: 2px 0 0; }
  .modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: none;
                     align-items: center; justify-content: center; z-index: 100;
                     padding: 16px; box-sizing: border-box; }
  .modal-backdrop.open { display: flex; }
  .modal-box { background: #1c1c1e; border-radius: 16px; padding: 20px; width: 100%;
               max-width: 340px; max-height: 90vh; overflow-y: auto; box-sizing: border-box; }
  .modal-title { font-size: 18px; font-weight: 700; margin-bottom: 14px; text-align: center; }
  .spinner { display: inline-block; width: 15px; height: 15px; border: 2px solid rgba(255,255,255,0.35);
             border-top-color: #fff; border-radius: 50%; animation: spin 0.7s linear infinite;
             vertical-align: middle; margin-left: 6px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .modal-status-line { text-align: center; font-size: 14px; color: #9b9ba1; margin: -6px 0 14px; }
  .date-picker-wrap { position: relative; margin-bottom: 16px; }
  .date-toggle-btn { width: 100%; background: #2c2c2e; font-size: 15px; padding: 10px 0; }
  /* The time picker also edits schedule windows, on top of the schedule editor. */
  #modal-backdrop { z-index: 110; }
  .win-ends { display: flex; gap: 8px; margin-bottom: 16px; }
  .win-ends button { flex: 1; background: #2c2c2e; font-size: 15px; padding: 10px 0; }
  .win-ends button.active, .win-days button.on { background: #0a84ff; color: #fff; }
  .win-apply { margin-bottom: 14px; }
  .win-days { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-top: 8px; }
  .win-days button { padding: 9px 0; font-size: 14px; background: #2c2c2e; color: #9b9ba1; }
  .win-note { font-size: 12px; color: #9b9ba1; margin-top: 6px; }
  .modal-delete-btn { background: transparent; box-shadow: inset 0 0 0 1px #ff453a; color: #ff453a; }
  .sched-chip { cursor: pointer; }
  .cal-panel { display: none; position: absolute; top: calc(100% + 8px); left: 0; right: 0;
               background: #262628; border: 1px solid #3a3a3c; border-radius: 12px; padding: 14px;
               z-index: 10; box-shadow: 0 8px 24px rgba(0,0,0,0.45); box-sizing: border-box; }
  .cal-panel.open { display: block; }
  .cal-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .cal-nav { flex: none; width: 40px; height: 40px; padding: 0; font-size: 20px;
             background: #2c2c2e; border-radius: 8px; }
  .cal-nav:disabled { opacity: 0.3; }
  .cal-month-label { font-size: 16px; font-weight: 600; }
  .cal-weekdays { display: grid; grid-template-columns: repeat(7, 1fr); text-align: center;
                  font-size: 12px; color: #8e8e93; margin-bottom: 4px; }
  .cal-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 4px; }
  .cal-day { aspect-ratio: 1; padding: 0; font-size: 15px; font-weight: 600;
             background: transparent; color: #eee; border-radius: 8px; }
  .cal-day:disabled { color: #4a4a4c; }
  .cal-day.selected { background: #0a84ff; }
  .cal-day.empty { visibility: hidden; }
  .time-columns-header { display: flex; gap: 8px; text-align: center; font-size: 13px;
                          color: #8e8e93; font-weight: 600; margin-bottom: 6px; }
  .time-columns-header div { flex: 1; }
  .time-columns { display: flex; gap: 8px; margin-bottom: 18px; }
  .time-col { flex: 1; display: flex; flex-direction: column; gap: 6px; }
  .time-col button { flex: none; padding: 10px 0; font-size: 16px; font-weight: 600; background: #2c2c2e; }
  .time-col button.selected { background: #0a84ff; }
  .modal-actions { display: flex; gap: 10px; }
  .modal-actions button { flex: 1; padding: 14px 0; }
  .modal-cancel-btn { background: #2c2c2e; }
  .sched-box { max-width: 420px; }
  .sched-day { border-bottom: 1px solid #2c2c2e; padding: 8px 0; }
  .sched-day-head { display: flex; justify-content: space-between; align-items: center; }
  .sched-day-name { font-weight: 700; }
  .sched-links button { background: none; color: #0a84ff; padding: 4px 6px; font-size: 13px; font-weight: 600; width: auto; }
  .sched-chip { display: inline-flex; align-items: center; gap: 6px; background: #2c2c2e; border-radius: 8px;
                padding: 5px 8px; margin: 6px 6px 0 0; font-size: 14px; }
  .sched-chip button { background: none; color: #ff453a; padding: 0 2px; font-size: 16px; width: auto; }
  .sched-none { color: #9b9ba1; font-size: 14px; margin-top: 4px; }
  .btns .sched-btn { grid-column: span 2; background: #2c2c2e; font-size: 15px; }
  .section-head { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
  .section-head .fold { color: #9b9ba1; font-size: 15px; transition: transform 0.15s; }
  .section-head.folded .fold { transform: rotate(-90deg); }
  .section-body.folded { display: none; }
  .row-revoke { display: block; width: 100%; margin-top: 10px; padding: 10px 0; font-size: 14px; }
  .activity-undo { background: none; color: #0a84ff; width: auto; padding: 2px 0; font-size: 13px; }
  .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
           width: calc(100% - 32px); max-width: 448px; background: #30d158;
           color: #052e13; padding: 16px; border-radius: 12px; text-align: center;
           font-size: 17px; font-weight: 700; display: none; box-sizing: border-box; }
  h2 { font-size: 18px; font-weight: 700; margin: 24px 0 10px; }
  .guest-row { background: #1c1c1e; border-radius: 10px; padding: 12px 14px; margin-bottom: 8px; }
  .guest-row-head { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
  .guest-row.collapsed .guest-row-body { display: none; }
  .guest-row-body { margin-top: 10px; }
  .guest-row .label { font-weight: 600; }
  .guest-row .expires { font-size: 13px; color: #9b9ba1; }
  .guest-row-btns { display: flex; gap: 6px; flex: none; }
  .guest-row-btns button { flex: none; width: auto; padding: 8px 12px; font-size: 13px; }
  .guest-url-field { display: block; width: 100%; box-sizing: border-box; padding: 10px;
                      border-radius: 8px; border: 1px solid #3a3a3c; background: #111;
                      color: #9b9ba1; font-size: 13px; }
  .copy-guest { background: #2c2c2e; color: #eee; }
  .health-banner { background: #3a1d1d; border: 1px solid #ff453a; color: #ffb4ae; border-radius: 10px;
                   padding: 10px 14px; margin-bottom: 14px; font-size: 14px; }
  .health-banner b { color: #ff6b61; }
  .admin-email-row { display: flex; gap: 6px; margin-top: 8px; }
  .admin-email-row input { flex: 1 1 auto; min-width: 0; }
  .admin-email-row button { flex: none; width: auto; padding: 8px 12px; font-size: 13px; }
  .add-admin-btn { width: 100%; margin-top: 8px; padding: 12px 0; font-size: 15px; }
  .guest-scope { margin: 10px 0 2px; font-size: 14px; color: #b8b8bd; }
  .guest-scope label { display: flex; align-items: center; gap: 8px; margin: 0 0 8px; }
  .guest-scope .scope-list { margin-left: 26px; }
  .guest-scope input { width: 18px; height: 18px; }
  .activity-summary { width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 12px; }
  .activity-summary th, .activity-summary td { text-align: left; padding: 6px 4px; border-bottom: 1px solid #2c2c2e; }
  .activity-summary th { color: #9b9ba1; font-weight: 600; }
  .activity-filter { width: 100%; padding: 10px; font-size: 15px; border-radius: 8px; background: #2c2c2e;
                     color: #eee; border: none; margin-bottom: 10px; }
  .activity-row { padding: 8px 2px; border-bottom: 1px solid #2c2c2e; font-size: 14px; }
  .activity-row .when { color: #9b9ba1; font-size: 12px; }
  .activity-row.failed { color: #ff6b61; }
  .revoke-guest { background: transparent; border: 1px solid #ff453a; color: #ff453a; }
  .guest-label-input { width: 100%; box-sizing: border-box; padding: 14px; font-size: 16px;
                        border-radius: 10px; border: 1px solid #3a3a3c; background: #1c1c1e;
                        color: #eee; margin-bottom: 10px; }
  .guest-duration-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .guest-duration-btns button { background: #2c2c2e; font-size: 15px; padding: 12px 0; }

  /* Phone-sized viewport profile. Sized so two fully expanded cards fit in
     view at once with no scrolling, for a returning user acting on the same
     two devices right away - this is noticeably more compact than a typical
     native app, trading some touch-target size for that goal. */
  @media (max-width: 700px) {
    body { padding: 12px; font-size: 15px; max-width: 450px; }
    h1 { font-size: 20px; margin: 0 0 12px; padding: 8px 0; }
    .card { border-radius: 12px; padding: 12px; margin-bottom: 10px; }
    .move-btns { gap: 5px; }
    .move { width: 38px; height: 38px; font-size: 15px; border-radius: 7px; }
    .name { font-size: 16px; margin-bottom: 3px; }
    .remaining { font-size: 14px; margin-bottom: 8px; }
    .schedule { font-size: 12px; margin: -6px 0 8px; }
    .add-token-body { margin-top: 10px; }
    .btns { gap: 7px; }
    .btns button { padding: 11px 0; font-size: 15px; }
    .btns .revoke, .btns .custom-btn, .btns .pause-btn, .btns .sched-btn { font-size: 13px; }
    button { padding: 11px 0; border-radius: 8px; font-size: 15px; }
    .modal-title { font-size: 16px; margin-bottom: 10px; }
    .spinner { width: 13px; height: 13px; margin-left: 5px; }
    .modal-status-line { font-size: 13px; margin: -6px 0 10px; }
    .date-picker-wrap { margin-bottom: 12px; }
    .date-toggle-btn { font-size: 14px; padding: 9px 0; }
    .cal-panel { border-radius: 11px; padding: 11px; }
    .cal-header { margin-bottom: 8px; }
    .cal-nav { width: 36px; height: 36px; font-size: 17px; border-radius: 7px; }
    .cal-month-label { font-size: 14px; }
    .cal-weekdays { font-size: 12px; margin-bottom: 3px; }
    .cal-grid { gap: 4px; }
    .cal-day { font-size: 14px; border-radius: 7px; }
    .time-columns-header { gap: 7px; font-size: 13px; margin-bottom: 5px; }
    .modal-actions { gap: 8px; }
    .modal-actions button { padding: 11px 0; }
    .toast { width: calc(100% - 24px); max-width: 426px; padding: 13px; border-radius: 10px; font-size: 15px; }
    h2 { font-size: 15px; margin: 18px 0 8px; }
    .guest-row { border-radius: 9px; padding: 10px 11px; margin-bottom: 6px; }
    .guest-row-body { margin-top: 8px; }
    .guest-row .expires { font-size: 12px; }
    .guest-row-btns { gap: 5px; }
    .guest-row-btns button { padding: 7px 11px; font-size: 12px; }
    .guest-url-field { padding: 8px; border-radius: 7px; font-size: 12px; }
    .guest-label-input { padding: 12px; font-size: 16px; border-radius: 9px; margin-bottom: 8px; }
    .guest-duration-btns { gap: 6px; }
    .guest-duration-btns button { font-size: 13px; padding: 10px 0; }

    /* The custom time picker specifically (not the "Share this link" popup,
       which also uses .modal-box) stays capped at the same size as the
       desktop version (same max-width/max-height) and otherwise sizes to
       its natural content, exactly like desktop - it only shrinks below
       that when a short screen means the natural size would exceed
       max-height and force a scrollbar. "flex: 1 1 auto" (not "flex: 1",
       which forces a 0 starting size with nothing to grow into here and
       collapses the columns) is what gives both behaviors from one rule:
       natural size when max-height isn't binding, proportional shrinking
       once it is. Only the time columns area is allowed to shrink - the
       title/date-toggle/action buttons stay fixed size always. */
    #modal-backdrop .modal-box { border-radius: 12px; padding: 14px; overflow-y: hidden;
                 display: flex; flex-direction: column; }
    #modal-backdrop .modal-title,
    #modal-backdrop .modal-status-line,
    #modal-backdrop .date-picker-wrap,
    #modal-backdrop .win-ends,
    #modal-backdrop .win-apply,
    #modal-backdrop .time-columns-header,
    #modal-backdrop .modal-actions { flex: none; }
    #modal-backdrop .time-columns { flex: 1 1 auto; min-height: 0; margin-bottom: 10px; }
    #modal-backdrop .time-col { min-height: 0; gap: 4px; }
    #modal-backdrop .time-col button { flex: 1 1 auto; min-height: 0; box-sizing: border-box;
                                       display: flex; align-items: center; justify-content: center; padding: 0; }
  }
</style>
</head>
<body>
<h1><img src="/icon.svg" alt="" class="app-icon">Reward Time</h1>
<div class="health-banner" id="health-banner" style="display:none"></div>
<div id="cards"></div>
<div id="admin-section" style="display:none">
  <h2 class="section-head" data-section="babysitter">Babysitter Access<span class="fold">&#9662;</span></h2>
  <div class="section-body" data-section-body="babysitter">
    <div id="guest-tokens-list"></div>
    <div class="card" id="add-token-card">
      <div class="card-head" data-card-id="-1"><div class="name">Add a token</div></div>
      <div class="add-token-body">
        <input class="guest-label-input" id="guest-label" placeholder="Who is this for? (e.g. Grandma)">
        <div class="guest-scope" id="guest-scope"></div>
        <div class="guest-duration-btns" id="guest-duration-btns"></div>
      </div>
    </div>
  </div>
  <h2 class="section-head" data-section="admin">Admin Access<span class="fold">&#9662;</span></h2>
  <div class="section-body" data-section-body="admin">
    <div id="admin-links-list"></div>
    <div class="card collapsed" id="add-admin-card">
      <div class="card-head" data-card-id="-2"><div class="name">Add an admin token</div></div>
      <div class="add-token-body">
        <input class="guest-label-input" id="admin-label" placeholder="Name (shows in activity)">
        <input class="guest-label-input" id="admin-email" type="email" placeholder="Alert email (optional)">
        <button class="add-admin-btn" id="add-admin-btn">Create admin token</button>
      </div>
    </div>
  </div>
  <h2 class="section-head" data-section="activity">Activity<span class="fold">&#9662;</span></h2>
  <div class="section-body" data-section-body="activity">
    <table class="activity-summary" id="activity-summary"></table>
    <select class="activity-filter" id="activity-filter"><option value="">Everyone</option></select>
    <div id="activity-list"></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<div class="modal-backdrop" id="modal-backdrop">
  <div class="modal-box">
    <div class="modal-title" id="modal-title">Custom time</div>
    <div class="modal-status-line" id="modal-status-line"></div>
    <div class="date-picker-wrap">
      <button type="button" class="date-toggle-btn" id="date-toggle-btn">Today</button>
      <div class="cal-panel" id="cal-panel">
        <div class="cal-header">
          <button type="button" class="cal-nav" id="cal-prev">&#8249;</button>
          <div class="cal-month-label" id="cal-month-label"></div>
          <button type="button" class="cal-nav" id="cal-next">&#8250;</button>
        </div>
        <div class="cal-weekdays"><div>S</div><div>M</div><div>T</div><div>W</div><div>T</div><div>F</div><div>S</div></div>
        <div class="cal-grid" id="cal-grid"></div>
      </div>
    </div>
    <div class="win-ends" id="win-ends" style="display:none">
      <button type="button" id="win-start-btn">Start</button>
      <button type="button" id="win-end-btn">End</button>
    </div>
    <div class="time-columns-header"><div>Hour</div><div>Min</div><div>&nbsp;</div></div>
    <div class="time-columns">
      <div class="time-col" id="hour-grid"></div>
      <div class="time-col" id="minute-grid"></div>
      <div class="time-col" id="ampm-row"></div>
    </div>
    <div class="win-apply" id="win-apply" style="display:none">
      <button type="button" class="date-toggle-btn" id="win-apply-toggle">Apply to&hellip;</button>
      <div id="win-days-wrap" style="display:none">
        <div class="win-days" id="win-days"></div>
        <div class="win-note">Other selected days get their times replaced with this one.</div>
      </div>
    </div>
    <div class="modal-actions">
      <button type="button" class="modal-delete-btn" id="modal-delete-btn" style="display:none">Delete</button>
      <button type="button" class="modal-cancel-btn" id="modal-cancel-btn">Cancel</button>
      <button type="button" id="modal-set-btn">Set</button>
    </div>
  </div>
</div>
<div class="modal-backdrop" id="sched-backdrop">
  <div class="modal-box sched-box">
    <div class="modal-title" id="sched-title">Schedule</div>
    <div class="sched-none" style="text-align:center;margin-bottom:6px">Times when internet is allowed</div>
    <div id="sched-days"></div>
    <div class="modal-actions" style="margin-top:14px">
      <button type="button" class="modal-cancel-btn" id="sched-cancel-btn">Cancel</button>
      <button type="button" id="sched-save-btn">Save</button>
    </div>
  </div>
</div>
<script>
var TOKEN = new URLSearchParams(location.search).get('token') || localStorage.getItem('rt_token') || '';
if (TOKEN) { localStorage.setItem('rt_token', TOKEN); }
if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js').catch(function(){}); }
var PRESETS = __PRESETS__;
var DURATION_PRESETS = __DURATION_PRESETS__;

var modalContext = null; // { type: 'reward', profileId } or { type: 'guest' }
var calendarViewDate = new Date();
var selectedDay = null;
var selectedHour = 12;
var selectedMinute = 0;
var selectedAmPm = 'AM';

function pad2(n) { return (n < 10 ? '0' : '') + n; }

function escapeHtml(s) {
  var div = document.createElement('div');
  div.textContent = String(s);
  return div.innerHTML;
}

function sameDay(a, b) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

function scrollSelectedIntoView(container) {
  var sel = container.querySelector('.selected');
  if (sel) sel.scrollIntoView({ block: 'nearest' });
}

function renderHourGrid() {
  var html = '';
  for (var h = 1; h <= 12; h++) {
    html += '<button type="button" class="' + (h === selectedHour ? 'selected' : '') +
            '" data-hour="' + h + '">' + h + '</button>';
  }
  var el = document.getElementById('hour-grid');
  el.innerHTML = html;
  scrollSelectedIntoView(el);
}

function renderMinuteGrid() {
  var html = '';
  for (var m = 0; m < 60; m += 5) {
    html += '<button type="button" class="' + (m === selectedMinute ? 'selected' : '') +
            '" data-minute="' + m + '">' + pad2(m) + '</button>';
  }
  var el = document.getElementById('minute-grid');
  el.innerHTML = html;
  scrollSelectedIntoView(el);
}

function renderAmPm() {
  document.getElementById('ampm-row').innerHTML = ['AM', 'PM'].map(function (v) {
    return '<button type="button" class="' + (v === selectedAmPm ? 'selected' : '') +
           '" data-ampm="' + v + '">' + v + '</button>';
  }).join('');
}

function formatDateButtonLabel() {
  var today = new Date();
  today.setHours(0, 0, 0, 0);
  if (sameDay(selectedDay, today)) return 'Today';
  var tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  if (sameDay(selectedDay, tomorrow)) return 'Tomorrow';
  return selectedDay.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
}

function updateDateButton() {
  document.getElementById('date-toggle-btn').textContent = formatDateButtonLabel();
}

function setDefaultTime() {
  var now = new Date();
  var rounded = new Date(Math.ceil(now.getTime() / 300000) * 300000);
  var hour24 = rounded.getHours();
  selectedHour = hour24 % 12 || 12;
  selectedMinute = rounded.getMinutes() - (rounded.getMinutes() % 5);
  selectedAmPm = hour24 >= 12 ? 'PM' : 'AM';
}

function renderCalendarGrid() {
  var year = calendarViewDate.getFullYear();
  var month = calendarViewDate.getMonth();
  var today = new Date();
  today.setHours(0, 0, 0, 0);
  document.getElementById('cal-month-label').textContent =
    calendarViewDate.toLocaleDateString([], { month: 'long', year: 'numeric' });
  var firstWeekday = new Date(year, month, 1).getDay();
  var daysInMonth = new Date(year, month + 1, 0).getDate();
  var html = '';
  for (var i = 0; i < firstWeekday; i++) html += '<button class="cal-day empty" disabled></button>';
  for (var d = 1; d <= daysInMonth; d++) {
    var thisDate = new Date(year, month, d);
    var isPast = thisDate < today;
    var isSelected = selectedDay && sameDay(selectedDay, thisDate);
    html += '<button type="button" class="cal-day' + (isSelected ? ' selected' : '') + '"' +
            (isPast ? ' disabled' : ' data-day="' + d + '"') + '>' + d + '</button>';
  }
  document.getElementById('cal-grid').innerHTML = html;
  document.getElementById('cal-prev').disabled =
    (year === today.getFullYear() && month === today.getMonth());
}

function openPicker(context) {
  modalContext = context;
  var isWindow = context.type === 'window';
  document.querySelector('#modal-backdrop .date-picker-wrap').style.display = isWindow ? 'none' : '';
  document.getElementById('win-ends').style.display = isWindow ? '' : 'none';
  document.getElementById('win-apply').style.display = isWindow ? '' : 'none';
  document.getElementById('modal-delete-btn').style.display = isWindow && context.index !== null ? '' : 'none';
  document.getElementById('modal-set-btn').textContent = isWindow ? 'Save' : 'Set';
  calendarViewDate = new Date();
  selectedDay = new Date();
  selectedDay.setHours(0, 0, 0, 0);
  setDefaultTime();
  if (isWindow) {
    document.getElementById('win-days-wrap').style.display = 'none';
    selectWindowEnd('start');
    renderWinDays();
  }
  renderHourGrid();
  renderMinuteGrid();
  renderAmPm();
  renderCalendarGrid();
  updateDateButton();
  document.getElementById('cal-panel').classList.remove('open');
  document.getElementById('modal-title').textContent =
    context.type === 'reward' ? 'Custom reward time'
    : context.type === 'pause' ? 'Pause internet until'
    : context.type === 'window' ? (context.index === null ? 'Add time: ' : 'Edit time: ') + DAY_NAMES[context.day]
    : 'Custom access length';
  document.getElementById('modal-status-line').textContent = '';
  document.getElementById('modal-backdrop').classList.add('open');
}

function closePicker() {
  document.getElementById('modal-backdrop').classList.remove('open');
  modalContext = null;
}

function getPickerEpoch() {
  var hour24 = (selectedHour % 12) + (selectedAmPm === 'PM' ? 12 : 0);
  var d = new Date(selectedDay.getFullYear(), selectedDay.getMonth(), selectedDay.getDate(),
                    hour24, selectedMinute, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

// --- Schedule window editing (the picker in 'window' mode) ---
// modalContext: { type: 'window', day, index (null when adding), start, end,
//                 editing: 'start'|'end', days: [7 booleans] }

function minutesToPicker(m) {
  var h24 = Math.floor(m / 60) % 24;  // 1440 (midnight, end of day) shows as 12:00 AM
  selectedHour = h24 % 12 || 12;
  selectedMinute = m % 60;
  selectedAmPm = h24 >= 12 ? 'PM' : 'AM';
}

function pickerToMinutes(isEnd) {
  var m = ((selectedHour % 12) + (selectedAmPm === 'PM' ? 12 : 0)) * 60 + selectedMinute;
  return isEnd && m === 0 ? 1440 : m;
}

function updateWindowEndButtons() {
  var c = modalContext;
  var startBtn = document.getElementById('win-start-btn');
  var endBtn = document.getElementById('win-end-btn');
  startBtn.textContent = 'Start ' + minuteLabel(c.start);
  endBtn.textContent = 'End ' + minuteLabel(c.end);
  startBtn.classList.toggle('active', c.editing === 'start');
  endBtn.classList.toggle('active', c.editing === 'end');
}

function selectWindowEnd(which) {
  modalContext.editing = which;
  minutesToPicker(which === 'start' ? modalContext.start : modalContext.end);
  renderHourGrid();
  renderMinuteGrid();
  renderAmPm();
  updateWindowEndButtons();
}

// Called after any hour/minute/AM-PM pick, to keep the edited end in sync.
function windowPickChanged() {
  if (!modalContext || modalContext.type !== 'window') return;
  var isEnd = modalContext.editing === 'end';
  modalContext[isEnd ? 'end' : 'start'] = pickerToMinutes(isEnd);
  updateWindowEndButtons();
}

function renderWinDays() {
  var days = modalContext.days;
  var all = days.every(function (on) { return on; });
  document.getElementById('win-days').innerHTML =
    '<button type="button" class="' + (all ? 'on' : '') + '" data-win-day="all">All</button>' +
    DAY_NAMES.map(function (name, d) {
      return '<button type="button" class="' + (days[d] ? 'on' : '') + '" data-win-day="' + d + '">' +
             name.slice(0, 3) + '</button>';
    }).join('');
}

function mergeWindows(windows) {
  var merged = [];
  windows.slice().sort(function (a, b) { return a[0] - b[0]; }).forEach(function (w) {
    var last = merged[merged.length - 1];
    if (last && w[0] <= last[1]) { last[1] = Math.max(last[1], w[1]); } else { merged.push([w[0], w[1]]); }
  });
  return merged;
}

function saveWindow() {
  var c = modalContext;
  if (c.end <= c.start) { toast('The end has to be after the start'); return; }
  var win = [c.start, c.end];
  c.days.forEach(function (on, d) {
    if (!on) return;
    if (d === c.day) {
      var others = schedEdit.days[d].filter(function (w, i) { return i !== c.index; });
      schedEdit.days[d] = mergeWindows(others.concat([win]));
    } else {
      schedEdit.days[d] = [[win[0], win[1]]];  // "Apply to" replaces that day's times
    }
  });
  closePicker();
  renderSchedule();
}

function openWindowEditor(day, index) {
  var w = index === null ? [420, 1260] : schedEdit.days[day][index];
  var days = [false, false, false, false, false, false, false];
  days[day] = true;
  openPicker({ type: 'window', day: day, index: index, start: w[0], end: w[1], editing: 'start', days: days });
}

function submitPicker() {
  if (modalContext.type === 'window') { saveWindow(); return; }
  var epoch = getPickerEpoch();
  if (epoch <= Math.floor(Date.now() / 1000)) {
    toast('Pick a time in the future');
    return;
  }

  if (modalContext.type === 'pause') {
    var pauseProfileId = modalContext.profileId;
    closePicker();
    sendProfileAction(pauseProfileId, '/api/pause', '&until=' + epoch, 'Paused');
    return;
  }

  if (modalContext.type === 'reward') {
    // Closes right away instead of blocking on this request - progress
    // shows in the card's own "remaining" line (same as the preset
    // buttons), so the user can immediately go set/revoke time on other
    // devices rather than being stuck waiting on this one modal.
    var profileId = modalContext.profileId;
    closePicker();
    beginBusy(profileId);
    var modalReqId = newRequestId();
    var modalPoll = pollRequestStatus(modalReqId, function (label) {
      profileStageText[profileId] = label;
      updateBusyDisplay(profileId);
    });
    fetch('/api/set_until?token=' + encodeURIComponent(TOKEN) +
          '&profile_id=' + profileId + '&until=' + epoch +
          '&request_id=' + modalReqId, { method: 'POST' })
      .then(parseResponse)
      .then(function () { toast('Reward time set'); })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { clearInterval(modalPoll); endBusy(profileId); });
    return;
  }

  var setBtn = document.getElementById('modal-set-btn');
  var cancelBtn = document.getElementById('modal-cancel-btn');
  setBusy(setBtn, true);
  cancelBtn.disabled = true;

  var label = document.getElementById('guest-label').value.trim() || 'Guest';
  var pickerScope = guestScopeParam();
  if (pickerScope === null) {
    toast('Pick at least one device');
    setBusy(setBtn, false);
    cancelBtn.disabled = false;
    return;
  }
  fetch('/api/tokens/create?token=' + encodeURIComponent(TOKEN) +
        '&label=' + encodeURIComponent(label) + '&until=' + epoch + pickerScope, { method: 'POST' })
    .then(parseResponse)
    .then(function (result) {
      copyText(guestUrl(result.token));
      document.getElementById('guest-label').value = '';
      renderGuestScope(true);
      loadGuestTokens();
      loadActivity();
    })
    .catch(function (err) { toast(err.message || 'Failed - check connection'); })
    .finally(function () {
      setBusy(setBtn, false);
      cancelBtn.disabled = false;
      closePicker();
    });
}

function formatDuration(hours) {
  if (hours < 24) return hours + 'h';
  var days = hours / 24;
  return days + (days === 1 ? ' day' : ' days');
}

function formatRemaining(totalMinutes) {
  var days = Math.floor(totalMinutes / 1440);
  var hours = Math.floor((totalMinutes % 1440) / 60);
  var minutes = totalMinutes % 60;
  var parts = [];
  if (days) parts.push(days + (days === 1 ? ' day' : ' days'));
  if (hours) parts.push(hours + (hours === 1 ? ' hr' : ' hrs'));
  if (minutes || !parts.length) parts.push(minutes + ' min');
  return parts.join(' ');
}

function formatUntil(epochSeconds) {
  var d = new Date(epochSeconds * 1000);
  var isToday = d.toDateString() === new Date().toDateString();
  return isToday
    ? d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
    : d.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function formatWindowEnd(startSeconds, endSeconds) {
  var sameDay = new Date(startSeconds * 1000).toDateString() === new Date(endSeconds * 1000).toDateString();
  return sameDay
    ? new Date(endSeconds * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
    : formatUntil(endSeconds);
}

function usageText(p) {
  if (!p.used_today_minutes) return 'No use today';
  return 'Used today: ' + formatRemaining(p.used_today_minutes) +
         (p.reward_used_today_minutes ? ' (' + formatRemaining(p.reward_used_today_minutes) + ' reward)' : '');
}

function scheduleText(p) {
  var start = p.schedule_window_start, end = p.schedule_window_end;
  if (p.schedule_state === 'off') return 'Next scheduled on: ' + formatUntil(start) + ' \u2013 ' + formatWindowEnd(start, end);
  if (p.schedule_state === 'on') return 'Scheduled on now: ' + formatUntil(start) + ' \u2013 ' + formatWindowEnd(start, end);
  if (p.schedule_state === 'always_off') return 'No scheduled on time';
  if (p.schedule_state === 'always_on') return 'Always on by schedule';
  return '';
}

function parseResponse(r) {
  if (r.ok) return r.json();
  return r.json().catch(function () { return {}; }).then(function (body) {
    throw new Error(body.error || ('Failed (HTTP ' + r.status + ')'));
  });
}

function toast(msg) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  setTimeout(function () { t.style.display = 'none'; }, 1800);
}

function setBusy(btn, busy) {
  if (busy) {
    btn.dataset.origText = btn.textContent;
    btn.innerHTML = '<span class="spinner"></span>';
    btn.disabled = true;
  } else {
    btn.textContent = btn.dataset.origText;
    btn.disabled = false;
  }
}

function newRequestId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

var STAGE_LABELS = {
  queued: 'Sending request...',
  checking: 'Checking current status...',
  applying: 'Applying change...'
};

function pollRequestStatus(requestId, onStage) {
  return setInterval(function () {
    fetch('/api/request_status?token=' + encodeURIComponent(TOKEN) + '&request_id=' + requestId)
      .then(function (r) { return r.json(); })
      .then(function (data) { if (STAGE_LABELS[data.stage]) onStage(STAGE_LABELS[data.stage]); })
      .catch(function () {});
  }, 250);
}

// Multiple requests (e.g. tapping +5m and +15m in quick succession) can be
// in flight for the same profile at once - rather than each one's poll
// writing stage text straight into the shared "remaining" line (which is
// what caused visible flicker when they landed out of order), every request
// against a profile counts against a shared busy counter. While it's above
// zero the card shows a single combined status instead of racing updates,
// and the real remaining-time text is only restored once every in-flight
// request for that profile has actually settled.
var profileBusy = {};
var profileStageText = {};

function remainingEl(id) {
  return document.querySelector('[data-remaining="' + id + '"]');
}

function busyDisplayText(id) {
  var count = profileBusy[id] || 0;
  if (count > 1) return 'Updating (' + count + ' changes pending)...';
  return profileStageText[id] || 'Sending request...';
}

function updateBusyDisplay(id) {
  var el = remainingEl(id);
  if (el && (profileBusy[id] || 0) > 0) el.textContent = busyDisplayText(id);
}

function beginBusy(id) {
  profileBusy[id] = (profileBusy[id] || 0) + 1;
  updateBusyDisplay(id);
}

function endBusy(id) {
  profileBusy[id] = Math.max(0, (profileBusy[id] || 0) - 1);
  if (profileBusy[id] === 0) {
    delete profileStageText[id];
    loadProfiles();
  }
}

var lastProfiles = [];

function loadOrder() {
  try { return JSON.parse(localStorage.getItem('rt_order') || '[]'); } catch (e) { return []; }
}

function saveOrder(ids) {
  try { localStorage.setItem('rt_order', JSON.stringify(ids)); } catch (e) {}
}

function loadExpanded() {
  try { return JSON.parse(localStorage.getItem('rt_expanded') || '[]'); } catch (e) { return []; }
}

function saveExpanded(ids) {
  try { localStorage.setItem('rt_expanded', JSON.stringify(ids)); } catch (e) {}
}

var ADD_TOKEN_CARD_ID = -1;
var ADD_ADMIN_CARD_ID = -2;

function toggleExpanded(id) {
  var expandedIds = loadExpanded();
  var pos = expandedIds.indexOf(id);
  var expanding = pos === -1;
  if (expanding) { expandedIds.push(id); } else { expandedIds.splice(pos, 1); }
  saveExpanded(expandedIds);
  render(lastProfiles);
  updateAddTokenCardCollapsedState();
  if (expanding) {
    // Expanding a card near the bottom of the page reveals its new content
    // below the current scroll position - bring it into view rather than
    // leaving the user to notice and scroll down manually.
    var el = id === ADD_TOKEN_CARD_ID ? document.getElementById('add-token-card')
      : id === ADD_ADMIN_CARD_ID ? document.getElementById('add-admin-card')
      : document.querySelector('.card-head[data-card-id="' + id + '"]');
    if (el) {
      if (el.closest) { el = el.closest('.card') || el; }
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }
}

function updateAddTokenCardCollapsedState() {
  var expandedIds = loadExpanded();
  document.getElementById('add-token-card').classList.toggle('collapsed', expandedIds.indexOf(ADD_TOKEN_CARD_ID) === -1);
  document.getElementById('add-admin-card').classList.toggle('collapsed', expandedIds.indexOf(ADD_ADMIN_CARD_ID) === -1);
}

function applyOrder(profiles) {
  var order = loadOrder();
  if (!order.length) return profiles.slice();
  var byId = {};
  profiles.forEach(function (p) { byId[p.id] = p; });
  var ordered = order.filter(function (id) { return byId[id]; }).map(function (id) { return byId[id]; });
  profiles.forEach(function (p) { if (order.indexOf(p.id) === -1) ordered.push(p); });
  return ordered;
}

function render(profiles) {
  lastProfiles = profiles;
  var ordered = applyOrder(profiles);
  var expanded = loadExpanded();
  var el = document.getElementById('cards');
  el.innerHTML = '';
  ordered.forEach(function (p, idx) {
    var isCollapsed = expanded.indexOf(p.id) === -1;
    var card = document.createElement('div');
    card.className = 'card' + (isCollapsed ? ' collapsed' : '');
    var remainingText = 'No active reward time';
    if (p.remaining_minutes > 0 && p.expires_at) {
      remainingText = formatRemaining(p.remaining_minutes) + ' remaining (until ' + formatUntil(p.expires_at) + ')';
    }
    if ((profileBusy[p.id] || 0) > 0) {
      // A request for this profile is still in flight - this fetch's
      // numbers may already be stale by the time they arrive, so keep
      // showing busy status rather than a value that might change again
      // the instant the in-flight request(s) settle.
      remainingText = busyDisplayText(p.id);
    }
    var btns = PRESETS.map(function (m) {
      return '<button data-id="' + p.id + '" data-minutes="' + m + '">+' + m + 'm</button>';
    }).join('');
    var revokeBtnHtml = '<button class="revoke" data-revoke-id="' + p.id + '">Revoke</button>';
    var PAUSE_ICON = '<span class="pause-icon"></span>';
    var moveBtns = '<div class="move-btns">' +
      '<button class="move" data-move-id="' + p.id + '" data-dir="up"' + (idx === 0 ? ' disabled' : '') + '>&#9650;</button>' +
      '<button class="move" data-move-id="' + p.id + '" data-dir="down"' + (idx === ordered.length - 1 ? ' disabled' : '') + '>&#9660;</button>' +
      '</div>';
    // Row 2: Custom + Edit schedule (admins); row 3: two pause buttons + Revoke.
    var untilRow = '<button class="custom-btn' + (isAdmin ? '' : ' wide') + '" data-open-reward-picker="' + p.id + '">Custom</button>' +
      (isAdmin ? '<button class="sched-btn" data-edit-schedule="' + p.id + '">Edit schedule</button>' : '');
    var pauseBtns = '<button class="pause-btn" data-pause-id="' + p.id + '" data-pause-minutes="30">' + PAUSE_ICON + ' +30m</button>' +
      '<button class="pause-btn" data-open-pause-picker="' + p.id + '">' + PAUSE_ICON + ' Until&hellip;</button>';
    var pausedLine = !p.paused ? ''
      : '<div class="paused-line">Paused ' + (p.paused_until ? 'until ' + formatUntil(p.paused_until) : '(no end time)') + '</div>';
    card.innerHTML = '<div class="card-head" data-card-id="' + p.id + '"><div class="name">' + escapeHtml(p.name) + '</div>' + moveBtns + '</div>' +
                      '<div class="remaining" data-remaining="' + p.id + '">' + remainingText + '</div>' + pausedLine +
                      '<div class="schedule">' + scheduleText(p) + '</div>' +
                      '<div class="schedule">' + usageText(p) + '</div>' +
                      '<div class="btns">' + btns + untilRow + pauseBtns + revokeBtnHtml + '</div>';
    el.appendChild(card);
  });
}

var isAdmin = false;

var loadProfilesSeq = 0;

function loadProfiles() {
  var seq = ++loadProfilesSeq;
  fetch('/api/status?token=' + encodeURIComponent(TOKEN))
    .then(function (r) { return r.json(); })
    .then(function (data) {
      // Multiple loadProfiles() calls can overlap (e.g. one per settled
      // grant), and network timing doesn't guarantee responses arrive in
      // the order they were sent - without this guard, a slower call
      // started earlier could land after a faster, more recent one and
      // overwrite the screen with stale data.
      if (seq !== loadProfilesSeq) return;
      isAdmin = data.is_admin;
      render(data.profiles);
      var section = document.getElementById('admin-section');
      section.style.display = isAdmin ? 'block' : 'none';
      renderHealth(isAdmin ? data.health : []);
      if (isAdmin) { loadAdminLinks(); loadActivity(); renderGuestScope(false); }
      if (isAdmin) {
        renderDurationButtons();
        loadGuestTokens();
        updateAddTokenCardCollapsedState();
      }
    });
}

function renderDurationButtons() {
  var el = document.getElementById('guest-duration-btns');
  if (el.childElementCount) return;
  var presetBtns = DURATION_PRESETS.map(function (h) {
    return '<button data-guest-hours="' + h + '">' + formatDuration(h) + '</button>';
  }).join('');
  var customPicker = '<button class="custom-btn" data-open-guest-picker="1">Custom</button>';
  el.innerHTML = presetBtns + customPicker;
}

var lastGuestTokens = [];
var expandedGuestTokens = {};

function renderGuestTokens(tokens) {
  lastGuestTokens = tokens;
  var el = document.getElementById('guest-tokens-list');
  if (!tokens.length) { el.innerHTML = ''; return; }
  el.innerHTML = tokens.map(function (t) {
    var expiresStr = new Date(t.expires_at * 1000).toLocaleString([],
      { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    var isCollapsed = !expandedGuestTokens[t.token];
    return '<div class="guest-row' + (isCollapsed ? ' collapsed' : '') + '">' +
           '<div class="guest-row-head" data-guest-toggle="' + t.token + '">' +
           '<div><div class="label">' + escapeHtml(t.label) + '</div>' +
           '<div class="expires">until ' + expiresStr + scopeText(t.profile_ids) + '</div></div>' +
           '<div class="guest-row-btns">' +
           '<button class="copy-guest" data-copy-guest="' + t.token + '">Copy</button>' +
           '</div></div>' +
           '<div class="guest-row-body"><input class="guest-url-field" readonly ' +
           'onclick="this.select()" value="' + escapeHtml(guestUrl(t.token)) + '">' +
           '<button class="revoke-guest row-revoke" data-revoke-guest="' + t.token + '">Revoke</button></div>' +
           '</div>';
  }).join('');
}

function toggleGuestExpanded(token) {
  var expanding = !expandedGuestTokens[token];
  expandedGuestTokens[token] = expanding;
  renderGuestTokens(lastGuestTokens);
  if (expanding) {
    var el = document.querySelector('[data-guest-toggle="' + token + '"]');
    if (el) {
      if (el.closest) { el = el.closest('.guest-row') || el; }
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }
}

function renderHealth(problems) {
  var el = document.getElementById('health-banner');
  if (!problems || !problems.length) { el.style.display = 'none'; return; }
  el.innerHTML = '<b>Something needs attention</b><br>' + problems.map(escapeHtml).join('<br>');
  el.style.display = '';
}

var lastAdminLinks = [];
var expandedAdminLinks = {};

function renderAdminLinks(admins) {
  lastAdminLinks = admins;
  var el = document.getElementById('admin-links-list');
  // An open email field keeps its in-progress text across the periodic refresh.
  var drafts = {};
  Array.prototype.forEach.call(el.querySelectorAll('input[data-admin-email]'), function (input) {
    drafts[input.dataset.adminEmail] = input.value;
  });
  el.innerHTML = admins.map(function (a) {
    var isCollapsed = !expandedAdminLinks[a.token];
    var sub = (a.is_me ? 'you &middot; ' : '') + (a.email ? 'alerts to ' + escapeHtml(a.email) : 'no alerts');
    var email = a.token in drafts ? drafts[a.token] : a.email;
    return '<div class="guest-row' + (isCollapsed ? ' collapsed' : '') + '">' +
           '<div class="guest-row-head" data-admin-toggle="' + a.token + '">' +
           '<div><div class="label">' + escapeHtml(a.label) + '</div>' +
           '<div class="expires">' + sub + '</div></div>' +
           '<div class="guest-row-btns">' +
           '<button class="copy-guest" data-copy-guest="' + a.token + '">Copy</button>' +
           '</div></div>' +
           '<div class="guest-row-body"><input class="guest-url-field" readonly ' +
           'onclick="this.select()" value="' + escapeHtml(guestUrl(a.token)) + '">' +
           '<div class="admin-email-row"><input class="guest-url-field" type="email" placeholder="Alert email (optional)" ' +
           'data-admin-email="' + a.token + '" value="' + escapeHtml(email) + '">' +
           '<button class="copy-guest" data-save-admin-email="' + a.token + '">Save</button></div>' +
           (a.is_me ? '' : '<button class="revoke-guest row-revoke" data-revoke-admin="' + a.token + '">Revoke</button>') +
           '</div>' +
           '</div>';
  }).join('');
}

function loadAdminLinks() {
  fetch('/api/admins?token=' + encodeURIComponent(TOKEN))
    .then(function (r) { return r.json(); })
    .then(renderAdminLinks);
}

function adminPost(path, params) {
  var query = Object.keys(params).map(function (k) {
    return '&' + k + '=' + encodeURIComponent(params[k]);
  }).join('');
  return fetch(path + '?token=' + encodeURIComponent(TOKEN) + query, { method: 'POST' }).then(parseResponse);
}

function profileName(id) {
  var p = lastProfiles.filter(function (x) { return x.id === id; })[0];
  return p ? p.name : 'profile ' + id;
}

function scopeText(profileIds) {
  return profileIds ? ' &middot; ' + escapeHtml(profileIds.map(profileName).join(', ')) : '';
}

// Profile checkboxes on the "Add a token" card - all ticked by default, so a
// babysitter link covers every profile unless something is unticked.
// "All devices" (ticked by default) on the "Add a token" card; unticking it
// lists the devices, in the same order as the cards, to pick from. Kept
// across the periodic refresh unless reset (after a link is created).
function renderGuestScope(reset) {
  var el = document.getElementById('guest-scope');
  var allBox = document.getElementById('scope-all');
  var all = reset || !allBox || allBox.checked;
  var ticked = {};
  if (!reset) {
    Array.prototype.forEach.call(el.querySelectorAll('input[data-scope-id]'), function (b) {
      ticked[b.dataset.scopeId] = b.checked;
    });
  }
  el.innerHTML = '<label><input type="checkbox" id="scope-all"' + (all ? ' checked' : '') + '>All devices</label>' +
    '<div class="scope-list" id="scope-list"' + (all ? ' style="display:none"' : '') + '>' +
    applyOrder(lastProfiles).map(function (p) {
      return '<label><input type="checkbox" data-scope-id="' + p.id + '"' + (ticked[p.id] ? ' checked' : '') + '>' +
             escapeHtml(p.name) + '</label>';
    }).join('') + '</div>';
}

// '' for all devices, '&profile_ids=...' for a selection, null if nothing picked.
function guestScopeParam() {
  if (document.getElementById('scope-all').checked) return '';
  var ticked = Array.prototype.filter.call(
    document.querySelectorAll('#guest-scope input[data-scope-id]'), function (b) { return b.checked; });
  if (!ticked.length) return null;
  return '&profile_ids=' + ticked.map(function (b) { return b.dataset.scopeId; }).join(',');
}

function describeActivity(e) {
  var who = escapeHtml(e.profile || '');
  var mins = function (m) { return formatRemaining(Math.abs(m)); };
  switch (e.action) {
    case 'grant': return '+' + mins(e.minutes) + ' for ' + who;
    case 'set_until':
      return who + ' until ' + formatUntil(e.until) +
             (e.minutes ? ' (' + (e.minutes > 0 ? '+' : '-') + mins(e.minutes) + ')' : '');
    case 'revoke': return 'revoked ' + who + (e.minutes ? ' (-' + mins(e.minutes) + ')' : '');
    case 'pause': return 'paused ' + who + ' until ' + formatUntil(e.until);
    case 'schedule_set':
      try {
        var change = JSON.parse(e.detail);
        var changed = DAY_NAMES.filter(function (name, d) {
          return JSON.stringify(change.before[d]) !== JSON.stringify(change.after[d]);
        }).map(function (name) { return name.slice(0, 3); });
        return 'changed schedule for ' + who + (changed.length ? ' (' + changed.join(', ') + ')' : ' (no change)');
      } catch (err) { return 'changed schedule for ' + who; }
    case 'unpause': return 'resumed ' + who;
    case 'guest_link_created': return 'created babysitter link ' + escapeHtml(e.detail || '');
    case 'guest_link_revoked': return 'revoked babysitter link ' + escapeHtml(e.detail || '');
    case 'admin_link_created': return 'created admin link ' + escapeHtml(e.detail || '');
    case 'admin_link_revoked': return 'revoked admin link ' + escapeHtml(e.detail || '');
    case 'admin_alert_email_set': return 'alert email for ' + escapeHtml(e.detail || '');
    default: return escapeHtml(e.action) + ' ' + who;
  }
}

var lastActivityEvents = [];

function renderActivity(data) {
  var people = Object.keys(data.summary).sort();
  var cell = function (s) {
    if (!s || !(s.grants + s.custom + s.revokes + s.pauses)) return '&ndash;';
    var parts = [];
    if (s.grants + s.custom) parts.push((s.grants + s.custom) + ' &middot; ' + formatRemaining(s.minutes));
    if (s.revokes) parts.push(s.revokes + ' revoked');
    if (s.pauses) parts.push(s.pauses + ' paused');
    return parts.join(' &middot; ');
  };
  document.getElementById('activity-summary').innerHTML = people.length
    ? '<tr><th></th><th>Last 7 days</th><th>Last 30 days</th></tr>' + people.map(function (name) {
        var s = data.summary[name];
        return '<tr><td>' + escapeHtml(name) + (s.kind === 'guest' ? ' <span class="when">(babysitter)</span>' : '') +
               '</td><td>' + cell(s.week) + '</td><td>' + cell(s.month) + '</td></tr>';
      }).join('')
    : '<tr><td>No activity yet</td></tr>';

  var filter = document.getElementById('activity-filter');
  var current = filter.value;
  filter.innerHTML = '<option value="">Everyone</option>' + data.people.map(function (name) {
    return '<option value="' + escapeHtml(name) + '"' + (name === current ? ' selected' : '') + '>' +
           escapeHtml(name) + '</option>';
  }).join('');

  lastActivityEvents = data.events;
  document.getElementById('activity-list').innerHTML = data.events.map(function (e, i) {
    var when = new Date(e.ts * 1000).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric',
                                                          hour: 'numeric', minute: '2-digit' });
    return '<div class="activity-row' + (e.ok ? '' : ' failed') + '"><div>' + escapeHtml(e.actor) + ': ' +
           describeActivity(e) + (e.ok ? '' : ' &ndash; failed' + (e.action === 'schedule_set' ? '' : ': ' + escapeHtml(e.detail || ''))) +
           (e.ok && e.action === 'schedule_set' ? ' <button class="activity-undo" data-undo-schedule="' + i + '">Undo</button>' : '') +
           '</div>' +
           '<div class="when">' + when + '</div></div>';
  }).join('');
}

function loadActivity() {
  var who = document.getElementById('activity-filter').value;
  fetch('/api/activity?token=' + encodeURIComponent(TOKEN) + '&limit=50' +
        (who ? '&who=' + encodeURIComponent(who) : ''))
    .then(function (r) { return r.json(); })
    .then(renderActivity);
}

document.addEventListener('change', function (e) {
  if (e.target.id === 'activity-filter') loadActivity();
  if (e.target.id === 'scope-all') {
    document.getElementById('scope-list').style.display = e.target.checked ? 'none' : '';
  }
});

// Foldable admin sections, remembered per browser like the cards.
function loadFolded() {
  try { return JSON.parse(localStorage.getItem('rt_folded_sections') || '[]'); } catch (e) { return []; }
}

function applyFolded() {
  var folded = loadFolded();
  Array.prototype.forEach.call(document.querySelectorAll('.section-head'), function (head) {
    var isFolded = folded.indexOf(head.dataset.section) !== -1;
    head.classList.toggle('folded', isFolded);
    document.querySelector('[data-section-body="' + head.dataset.section + '"]').classList.toggle('folded', isFolded);
  });
}

document.addEventListener('click', function (e) {
  var head = e.target.closest('.section-head');
  if (!head) return;
  var folded = loadFolded();
  var pos = folded.indexOf(head.dataset.section);
  if (pos === -1) { folded.push(head.dataset.section); } else { folded.splice(pos, 1); }
  try { localStorage.setItem('rt_folded_sections', JSON.stringify(folded)); } catch (err) {}
  applyFolded();
});
applyFolded();

function loadGuestTokens() {
  fetch('/api/tokens?token=' + encodeURIComponent(TOKEN))
    .then(function (r) { return r.json(); })
    .then(renderGuestTokens);
}

function copyText(text) {
  var done = function () { toast('Link copied'); };
  var fail = function () { toast('Copy failed - long-press the link to copy manually'); };
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(done, fail);
  } else {
    var tmp = document.createElement('textarea');
    tmp.value = text;
    tmp.style.position = 'fixed';
    tmp.style.opacity = '0';
    document.body.appendChild(tmp);
    tmp.select();
    try { document.execCommand('copy'); done(); } catch (e) { fail(); }
    document.body.removeChild(tmp);
  }
}

function guestUrl(token) {
  return location.origin + location.pathname + '?token=' + encodeURIComponent(token);
}


var DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
var schedEdit = null; // { profileId, name, days: [[ [start, end], ... ] x7] }

function minuteLabel(m) {
  if (m === 1440) return 'midnight';
  var h = Math.floor(m / 60), mm = m % 60;
  return ((h + 11) % 12 + 1) + ':' + (mm < 10 ? '0' : '') + mm + ' ' + (h < 12 ? 'AM' : 'PM');
}

function renderSchedule() {
  document.getElementById('sched-title').textContent = 'Schedule: ' + schedEdit.name;
  document.getElementById('sched-days').innerHTML = schedEdit.days.map(function (windows, d) {
    var chips = windows.length ? windows.map(function (w, i) {
      return '<span class="sched-chip" data-sched-edit="' + d + ',' + i + '">' + minuteLabel(w[0]) + ' &ndash; ' + minuteLabel(w[1]) +
             '<button data-sched-remove="' + d + ',' + i + '" aria-label="Remove">&times;</button></span>';
    }).join('') : '<div class="sched-none">Blocked all day</div>';
    return '<div class="sched-day"><div class="sched-day-head"><span class="sched-day-name">' + DAY_NAMES[d] + '</span>' +
           '<span class="sched-links"><button data-sched-add="' + d + '">+ Add</button>' +
           '<button data-sched-copy="' + d + '">Copy to all days</button></span></div>' + chips + '</div>';
  }).join('');
}

function openScheduleEditor(profileId) {
  var p = lastProfiles.filter(function (x) { return String(x.id) === String(profileId); })[0];
  fetch('/api/schedule?token=' + encodeURIComponent(TOKEN) + '&profile_id=' + profileId)
    .then(parseResponse)
    .then(function (data) {
      schedEdit = { profileId: profileId, name: p ? p.name : 'profile', days: data.days };
      renderSchedule();
      document.getElementById('sched-backdrop').classList.add('open');
    })
    .catch(function (err) { toast(err.message || 'Failed - check connection'); });
}

function closeScheduleEditor() {
  document.getElementById('sched-backdrop').classList.remove('open');
  schedEdit = null;
}

function saveSchedule(profileId, days, confirmed, doneMessage) {
  return fetch('/api/schedule/set?token=' + encodeURIComponent(TOKEN) + '&profile_id=' + profileId +
               '&days=' + encodeURIComponent(JSON.stringify(days)) + (confirmed ? '&confirm=1' : '') +
               '&request_id=' + newRequestId(), { method: 'POST' })
    .then(function (r) {
      if (r.ok) return r.json();
      return r.json().then(function (body) {
        if (body.needs_confirm && !confirmed &&
            confirm(body.error + '. Save it anyway? The profile will have no internet at all except reward time.')) {
          return saveSchedule(profileId, days, true, doneMessage);
        }
        throw new Error(body.needs_confirm ? 'Not saved' : (body.error || 'Failed (HTTP ' + r.status + ')'));
      });
    })
    .then(function (result) {
      if (result && result.ok) { toast(doneMessage); loadProfiles(); loadActivity(); }
      return result;
    });
}

// Sends a per-profile action, showing its progress in the card like the
// reward buttons do.
function sendProfileAction(profileId, path, extraParams, doneMessage) {
  beginBusy(profileId);
  var reqId = newRequestId();
  var poll = pollRequestStatus(reqId, function (label) {
    profileStageText[profileId] = label;
    updateBusyDisplay(profileId);
  });
  fetch(path + '?token=' + encodeURIComponent(TOKEN) + '&profile_id=' + profileId +
        extraParams + '&request_id=' + reqId, { method: 'POST' })
    .then(parseResponse)
    .then(function () { toast(doneMessage); })
    .catch(function (err) { toast(err.message || 'Failed - check connection'); })
    .finally(function () { clearInterval(poll); endBusy(profileId); });
}

document.addEventListener('click', function (e) {
  var editSchedBtn = e.target.closest('button[data-edit-schedule]');
  if (editSchedBtn) { openScheduleEditor(editSchedBtn.dataset.editSchedule); return; }
  if (schedEdit) {
    var t = e.target.closest('button');
    if (t && t.id === 'sched-cancel-btn') { closeScheduleEditor(); return; }
    if (t && t.id === 'sched-save-btn') {
      setBusy(t, true);
      saveSchedule(schedEdit.profileId, schedEdit.days, false, 'Schedule saved')
        .then(function (result) { if (result && result.ok) closeScheduleEditor(); })
        .catch(function (err) { toast(err.message || 'Failed - check connection'); })
        .finally(function () { setBusy(t, false); });
      return;
    }
    if (t && t.dataset.schedAdd !== undefined) { openWindowEditor(Number(t.dataset.schedAdd), null); return; }
    var chip = !t && e.target.closest('[data-sched-edit]');
    if (chip) {
      var at = chip.dataset.schedEdit.split(',');
      openWindowEditor(Number(at[0]), Number(at[1]));
      return;
    }
    if (t && t.dataset.schedRemove !== undefined) {
      var parts = t.dataset.schedRemove.split(',');
      schedEdit.days[Number(parts[0])].splice(Number(parts[1]), 1);
      renderSchedule();
      return;
    }
    if (t && t.dataset.schedCopy !== undefined) {
      var src = schedEdit.days[Number(t.dataset.schedCopy)];
      schedEdit.days = schedEdit.days.map(function () { return src.map(function (w) { return [w[0], w[1]]; }); });
      renderSchedule();
      return;
    }
  }
  var undoBtn = e.target.closest('button[data-undo-schedule]');
  if (undoBtn) {
    var ev = lastActivityEvents[Number(undoBtn.dataset.undoSchedule)];
    if (!confirm('Put ' + ev.profile + "'s schedule back the way it was before this change?")) return;
    undoBtn.disabled = true;
    saveSchedule(ev.profile_id, JSON.parse(ev.detail).before, false, 'Schedule restored')
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { undoBtn.disabled = false; });
    return;
  }

  var pauseBtn = e.target.closest('button[data-pause-id]');
  if (pauseBtn) {
    sendProfileAction(pauseBtn.dataset.pauseId, '/api/pause',
                      '&minutes=' + pauseBtn.dataset.pauseMinutes, 'Pause +' + pauseBtn.dataset.pauseMinutes + ' min');
    return;
  }
  var pausePickerBtn = e.target.closest('button[data-open-pause-picker]');
  if (pausePickerBtn) {
    openPicker({ type: 'pause', profileId: pausePickerBtn.dataset.openPausePicker });
    return;
  }

  var grantBtn = e.target.closest('button[data-id]');
  if (grantBtn) {
    var grantId = grantBtn.dataset.id;
    beginBusy(grantId);
    var grantReqId = newRequestId();
    var grantPoll = pollRequestStatus(grantReqId, function (label) {
      profileStageText[grantId] = label;
      updateBusyDisplay(grantId);
    });
    fetch('/api/grant?token=' + encodeURIComponent(TOKEN) +
          '&profile_id=' + grantId + '&minutes=' + grantBtn.dataset.minutes +
          '&request_id=' + grantReqId, { method: 'POST' })
      .then(parseResponse)
      .then(function () { toast('+' + grantBtn.dataset.minutes + ' min added'); })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { clearInterval(grantPoll); endBusy(grantId); });
    return;
  }

  var revokeBtn = e.target.closest('button[data-revoke-id]');
  if (revokeBtn) {
    var revokeId = revokeBtn.dataset.revokeId;
    beginBusy(revokeId);
    var revokeReqId = newRequestId();
    var revokePoll = pollRequestStatus(revokeReqId, function (label) {
      profileStageText[revokeId] = label;
      updateBusyDisplay(revokeId);
    });
    fetch('/api/revoke?token=' + encodeURIComponent(TOKEN) +
          '&profile_id=' + revokeId + '&request_id=' + revokeReqId, { method: 'POST' })
      .then(parseResponse)
      .then(function () { toast('Back to the normal schedule'); })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { clearInterval(revokePoll); endBusy(revokeId); });
    return;
  }

  var moveBtn = e.target.closest('button[data-move-id]');
  if (moveBtn && !moveBtn.disabled) {
    var ids = applyOrder(lastProfiles).map(function (p) { return p.id; });
    var idx = ids.indexOf(Number(moveBtn.dataset.moveId));
    var swapWith = moveBtn.dataset.dir === 'up' ? idx - 1 : idx + 1;
    if (idx !== -1 && swapWith >= 0 && swapWith < ids.length) {
      var tmp = ids[idx];
      ids[idx] = ids[swapWith];
      ids[swapWith] = tmp;
      saveOrder(ids);
      render(lastProfiles);
    }
    return;
  }

  var cardHead = e.target.closest('.card-head');
  if (cardHead) {
    toggleExpanded(Number(cardHead.dataset.cardId));
    return;
  }

  var durationBtn = e.target.closest('button[data-guest-hours]');
  if (durationBtn) {
    var label = document.getElementById('guest-label').value.trim() || 'Guest';
    var durationScope = guestScopeParam();
    if (durationScope === null) { toast('Pick at least one device'); return; }
    setBusy(durationBtn, true);
    fetch('/api/tokens/create?token=' + encodeURIComponent(TOKEN) +
          '&label=' + encodeURIComponent(label) + '&hours=' + durationBtn.dataset.guestHours + durationScope,
          { method: 'POST' })
      .then(parseResponse)
      .then(function (result) {
        copyText(guestUrl(result.token));
        document.getElementById('guest-label').value = '';
        renderGuestScope(true);
        loadGuestTokens();
        loadActivity();
      })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { setBusy(durationBtn, false); });
    return;
  }

  if (e.target.closest('#add-admin-btn')) {
    var addBtn = e.target.closest('#add-admin-btn');
    var name = document.getElementById('admin-label').value.trim();
    if (!name) { toast('Give the new admin link a name'); return; }
    setBusy(addBtn, true);
    adminPost('/api/admins/create', { label: name, email: document.getElementById('admin-email').value.trim() })
      .then(function (result) {
        copyText(guestUrl(result.token));
        document.getElementById('admin-label').value = '';
        document.getElementById('admin-email').value = '';
        loadAdminLinks();
      })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { setBusy(addBtn, false); });
    return;
  }

  var saveEmailBtn = e.target.closest('button[data-save-admin-email]');
  if (saveEmailBtn) {
    var target = saveEmailBtn.dataset.saveAdminEmail;
    var input = document.querySelector('input[data-admin-email="' + target + '"]');
    saveEmailBtn.disabled = true;
    adminPost('/api/admins/set_email', { admin_token: target, email: input.value.trim() })
      .then(function () {
        toast(input.value.trim() ? 'Alerts will go to ' + input.value.trim() : 'Alerts turned off');
        input.removeAttribute('data-admin-email');
        loadAdminLinks();
      })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { saveEmailBtn.disabled = false; });
    return;
  }

  var revokeAdminBtn = e.target.closest('button[data-revoke-admin]');
  if (revokeAdminBtn) {
    var who = lastAdminLinks.filter(function (a) { return a.token === revokeAdminBtn.dataset.revokeAdmin; })[0];
    if (!confirm('Revoke the admin link for ' + (who ? who.label : 'this person') + '? It stops working immediately.')) return;
    revokeAdminBtn.disabled = true;
    adminPost('/api/admins/revoke', { admin_token: revokeAdminBtn.dataset.revokeAdmin })
      .then(function () { toast('Admin link revoked'); loadAdminLinks(); })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { revokeAdminBtn.disabled = false; });
    return;
  }

  var adminToggle = e.target.closest('[data-admin-toggle]');
  if (adminToggle && !e.target.closest('button')) {
    var t = adminToggle.dataset.adminToggle;
    expandedAdminLinks[t] = !expandedAdminLinks[t];
    renderAdminLinks(lastAdminLinks);
    return;
  }

  var revokeGuestBtn = e.target.closest('button[data-revoke-guest]');
  if (revokeGuestBtn) {
    var guest = lastGuestTokens.filter(function (t) { return t.token === revokeGuestBtn.dataset.revokeGuest; })[0];
    if (!confirm('Revoke the babysitter link for ' + (guest ? guest.label : 'this person') + '? It stops working immediately.')) return;
    revokeGuestBtn.disabled = true;
    fetch('/api/tokens/revoke?token=' + encodeURIComponent(TOKEN) +
          '&guest_token=' + encodeURIComponent(revokeGuestBtn.dataset.revokeGuest), { method: 'POST' })
      .then(parseResponse)
      .then(function () {
        toast('Access revoked');
        loadGuestTokens();
      })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { revokeGuestBtn.disabled = false; });
    return;
  }

  var copyGuestBtn = e.target.closest('button[data-copy-guest]');
  if (copyGuestBtn) {
    copyText(guestUrl(copyGuestBtn.dataset.copyGuest));
    return;
  }

  var guestToggle = e.target.closest('[data-guest-toggle]');
  if (guestToggle) {
    toggleGuestExpanded(guestToggle.dataset.guestToggle);
    return;
  }

  var openRewardBtn = e.target.closest('button[data-open-reward-picker]');
  if (openRewardBtn) {
    openPicker({ type: 'reward', profileId: openRewardBtn.dataset.openRewardPicker });
    return;
  }

  var openGuestBtn = e.target.closest('button[data-open-guest-picker]');
  if (openGuestBtn) {
    openPicker({ type: 'guest' });
    return;
  }

  if (e.target.id === 'cal-prev' || e.target.id === 'cal-next') {
    calendarViewDate.setMonth(calendarViewDate.getMonth() + (e.target.id === 'cal-next' ? 1 : -1));
    renderCalendarGrid();
    return;
  }

  var dayBtn = e.target.closest('.cal-day[data-day]');
  if (dayBtn) {
    selectedDay = new Date(calendarViewDate.getFullYear(), calendarViewDate.getMonth(), Number(dayBtn.dataset.day));
    updateDateButton();
    document.getElementById('cal-panel').classList.remove('open');
    return;
  }

  if (e.target.id === 'date-toggle-btn') {
    document.getElementById('cal-panel').classList.toggle('open');
    return;
  }

  var hourBtn = e.target.closest('#hour-grid button[data-hour]');
  if (hourBtn) {
    selectedHour = Number(hourBtn.dataset.hour);
    renderHourGrid();
    windowPickChanged();
    return;
  }

  var minuteBtn = e.target.closest('#minute-grid button[data-minute]');
  if (minuteBtn) {
    selectedMinute = Number(minuteBtn.dataset.minute);
    renderMinuteGrid();
    windowPickChanged();
    return;
  }

  var ampmBtn = e.target.closest('#ampm-row button[data-ampm]');
  if (ampmBtn) {
    selectedAmPm = ampmBtn.dataset.ampm;
    renderAmPm();
    windowPickChanged();
    return;
  }

  if (e.target.id === 'modal-set-btn') {
    submitPicker();
    return;
  }
  if (e.target.id === 'win-start-btn' || e.target.id === 'win-end-btn') {
    selectWindowEnd(e.target.id === 'win-start-btn' ? 'start' : 'end');
    return;
  }
  if (e.target.id === 'win-apply-toggle') {
    var wrap = document.getElementById('win-days-wrap');
    wrap.style.display = wrap.style.display === 'none' ? '' : 'none';
    return;
  }
  var winDayBtn = e.target.closest('button[data-win-day]');
  if (winDayBtn) {
    var key = winDayBtn.dataset.winDay;
    var wd = modalContext.days;
    if (key === 'all') {
      var allOn = wd.every(function (on) { return on; });
      modalContext.days = wd.map(function (on, d) { return allOn ? d === modalContext.day : true; });
    } else {
      wd[Number(key)] = !wd[Number(key)];
    }
    renderWinDays();
    return;
  }
  if (e.target.id === 'modal-delete-btn') {
    schedEdit.days[modalContext.day].splice(modalContext.index, 1);
    closePicker();
    renderSchedule();
    return;
  }

  if (e.target.id === 'modal-cancel-btn' || e.target.id === 'modal-backdrop') {
    closePicker();
  }
});

loadProfiles();
</script>
</body>
</html>
"""


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    # Without this, a slow/incomplete connection (scanner bots hit this port constantly
    # since it's open to the internet) can hang a handler thread indefinitely.
    timeout = REQUEST_TIMEOUT_SECONDS

    def setup(self):
        self.request.settimeout(REQUEST_TIMEOUT_SECONDS)
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)
        self._handshake_ok = True
        try:
            self.request.do_handshake()
        except (socket.timeout, ssl.SSLError):
            # Not a real client (scanner probing the port, incomplete/garbage TLS) - bail
            # out of this connection only; other threads are unaffected.
            self._handshake_ok = False

    def handle(self):
        if not self._handshake_ok:
            return
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.handle(self)
        except (socket.timeout, ssl.SSLError):
            pass

    def _supplied_token(self, qs):
        supplied = qs.get('token', [''])[0]
        auth = self.headers.getheader('Authorization', '')
        if auth.startswith('Bearer '):
            supplied = auth[len('Bearer '):]
        return supplied

    def _request_id(self, qs):
        supplied = qs.get('request_id', [''])[0]
        if supplied and REQUEST_ID_RE.match(supplied):
            return supplied
        return '%d_%s' % (int(time.time() * 1000), binascii.hexlify(os.urandom(4)))

    def _token_ok(self, qs):
        return is_token_valid(self._supplied_token(qs))

    def _send_json(self, obj, status=200):
        body = json.dumps(obj)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(parsed.query)

        if parsed.path == '/icon.svg':
            body = ICON_SVG
            self.send_response(200)
            self.send_header('Content-Type', 'image/svg+xml')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path in ('/icon-192.png', '/icon-512.png'):
            # Desktop PWA installs (e.g. Chrome on Linux) generate the actual
            # OS-level taskbar/window icon from the manifest, and that path
            # is far more reliable with a real raster icon than an SVG-only
            # manifest entry.
            body = ICON_PNG_192 if parsed.path == '/icon-192.png' else ICON_PNG_512
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == '/manifest.json':
            body = build_manifest_json(self._supplied_token(qs))
            self.send_response(200)
            self.send_header('Content-Type', 'application/manifest+json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == '/sw.js':
            body = SERVICE_WORKER_JS
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == '/':
            if not self._token_ok(qs):
                self._send_html('<h1>Forbidden</h1>', status=403)
                return
            page = PAGE_TEMPLATE.replace('__PRESETS__', json.dumps(PRESETS))
            page = page.replace('__DURATION_PRESETS__', json.dumps(DURATION_PRESETS_HOURS))
            manifest_href = '/manifest.json?token=' + urllib.quote(self._supplied_token(qs))
            page = page.replace('__MANIFEST_HREF__', manifest_href)
            self._send_html(page)
            return

        if parsed.path == '/api/status':
            if not self._token_ok(qs):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            cleanup_pending()
            actor = get_actor(self._supplied_token(qs))
            admin = get_admin(self._supplied_token(qs))
            profiles = [p for p in get_profiles() if can_change(actor, p['id'])]
            status = {'profiles': profiles, 'is_admin': admin is not None}
            if admin:
                status['me'] = admin['label']
                status['health'] = get_health()
            self._send_json(status)
            return

        if parsed.path == '/api/schedule':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
            except (KeyError, ValueError):
                self._send_json({'error': 'bad request'}, status=400)
                return
            self._send_json({'days': get_on_windows(profile_id)})
            return

        if parsed.path == '/api/activity':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            who = qs.get('who', [''])[0] or None
            try:
                limit = max(1, min(int(qs.get('limit', ['100'])[0]), 1000))
            except ValueError:
                limit = 100
            self._send_json(list_activity(who, limit))
            return

        if parsed.path == '/api/admins':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            me = self._supplied_token(qs)
            admins = list_admin_tokens()
            for a in admins:
                a['is_me'] = a['token'] == me
            self._send_json(admins)
            return

        if parsed.path == '/api/tokens':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            self._send_json(list_guest_tokens())
            return

        if parsed.path == '/api/request_status':
            if not self._token_ok(qs):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            request_id = qs.get('request_id', [''])[0]
            try:
                stage = get_request_stage(request_id)
            except ValueError:
                self._send_json({'error': 'bad request'}, status=400)
                return
            self._send_json({'stage': stage})
            return

        self._send_html('<h1>Not found</h1>', status=404)

    def do_POST(self):
        parsed = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(parsed.query)

        if parsed.path == '/api/grant':
            actor = get_actor(self._supplied_token(qs))
            if not actor:
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
                minutes = int(qs['minutes'][0])
            except (KeyError, ValueError):
                self._send_json({'error': 'bad request'}, status=400)
                return
            if not can_change(actor, profile_id):
                self._send_json({'error': "This link can't change that profile"}, status=403)
                return
            if minutes <= 0 or minutes > 24 * 60:
                self._send_json({'error': 'minutes out of range'}, status=400)
                return
            try:
                grant_time(profile_id, minutes, self._request_id(qs))
            except Exception as exc:
                log.exception('grant failed for profile_id=%s minutes=%s', profile_id, minutes)
                record_activity(actor, 'grant', profile_id, minutes=minutes, ok=False, detail=str(exc))
                self._send_json({'error': str(exc)}, status=500)
                return
            record_activity(actor, 'grant', profile_id, minutes=minutes)
            self._send_json({'ok': True})
            return

        if parsed.path == '/api/revoke':
            actor = get_actor(self._supplied_token(qs))
            if not actor:
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
            except (KeyError, ValueError):
                self._send_json({'error': 'bad request'}, status=400)
                return
            if not can_change(actor, profile_id):
                self._send_json({'error': "This link can't change that profile"}, status=403)
                return
            now = int(time.time())
            previous_expiry = profile_reward_state(profile_id)[1]
            removed = -((previous_expiry - now) // 60) if previous_expiry else 0
            # Revoke puts the profile back on its normal schedule: reward
            # time is removed and any pause is ended.
            paused = profile_pause_state(profile_id)[0]
            request_id = self._request_id(qs)
            try:
                revoke_time(profile_id, request_id)
            except Exception as exc:
                log.exception('revoke failed for profile_id=%s', profile_id)
                record_activity(actor, 'revoke', profile_id, minutes=removed, ok=False, detail=str(exc))
                self._send_json({'error': str(exc)}, status=500)
                return
            record_activity(actor, 'revoke', profile_id, minutes=removed)
            if paused:
                try:
                    unpause_profile(profile_id, request_id + '_unpause')
                except Exception as exc:
                    log.exception('unpause after revoke failed for profile_id=%s', profile_id)
                    record_activity(actor, 'unpause', profile_id, ok=False, detail=str(exc))
                    self._send_json({'error': 'Reward time removed, but the pause could not be ended: %s' % exc},
                                    status=500)
                    return
                record_activity(actor, 'unpause', profile_id)
            self._send_json({'ok': True})
            return

        if parsed.path == '/api/schedule/set':
            actor = get_actor(self._supplied_token(qs))
            if not actor or actor['kind'] != 'admin':
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
                days = json.loads(qs['days'][0])
                validate_on_windows(days)
            except (KeyError, ValueError) as exc:
                self._send_json({'error': 'Invalid schedule: %s' % exc}, status=400)
                return
            if not any(days) and qs.get('confirm', [''])[0] != '1':
                self._send_json({'error': 'This schedule never allows internet', 'needs_confirm': True},
                                status=400)
                return
            before = get_on_windows(profile_id)
            detail = json.dumps({'before': before, 'after': days})
            try:
                set_schedule(profile_id, days, self._request_id(qs))
            except Exception as exc:
                log.exception('set_schedule failed for profile_id=%s', profile_id)
                record_activity(actor, 'schedule_set', profile_id, ok=False,
                                detail=json.dumps({'before': before, 'after': days, 'error': str(exc)}))
                self._send_json({'error': str(exc)}, status=500)
                return
            record_activity(actor, 'schedule_set', profile_id, detail=detail)
            self._send_json({'ok': True})
            return

        if parsed.path in ('/api/pause', '/api/unpause'):
            actor = get_actor(self._supplied_token(qs))
            if not actor:
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
            except (KeyError, ValueError):
                self._send_json({'error': 'bad request'}, status=400)
                return
            if not can_change(actor, profile_id):
                self._send_json({'error': "This link can't change that profile"}, status=403)
                return
            now = int(time.time())
            action = parsed.path[len('/api/'):]
            until = None
            added_minutes = None
            if action == 'pause':
                try:
                    if 'minutes' in qs:
                        # Repeated presses extend: added to a timed pause's
                        # current end, otherwise counted from now.
                        paused, timed_until = profile_pause_state(profile_id)
                        start = timed_until if (paused and timed_until and timed_until > now) else now
                        until = start + int(qs['minutes'][0]) * 60
                        added_minutes = int(qs['minutes'][0])
                    else:
                        until = int(qs['until'][0])
                except (KeyError, ValueError):
                    self._send_json({'error': 'bad request'}, status=400)
                    return
                if until <= now or until > now + 32 * 24 * 3600:
                    self._send_json({'error': 'Pick a time within one month from now'}, status=400)
                    return
            # Logged as the time this press added (a repeat press adds to the end).
            minutes = None
            if until:
                minutes = added_minutes if 'minutes' in qs else (until - now) // 60
            try:
                if action == 'pause':
                    pause_profile(profile_id, until, self._request_id(qs))
                else:
                    unpause_profile(profile_id, self._request_id(qs))
            except Exception as exc:
                log.exception('%s failed for profile_id=%s', action, profile_id)
                record_activity(actor, action, profile_id, minutes=minutes, until=until,
                                ok=False, detail=str(exc))
                self._send_json({'error': str(exc)}, status=500)
                return
            record_activity(actor, action, profile_id, minutes=minutes, until=until)
            self._send_json({'ok': True})
            return

        if parsed.path == '/api/set_until':
            actor = get_actor(self._supplied_token(qs))
            if not actor:
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
                until = int(qs['until'][0])
            except (KeyError, ValueError):
                self._send_json({'error': 'bad request'}, status=400)
                return
            if not can_change(actor, profile_id):
                self._send_json({'error': "This link can't change that profile"}, status=403)
                return
            now = int(time.time())
            if until <= now or until > now + 32 * 24 * 3600:
                self._send_json({'error': 'Pick a date within one month from today'}, status=400)
                return
            previous_expiry = profile_reward_state(profile_id)[1]
            added = (until - max(now, previous_expiry or now)) // 60
            try:
                set_expiry(profile_id, until, self._request_id(qs))
            except Exception as exc:
                log.exception('set_until failed for profile_id=%s', profile_id)
                record_activity(actor, 'set_until', profile_id, minutes=added, until=until,
                                ok=False, detail=str(exc))
                self._send_json({'error': str(exc)}, status=500)
                return
            record_activity(actor, 'set_until', profile_id, minutes=added, until=until)
            self._send_json({'ok': True})
            return

        if parsed.path == '/api/tokens/create':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            label = qs.get('label', [''])[0].strip() or 'Guest'
            now = int(time.time())
            if 'until' in qs:
                try:
                    expires_at = int(qs['until'][0])
                except ValueError:
                    self._send_json({'error': 'bad request'}, status=400)
                    return
            else:
                try:
                    expires_at = now + int(float(qs['hours'][0]) * 3600)
                except (KeyError, ValueError):
                    self._send_json({'error': 'bad request'}, status=400)
                    return
            if expires_at <= now or expires_at > now + 365 * 24 * 3600:
                self._send_json({'error': 'Pick a date within the next year'}, status=400)
                return
            profile_ids = None
            if qs.get('profile_ids', [''])[0]:
                try:
                    profile_ids = sorted(set(int(x) for x in qs['profile_ids'][0].split(',')))
                except ValueError:
                    self._send_json({'error': 'bad request'}, status=400)
                    return
            new_token = create_guest_token(label, expires_at, profile_ids)
            scope = 'all profiles' if profile_ids is None else ', '.join(
                profile_reward_state(pid)[0] or str(pid) for pid in profile_ids)
            record_activity(get_actor(self._supplied_token(qs)), 'guest_link_created', until=expires_at,
                            detail='%s (%s)' % (label, scope))
            self._send_json({'ok': True, 'token': new_token})
            return

        if parsed.path in ('/api/admins/create', '/api/admins/set_email', '/api/admins/revoke'):
            me = self._supplied_token(qs)
            if not is_admin_token(me):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            email = qs.get('email', [''])[0].strip()
            if email and not EMAIL_RE.match(email):
                self._send_json({'error': "That email address doesn't look right"}, status=400)
                return
            if parsed.path == '/api/admins/create':
                label = qs.get('label', [''])[0].strip()
                if not label:
                    self._send_json({'error': 'Give the new admin link a name'}, status=400)
                    return
                new_token = create_admin_token(label, email)
                record_activity(get_actor(me), 'admin_link_created', detail=label)
                self._send_json({'ok': True, 'token': new_token})
                return
            target = qs.get('admin_token', [''])[0]
            if not target:
                self._send_json({'error': 'bad request'}, status=400)
                return
            target_label = ([a['label'] for a in list_admin_tokens() if a['token'] == target] or ['?'])[0]
            if parsed.path == '/api/admins/set_email':
                set_admin_email(target, email)
                record_activity(get_actor(me), 'admin_alert_email_set',
                                detail='%s: %s' % (target_label, email or 'alerts off'))
            else:
                if target == me:
                    self._send_json({'error': "You can't revoke your own link"}, status=400)
                    return
                try:
                    revoke_admin_token(target)
                except ValueError as exc:
                    self._send_json({'error': str(exc)}, status=400)
                    return
                record_activity(get_actor(me), 'admin_link_revoked', detail=target_label)
            self._send_json({'ok': True})
            return

        if parsed.path == '/api/tokens/revoke':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            guest_token = qs.get('guest_token', [''])[0]
            if not guest_token:
                self._send_json({'error': 'bad request'}, status=400)
                return
            revoked_label = revoke_guest_token(guest_token)
            if revoked_label:
                record_activity(get_actor(self._supplied_token(qs)), 'guest_link_revoked', detail=revoked_label)
            self._send_json({'ok': True})
            return

        self._send_json({'error': 'not found'}, status=404)

    def address_string(self):
        # The stdlib default does a reverse-DNS lookup (socket.getfqdn()) with no
        # timeout, on every single request - this app is internet-facing and gets
        # hit by scanners constantly, so that's a real hang/resource risk. The raw
        # IP is all this app ever needs for logging.
        return self.client_address[0]

    def log_message(self, fmt, *args):
        # Never let the bearer token reach the log - the default request-line
        # logging includes the full query string, token and all.
        msg = TOKEN_REDACT_RE.sub(r'\1REDACTED', fmt % args)
        log.info("%s - %s", self.address_string(), msg)


class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True


def main():
    server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    server.socket = ssl.wrap_socket(
        server.socket, certfile=CERT_FILE, keyfile=KEY_FILE, server_side=True,
        do_handshake_on_connect=False)
    server.serve_forever()


if __name__ == '__main__':
    main()
