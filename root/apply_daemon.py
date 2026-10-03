#!/usr/bin/env python
# Must run as root - calls synowebapi, which is root-only. Watches PENDING_DIR for
# request files dropped by the (unprivileged) reward_server.py app, and applies them
# via the real Safe Access API (SYNO.SafeAccess.AccessControl.ConfigGroup.Reward.Ultra),
# which - unlike a direct SQLite write - actually notifies the enforcement daemon.
#
# This file lives in the root-owned ROOT_DIR, never in the app's own directory:
# anything root runs from a directory the app user can write to is effectively
# root access for the app user. PENDING_DIR, by contrast, *is* writable by the
# internet-facing app, so nothing here opens a path in it in a way that could
# follow a symlink planted there: requests are read with O_NOFOLLOW, and
# status files are written to a fresh, randomly named file (O_CREAT|O_EXCL,
# which never follows a symlink) and then renamed into place.
import binascii
import glob
import json
import logging
import logging.handlers
import os
import subprocess
import time

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PENDING_DIR = '__APP_DIR__/pending'
MAX_REQUEST_BYTES = 4096
# Rewritten every HEARTBEAT_SECONDS so the unprivileged app and monitor can
# tell this daemon is alive (they can't signal a root process to check).
HEARTBEAT_PATH = os.path.join(ROOT_DIR, 'apply_daemon.heartbeat')
HEARTBEAT_SECONDS = 30
SYNOWEBAPI = '/usr/syno/bin/synowebapi'
API = 'SYNO.SafeAccess.AccessControl.ConfigGroup.Reward.Ultra'
PAUSE_API = 'SYNO.SafeAccess.AccessControl.ConfigGroup'
# Safe Access only pauses indefinitely (it ignores any expiry), so timed
# pauses are tracked here - {config_group_id: unpause_at} - and undone by
# this daemon when due. World-readable so the app can show "paused until".
PAUSES_PATH = os.path.join(ROOT_DIR, 'pauses.json')
PAUSE_CHECK_SECONDS = 5
PAUSE_ACTIONS = ('pause', 'unpause')
POLL_SECONDS = 0.3

log = logging.getLogger('apply_daemon')
log.setLevel(logging.INFO)
_handler = logging.handlers.RotatingFileHandler(
    os.path.join(ROOT_DIR, 'apply_daemon.log'), maxBytes=2 * 1024 * 1024, backupCount=1)
_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
log.addHandler(_handler)


def get_current_reward(config_group_id):
    out = subprocess.check_output([
        SYNOWEBAPI, '--exec', 'api=%s' % API, 'method=get', 'version=1',
        'config_group_id=%d' % config_group_id
    ])
    data = json.loads(out[out.index('{'):])
    groups = data.get('data', {}).get('config_groups') or []
    if not groups:
        return None
    rewards = groups[0].get('ultra_rewards') or []
    now = int(time.time())
    active = [r for r in rewards if r['expired'] > now]
    if not active:
        return None
    return max(active, key=lambda r: r['expired'])


def set_reward(config_group_id, available, expired):
    payload = json.dumps([{'available': available, 'expired': expired}])
    subprocess.check_output([
        SYNOWEBAPI, '--exec', 'api=%s' % API, 'method=set', 'version=1',
        'config_group_id=%d' % config_group_id, 'ultra_rewards=%s' % payload
    ])


def set_pause(config_group_id, paused):
    subprocess.check_output([
        SYNOWEBAPI, '--exec', 'api=%s' % PAUSE_API, 'method=set', 'version=1',
        'config_group_id=%d' % config_group_id, 'pause=%s' % ('true' if paused else 'false')
    ])


def load_pauses():
    try:
        with open(PAUSES_PATH) as f:
            return dict((int(k), int(v)) for k, v in json.load(f).items())
    except (IOError, ValueError):
        return {}


def save_pauses(pauses):
    tmp = PAUSES_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(dict((str(k), v) for k, v in pauses.items()), f)
    os.chmod(tmp, 0o644)
    os.rename(tmp, PAUSES_PATH)


def process_pause(path, base, req):
    # 'pause' with until (epoch) for a timed pause, or until=0 for no end
    # time; 'unpause' resumes now. Either replaces any earlier timed pause.
    cgid = int(req['config_group_id'])
    try:
        write_stage(base, 'applying')
        pauses = load_pauses()
        if req['action'] == 'pause':
            until = int(req.get('until', 0))
            set_pause(cgid, True)
            if until:
                pauses[cgid] = until
            else:
                pauses.pop(cgid, None)
        else:
            set_pause(cgid, False)
            pauses.pop(cgid, None)
        save_pauses(pauses)
        finish_ok(path, base, req['action'], cgid)
    except Exception as exc:
        finish_error(path, base, exc)


def expire_pauses():
    pauses = load_pauses()
    now = int(time.time())
    due = [cgid for cgid, until in pauses.items() if until <= now]
    for cgid in due:
        try:
            set_pause(cgid, False)
            pauses.pop(cgid)
            log.info('pause ended config_group_id=%s', cgid)
        except Exception:
            log.exception('could not end pause for config_group_id=%s (will retry)', cgid)
    if due:
        save_pauses(pauses)


def write_marker(path, content):
    # The finished file belongs to PENDING_DIR's owner (the app user), who
    # reads and then deletes it.
    tmp = '%s.%s.tmp' % (path, binascii.hexlify(os.urandom(8)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        st = os.stat(PENDING_DIR)
        os.fchown(f.fileno(), st.st_uid, st.st_gid)
        f.write(content)
    os.rename(tmp, path)


def read_request(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        data = f.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError('request file too large')
    return json.loads(data)


def write_stage(base, stage):
    write_marker(base + '.status', stage)


def finish_ok(path, base, action, cgid):
    os.remove(path)
    try:
        os.remove(base + '.status')
    except OSError:
        pass
    write_marker(base + '.done', '')
    log.info('%s config_group_id=%s -> ok', action, cgid)


def finish_error(path, base, exc):
    log.exception('failed processing %s', path)
    try:
        os.remove(base + '.status')
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass
    try:
        write_marker(base + '.error', str(exc))
    except Exception:
        log.exception('could not write error marker for %s', path)


def process_group(cgid, items):
    # items: [(path, base, req), ...] for one config_group_id, oldest first.
    # synowebapi is a separate process per call and is the slow part here -
    # with the client no longer throttling how fast a user can tap through
    # several presets, requests for the same profile often land in the same
    # poll cycle. Handling them with one get + one set instead of a get/set
    # pair per request (applying each one's effect to an in-memory running
    # total first) cuts that case from 2N synowebapi calls to 2 regardless
    # of N, which is what actually keeps it under the client's wait timeout.
    for path, base, req in items:
        write_stage(base, 'checking')
    try:
        current = get_current_reward(cgid)
        state = (current['available'], current['expired']) if current else None
        for path, base, req in items:
            write_stage(base, 'applying')
            action = req['action']
            now = int(time.time())
            if action == 'grant':
                minutes = int(req['minutes'])
                if state is None:
                    state = (now, now + minutes * 60)
                else:
                    state = (state[0], state[1] + minutes * 60)
            elif action == 'set_until':
                until = int(req['until'])
                state = (state[0] if state else now, until)
            elif action == 'revoke':
                if state is not None:
                    state = (state[0], now)
            else:
                raise ValueError('unknown action %r' % action)
        if state is not None:
            set_reward(cgid, state[0], state[1])
        for path, base, req in items:
            finish_ok(path, base, req['action'], cgid)
    except Exception as exc:
        for path, base, req in items:
            finish_error(path, base, exc)


def write_heartbeat():
    tmp = HEARTBEAT_PATH + '.tmp'
    with open(tmp, 'w') as f:
        f.write('%d\n' % int(time.time()))
    os.chmod(tmp, 0o644)
    os.rename(tmp, HEARTBEAT_PATH)


def main():
    # PENDING_DIR is created by the app itself (as the app user); creating it
    # here as root would leave the app unable to write to it.
    log.info('apply_daemon started')
    last_heartbeat = 0
    last_pause_check = 0
    while True:
        if time.time() - last_pause_check >= PAUSE_CHECK_SECONDS:
            try:
                expire_pauses()
            except Exception:
                log.exception('pause expiry check failed')
            last_pause_check = time.time()
        if time.time() - last_heartbeat >= HEARTBEAT_SECONDS:
            try:
                write_heartbeat()
            except Exception:
                log.exception('heartbeat write failed')
            last_heartbeat = time.time()
        groups = {}
        for path in sorted(glob.glob(os.path.join(PENDING_DIR, '*.json'))):
            base = path[:-len('.json')]
            try:
                req = read_request(path)
                cgid = int(req['config_group_id'])
                if req.get('action') in PAUSE_ACTIONS:
                    process_pause(path, base, req)
                    continue
            except Exception as exc:
                finish_error(path, base, exc)
                continue
            groups.setdefault(cgid, []).append((path, base, req))
        for cgid, items in groups.items():
            process_group(cgid, items)
        time.sleep(POLL_SECONDS)


if __name__ == '__main__':
    main()
