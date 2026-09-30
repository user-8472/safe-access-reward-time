#!/usr/bin/env python
# Must run as root - calls synowebapi, which is root-only. Watches PENDING_DIR for
# request files dropped by the (unprivileged) reward_server.py app, and applies them
# via the real Safe Access API (SYNO.SafeAccess.AccessControl.ConfigGroup.Reward.Ultra),
# which - unlike a direct SQLite write - actually notifies the enforcement daemon.
import glob
import json
import logging
import logging.handlers
import os
import subprocess
import time

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PENDING_DIR = os.path.join(APP_DIR, 'pending')
SYNOWEBAPI = '/usr/syno/bin/synowebapi'
API = 'SYNO.SafeAccess.AccessControl.ConfigGroup.Reward.Ultra'
POLL_SECONDS = 0.3

log = logging.getLogger('apply_daemon')
log.setLevel(logging.INFO)
_handler = logging.handlers.RotatingFileHandler(
    os.path.join(APP_DIR, 'apply_daemon.log'), maxBytes=2 * 1024 * 1024, backupCount=1)
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


def write_stage(base, stage):
    with open(base + '.status', 'w') as f:
        f.write(stage)


def process(path):
    base = path[:-len('.json')]
    try:
        with open(path) as f:
            req = json.load(f)
        action = req['action']
        cgid = int(req['config_group_id'])
        now = int(time.time())

        write_stage(base, 'checking')
        current = get_current_reward(cgid)

        write_stage(base, 'applying')
        if action == 'grant':
            minutes = int(req['minutes'])
            if current:
                set_reward(cgid, current['available'], current['expired'] + minutes * 60)
            else:
                set_reward(cgid, now, now + minutes * 60)
        elif action == 'set_until':
            until = int(req['until'])
            available = current['available'] if current else now
            set_reward(cgid, available, until)
        elif action == 'revoke':
            if current:
                set_reward(cgid, current['available'], now)
        else:
            raise ValueError('unknown action %r' % action)

        os.remove(path)
        try:
            os.remove(base + '.status')
        except OSError:
            pass
        open(base + '.done', 'w').close()
        log.info('%s config_group_id=%s -> ok', action, cgid)
    except Exception as exc:
        log.exception('failed processing %s', path)
        try:
            os.remove(base + '.status')
        except OSError:
            pass
        try:
            os.remove(path)
        except OSError:
            pass
        with open(base + '.error', 'w') as f:
            f.write(str(exc))


def main():
    if not os.path.isdir(PENDING_DIR):
        os.makedirs(PENDING_DIR)
    log.info('apply_daemon started')
    while True:
        for path in sorted(glob.glob(os.path.join(PENDING_DIR, '*.json'))):
            process(path)
        time.sleep(POLL_SECONDS)


if __name__ == '__main__':
    main()
