#!/usr/bin/env python
# Keeps Reward Time's block page (rt-blocked.cgi) in place of Synology's
# blocked.cgi on Safe Access's "blocked by schedule" page. Run by root's cron
# every 5 minutes; writes a one-line status to blockpage.status, which
# monitor.py watches.
#
# The only Synology file changed is block_page/blocktime/.htaccess, whose
# rewrite rules send every URL to blocked.cgi; the patched copy sends them to
# rt-blocked.cgi instead. Each run, by fingerprint (sha256):
#   - .htaccess is our patched copy: make sure rt-blocked.cgi is current.
#   - .htaccess is Synology's original (a Safe Access update put it back):
#     patch it again, and say so (monitor.py sends that as an event).
#   - anything else, or blocked.cgi itself changed: touch nothing and report
#     "failed", so the monitor emails a PROBLEM to look at.
#
#   blockpage_patch.py                 check, re-applying if needed (cron)
#   blockpage_patch.py --install       record the original files, then patch
#   blockpage_patch.py --record-stock  remember the current (original) files
#   blockpage_patch.py --remove        put Synology's .htaccess back
import hashlib
import json
import os
import pwd
import sys
import time

ROOT_DIR = '__ROOT_DIR__'
HERE = os.path.join(ROOT_DIR, 'blockpage')
BLOCK_DIR = '/var/packages/SafeAccess/target/block_page/blocktime'
HTACCESS = os.path.join(BLOCK_DIR, '.htaccess')
STOCK_CGI = os.path.join(BLOCK_DIR, 'cgi', 'blocked.cgi')
OUR_CGI = os.path.join(BLOCK_DIR, 'rt-blocked.cgi')
OUR_CGI_SRC = os.path.join(HERE, 'rt-blocked.cgi')
STOCK_RECORD = os.path.join(HERE, 'stock.json')
STOCK_HTACCESS = os.path.join(HERE, 'htaccess.stock')
CACHE_DIR = os.path.join(ROOT_DIR, 'blockpage-cache')
STATUS = os.path.join(ROOT_DIR, 'blockpage.status')
WEB_USER = 'system'   # what the block page's httpd runs CGIs as


def read(path):
    with open(path, 'rb') as f:
        return f.read()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def patched(stock_text):
    return stock_text.replace(b'/blocked.cgi', b'/rt-blocked.cgi')


def write_atomic(path, data, mode):
    tmp = '%s.rt-%d.tmp' % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chown(tmp, 0, 0)
    os.chmod(tmp, mode)
    os.rename(tmp, path)


def status(text):
    write_atomic(STATUS, ('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), text)).encode('utf-8'), 0o644)
    print(text)


def ensure_cache_dir():
    pw = pwd.getpwnam(WEB_USER)
    if os.path.islink(CACHE_DIR):
        os.remove(CACHE_DIR)
    if not os.path.isdir(CACHE_DIR):
        os.mkdir(CACHE_DIR, 0o700)
    st = os.lstat(CACHE_DIR)
    if st.st_uid != pw.pw_uid:
        os.chown(CACHE_DIR, pw.pw_uid, pw.pw_gid)
    os.chmod(CACHE_DIR, 0o700)


def ensure_our_cgi():
    src = read(OUR_CGI_SRC)
    if os.path.islink(OUR_CGI) or not os.path.isfile(OUR_CGI) or read(OUR_CGI) != src:
        write_atomic(OUR_CGI, src, 0o755)
        return True
    return False


def record_stock():
    text = read(HTACCESS)
    if b'rt-blocked.cgi' in text or b'/blocked.cgi' not in text:
        sys.exit('.htaccess does not look like Synology\'s original - not recording it')
    write_atomic(STOCK_HTACCESS, text, 0o644)
    record = {'htaccess': sha(text), 'blocked_cgi': sha(read(STOCK_CGI)),
              'recorded': time.strftime('%Y-%m-%d %H:%M:%S')}
    write_atomic(STOCK_RECORD, json.dumps(record, indent=1).encode('utf-8'), 0o644)
    print('recorded stock files: %s' % record)


def check(installing=False):
    try:
        stock = json.loads(read(STOCK_RECORD).decode('utf-8'))
        stock_text = read(STOCK_HTACCESS)
    except (IOError, OSError, ValueError):
        return status('failed: no record of the original files - run --record-stock')
    if sha(read(STOCK_CGI)) != stock['blocked_cgi']:
        return status('failed: Synology\'s blocked.cgi changed (Safe Access update?) - '
                      'check the block page, then re-run --record-stock')
    current = sha(read(HTACCESS))
    ensure_cache_dir()
    if current == sha(patched(stock_text)):
        updated = ensure_our_cgi()
        return status('ok: patched' + (' (rt-blocked.cgi updated)' if updated else ''))
    if current == stock['htaccess']:
        ensure_our_cgi()
        write_atomic(HTACCESS, patched(stock_text), 0o644)
        if installing:
            return status('ok: installed')
        return status('ok: re-applied - .htaccess was back to Synology\'s original')
    return status('failed: block page .htaccess is not the original or our patched copy - left alone')


def remove():
    write_atomic(HTACCESS, read(STOCK_HTACCESS), 0o644)
    if os.path.isfile(OUR_CGI) and not os.path.islink(OUR_CGI):
        os.remove(OUR_CGI)
    status('removed: Synology\'s block page restored (remove the cron line to keep it)')


if __name__ == '__main__':
    if os.getuid() != 0:
        sys.exit('run as root')
    arg = sys.argv[1] if len(sys.argv) > 1 else ''
    if arg == '--install':
        record_stock()
        check(installing=True)
    elif arg == '--record-stock':
        record_stock()
    elif arg == '--remove':
        remove()
    elif arg == '':
        check()
    else:
        sys.exit(__doc__ if __doc__ else 'usage: blockpage_patch.py [--record-stock|--remove]')
