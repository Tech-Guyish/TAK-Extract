"""Regression tests for the auth system: roles, session timeout, failed-
login lockout, CSRF, password rules, and the bootstrap-password flow.

No live Postgres needed - this is all access control / packaging, not
query logic (matches this project's usual dev flow - see test_db.py for
the one script that *does* need a live database).

AUTH_MODE is read as a module-level constant at import time (see app.py),
so each mode's scenarios run in their own subprocess rather than trying to
reload the module in-process. Run with: python tests/test_auth.py
"""
import os
import subprocess
import sys
import tempfile

# This file lives in tests/; REPO is the checkout above it - the directory
# every snippet below runs in, because app.py, exports.py and the rest are
# imported from there. HERE is this folder, which the snippets need on
# PYTHONPATH for test_support.
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
failures = []


def check(label, cond):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}")
    if not cond:
        failures.append(label)


def run(code, env_overrides):
    """Run a snippet of Python in a fresh subprocess with the given env,
    from this repo's directory. Returns the completed process."""
    env = dict(os.environ)
    env.update(env_overrides)
    # cwd is the checkout, so `import app` resolves there; tests/ goes on
    # PYTHONPATH behind it so `import test_support` resolves here.
    env["PYTHONPATH"] = os.pathsep.join(
        [HERE] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    # Every snippet gets the login() helper (see test_support.py) without
    # spelling out the import - /login now needs a CSRF token, and this
    # keeps the 27 call sites as one-line replacements.
    code = "from test_support import login, logout" + chr(10) + code
    return subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env,
                           capture_output=True, text=True)


# NO_COLOR so the startup banner these tests parse comes out as plain text.
# The banner now highlights the admin username/password/URL in ANSI (see
# app.py's _hl) for the human reading `docker compose logs`; a test that
# greps the password out of it needs the machine-readable form, which is
# exactly what NO_COLOR is the standard switch for. The color itself is
# covered by its own test below.
DB_ENV = {"DB_HOST": "unused", "DB_PORT": "5432", "DB_NAME": "unused",
          "DB_USER": "unused", "DB_PASSWORD": "unused", "NO_COLOR": "1"}


def local_env(**extra):
    env = dict(DB_ENV)
    env.update({
        "AUDIT_DB": tempfile.mktemp(suffix=".sqlite"),
        "AUTH_MODE": "local",
        "SECRET_KEY": "test-secret",
        "BOOTSTRAP_ADMIN_USERNAME": "admin",
        "BOOTSTRAP_ADMIN_PASSWORD": "adminpass12345",
    })
    env.update(extra)
    return env


# ---------------------------------------------------------------------------
# Local mode: session timeout + session.permanent
# ---------------------------------------------------------------------------
# An unreadable .env must not kill the import. On a side-by-side install
# .env is owner-only (SECRET_KEY, the database password) and systemd reads
# it as root before dropping privileges - so a tool running AS the service
# account cannot open it, and those callers put the settings in the
# environment instead. This died with PermissionError on a real install,
# taking connect-database.sh's baseline step and check-database.sh with it.
r = run("""
import builtins, os, sys, tempfile
# There must BE a .env for this to test anything: it is gitignored, so on a
# clean checkout find_dotenv() returns '' and load_dotenv() never calls
# open() at all - the test would pass without exercising the guard. Write
# one into a temp cwd so the unreadable path is genuinely taken. The repo
# goes on sys.path first, because find_dotenv() searches the working
# directory and `import app` would otherwise follow it out of the repo.
_repo = os.getcwd()
sys.path.insert(0, _repo)
_d = tempfile.mkdtemp()
with open(os.path.join(_d, '.env'), 'w') as fh:
    fh.write('UNREADABLE=1' + chr(10))
os.chdir(_d)
_opened = []
_real_open = builtins.open
def _denying_open(file, *a, **kw):
    if str(file).endswith('.env'):
        _opened.append(str(file))
        raise PermissionError(13, 'Permission denied', str(file))
    return _real_open(file, *a, **kw)
builtins.open = _denying_open
try:
    import app
finally:
    builtins.open = _real_open
assert _opened, 'the guard was never exercised - no .env was opened'
assert app.app.config['SECRET_KEY'], 'settings should come from the environment'
print('OK')
""", local_env())
check("an unreadable .env does not stop the app importing - the environment "
      "carries the settings instead",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# audit.sqlite must not be left at the umask's mercy. sqlite3 creates it
# 0666 & ~umask - measured at 644 on a real install - and it holds the TAK
# Server password in plaintext (app_settings), every password hash, and the
# hash-chained log. Asserted by watching the call rather than the resulting
# mode, because Windows cannot express 0600 and the mode check would pass
# vacuously there.
r = run("""
import os
_calls = []
_real_chmod = os.chmod
def _watch(path, mode, *a, **kw):
    _calls.append((str(path), mode))
    return _real_chmod(path, mode, *a, **kw)
os.chmod = _watch
try:
    import app
finally:
    os.chmod = _real_chmod
db = os.environ['AUDIT_DB']
hits = [m for p, m in _calls if os.path.basename(p) == os.path.basename(db)]
assert hits, 'the audit database mode was never restricted'
assert 0o600 in hits, 'expected 0o600, got %s' % [oct(m) for m in hits]
print('OK')
""", local_env())
check("the audit database is restricted to its owner on startup, whatever "
      "the umask was",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

r = run("""
import app
c = app.app.test_client()
r = login(c, data={'username': 'admin', 'password': 'adminpass12345'})
with c.session_transaction() as sess:
    assert sess.permanent is True, "session.permanent must be set at login"
cookie = next(h for h in r.headers.getlist('Set-Cookie') if h.startswith('session='))
assert 'Max-Age=1800' in cookie or 'Expires=' in cookie, cookie
print('OK')
""", local_env())
check("login sets session.permanent + a ~30min cookie expiry",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Local mode: failed-login lockout
# ---------------------------------------------------------------------------
r = run("""
import app
c = app.app.test_client()
for _ in range(app.FAILED_LOGIN_LIMIT):
    resp = login(c, data={'username': 'admin', 'password': 'wrong'})
    assert resp.status_code == 200
# 6th attempt - even with the CORRECT password - must still be locked out.
resp = login(c, data={'username': 'admin', 'password': 'adminpass12345'})
assert b'temporarily locked' in resp.data, resp.data[:300]

# Back-date the lockout and confirm a correct login now succeeds and resets state.
import sqlite3, datetime
con = sqlite3.connect(app.AUDIT_DB)
past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).isoformat()
con.execute("UPDATE users SET locked_until = ? WHERE username = 'admin';", (past,))
con.commit(); con.close()
resp = login(c, data={'username': 'admin', 'password': 'adminpass12345'}, follow_redirects=False)
assert resp.status_code == 302, resp.data[:300]
con = sqlite3.connect(app.AUDIT_DB)
row = con.execute("SELECT failed_attempts, locked_until FROM users WHERE username='admin';").fetchone()
con.close()
assert row == (0, None), row
print('OK')
""", local_env())
check("5 failed logins lock the account; expired lockout + correct password resets it",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Local mode: /login's `next` can't be turned into an open redirect
# ---------------------------------------------------------------------------
r = run("""
import app
c = app.app.test_client()

# A normal same-site path survives untouched.
resp = c.get('/login?next=/audit')
assert 'value="/audit"' in resp.data.decode(), resp.data[:300]

# An absolute URL, a protocol-relative one, and the backslash trick that
# browsers can normalize INTO a protocol-relative one - none of these may
# survive into the rendered `next` field, and none may survive into the
# actual redirect Location after a real login either.
bad_targets = [
    'https://evil.example/',
    '//evil.example',
    '/\\\\evil.example',
    'javascript:alert(1)',
]
safe_values = ['value="/"', 'value=""']
for bad in bad_targets:
    resp = c.get('/login', query_string={'next': bad})
    page = resp.data.decode()
    assert bad not in page, (bad, page[:300])
    assert any(v in page for v in safe_values), (bad, page[:300])

    resp = login(c, data={'username': 'admin', 'password': 'adminpass12345', 'next': bad},
                  follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers.get('Location', '')
    assert bad not in location, (bad, location)
    assert location == '/', (bad, location)
    logout(c)
print('OK')
""", local_env())
check("login's next= can't be turned into an open redirect (absolute URL, //, backslash trick, javascript:)",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Local mode: CSRF - full coverage across every POST route
# ---------------------------------------------------------------------------
r = run("""
import re
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})

html = c.get('/admin').data.decode()
token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
assert token, "no csrf token rendered"

# Missing token -> 403
resp = c.post('/api/admin/users', json={'username': 'x', 'role': 'viewer'})
assert resp.status_code == 403 and 'CSRF' in resp.get_json()['error'], resp.get_json()

# Wrong token -> 403
resp = c.post('/api/admin/users', json={'username': 'x', 'role': 'viewer'},
              headers={'X-CSRFToken': 'not-the-real-token'})
assert resp.status_code == 403

# Correct token -> succeeds
resp = c.post('/api/admin/users', json={'username': 'x', 'role': 'viewer'},
              headers={'X-CSRFToken': token})
assert resp.status_code == 200 and resp.get_json().get('ok'), resp.get_json()

# GET routes need no token at all
resp = c.get('/api/admin/users')
assert resp.status_code == 200
print('OK')
""", local_env())
check("CSRF: missing/wrong token blocked, correct token succeeds, GET routes unaffected",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Local mode: login CSRF - the form itself carries a token
# ---------------------------------------------------------------------------
r = run("""
import app
c = app.app.test_client()
# Straight POST with valid credentials but no token (what a hostile
# cross-site form would send) - must be refused and must NOT log in.
resp = c.post('/login', data={'username': 'admin', 'password': 'adminpass12345'})
assert resp.status_code == 403, resp.status_code
assert b'expired' in resp.data
with c.session_transaction() as sess:
    assert 'username' not in sess, "token-less POST must not create a session"
# Wrong token - same
c.get('/login')
resp = c.post('/login', data={'username': 'admin', 'password': 'adminpass12345',
                              'csrf_token': 'forged'})
assert resp.status_code == 403
# The real flow (GET the form, submit its token) still works
resp = login(c, data={'username': 'admin', 'password': 'adminpass12345'}, follow_redirects=False)
assert resp.status_code == 302, resp.status_code
print('OK')
""", local_env())
check("login CSRF: POST without/with a forged form token is refused; the real form flow works",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Local mode: minimum password length
# ---------------------------------------------------------------------------
r = run("""
import re
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
html = c.get('/admin').data.decode()
token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
hdr = {'X-CSRFToken': token}

resp = c.post('/api/admin/users', json={'username': 'short', 'role': 'viewer', 'password': 'abc123'}, headers=hdr)
assert resp.status_code == 400 and 'at least' in resp.get_json()['error'], resp.get_json()

resp = c.post('/api/admin/users', json={'username': 'short', 'role': 'viewer', 'password': 'abcdefghij'}, headers=hdr)
assert resp.status_code == 200 and resp.get_json().get('ok'), resp.get_json()

# reset-password same rule
users = c.get('/api/admin/users').get_json()
uid = next(u['id'] for u in users if u['username'] == 'short')
resp = c.post(f'/api/admin/users/{uid}/reset-password', json={'password': 'short1'}, headers=hdr)
assert resp.status_code == 400
resp = c.post(f'/api/admin/users/{uid}/reset-password', json={'password': 'longenough1'}, headers=hdr)
assert resp.status_code == 200 and resp.get_json().get('ok')
print('OK')
""", local_env())
check("password length floor enforced on add-user and reset-password",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)


# ---------------------------------------------------------------------------
# Bootstrap password: generated + printed once, verifies, doesn't reprint
# ---------------------------------------------------------------------------
same_db_env = local_env(BOOTSTRAP_ADMIN_PASSWORD="")
same_db_env["AUDIT_DB"] = tempfile.mktemp(suffix=".sqlite")

first = run("import app", same_db_env)
banner_ok = (
    first.returncode == 0
    and "first admin account created" in first.stdout
    and "Username: admin" in first.stdout
    and "Password: " in first.stdout
)
check("bootstrap_admin() prints a one-time banner with username+password when no explicit password is set",
      banner_ok)
if not banner_ok:
    print(first.stdout, first.stderr)

pw_line = next((l for l in first.stdout.splitlines() if l.strip().startswith("Password:")), None)
generated_pw = pw_line.split("Password:", 1)[1].strip() if pw_line else None
check("a real password was printed in the banner", bool(generated_pw))

if generated_pw:
    verify = run(f"""
import app
from werkzeug.security import check_password_hash
import sqlite3
con = sqlite3.connect(app.AUDIT_DB)
pw_hash = con.execute("SELECT password_hash FROM users WHERE username='admin';").fetchone()[0]
con.close()
assert check_password_hash(pw_hash, {generated_pw!r}), "printed password does not match stored hash"
print('OK')
""", same_db_env)
    check("printed bootstrap password verifies against the stored hash",
          verify.returncode == 0 and "OK" in verify.stdout)
    if verify.returncode != 0:
        print(verify.stdout, verify.stderr)

# Second startup - an admin already exists, so no new banner/password.
second = run("import app", same_db_env)
check("a second startup (admin already exists) prints no banner",
      "first admin account created" not in second.stdout)

# ---------------------------------------------------------------------------
# The banner highlights the username/password/URL in ANSI so they stand out
# among gunicorn's own log lines - the three things someone scans it for.
# Default: colored. NO_COLOR set: plain (the machine/plain-log escape hatch,
# which everything else in this file relies on). Both directions pinned so
# neither can silently regress.
# ---------------------------------------------------------------------------
ESC = "\033["
color_env = local_env(BOOTSTRAP_ADMIN_PASSWORD="")
color_env["AUDIT_DB"] = tempfile.mktemp(suffix=".sqlite")
del color_env["NO_COLOR"]   # DB_ENV sets it; this test is specifically about color being ON
colored = run("import app", color_env)
check("banner highlights the password in ANSI color by default",
      colored.returncode == 0 and ESC in colored.stdout
      and "Password:" in colored.stdout)
if colored.returncode != 0:
    print(colored.stdout, colored.stderr)

nocolor_env = local_env(BOOTSTRAP_ADMIN_PASSWORD="")
nocolor_env["AUDIT_DB"] = tempfile.mktemp(suffix=".sqlite")
nocolor_env["NO_COLOR"] = "1"
plain = run("import app", nocolor_env)
check("banner has no ANSI codes when NO_COLOR is set",
      plain.returncode == 0 and ESC not in plain.stdout
      and "first admin account created" in plain.stdout)
if plain.returncode != 0:
    print(plain.stdout, plain.stderr)

# ---------------------------------------------------------------------------
# Bootstrap password: concurrent gunicorn workers (this app always runs at
# least 2 - see gunicorn.conf.py) each independently import app.py, so
# bootstrap_admin() genuinely runs more than once, concurrently, on every
# real startup. Without a lock around the admin_count check, multiple
# workers can each see 0 admins, each generate and write their OWN random
# password, and each print their own (different) banner - reproduced 100%
# of the time (8/8 runs) against the pre-fix code before this was added.
# ---------------------------------------------------------------------------
concurrent_env = local_env(BOOTSTRAP_ADMIN_PASSWORD="")
concurrent_env["AUDIT_DB"] = tempfile.mktemp(suffix=".sqlite")
procs = [
    subprocess.Popen([sys.executable, "-c", "import app"], cwd=REPO,
                      env=concurrent_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for _ in range(4)
]
concurrent_results = [p.communicate() for p in procs]
banner_count = sum(1 for out, _ in concurrent_results if "first admin account created" in out)
concurrent_passwords = set()
for out, _ in concurrent_results:
    for line in out.splitlines():
        if line.strip().startswith("Password:"):
            concurrent_passwords.add(line.split("Password:", 1)[1].strip())
check("bootstrap_admin() under 4 concurrent workers: exactly one banner is printed",
      banner_count == 1)
if banner_count != 1:
    for out, err in concurrent_results:
        print(out, err)

if banner_count == 1 and len(concurrent_passwords) == 1:
    verify = run(f"""
import app
from werkzeug.security import check_password_hash
import sqlite3
con = sqlite3.connect(app.AUDIT_DB)
pw_hash = con.execute("SELECT password_hash FROM users WHERE username='admin';").fetchone()[0]
con.close()
assert check_password_hash(pw_hash, {next(iter(concurrent_passwords))!r}), "printed password does not match stored hash"
print('OK')
""", concurrent_env)
    check("bootstrap_admin() under concurrency: the one printed password matches what's actually stored",
          verify.returncode == 0 and "OK" in verify.stdout)
    if verify.returncode != 0:
        print(verify.stdout, verify.stderr)

# ---------------------------------------------------------------------------
# Authentik mode: CSRF still enforced, /login bounces, roles still enforced
# ---------------------------------------------------------------------------
# CSRF used to be switched off in this mode, on the reasoning that a
# header-based identity has no ambient cookie to ride along. But the proxy
# only sets that header after validating the Authentik cookie, which a
# cross-site POST carries just like any other - so the multipart
# /api/admin/restore route was reachable from a hostile page. The token
# is issued and checked in both modes now; this test used to assert the
# opposite.
authentik_env = dict(DB_ENV)
authentik_env.update({
    "AUDIT_DB": tempfile.mktemp(suffix=".sqlite"),
    "AUTH_MODE": "authentik",
    "SECRET_KEY": "test-secret",
    "BOOTSTRAP_ADMIN_USERNAME": "svc-admin",
})
r = run("""
import app, re
c = app.app.test_client()
h = {'X-authentik-username': 'svc-admin'}

html = c.get('/admin', headers=h).data.decode()
m = re.search(r'name="csrf-token" content="([^"]+)"', html)
assert m, "authentik mode must issue a real csrf token"
token = m.group(1)

# No CSRF header - must now be REJECTED, exactly like local mode
resp = c.post('/api/admin/users', json={'username': 'carol', 'role': 'viewer'}, headers=h)
assert resp.status_code == 403, (resp.status_code, resp.get_json())

# With the token - succeeds
h2 = dict(h); h2['X-CSRFToken'] = token
resp = c.post('/api/admin/users', json={'username': 'carol', 'role': 'viewer'}, headers=h2)
assert resp.status_code == 200 and resp.get_json().get('ok'), resp.get_json()

# The multipart restore route - the one a cross-site FORM could reach -
# must be rejected without the token too, and must not touch the live db.
import io
resp = c.post('/api/admin/restore', headers=h,
              data={'backup': (io.BytesIO(b'junk'), 'x.sqlite')},
              content_type='multipart/form-data')
assert resp.status_code == 403, (resp.status_code, resp.get_json())

resp = c.get('/login', follow_redirects=False)
assert resp.status_code == 302

resp = c.get('/', headers={'X-authentik-username': 'carol'})
assert resp.status_code == 403
resp = c.get('/verify', headers={'X-authentik-username': 'carol'})
assert resp.status_code == 200
print('OK')
""", authentik_env)
check("authentik mode: csrf token issued and enforced (incl. multipart restore), /login bounces, roles enforced",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Regression: self-delete / last-admin-delete still blocked, viewer still restricted
# ---------------------------------------------------------------------------
r = run("""
import re
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
html = c.get('/admin').data.decode()
token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
hdr = {'X-CSRFToken': token}

users = c.get('/api/admin/users').get_json()
admin_id = next(u['id'] for u in users if u['username'] == 'admin')
resp = c.post(f'/api/admin/users/{admin_id}/delete', headers=hdr)
assert resp.status_code == 400 and 'own account' in resp.get_json()['error']

c.post('/api/admin/users', json={'username': 'bob', 'role': 'viewer', 'password': 'bobpassword1'}, headers=hdr)
logout(c)
login(c, data={'username': 'bob', 'password': 'bobpassword1'})
resp = c.get('/')
assert resp.status_code == 403
resp = c.get('/verify')
assert resp.status_code == 200
resp = c.get('/api/admin/check-updates')
assert resp.status_code == 403
print('OK')
""", local_env())
check("regression: self-delete blocked, viewer still restricted to /verify (incl. check-updates)",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Check for updates - runs against THIS actual git checkout (real .git,
# real GitHub remote), so this is a real end-to-end exercise of the git
# subprocess logic, not a mock. Only asserts on the RESPONSE SHAPE
# ("checked" is present and boolean, plus whichever fields that implies),
# not on specific commit hashes or ahead/behind counts - those depend on
# this checkout's actual state at test time (mid-development, this repo
# routinely has local commits not yet pushed - see the app.py endpoint's
# own comment on why behind==0 alone doesn't mean "identical to
# upstream"), which is exactly what this test can't assume. Needs network
# access to github.com to reach "checked": true at all; still passes
# either way, since "checked": false is itself a valid, correctly-typed
# response (see the endpoint's own docstring on why an unreachable remote
# isn't this app's own failure).
# ---------------------------------------------------------------------------
r = run("""
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
d = c.get('/api/admin/check-updates').get_json()
assert isinstance(d.get('checked'), bool), d
if d['checked']:
    assert isinstance(d.get('up_to_date'), bool), d
    assert isinstance(d.get('behind_count'), int), d
    assert isinstance(d.get('ahead_count'), int), d
    assert isinstance(d.get('current_commit'), str) and len(d['current_commit']) == 8, d
    assert isinstance(d.get('in_container'), bool), d
else:
    assert isinstance(d.get('error'), str) and d['error'], d
print('OK')
""", local_env())
check("check-updates: response shape is correct against a real git checkout",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# A viewer landing on the plain default next= (no explicit destination -
# the common case: typing the site's base URL, or a bookmark to /login)
# goes straight to /verify, not the Export page they can't access.
# ---------------------------------------------------------------------------
r = run("""
import re
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
html = c.get('/admin').data.decode()
token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
c.post('/api/admin/users', json={'username': 'carol-redirect-test', 'role': 'viewer', 'password': 'carolpassword1'},
       headers={'X-CSRFToken': token})
logout(c)

resp = login(c, data={'username': 'carol-redirect-test', 'password': 'carolpassword1'})
assert resp.status_code == 302, f'expected a redirect, got {resp.status_code}'
assert resp.headers['Location'] == '/verify', f\"expected /verify, got {resp.headers['Location']}\"
print('OK')
""", local_env())
check("viewer with no explicit next= is redirected straight to /verify after login, not the Export page",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Backup: full snapshot except the DB password, restorable with no special
# import step (just point a fresh AUDIT_DB at it and start the app).
# ---------------------------------------------------------------------------
backup_env = local_env()
r = run("""
import app
app.set_setting('db_host', '10.0.0.5')
app.set_setting('db_password', 'super-secret-tak-password')

c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
resp = c.get('/api/admin/backup')
assert resp.status_code == 200
assert resp.mimetype == 'application/x-sqlite3'
assert 'tak-extract-backup-' in resp.headers.get('Content-Disposition', '')

import tempfile, sqlite3
out_path = tempfile.mktemp(suffix='.sqlite')
with open(out_path, 'wb') as f:
    f.write(resp.data)

con = sqlite3.connect(out_path)
users = con.execute("SELECT username, role FROM users;").fetchall()
assert ('admin', 'admin') in users, users
settings = dict(con.execute("SELECT key, value FROM app_settings;").fetchall())
assert settings.get('db_host') == '10.0.0.5', settings
assert 'db_password' not in settings, settings
con.close()

con = sqlite3.connect(app.AUDIT_DB)
rows = con.execute(
    "SELECT outcome FROM export_log WHERE export_kind = 'admin-backup-download';"
).fetchall()
con.close()
assert rows == [('ok',)], rows

print(out_path)
""", backup_env)
backup_ok = (
    r.returncode == 0
    and r.stdout.strip().endswith(".sqlite")
)
check("backup: includes users/settings, excludes db_password, is itself audited",
      backup_ok)
if not backup_ok:
    print(r.stdout, r.stderr)

# The check above passes on a DELETE alone - the row is gone from the
# table while the bytes are still sitting in a freed page, which is
# exactly how the password shipped in every backup until it was caught.
# This one reads the raw file, so it can only pass if the value is
# genuinely not in there.
#
# Deliberately NOT reusing `r`: the restore check below reads the LAST
# line of `r.stdout` as the backup's path, so clobbering it here points
# that test at a file named after whatever this snippet last printed -
# it then creates that file, bootstraps a fresh admin into it and passes
# for entirely the wrong reason. (Which is exactly what happened when
# this test was first added.)
r_bytes = run("""
import app
SENTINEL = 'sentinel-tak-password-not-in-bytes'
app.set_setting('db_password', SENTINEL)

c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
resp = c.get('/api/admin/backup')
assert resp.status_code == 200
assert SENTINEL.encode() not in resp.data, 'db_password recoverable from backup bytes'
print('OK')
""", local_env())
check("backup: db_password is not recoverable from the raw file bytes",
      r_bytes.returncode == 0 and "OK" in r_bytes.stdout)
if r_bytes.returncode != 0:
    print(r_bytes.stdout, r_bytes.stderr)

if backup_ok:
    restored_path = r.stdout.strip().splitlines()[-1]
    restore_env = dict(backup_env)
    restore_env["AUDIT_DB"] = restored_path
    r2 = run("""
import app
c = app.app.test_client()
resp = login(c, data={'username': 'admin', 'password': 'adminpass12345'}, follow_redirects=False)
assert resp.status_code == 302, resp.status_code
print('OK')
""", restore_env)
    check("restore: pointing AUDIT_DB at the backup file needs no special import step",
          r2.returncode == 0 and "OK" in r2.stdout)
    if r2.returncode != 0:
        print(r2.stdout, r2.stderr)

# ---------------------------------------------------------------------------
# Restore via the admin-page upload route itself, not just a manual file
# drop: a fresh install (different admin, different data) uploads a
# backup taken from a DIFFERENT install and ends up with that install's
# data; bad uploads are rejected without touching the live database.
# ---------------------------------------------------------------------------
r = run("""
import app, io, re

# "Machine A": distinctive user, then a backup of it.
a = app.app.test_client()
login(a, data={'username': 'admin', 'password': 'adminpass12345'})
token_a = re.search(r'name="csrf-token" content="([^"]+)"', a.get('/admin').data.decode()).group(1)
a.post('/api/admin/users', json={'username': 'from-machine-a', 'role': 'viewer', 'password': 'somepassword1'},
       headers={'X-CSRFToken': token_a})
backup_bytes = a.get('/api/admin/backup').data

# "Machine B" (this same process's AUDIT_DB, standing in for a different
# install) uploads machine A's backup through the restore route.
token_b = re.search(r'name="csrf-token" content="([^"]+)"', a.get('/admin').data.decode()).group(1)
resp = a.post('/api/admin/restore',
              data={'backup': (io.BytesIO(backup_bytes), 'backup.sqlite')},
              headers={'X-CSRFToken': token_b},
              content_type='multipart/form-data')
assert resp.status_code == 200 and resp.get_json().get('ok'), resp.get_json()

# The restored database now has machine A's user in it.
users = a.get('/api/admin/users').get_json()
assert any(u['username'] == 'from-machine-a' for u in users), users
print('OK')
""", local_env())
check("restore via upload: admin page upload flow applies a backup's data",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

r = run("""
import app, io, re
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
token = re.search(r'name="csrf-token" content="([^"]+)"', c.get('/admin').data.decode()).group(1)

# Not a sqlite file at all.
resp = c.post('/api/admin/restore', data={'backup': (io.BytesIO(b'not a database'), 'junk.sqlite')},
              headers={'X-CSRFToken': token}, content_type='multipart/form-data')
assert resp.status_code == 400 and 'not a valid sqlite' in resp.get_json()['error'], resp.get_json()

# A real sqlite file, but not one of ours (no users/app_settings/export_log).
import sqlite3, tempfile
unrelated_path = tempfile.mktemp(suffix='.sqlite')
con = sqlite3.connect(unrelated_path)
con.execute('CREATE TABLE something_else (x int);')
con.commit(); con.close()
with open(unrelated_path, 'rb') as f:
    unrelated_bytes = f.read()
resp = c.post('/api/admin/restore', data={'backup': (io.BytesIO(unrelated_bytes), 'unrelated.sqlite')},
              headers={'X-CSRFToken': token}, content_type='multipart/form-data')
assert resp.status_code == 400 and 'missing expected table' in resp.get_json()['error'], resp.get_json()

# The live database must be completely unaffected by either rejected attempt.
resp = login(c, data={'username': 'admin', 'password': 'adminpass12345'}, follow_redirects=False)
assert resp.status_code == 302
print('OK')
""", local_env())
check("restore rejects a non-sqlite upload and an unrelated sqlite file, live data untouched",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Theme: one site-wide setting, not per-browser - admin-only, rendered
# server-side into every page's <html> tag, no client-side toggle left
# anywhere to override it.
# ---------------------------------------------------------------------------
r = run("""
import re, app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
html = c.get('/admin').data.decode()
token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
hdr = {'X-CSRFToken': token}

# Default, before anything's ever been saved.
resp = c.get('/api/theme')
assert resp.get_json() == {'theme': 'system'}, resp.get_json()

# Invalid value rejected.
resp = c.post('/api/theme', json={'theme': 'purple'}, headers=hdr)
assert resp.status_code == 400, resp.get_json()

# Valid value persists for THIS account and is reflected in every page's
# rendered <html> tag while logged in as them.
resp = c.post('/api/theme', json={'theme': 'dark'}, headers=hdr)
assert resp.status_code == 200 and resp.get_json().get('ok'), resp.get_json()
assert c.get('/api/theme').get_json() == {'theme': 'dark'}

for path in ('/', '/audit', '/verify', '/admin'):
    page = c.get(path).data.decode()
    assert '<html data-theme="dark">' in page, (path, page[:200])

# No client-side toggle left anywhere - server-rendered only now.
for path in ('/', '/audit', '/verify', '/admin'):
    page = c.get(path).data.decode()
    assert 'themeToggle' not in page, path
    assert 'localStorage' not in page, path

# Switching to 'system' means no data-theme attribute at all (the
# prefers-color-scheme media query decides on its own).
c.post('/api/theme', json={'theme': 'system'}, headers=hdr)
page = c.get('/').data.decode()
assert '<html data-theme=' not in page, page[:200]
assert '<html>' in page

# It's a personal preference, not an administrative action - not audited.
import sqlite3
con = sqlite3.connect(app.AUDIT_DB)
rows = con.execute("SELECT detail FROM export_log WHERE export_kind LIKE '%theme%';").fetchall()
con.close()
assert rows == [], rows

# A SECOND, unrelated account's theme is independent - setting admin's
# doesn't touch it, and a viewer can set their own without admin rights.
c.post('/api/admin/users', json={'username': 'bob-theme-test', 'role': 'viewer', 'password': 'bobpassword1'},
       headers=hdr)
logout(c)
login(c, data={'username': 'bob-theme-test', 'password': 'bobpassword1'})
assert c.get('/api/theme').get_json() == {'theme': 'system'}

# No CSRF token sent - expect a rejection, not a silent success.
resp = c.post('/api/theme', json={'theme': 'light'})
assert resp.status_code == 403, resp.get_json()

html = c.get('/verify').data.decode()
token2 = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
resp = c.post('/api/theme', json={'theme': 'light'}, headers={'X-CSRFToken': token2})
assert resp.status_code == 200 and resp.get_json().get('ok'), resp.get_json()
page = c.get('/verify').data.decode()
assert '<html data-theme="light">' in page, page[:200]

# admin's own theme is unaffected by the other account's change.
logout(c)
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
assert c.get('/api/theme').get_json() == {'theme': 'system'}
print('OK')
""", local_env())
check("theme: per-account preference, rejects invalid values, renders per-page, no client toggle left, not audited, independent per account",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

r = run("""
import app
c = app.app.test_client()
page = c.get('/login').data.decode()
assert '<html>' in page and '<html data-theme=' not in page, page[:200]
print('OK')
""", local_env())
check("login page (pre-authentication, no known account yet) always renders with no theme override",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# /api/verify-window: does a file's REAL data range fall inside the window
# an export_log row recorded, once that row's window_timezone converts its
# timezone-naive window_start/window_end to UTC? Two export_log rows are
# inserted directly (no live Postgres needed - the same convention this
# whole file already uses for lockout/CSRF/etc.), sharing one package hash:
# one with a recorded timezone, one without (as every row before that
# column existed looks like).
# ---------------------------------------------------------------------------
r = run("""
import app, sqlite3, re
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
html = c.get('/verify').data.decode()
token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
hdr = {'X-CSRFToken': token}

file_hash = 'a' * 64
con = sqlite3.connect(app.AUDIT_DB)
cur = con.execute(
    "INSERT INTO export_log (ts_utc, export_kind, window_start, window_end, window_timezone, package_sha256, outcome) "
    "VALUES ('2026-09-02T00:00:00+00:00', 'locations', '2026-09-01T21:55', '2026-09-04T21:55', 'America/Chicago', ?, 'generated');",
    (file_hash,))
row_with_tz = cur.lastrowid
cur = con.execute(
    "INSERT INTO export_log (ts_utc, export_kind, window_start, window_end, window_timezone, package_sha256, outcome) "
    "VALUES ('2026-09-02T00:00:00+00:00', 'locations', '2026-09-01T21:55', '2026-09-04T21:55', NULL, ?, 'generated');",
    (file_hash,))
row_no_tz = cur.lastrowid
con.commit(); con.close()

# File range comfortably inside the recorded window once converted from
# America/Chicago (CDT, UTC-5 in September) to UTC.
resp = c.post('/api/verify-window', json={
    'hash': file_hash,
    'file_min_utc': '2026-09-02T10:00:00Z',
    'file_max_utc': '2026-09-04T10:00:00Z',
}, headers=hdr)
results = resp.get_json()['results']
assert results[str(row_with_tz)] is True, results
# No timezone recorded on this row - "can't verify," not a silent False.
assert results[str(row_no_tz)] is None, results

# File range starts before the recorded window even after UTC conversion -
# containment, not mere overlap, so this must come back False.
resp = c.post('/api/verify-window', json={
    'hash': file_hash,
    'file_min_utc': '2026-09-01T00:00:00Z',
    'file_max_utc': '2026-09-04T10:00:00Z',
}, headers=hdr)
assert resp.get_json()['results'][str(row_with_tz)] is False

# Malformed input rejected outright, not silently ignored.
resp = c.post('/api/verify-window',
              json={'hash': 'not-a-hash', 'file_min_utc': 'x', 'file_max_utc': 'y'}, headers=hdr)
assert resp.status_code == 400, resp.get_json()
resp = c.post('/api/verify-window',
              json={'hash': file_hash, 'file_min_utc': 'not-a-date', 'file_max_utc': 'also-not'}, headers=hdr)
assert resp.status_code == 400, resp.get_json()
print('OK')
""", local_env())
check("verify-window: containment check across a real IANA timezone, unrecorded-timezone rows come back null, malformed input rejected",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# SERVE_TLS: off by default (no redirect at all, existing behavior
# unchanged), forces http -> https when on, but never redirects a request
# that's already secure (would otherwise be an infinite-redirect risk if
# is_secure were ever miscomputed).
# ---------------------------------------------------------------------------
r = run("""
import app
c = app.app.test_client()
resp = c.get('/login')
assert resp.status_code != 302 or 'https://' not in (resp.headers.get('Location') or ''), \\
    f"SERVE_TLS is off - should never redirect to https, got {resp.headers.get('Location')}"
print('OK')
""", local_env())
check("SERVE_TLS off (default): no http->https redirect", r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

r = run("""
import app
c = app.app.test_client()
resp = c.get('/login')
assert resp.status_code == 302, f'expected a redirect, got {resp.status_code}'
assert resp.headers['Location'].startswith('https://'), \\
    f"expected an https:// redirect, got {resp.headers['Location']}"
print('OK')
""", local_env(SERVE_TLS="true"))
check("SERVE_TLS on: a plain http request is redirected to https", r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

r = run("""
import app
c = app.app.test_client()
resp = c.get('/login', base_url='https://example.test/')
assert resp.status_code != 302 or 'https://' not in (resp.headers.get('Location') or ''), \\
    f"an already-secure request should never be redirected again, got {resp.headers.get('Location')}"
print('OK')
""", local_env(SERVE_TLS="true"))
check("SERVE_TLS on: a request already over https is not redirected again", r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Security headers: present on every response, and HSTS specifically only
# when the connection is genuinely secure right now (sending it over plain
# http:// would be meaningless at best, actively wrong if a reverse proxy
# in front is what actually owns TLS for this domain).
# ---------------------------------------------------------------------------
r = run("""
import app
c = app.app.test_client()
h = c.get('/login').headers
assert h.get('X-Content-Type-Options') == 'nosniff', h
assert h.get('X-Frame-Options') == 'DENY', h
assert h.get('Content-Security-Policy'), h
assert h.get('Permissions-Policy'), h
assert 'Strict-Transport-Security' not in h, h
h2 = c.get('/login', base_url='https://example.test/').headers
assert 'max-age' in (h2.get('Strict-Transport-Security') or ''), h2
print('OK')
""", local_env())
check("security headers present on every response; HSTS only when the connection is actually secure",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# gunicorn.conf.py's timeout: gunicorn's own default (30s) is too short for
# building a full evidence package against a real TAK Server - confirmed
# live via a "WORKER TIMEOUT" in gunicorn's own log, not guessed. Regression
# test for the fix, not the auth system - kept here anyway since there's no
# other home for infra-level config checks in this repo yet.
# ---------------------------------------------------------------------------
r = run("""
import importlib.util, os, sys
sys.path.insert(0, r'%s')

def load_timeout():
    spec = importlib.util.spec_from_file_location('gconf', r'%s/gunicorn.conf.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.timeout

os.environ.pop('GUNICORN_TIMEOUT', None)
default = load_timeout()
assert default == 300, f"expected the default to be 300s, got {default}"

os.environ['GUNICORN_TIMEOUT'] = '600'
overridden = load_timeout()
assert overridden == 600, f"expected the override to be honored, got {overridden}"
print('OK')
""" % (REPO, REPO), local_env())
check("gunicorn.conf.py: timeout defaults to 300s and GUNICORN_TIMEOUT overrides it",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# ProxyFix: trusts X-Forwarded-For only when SERVE_TLS is off (the assumed-
# behind-a-reverse-proxy case) - without this, request.remote_addr (used by
# the audit log, login lockout, and auth.log below) would always be the
# proxy's own IP in this app's own default deployment. Must NOT trust it
# when SERVE_TLS is on, or anyone could spoof their source IP by just
# sending a fake header directly, with no real proxy in front to strip it.
# ---------------------------------------------------------------------------
r = run("""
import app
from flask import request as _r
@app.app.route('/__whatip')
def _whatip():
    return {'remote_addr': _r.remote_addr}
c = app.app.test_client()
r1 = c.get('/__whatip', headers={'X-Forwarded-For': '203.0.113.7'})
assert r1.get_json()['remote_addr'] == '203.0.113.7', r1.get_json()
print('OK')
""", local_env())
check("ProxyFix: X-Forwarded-For trusted when SERVE_TLS is off", r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

r = run("""
import app
from flask import request as _r
@app.app.route('/__whatip')
def _whatip():
    return {'remote_addr': _r.remote_addr}
c = app.app.test_client()
r1 = c.get('/__whatip', headers={'X-Forwarded-For': '203.0.113.7'}, base_url='https://example.test/')
assert r1.get_json()['remote_addr'] != '203.0.113.7', \\
    f"SERVE_TLS on must NOT trust X-Forwarded-For (spoofable with no proxy in front) - got {r1.get_json()}"
print('OK')
""", local_env(SERVE_TLS="true"))
check("ProxyFix: X-Forwarded-For ignored when SERVE_TLS is on (anti-spoofing)",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# auth.log: one line per login attempt (success/failure/locked-account),
# fail2ban-parseable, including attempts against usernames that don't
# exist at all - the per-username lockout above can't track those (no row
# to update), but IP-based banning needs every attempt regardless. A
# crafted username containing a newline must not be able to inject a fake
# extra log line.
# ---------------------------------------------------------------------------
# auth.log lives alongside AUDIT_DB's own directory (see _auth_log_path())
# - every other test in this file shares the same OS temp *directory* for
# its own uniquely-named AUDIT_DB file, which would make auth.log itself a
# shared, cross-test file. A dedicated subdirectory keeps this one
# genuinely isolated.
authlog_dir = tempfile.mkdtemp()
r = run("""
import app, re
c = app.app.test_client()
log_path = app._auth_log_path()

login(c, data={'username': 'admin', 'password': 'wrongpassword'})
login(c, data={'username': 'totally-made-up-user', 'password': 'x'})
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
login(c, data={
    'username': 'evil\\n2099-01-01T00:00:00+00:00 LOGIN_SUCCESS user=admin ip=6.6.6.6',
    'password': 'x',
})

with open(log_path, encoding='utf-8') as f:
    lines = f.read().splitlines()

assert len(lines) == 4, f"expected 4 lines (one per attempt) - log injection added an extra one: {lines}"
assert re.match(r'^\\S+ LOGIN_FAILED user=admin ip=', lines[0]), lines[0]
assert re.match(r'^\\S+ LOGIN_FAILED user=totally-made-up-user ip=', lines[1]), lines[1]
assert re.match(r'^\\S+ LOGIN_SUCCESS user=admin ip=', lines[2]), lines[2]
assert 'LOGIN_SUCCESS user=6.6.6.6' not in lines[3], f"forged a fake line: {lines[3]}"
print('OK')
""", local_env(AUDIT_DB=os.path.join(authlog_dir, "audit.sqlite")))
check("auth.log: logs every attempt including nonexistent usernames; newline injection sanitized",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# get_connection(): a fresh install with no DB_HOST/DB_USER set yet (the
# expected state right after `setup.sh`, before an admin has visited the
# System page) must fail with a clear, readable message - not psycopg2's
# own cryptic failure to even resolve a blank hostname.
# ---------------------------------------------------------------------------
r = run("""
import re, app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
token = re.search(r'name="csrf-token" content="([^"]+)"', c.get('/').data.decode()).group(1)
resp = c.post('/api/count', json={
    'case_id': 'TEST', 'start': '2020-01-01T00:00', 'end': '2020-01-02T00:00',
    'north': 40.0, 'south': 39.0, 'east': -74.0, 'west': -75.0,
}, headers={'X-CSRFToken': token})
err = resp.get_json().get('error', '')
assert "isn't configured yet" in err and 'System page' in err, err
print('OK')
""", local_env(DB_HOST="", DB_USER=""))
check("get_connection(): blank DB_HOST/DB_USER fails with a clear 'not configured yet' message",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# ---------------------------------------------------------------------------
# Bootstrap banner: nudges toward System -> TAK Server connection only when
# the DB genuinely isn't configured yet - silent once it is, so a normal
# reinstall with DB_HOST/DB_USER already set in .env doesn't get a false
# "not connected" nudge alongside its real one-time password banner.
# ---------------------------------------------------------------------------
env = local_env(BOOTSTRAP_ADMIN_PASSWORD="", DB_HOST="", DB_USER="")
env["AUDIT_DB"] = tempfile.mktemp(suffix=".sqlite")
r = run("import app", env)
check("bootstrap banner: DB-not-connected nudge shown when DB_HOST/DB_USER are blank",
      r.returncode == 0 and "database isn't connected yet" in r.stdout
      and "System -> TAK Server connection" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

env = local_env(BOOTSTRAP_ADMIN_PASSWORD="")
env["AUDIT_DB"] = tempfile.mktemp(suffix=".sqlite")
r = run("import app", env)
check("bootstrap banner: DB-not-connected nudge stays silent when DB_HOST/DB_USER are already set",
      r.returncode == 0 and "database isn't connected yet" not in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# --- The re-check routes: token-authenticated, no session, no CSRF.
r = run("""
import io, hashlib, sqlite3, datetime
import app
c = app.app.test_client()
script = "-- t-queries.sql\\nSELECT 1;\\n"
raw_hash = "ab" * 32
tok = app.create_recheck_token("CASE-9", "cd" * 32, raw_hash, script, "authenticated: admin",
                               requested_for="Det. Example")

# fetch: exact bytes, right name only
r1 = c.get(f"/recheck/{tok}/CASE-9-queries.sql")
assert r1.status_code == 200 and r1.data == script.encode("utf-8"), (r1.status_code, r1.data[:40])
assert c.get(f"/recheck/{tok}/other.sql").status_code == 404
assert c.get("/recheck/not-a-token/CASE-9-queries.sql").status_code == 404

# result: a matching hash file -> one 'recheck' audit row, outcome 'raw match', INFO text back
script_hash = hashlib.sha256(script.encode("utf-8")).hexdigest()
sums = (f"{raw_hash}  CASE-9-recheck-cot_router-raw.csv\\n{script_hash}  CASE-9-queries.sql\\n"
        f"{'ef' * 32}  CASE-9-recheck-cot.csv\\n")
r2 = c.post(f"/recheck/{tok}/result", data={
    "sums": (io.BytesIO(sums.encode()), "CASE-9-recheck-SHA256SUMS.txt"),
    "tgz_sha256": "12" * 32, "host": "takserver", "path": "/var/lib/takextract/recheck/CASE-9/2026-09-19T14-02"},
    content_type="multipart/form-data")
body = r2.data.decode()
assert r2.status_code == 200, (r2.status_code, body[:200])
assert body.startswith("recorded: CASE-9 re-check, 3 files, cot_router-raw.csv matches the package: yes"), body[:120]
assert "SQL query script       : yes" in body and "takserver:/var/lib/takextract/recheck/CASE-9/2026-09-19T14-02" in body
# The count of comparisons, stated beside the count of files, so "3 files"
# is never read as three comparisons.
assert "Compared by hash       : 2 of 3" in body, body
con = sqlite3.connect(app.AUDIT_DB); con.row_factory = sqlite3.Row
rows = con.execute("SELECT * FROM export_log WHERE export_kind='recheck' ORDER BY id;").fetchall()
assert len(rows) == 1 and rows[0]["outcome"] == "raw match" and rows[0]["package_sha256"] == "cd" * 32, [dict(x) for x in rows]
# The re-check belongs to the same request the package was exported for.
assert rows[0]["requested_for"] == "Det. Example", dict(rows[0])
assert con.execute("SELECT requested_for FROM export_log WHERE export_kind='recheck-fetch';").fetchone()[0] == "Det. Example"

assert rows[0]["actor"] == "authenticated: admin" and rows[0]["case_id"] == "CASE-9"
# the two artefacts are named where their hashes are recorded
assert "hash file CASE-9-recheck-SHA256SUMS.txt sha256 " in rows[0]["detail"], rows[0]["detail"]
assert "archive CASE-9-recheck.tgz sha256 " + "12" * 32 in rows[0]["detail"], rows[0]["detail"]
# Every file the server hashed is kept, not just the two that were compared,
# so the entry can list what the server produced and what it got for each.
_d = rows[0]["detail"]
assert "SQL query script match: yes" in _d and "raw table rows match: yes" in _d, _d
assert "compared: 2 of 3 file(s), the rest recorded not compared" in _d, _d
assert "server files: " in _d and f"{'ef' * 32} CASE-9-recheck-cot.csv" in _d, _d
assert f"{script_hash} CASE-9-queries.sql" in _d and f"{raw_hash} CASE-9-recheck-cot_router-raw.csv" in _d, _d
# A name the server reports that is not shaped like one of ours is counted,
# never written into the detail: the hash file is posted by whoever holds
# the token, and detail clauses are chained text read as key and value.
_odd = (f"{raw_hash}  CASE-9-recheck-cot_router-raw.csv\\n{script_hash}  CASE-9-queries.sql\\n"
        f"{'ab' * 32}  CASE-9-recheck-x;archive.csv\\n")
_r = c.post(f"/recheck/{tok}/result", data={"sums": (io.BytesIO(_odd.encode()), "s.txt")},
            content_type="multipart/form-data")
assert _r.status_code == 200, _r.status_code
_d2 = con.execute("SELECT detail FROM export_log WHERE export_kind='recheck' "
                  "ORDER BY id DESC LIMIT 1;").fetchone()[0]
assert "x;archive" not in _d2 and "(+1 not listed)" in _d2, _d2
# A space was enough on its own: the folder is the FIRST clause of the
# detail, so "hash file x sha256 <64 hex>" inside it beat the values this
# route recorded for anything reading without requiring a clause boundary.
# The folder this tool's own command builds never contains a space.
_spaced = "/evidence/case42 hash file x sha256 " + ("11" * 32)
_r2 = c.post(f"/recheck/{tok}/result",
             data={"sums": (io.BytesIO(sums.encode()), "s.txt"), "host": "tak01", "path": _spaced},
             content_type="multipart/form-data")
assert _r2.status_code == 400 and b"without spaces" in _r2.data, (_r2.status_code, _r2.data[:80])
_c3 = sqlite3.connect(app.AUDIT_DB)
assert _c3.execute("SELECT count(*) FROM export_log WHERE detail LIKE '%case42%';").fetchone()[0] == 0
assert con.execute("SELECT count(*) FROM export_log WHERE export_kind='recheck-fetch';").fetchone()[0] == 1
assert app.verify_audit_chain()["ok"]

# a mismatching raw line -> 'raw MISMATCH', its own row
bad = f"{'00' * 32}  CASE-9-recheck-cot_router-raw.csv\\n"
r3 = c.post(f"/recheck/{tok}/result", data={"sums": (io.BytesIO(bad.encode()), "s.txt")}, content_type="multipart/form-data")
assert r3.status_code == 200 and "matches the package: NO" in r3.data.decode()
assert con.execute("SELECT outcome FROM export_log WHERE export_kind='recheck' ORDER BY id DESC LIMIT 1;").fetchone()[0] == "raw MISMATCH"

# malformed inputs are refused, and write nothing
before = con.execute("SELECT count(*) FROM export_log;").fetchone()[0]
assert c.post(f"/recheck/{tok}/result", data={"sums": (io.BytesIO(b"not a sums file"), "s.txt")}, content_type="multipart/form-data").status_code == 400
# The folder the server reports becomes the FIRST clause of a chained
# detail, and whoever holds the token is the party the re-check is an
# independent check on. A separator in it would let them write further
# clauses - verdicts among them - ahead of the ones this route decides.
con2 = sqlite3.connect(app.AUDIT_DB)
_forge = ("/var/lib/takextract/recheck; SQL query script match: yes; "
          "raw table rows match: yes")
_r = c.post(f"/recheck/{tok}/result",
            data={"sums": (io.BytesIO(sums.encode()), "s.txt"), "host": "tak01", "path": _forge},
            content_type="multipart/form-data")
assert _r.status_code == 400 and b"plain printable path" in _r.data, (_r.status_code, _r.data[:80])
assert con2.execute("SELECT count(*) FROM export_log WHERE detail LIKE '%recheck; SQL%';").fetchone()[0] == 0
assert c.post(f"/recheck/{tok}/result", data={"sums": (io.BytesIO(b"a" * 70000), "s.txt")}, content_type="multipart/form-data").status_code == 400
assert c.post(f"/recheck/{tok}/result", data={"sums": (io.BytesIO(sums.encode()), "s.txt"), "host": "bad host;rm"}, content_type="multipart/form-data").status_code == 400
assert c.post(f"/recheck/{tok}/result", data={"sums": (io.BytesIO(sums.encode()), "s.txt"), "path": "/x\\x07y"}, content_type="multipart/form-data").status_code == 400
assert c.post(f"/recheck/{tok}/result", data={}, content_type="multipart/form-data").status_code == 400
assert con.execute("SELECT count(*) FROM export_log;").fetchone()[0] == before

# caps: a token dies after RECHECK_MAX_RESULTS posts (and RECHECK_MAX_FETCHES fetches)
con.execute("UPDATE recheck_tokens SET result_count = ?, fetch_count = ? WHERE token = ?;", (app.RECHECK_MAX_RESULTS, app.RECHECK_MAX_FETCHES, tok)); con.commit()
assert c.post(f"/recheck/{tok}/result", data={"sums": (io.BytesIO(sums.encode()), "s.txt")}, content_type="multipart/form-data").status_code == 404
assert c.get(f"/recheck/{tok}/CASE-9-queries.sql").status_code == 404
con.execute("UPDATE recheck_tokens SET result_count = 0, fetch_count = 0 WHERE token = ?;", (tok,)); con.commit()

# expiry: an expired token is a 404 for both routes
con.execute("UPDATE recheck_tokens SET expires_utc = ? WHERE token = ?;", ("2000-01-01T00:00:00+00:00", tok)); con.commit()
assert c.get(f"/recheck/{tok}/CASE-9-queries.sql").status_code == 404
assert c.post(f"/recheck/{tok}/result", data={"sums": (io.BytesIO(sums.encode()), "s.txt")}, content_type="multipart/form-data").status_code == 404
# A token minted before the column existed (no requested_for key at all)
# still works - the row is written with nothing in that column.
con.execute("UPDATE recheck_tokens SET requested_for = NULL, result_count = 0, expires_utc = ? WHERE token = ?;",
            ("2099-01-01T00:00:00+00:00", tok)); con.commit()
r3 = c.post(f"/recheck/{tok}/result", data={
    "sums": (io.BytesIO(sums.encode()), "s.txt"), "host": "takserver"}, content_type="multipart/form-data")
assert r3.status_code == 200, r3.status_code
assert con.execute("SELECT requested_for FROM export_log WHERE export_kind='recheck' ORDER BY id DESC LIMIT 1;").fetchone()[0] is None
# A case typed with a space is filed in the log as typed, while its files
# are named without it - the re-check must land under the export's case,
# not under the filename spelling, or the two read as separate cases.
spaced = app.create_recheck_token("RiverRoad", "ef" * 32, "fa" * 32, "SELECT 1;",
                                  "authenticated: admin", case_id="River Road")
c.get(f"/recheck/{spaced}/RiverRoad-queries.sql")
c.post(f"/recheck/{spaced}/result", data={
    "sums": (io.BytesIO((("fa" * 32) + "  RiverRoad-recheck-cot_router-raw.csv" + chr(10)).encode()), "s.txt")},
    content_type="multipart/form-data")
con4 = sqlite3.connect(app.AUDIT_DB)
filed = [r[0] for r in con4.execute(
    "SELECT case_id FROM export_log WHERE export_kind IN ('recheck','recheck-fetch') AND package_sha256 = ?;",
    ("ef" * 32,)).fetchall()]
con4.close()
assert filed and all(x == "River Road" for x in filed), filed

con.close()

# the System page's indicator: the newest 'recheck' row (host:path, when, outcome)
# plus the .env marker connect-database.sh writes - admin only
assert c.get("/api/admin/recheck-setup").status_code in (401, 403, 302)
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
d = c.get("/api/admin/recheck-setup").get_json()
assert d["marker"] == "2026-09-19T15:00:00Z on takserver by admin (connect-database.sh)", d
# the Export page watches this token while the administrator is at the server:
# nothing yet, then the fetch, then the verdict (admin-only, hence after login)
c.get(f"/recheck/{tok}/CASE-9-queries.sql")   # the server fetching the script
d0 = c.get(f"/api/recheck-progress/{tok}").get_json()
assert d0["fetched"] >= 1 and d0["results"] >= 1 and d0["outcome"] in ("raw match", "raw MISMATCH"), d0
assert d0["where"] == "takserver" and d0["when"], d0   # host only, no trailing colon
assert c.get("/api/recheck-progress/not-a-token").status_code == 404
con = sqlite3.connect(app.AUDIT_DB); con.row_factory = sqlite3.Row
newest = con.execute("SELECT outcome, detail FROM export_log WHERE export_kind='recheck' ORDER BY id DESC LIMIT 1;").fetchone(); con.close()
assert d["last"]["outcome"] == newest["outcome"] and newest["detail"].startswith("re-check at " + d["last"]["where"] + ";"), (d, dict(newest))
print('OK')
""", local_env(RECHECK_FOLDER_SETUP="2026-09-19T15:00:00Z on takserver by admin (connect-database.sh)"))
check("re-check routes: token serves the exact script, records match/mismatch as chained audit rows, refuses malformed input, 404s when expired; the System page's setup indicator reads the marker and the newest re-check",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# --- Asking the log for a re-check of an export made earlier.
r = run("""
import re, hashlib, sqlite3
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
csrf = re.search(r'name="csrf-token" content="([^"]+)"', c.get('/audit').data.decode()).group(1)
H = {'X-CSRFToken': csrf}

script = "-- LATER-queries.sql" + chr(10) + "SELECT 1;" + chr(10)
script_hash = hashlib.sha256(script.encode("utf-8")).hexdigest()
pkg = "7a" * 32

def export_row(detail, pkg_hash=pkg):
    con = sqlite3.connect(app.AUDIT_DB)
    con.execute("INSERT INTO export_log (ts_utc, ts_local, actor, client_ip, case_id, export_kind,"
                " record_count, outcome, package_sha256, detail, requested_for)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                ("2026-09-01T10:00:00+00:00", "2026-09-01 10:00:00 UTC", "authenticated: admin",
                 "10.0.0.1", "LATER", "package", 12, "generated / delivered", pkg_hash,
                 detail, "Det. Example"))
    con.commit(); con.close()

# An export whose entry records its script's hash, and whose script was kept.
export_row("file: LATER-package.zip; package files: " + script_hash + " LATER-queries.sql, "
           + "bb" * 32 + " LATER-cot.csv")
app.store_recheck_script("LATER", pkg, "cc" * 32, script, "authenticated: admin",
                         requested_for="Det. Example", case_id="LATER")

r1 = c.post("/api/audit/recheck/" + pkg, json={"base": "https://takx.example.gov"}, headers=H)
d = r1.get_json()
assert r1.status_code == 200 and d["ok"] and d["checked"] is True, (r1.status_code, d)
assert d["prefix"] == "LATER" and len(d["token"]) > 20, d
# The command is the server's own, and it carries the new token and the
# package's short hash - two re-checks of one case never share a folder.
assert d["command"].startswith("D=/var/lib/takextract/recheck/LATER/"), d["command"][:60]
assert ("/recheck/" + d["token"] + "/LATER-queries.sql") in d["command"], d["command"][:200]
assert "-" + pkg[:8] in d["command"] and "https://takx.example.gov" in d["command"]
assert d["command"] == app.recheck_command("https://takx.example.gov", "LATER", d["token"],
                                           tag="-" + pkg[:8]), "not the shared builder"

# The token works: it is a real one, for this package, with the kept script.
got = c.get("/recheck/" + d["token"] + "/LATER-queries.sql")
assert got.status_code == 200 and got.data == script.encode("utf-8"), got.status_code

# It is recorded, under the case, against the package, as its own kind.
con = sqlite3.connect(app.AUDIT_DB); con.row_factory = sqlite3.Row
row = con.execute("SELECT * FROM export_log WHERE export_kind='recheck-issued'"
                  " ORDER BY id DESC LIMIT 1;").fetchone()
assert row["case_id"] == "LATER" and row["package_sha256"] == pkg and row["outcome"] == "issued", dict(row)
assert row["actor"] == "authenticated: admin" and row["requested_for"] == "Det. Example", dict(row)
assert script_hash in row["detail"] and "checked against the export entry: yes" in row["detail"], row["detail"]
assert app.verify_audit_chain()["ok"]
con.close()

# An export with no kept script - everything exported before this version.
old = "8b" * 32
export_row("file: OLD-package.zip", old)
r2 = c.post("/api/audit/recheck/" + old, json={}, headers=H)
assert r2.status_code == 404 and r2.get_json()["error"] == "no-script", (r2.status_code, r2.get_json())
assert "README" in r2.get_json()["message"]

# A kept script that is not the one the export recorded: no token, and the
# disagreement is the thing that gets written down.
bad = "9c" * 32
export_row("file: BAD-package.zip; package files: " + "dd" * 32 + " BAD-queries.sql", bad)
app.store_recheck_script("BAD", bad, "", "-- a different script" + chr(10), "authenticated: admin")
r3 = c.post("/api/audit/recheck/" + bad, json={}, headers=H)
assert r3.status_code == 409 and r3.get_json()["error"] == "script-mismatch", r3.status_code
con = sqlite3.connect(app.AUDIT_DB); con.row_factory = sqlite3.Row
m = con.execute("SELECT * FROM export_log WHERE export_kind='recheck-issued'"
                " ORDER BY id DESC LIMIT 1;").fetchone()
assert m["outcome"] == "script MISMATCH" and "NOT offered" in m["detail"], dict(m)
assert app.verify_audit_chain()["ok"]
con.close()

# An export the log does not hold, a hash that is not one, an address that
# is not an address, and the same request without a session.
assert c.post("/api/audit/recheck/" + "1f" * 32, json={}, headers=H).status_code == 404
assert c.post("/api/audit/recheck/not-a-hash", json={}, headers=H).status_code == 400
assert c.post("/api/audit/recheck/" + pkg, json={"base": "https://x.gov; rm -rf /"},
              headers=H).status_code == 400
assert c.post("/api/audit/recheck/" + pkg, json={}).status_code in (400, 403)
logout(c)
assert c.post("/api/audit/recheck/" + pkg, json={}, headers=H).status_code in (302, 401, 403)
print('OK')
""", local_env())
check("re-check from the audit log: mints a fresh token from the kept script, refuses when the log "
      "and the kept copy disagree, records both outcomes, and takes no shell metacharacters in the address",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)


# --- The certification, produced from the log rather than filled in by hand.
r = run("""
import re, sqlite3
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})

pkg = "3c" * 32
con = sqlite3.connect(app.AUDIT_DB)
con.execute("INSERT INTO export_log (ts_utc, ts_local, actor, client_ip, case_id, export_kind,"
            " record_count, outcome, package_sha256, detail, requested_for, tool_version,"
            " window_start, window_end, window_timezone)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("2026-09-01T10:00:00+00:00", "2026-09-01 10:00:00 UTC", "authenticated: admin",
             "10.0.0.1", "CERT-1", "package", 12, "generated / delivered", pkg,
             "file: CERT-1-package.zip; package files: " + "aa" * 32 + " CERT-1-cot.csv, "
             + "bb" * 32 + " CERT-1-queries.sql",
             "Det. Example", "TAK-Extract test", "2026-08-01T00:00", "2026-08-02T00:00", "UTC"))
con.commit(); con.close()

r1 = c.get("/api/certification/" + pkg)
t = r1.get_data(as_text=True)
assert r1.status_code == 200, r1.status_code
assert "attachment" in r1.headers["Content-Disposition"] and "CERT-1-certification.txt" in r1.headers["Content-Disposition"]
# section 1 and 2 come from the row, not from a form
assert "CERT-1" in t and "Det. Example" in t and "authenticated: admin" in t, t[:300]
assert ("aa" * 32) in t and "CERT-1-cot.csv" in t and ("bb" * 32) in t, t[:600]
# section 3 is filled, not underscores
assert pkg in t and "____" not in t.split("5. DECLARATION")[0], t.split("3. THE PACKAGE")[1][:200]
# no re-check yet: said as a fact
assert "No re-check is recorded for this package" in t, t[t.find("4. THE"):][:200]
assert "over and above the standard" in t and "not deficient" in t

# now a re-check exists for it
con = sqlite3.connect(app.AUDIT_DB)
con.execute("INSERT INTO export_log (ts_utc, ts_local, actor, client_ip, case_id, export_kind,"
            " record_count, outcome, package_sha256, detail)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("2026-09-01T11:00:00+00:00", "2026-09-01 11:00:00 UTC", "authenticated: admin",
             "10.0.0.2", "CERT-1", "recheck", 16, "raw match", pkg,
             "re-check at takserver:/var/lib/takextract/recheck/CERT-1/x; "
             "hash file CERT-1-recheck-SHA256SUMS.txt sha256 " + "ee" * 32 + "; "
             "archive CERT-1-recheck.tgz sha256 " + "dd" * 32 + "; "
             "SQL query script match: yes; raw table rows match: yes"))
con.commit(); con.close()
t2 = c.get("/api/certification/" + pkg).get_data(as_text=True)
assert "takserver:/var/lib/takextract/recheck/CERT-1/x" in t2, t2[t2.find("4. THE"):][:300]
assert ("ee" * 32) in t2 and ("dd" * 32) in t2
assert t2.count(": yes") == 2 and "recorded, not compared" in t2
assert "____" not in t2.split("5. DECLARATION")[0]

# an export the log does not hold, and a hash that is not one
assert c.get("/api/certification/" + "9f" * 32).status_code == 404
assert c.get("/api/certification/not-a-hash").status_code == 404

# a viewer verifying a package is exactly who needs this
logout(c)
from werkzeug.security import generate_password_hash
_c = sqlite3.connect(app.AUDIT_DB)
_c.execute("INSERT INTO users (username, password_hash, role, created_ts_utc) VALUES (?,?,?,?);",
           ('v.cert', generate_password_hash('viewerpass12345'), 'viewer', '2026-01-01T00:00:00+00:00'))
_c.commit(); _c.close()
login(c, data={'username': 'v.cert', 'password': 'viewerpass12345'})
assert c.get("/api/certification/" + pkg).status_code == 200
logout(c)
assert c.get("/api/certification/" + pkg).status_code in (302, 401, 403)
print('OK')
""", local_env())
check("the certification is produced from the audit log with its facts filled in, and a viewer can get it",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)


# --- Which database an export came from.
r = run("""
import re, sqlite3
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})

def add(case, ident, when, kind='package'):
    con = sqlite3.connect(app.AUDIT_DB)
    con.execute("INSERT INTO export_log (ts_utc, ts_local, actor, client_ip, case_id, export_kind,"
                " record_count, outcome, package_sha256, detail)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (when + "+00:00", when.replace("T", " ") + " UTC", "authenticated: admin",
                 "10.0.0.1", case, kind, 1, "generated", None,
                 "file: " + case + "-package.zip" +
                 ("; source database: " + ident if ident else "")))
    con.commit(); con.close()

# nothing recorded yet
assert app.recent_source_identities() == []

add("SRC-1", "cluster 7412345678901234567", "2026-09-01T10:00:00")
add("SRC-2", "cluster 7412345678901234567", "2026-09-02T10:00:00")
seen = app.recent_source_identities()
assert len(seen) == 1 and seen[0]["identity"] == "cluster 7412345678901234567", seen
assert seen[0]["when"].startswith("2026-09-02"), seen   # newest first

# repointed at another server
add("SRC-3", "cluster 9998887776665554443", "2026-09-03T10:00:00")
seen = app.recent_source_identities()
assert len(seen) == 2, seen
assert seen[0]["identity"] == "cluster 9998887776665554443" and seen[0]["case_id"] == "SRC-3", seen

# an export recorded before any of this carries no clause and is not counted
add("SRC-OLD", None, "2026-09-04T10:00:00")
assert len(app.recent_source_identities()) == 2

# a re-check row is not an export and must not be read as one
add("SRC-4", "cluster 1111111111111111111", "2026-09-05T10:00:00", kind="recheck")
assert len(app.recent_source_identities()) == 2, app.recent_source_identities()

# the route itself: no TAK Server in this environment, so it must say so
# rather than fail - and it is admin-only either way
d = c.get("/api/admin/source-identity").get_json()
assert d["checked"] is False and d["error"], d
logout(c)
assert c.get("/api/admin/source-identity").status_code in (302, 401, 403)
print('OK')
""", local_env())
check("the log records which database each export read: newest first, distinct, exports only",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)


# --- Full-tree security review (2026-09-19) follow-ups.
r = run("""
import re
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
csrf = re.search(r'name="csrf-token" content="([^"]+)"', c.get('/admin').data.decode()).group(1)
H = {'X-CSRFToken': csrf}

# test-connection: the saved password only goes to the saved server. Saved
# host 'unused' (from the env) - a different host with a blank password is
# refused before any connection is attempted; the saved host is not.
d = c.post('/api/admin/test-connection', json={'db_host': 'attacker.example'}, headers=H).get_json()
assert d['ok'] is False and 'saved password is only used for the saved connection' in d['error'], d
d = c.post('/api/admin/test-connection', json={'db_user': 'someone-else'}, headers=H).get_json()
assert d['ok'] is False and 'saved password' in d['error'], d
d = c.post('/api/admin/test-connection', json={'db_host': 'attacker.example', 'db_password': 'typed'}, headers=H).get_json()
assert d['ok'] is False and 'saved password' not in d['error'], d   # attempted (and fails to connect)
d = c.post('/api/admin/test-connection', json={}, headers=H).get_json()
assert d['ok'] is False and 'saved password' not in d['error'], d   # the saved target: attempted

# verify-hash: a verifier gets the record, not the exporter's IP or the chain hashes
app.audit('authenticated: admin', '10.9.8.7', {'case_id': 'C'}, 'package', 3, 'generated', package_hash='ab' * 32)
d = c.post('/api/verify-hash', json={'hash': 'ab' * 32}, headers=H).get_json()
assert d['matched'] and len(d['matches']) == 1, d
m = d['matches'][0]
assert 'client_ip' not in m and 'prev_hash' not in m and 'row_hash' not in m, sorted(m)
assert m['actor'] == 'authenticated: admin' and m['package_sha256'] == 'ab' * 32 and m['export_kind'] == 'package', m
print('OK')
""", local_env())
check("review follow-ups: test-connection refuses to send the saved password to a different target; verify-hash withholds client_ip and chain hashes",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# --- Hardening (2026-09-19): script nonce, logout as a POST, login timing.
r = run("""
import re, time, statistics
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})

# CSP: a fresh nonce per response, the same one stamped on the page's inline script, no 'unsafe-inline' on script-src
r1 = c.get('/'); r2 = c.get('/')
csp1, csp2 = r1.headers['Content-Security-Policy'], r2.headers['Content-Security-Policy']
n1 = re.search(r"script-src 'self' 'nonce-([A-Za-z0-9_-]+)' https://unpkg.com;", csp1).group(1)
n2 = re.search(r"script-src 'self' 'nonce-([A-Za-z0-9_-]+)' https://unpkg.com;", csp2).group(1)
assert n1 != n2 and len(n1) >= 20, (n1, n2)
assert '<script nonce="' + n1 + '">' in r1.data.decode(), 'inline script not stamped with the response nonce'
assert "'unsafe-inline'" not in csp1.split('style-src')[0], csp1
for path in ('/verify', '/audit', '/admin', '/login'):
    rr = c.get(path)
    nn = re.search(r"'nonce-([A-Za-z0-9_-]+)'", rr.headers['Content-Security-Policy']).group(1)
    body = rr.data.decode()
    assert ('<script' not in body) or ('<script nonce="' + nn + '">' in body), path

# logout: GET is refused; POST without the token is refused and keeps the session; POST with it signs out
assert c.get('/logout').status_code == 405
assert c.post('/logout').status_code == 403
assert c.get('/api/admin/settings').status_code == 200, 'still signed in after the refused logout'
r = logout(c)
assert r.status_code == 302 and c.get('/api/admin/settings').status_code == 401

# login timing: a nonexistent user costs the same as a wrong password for a real one
def t(user):
    s = time.perf_counter(); login(c, data={'username': user, 'password': 'wrong-password-xx'}); return time.perf_counter() - s
real = statistics.median(t('admin') for _ in range(5))
fake = statistics.median(t('no-such-user-zz') for _ in range(5))
assert fake > real * 0.5, (real, fake)   # without the guard the fake path is ~instant (well under half)
print('OK')
""", local_env())
check("hardening: per-response script nonce stamped on every page, logout is POST+token only, unknown-user login takes as long as a wrong password",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# --- /api/audit?group=case: the audit page's default view.
r = run("""
import re
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
csrf = re.search(r'name="csrf-token" content="([^"]+)"', c.get('/admin').data.decode()).group(1)

# Oldest first, so ids ascend with time the way a real log's do.
app.audit('authenticated: admin', '10.0.0.1', {'case_id': 'CASE-A'}, 'package', 5, 'generated', package_hash='aa' * 32)
app.audit('authenticated: admin', '10.0.0.1', {'case_id': 'CASE-A'}, 'recheck-fetch', 0, 'ok', package_hash='aa' * 32)
app.audit('authenticated: admin', '10.0.0.1', {'case_id': 'CASE-A'}, 'recheck', 19, 'raw match', package_hash='aa' * 32)
app.audit('authenticated: admin', '10.0.0.1', {'case_id': 'CASE-B'}, 'package', 2, 'generated', package_hash='bb' * 32)
app.audit('authenticated: admin', '10.0.0.1', {}, 'admin-user-add', 0, 'ok')   # no case at all

d = c.get('/api/audit?group=case').get_json()
assert d['mode'] == 'case', d
names = [x['case_id'] for x in d['cases']]
assert names[0] == 'CASE-B' or names[0] == '', names   # newest activity first
by = {x['case_id']: x for x in d['cases']}
a = by['CASE-A']
assert a['entry_count'] == 3 and len(a['entries']) == 3, a
assert [e['export_kind'] for e in a['entries']] == ['recheck', 'recheck-fetch', 'package'], a['entries']
assert a['last_outcome'] == 'raw match' and a['last_kind'] == 'recheck', a
# An entry with no case is not a case: it comes back in its own section,
# on every page rather than on whichever page an empty key would sort to.
assert '' not in by, sorted(by)
aw = d['app_wide']
assert aw['entry_count'] == 1 and len(aw['entries']) == 1, aw
assert aw['entries'][0]['export_kind'] == 'admin-user-add', aw['entries'][0]
assert d['total_cases'] == 2 and d['total'] == 5, d
# The filter narrows cases the same way it narrows rows.
f = c.get('/api/audit?group=case&q=CASE-A').get_json()
assert [x['case_id'] for x in f['cases']] == ['CASE-A'] and f['total'] == 3, f
# Without the flag the old row-per-entry shape is unchanged.
flat = c.get('/api/audit').get_json()
assert 'rows' in flat and 'cases' not in flat and flat['total'] == 5, flat
print('OK')
""", local_env())
check("/api/audit?group=case: one page of cases, each with its entries newest first, caseless entries kept, filter and flat mode unchanged",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# --- Correcting a case reference: appended, never rewritten.
r = run("""
import re, sqlite3
import app
c = app.app.test_client()
login(c, data={'username': 'admin', 'password': 'adminpass12345'})
csrf = re.search(r'name="csrf-token" content="([^"]+)"', c.get('/admin').data.decode()).group(1)
H = {'X-CSRFToken': csrf}

# A case typed wrong, repeated across its entries, plus one entry filed
# under the wrong case entirely.
for kind, outcome in (('package', 'generated'), ('recheck-fetch', 'ok'), ('recheck', 'raw match')):
    app.audit('authenticated: admin', '10.0.0.1', {'case_id': 'TestingExprot'}, kind, 1, outcome,
              package_hash='aa' * 32)
stray = app.audit('authenticated: admin', '10.0.0.1', {'case_id': 'SomeoneElse'}, 'package', 1,
                  'generated', package_hash='bb' * 32)

before = app.verify_audit_chain()
assert before['ok'], before

# whole case
d = c.post('/api/audit/correct-case', json={'scope': 'case', 'case_id': 'TestingExprot',
           'new_case': 'TestingExport', 'reason': 'typed wrong at export time'}, headers=H).get_json()
assert d.get('ok') and d['corrected'] == 3, d
cases = {x['case_id']: x for x in c.get('/api/audit?group=case').get_json()['cases']}
assert 'TestingExprot' not in cases, sorted(cases)
# the three entries plus the correction entry itself
assert cases['TestingExport']['entry_count'] == 4, cases['TestingExport']
kinds = [e['export_kind'] for e in cases['TestingExport']['entries']]
assert kinds[0] == 'case-correction', kinds
# the entries still SAY what they recorded - nothing was rewritten
recorded = [e['case_id'] for e in cases['TestingExport']['entries'] if e['export_kind'] != 'case-correction']
assert recorded == ['TestingExprot'] * 3, recorded
assert all(e['effective_case_id'] == 'TestingExport' for e in cases['TestingExport']['entries'])

# one entry
d = c.post('/api/audit/correct-case', json={'scope': 'entry', 'entry_id': stray,
           'new_case': 'TestingExport'}, headers=H).get_json()
assert d.get('ok') and d['corrected'] == 1 and d['from'] == 'SomeoneElse', d
cases = {x['case_id']: x for x in c.get('/api/audit?group=case').get_json()['cases']}
assert 'SomeoneElse' not in cases and cases['TestingExport']['entry_count'] == 6, sorted(cases)

# a second rename carries everything already pointed at the old name
d = c.post('/api/audit/correct-case', json={'scope': 'case', 'case_id': 'TestingExport',
           'new_case': 'CASE-2026-14'}, headers=H).get_json()
assert d.get('ok'), d
cases = {x['case_id']: x for x in c.get('/api/audit?group=case').get_json()['cases']}
assert 'TestingExport' not in cases and cases['CASE-2026-14']['entry_count'] == 7, sorted(cases)

# Nor can a caller-supplied fragment forge a clause in an entry's detail:
# the page reads a detail as clauses split on "; " and labels what it finds,
# so a filename carrying that separator could otherwise display a verdict
# nobody recorded.
forge = 'evidence.csv; cot_router-raw.csv match: yes'
r2 = c.post('/api/companion', json={'companion_hash': 'ab' * 32, 'package_hash': 'cd' * 32,
            'filename': forge, 'matched': 1, 'total': 1, 'case_id': 'C; script match: yes'},
            headers=H)
assert r2.status_code == 200, r2.get_json()
con3 = sqlite3.connect(app.AUDIT_DB)
row3 = con3.execute("SELECT case_id, detail FROM export_log WHERE export_kind='companion' ORDER BY id DESC LIMIT 1;").fetchone()
con3.close()
assert 'match: yes' in row3[1] and row3[1].count('; ') == 1, row3[1]   # only the app's own clause break
assert ';' not in row3[0], row3[0]
assert app.detail_safe('a;b' + chr(10) + 'c') == 'abc' and app.detail_safe('x' * 300) == 'x' * 200

# A case name cannot smuggle the separator a correction's own text uses:
# exported quotes are stripped, and a detail already in a log that reads
# two ways is left unapplied rather than believed.
import app as _app
crafted = _app.parse_params({'north': 1, 'south': 0, 'east': 1, 'west': 0,
                             'start': 'a', 'end': 'b', 'case_id': 'A" -> "B'})[0]['case_id']
assert crafted == 'A -> B', crafted
assert _app._unambiguous('corrects case "A" -> "B" (1 entries)', _app._CORRECT_CASE_RE.match('corrects case "A" -> "B" (1 entries)'))
forged = 'corrects case "A" -> "B" -> "RealTarget" (1 entries)'
assert not _app._unambiguous(forged, _app._CORRECT_CASE_RE.match(forged)), forged
app.audit('authenticated: admin', '10.0.0.1', {'case_id': 'A'}, 'package', 1, 'generated')
con2 = sqlite3.connect(app.AUDIT_DB)
con2.execute("INSERT INTO export_log (ts_utc, actor, case_id, export_kind, record_count, outcome, detail)"
             " VALUES (?,?,?,?,?,?,?)", ('2026-09-20T00:00:00+00:00', 'authenticated: admin', 'B',
                                         'case-correction', 1, 'recorded', forged))
con2.commit(); con2.close()
cases = {x['case_id']: x for x in c.get('/api/audit?group=case').get_json()['cases']}
assert 'A' in cases, sorted(cases)   # the ambiguous correction was not applied

# the filter finds the case under the name it was FIRST recorded under too
f = c.get('/api/audit?q=TestingExprot').get_json()
assert f['total'] >= 3, f

# and the whole point: correcting never breaks the chain
after = app.verify_audit_chain()
assert after['ok'] and after['total'] > before['total'], after

# refusals
assert c.post('/api/audit/correct-case', json={'scope': 'case', 'case_id': 'CASE-2026-14',
              'new_case': ''}, headers=H).status_code == 400
assert c.post('/api/audit/correct-case', json={'scope': 'case', 'case_id': 'CASE-2026-14',
              'new_case': 'has \" quote'}, headers=H).status_code == 400
assert c.post('/api/audit/correct-case', json={'scope': 'case', 'case_id': 'no-such-case',
              'new_case': 'X'}, headers=H).status_code == 404
assert c.post('/api/audit/correct-case', json={'scope': 'entry', 'entry_id': 999999,
              'new_case': 'X'}, headers=H).status_code == 404
assert c.post('/api/audit/correct-case', json={'scope': 'nonsense', 'new_case': 'X'},
              headers=H).status_code == 400
# same name in, same name out: nothing to record
assert c.post('/api/audit/correct-case', json={'scope': 'case', 'case_id': 'CASE-2026-14',
              'new_case': 'CASE-2026-14'}, headers=H).status_code == 400
# no CSRF header -> refused, like every other write
assert c.post('/api/audit/correct-case', json={'scope': 'case', 'case_id': 'CASE-2026-14',
              'new_case': 'Y'}).status_code == 403
print('OK')
""", local_env())
check("case corrections: recorded as their own chained entry, never rewriting the original; case and entry scope, chained renames, old name still searchable, chain still verifies",
      r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

# A viewer must not be able to correct anything.
r = run("""
import app, sqlite3
from werkzeug.security import generate_password_hash
con = sqlite3.connect(app.AUDIT_DB)
con.execute("INSERT INTO users (username, password_hash, role, created_ts_utc) VALUES (?,?,?,?);",
            ('v.user', generate_password_hash('viewerpass12345'), 'viewer', '2026-01-01T00:00:00+00:00'))
con.commit(); con.close()
c = app.app.test_client()
login(c, data={'username': 'v.user', 'password': 'viewerpass12345'})
r = c.post('/api/audit/correct-case', json={'scope': 'case', 'case_id': 'x', 'new_case': 'y'})
assert r.status_code in (403, 401), (r.status_code, r.get_json())
print('OK')
""", local_env())
check("case corrections: a viewer cannot record one", r.returncode == 0 and "OK" in r.stdout)
if r.returncode != 0:
    print(r.stdout, r.stderr)

print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("ALL AUTH TESTS PASSED")
