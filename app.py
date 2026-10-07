# Checked first, before any other import: a too-old interpreter otherwise
# fails deep inside a third-party dependency (or on a syntax feature this
# file itself uses) with a confusing traceback that gives no hint the real
# problem is just the Python version. sys is the one import guaranteed to
# work on literally any Python ever released, so this check itself can't
# be what fails. str.format(), not an f-string, for the same reason - an
# f-string wouldn't even be legal syntax pre-3.6, and the whole point is
# for this message to actually display instead of a bare SyntaxError.
# 3.10 because that is what Ubuntu 22.04 ships, and 22.04 is what TAK
# Server is commonly deployed on. This was 3.12 until 2026-10-03, matching
# the Dockerfile's python:3.12-slim base - which meant a side-by-side
# install on 22.04 needed Python from the deadsnakes PPA, and on a
# restricted agency network that PPA can be unreachable entirely, so the
# install could not be completed at all.
#
# Lowered only after testing rather than reasoning: every suite that can
# run without a browser passes on 22.04's stock 3.10.12, resolving the same
# dependency versions 3.12 does. A grep for 3.11/3.12-only features found
# none, but the grep was not what settled it - the test run was.
#
# This is a FLOOR, not a target: 3.12, 3.13 and later all satisfy it, so
# nothing here needs revisiting as newer releases ship. The Dockerfile
# deliberately stays on 3.12 - the container should run a current Python
# even though the app no longer requires one. CI runs the suites on both
# 3.10 and 3.12 so this floor cannot quietly stop being true; the
# transitive Flask dependencies (Werkzeug and friends) are unpinned, and
# the day one of them drops 3.10 support is the day the two interpreters
# can start behaving differently.
import sys

if sys.version_info < (3, 10):
    sys.stderr.write(
        "TAK-Extract requires Python 3.10 or newer (found {}.{}.{}).\n"
        "See README.md's Prerequisites section for how to install a newer "
        "Python without disturbing your system's default one.\n".format(
            *sys.version_info[:3]
        )
    )
    sys.exit(1)

import csv
import hashlib
import io
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import kmz
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import psycopg2
from dotenv import load_dotenv
from flask import (Flask, Response, g, jsonify, redirect, render_template,
                    request, session, url_for, abort, send_from_directory)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import exports
import shapes
from tls import detect_local_ip, ensure_self_signed_cert, running_in_container

# A .env this process cannot READ is not an error. On a side-by-side
# install .env is owned by the administrator and mode 600, because it holds
# SECRET_KEY and the database password; systemd passes its contents to the
# service by reading it as root before dropping privileges, so the app never
# needs to open it itself. A command-line tool running AS the service
# account (check-database.sh does exactly this) therefore hits
# PermissionError here and dies on import, before main() can explain
# anything - which is what happened to connect-database.sh's baseline step
# on a real install. Those callers put the settings in the environment
# instead, which is where load_dotenv would have put them anyway.
#
# Only the permission case is swallowed. A malformed .env, or any other
# failure, still raises.
try:
    load_dotenv()
except (PermissionError, OSError):
    pass

app = Flask(__name__)

# Where the audit log lives. Records WHO exported WHAT PARAMETERS and WHEN.
# Deliberately contains no location data - only the shape of the request.
AUDIT_DB = os.getenv("AUDIT_DB", "audit.sqlite")

# Semantic versioning (MAJOR.MINOR.PATCH), tracked in CHANGELOG.md from
# v0.4.0 on - bump this alongside every new dated entry there. Embedded as
# plain descriptive text in generated exports (KMZ popups, package README,
# parameters.txt) and recorded in the audit log via kmz.py/exports.py -
# nothing parses this string, so its exact format is free to change without
# breaking anything downstream.
#
# It says which build produced a given export, so a stale value here is a
# false statement in an evidence file rather than a cosmetic slip: this sat
# at 1.0.0 from v1.0.0 through v1.6.1 while releases moved on, and every
# package produced in that period names the wrong producing version. This
# is the ONLY place the version is written - exports.build_package() takes
# it as a required argument rather than defaulting to its own copy, which
# is how the two were able to disagree in the first place.
APP_VERSION = "TAK-Extract 1.21.5 (BETA)"


def _detect_commit():
    """The git commit of the code that is running, read from the checkout
    (.git ships in the Docker image for the same reason - see
    .dockerignore) or from APP_COMMIT in the environment. Named in every
    package README, certification template and audit entry beside the
    version string, so "which code ran" has an answer that can be checked
    against the public repository. None when it cannot be read."""
    env = os.environ.get("APP_COMMIT", "").strip()
    if env:
        return env[:40]
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        head = open(os.path.join(here, ".git", "HEAD"), encoding="utf-8").read().strip()
        if not head.startswith("ref: "):
            return head[:40]
        ref = head[5:]
        ref_path = os.path.join(here, ".git", *ref.split("/"))
        if os.path.exists(ref_path):
            return open(ref_path, encoding="utf-8").read().strip()[:40]
        packed = os.path.join(here, ".git", "packed-refs")
        if os.path.exists(packed):
            for line in open(packed, encoding="utf-8"):
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0][:40]
    except Exception:
        pass
    return None


APP_COMMIT = _detect_commit()
TOOL_VERSION = APP_VERSION + (f" (commit {APP_COMMIT})" if APP_COMMIT else "")

# Off by default: without it, this app is loopback-only everywhere (see
# gunicorn.conf.py) and a reverse proxy is expected to provide any real
# network exposure and its own TLS - the common case, and the one every
# other piece of this app already assumes (docker-compose.yml,
# tak-extract.service). SERVE_TLS is for the opposite case: someone who
# wants this app directly reachable with no proxy in front of it at all.
# gunicorn.conf.py reads this same variable to decide its own bind
# address and generate a self-signed cert (see tls.py) - this constant is
# only for app.py's own behavior (the redirect below, the dev-server
# block, the bootstrap message's URL scheme).
SERVE_TLS = os.getenv("SERVE_TLS", "false").strip().lower() in ("true", "1", "yes")

# The port this process actually listens on, in ONE place, because the
# two had drifted: the startup banner printed PORT (default 8080) while
# `python app.py` was hardcoded to 5000, so running the dev server with
# PORT set announced a URL nothing was listening on.
#
# The banner prints at import time, below, before the __main__ block at
# the bottom runs - so it cannot be told which of the two is starting.
# It works it out instead: when this file is run directly its module
# name is already "__main__" by the time this line executes, and under
# gunicorn (both install shapes) it is "app".
#
# The dev server deliberately does NOT read PORT: README's quick start
# says to copy .env.example, which carries PORT=8080, and that would
# silently move `python app.py` off the 5000 the same page tells you to
# open. PORT stays what it has always been - the served install's port.
DEV_SERVER = __name__ == "__main__"
LISTEN_PORT = "5000" if DEV_SERVER else (os.getenv("PORT") or "8080")


def _tls_expected_hosts():
    """The hostnames this install answers to when SERVE_TLS is on.

    Derived the same way the certificate's own subject is (see the startup
    banner and tls.py): TLS_CERT_HOST when set - which is what setup.sh
    writes and what the cert is issued for - otherwise the detected LAN
    address, which is meaningless inside a container. Loopback is always
    valid for somebody working on the box itself."""
    hosts = {"localhost", "127.0.0.1", "::1"}
    configured = (os.getenv("TLS_CERT_HOST") or "").strip().lower()
    if configured:
        hosts.add(configured)
    elif not running_in_container():
        detected = (detect_local_ip() or "").strip().lower()
        if detected:
            hosts.add(detected)
    return hosts


TLS_EXPECTED_HOSTS = _tls_expected_hosts() if SERVE_TLS else set()
# Where to send a request whose Host is none of the above. Never the host
# that arrived - that is the whole point - and never empty.
TLS_PREFERRED_HOST = ((os.getenv("TLS_CERT_HOST") or "").strip()
                      or (sorted(TLS_EXPECTED_HOSTS - {"localhost", "127.0.0.1", "::1"}) or [""])[0]
                      or "localhost") if SERVE_TLS else ""

# request.remote_addr - used everywhere a real client IP matters (the
# audit log, login lockout, the fail2ban-oriented auth log below) - would
# otherwise always be the reverse proxy's OWN IP, not the real client's,
# in this app's own default/recommended deployment (a reverse proxy in
# front - see SERVE_TLS above). ProxyFix trusts exactly ONE hop of
# X-Forwarded-For, matching that single-reverse-proxy topology (Caddy/
# nginx directly in front, nothing more elaborate between this app and
# the internet) - only applied when SERVE_TLS is off, i.e. only when a
# reverse proxy is actually the expected topology in the first place.
# Deliberately NOT applied when SERVE_TLS is on: in that mode this app
# faces the internet directly with no proxy to trust, and blindly
# trusting X-Forwarded-For there would let anyone spoof their own source
# IP just by sending a fake header - request.remote_addr is already the
# real, untrusted-header-immune connecting IP in that mode.
if not SERVE_TLS:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# ---------------------------------------------------------------------------
# Auth mode
# ---------------------------------------------------------------------------
# Authentication is pluggable; authorization is not. In 'authentik' mode a
# reverse proxy's forward-auth sets X-authentik-username and this app
# trusts it (see identify()); in 'local' mode this app's own login/session
# does the job. Either way ROLE always comes from this app's own `users`
# table (lookup_role()) - Authentik vouching for identity never grants a
# role by itself.
#
# Not inferred from the header's mere presence - that would tie
# correctness to gunicorn staying bound to 127.0.0.1 only, a network
# assumption rather than an explicit fail-closed flag. Refusing to start
# on an invalid AUTH_MODE follows the same logic: a wrong silent default
# is worse than a crash pointing straight at the fix.
AUTH_MODE = os.getenv("AUTH_MODE", "").strip().lower()
if AUTH_MODE not in ("authentik", "local"):
    raise RuntimeError(
        "AUTH_MODE must be set to 'authentik' or 'local' in the environment - "
        "refusing to start with access control in an undefined state."
    )

# These two are individually reasonable and catastrophic together, so the
# combination is refused outright rather than left to be discovered.
#
# 'authentik' mode's ONLY proof of identity is the X-authentik-username
# header (see current_identity()), which is trustworthy exactly as long as
# a forward-auth reverse proxy is the only thing that can reach this app
# and it overwrites that header on every request. SERVE_TLS means the
# opposite by definition: no proxy in front, and gunicorn binds 0.0.0.0
# (see gunicorn.conf.py) so it's reachable directly. Together they mean
# anyone who can reach the port is whoever they say they are - one curl
# with a made-up header is full admin access to real location history.
#
# Note this is the same reasoning that already keeps ProxyFix off in
# SERVE_TLS mode just below: a header from an untrusted peer can't be
# believed. That applies at least as strongly to the header that IS the
# authentication.
if AUTH_MODE == "authentik" and SERVE_TLS:
    raise RuntimeError(
        "AUTH_MODE=authentik with SERVE_TLS=true is refused: authentik mode "
        "trusts the X-authentik-username header, which is only safe behind a "
        "forward-auth reverse proxy, but SERVE_TLS means this app faces the "
        "network directly with no proxy to set it. Anyone able to reach this "
        "port could send that header themselves and be treated as any user. "
        "Use AUTH_MODE=local for a directly-exposed deployment, or put a "
        "forward-auth proxy in front and set SERVE_TLS=false."
    )

# Required in both modes (not just 'local') for a simpler mental model - one
# less thing to get right per deployment. Signs the Flask session cookie
# used for local-mode login; unused for the access-control decision itself
# in authentik mode, but still needed so Flask can run session() at all.
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    raise RuntimeError("SECRET_KEY is required (signs the login session cookie). Set it in .env.")
app.config["SECRET_KEY"] = _secret_key

# 30-minute IDLE timeout (not a fixed absolute one) - session.permanent is
# set once, at login (see login_page()), and Flask's own default
# SESSION_REFRESH_EACH_REQUEST=True (untouched) resends a freshly-expiring
# cookie on every active request, so the clock only runs out after this
# many minutes with no requests at all. Inert in authentik mode, which
# never sets session.permanent in the first place.
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# HTTPONLY is Flask's own default already - set explicitly so the intent
# is documented in code, not left to a library default someone has to
# already know about. SECURE defaults to True (fail-closed, same posture
# as AUTH_MODE/SECRET_KEY above) - but a Secure-flagged cookie is silently
# never sent back by a browser over plain http://, which is exactly how
# local dev (`python app.py` on localhost) has been run all along, so this
# needs to be overridable - see .env.example for the local-dev opt-out.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "true").strip().lower() not in (
    "false", "0", "no",
)

# A restored backup is just a sqlite file of text/metadata (the audit log,
# users, settings) - it should never be more than a few MB even with a
# large history. This cap is a safety rail against a mistaken or abusive
# upload exhausting memory, not a realistic ceiling for a real backup -
# and admin_restore writes the whole upload to disk before validating
# it, so the cap is the only thing bounding that write. 16 MB is still
# several times any plausible real backup.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


# One shared policy for every page - simpler than per-route, and no page
# needs anything stricter would deny. Origins are the verified union of
# what this app actually loads: unpkg.com for the pinned CDN libraries AND
# the image assets their CSS references (Leaflet/leaflet-draw icons,
# resolved relative to unpkg.com even though no template spells that path
# out), OpenStreetMap tiles, and Nominatim (called from geocoder JS, never
# a literal URL in a template).
#
# img-src needs BOTH tile hostname forms: index.html's map uses the
# current unsharded tile.openstreetmap.org, verify.html still uses the
# older {s}.tile.openstreetmap.org sharding - a wildcard host-source only
# matches when something fills the position it wildcards, so
# *.tile.openstreetmap.org alone does NOT also match the bare hostname.
# Caught live: index.html's tiles went silently blank until this was
# fixed.
#
# connect-src also allows unpkg.com: with DevTools open, Chrome fetches
# each script's .js.map source map in the background, which connect-src
# governs rather than script-src - harmless, but was producing a
# scary-looking console violation.
#
# script-src carries a per-request nonce (see _csp_nonce below) and no
# 'unsafe-inline': every page's own JS lives in one inline <script> block
# that the template stamps with the nonce, so only that block and the
# pinned unpkg.com libraries can run. Markup that reaches the page any
# other way - a callsign out of a dropped file, a value out of the audit
# log - cannot start script even if an escaping slip let it through as
# HTML. (Event-handler attributes and javascript: URLs are blocked by the
# same rule; the templates use neither.)
#
# style-src keeps 'unsafe-inline': the templates and Leaflet use style=
# attributes throughout, and the popup sanitiser on the Verify page
# deliberately keeps a restricted style= on a dropped file's description.
# A nonce on style-src would need all of that reworked for the much
# smaller gain of blocking CSS injection.
CSP_TEMPLATE = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}' https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://unpkg.com; "
    "img-src 'self' data: https://unpkg.com https://tile.openstreetmap.org "
    "https://*.tile.openstreetmap.org; "
    "connect-src 'self' https://nominatim.openstreetmap.org https://unpkg.com; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none';"
)

# The two sources above that leave the network, and what turns each off.
# With a map setting off, the template stops rendering the thing that
# would have made the request - and this takes the permission away too,
# so the browser refuses it rather than relying on the markup being the
# only route to it. Only the Export and Verify pages draw a map and only
# they set g.map_opts (see index/verify_page), so every other response
# keeps the policy exactly as before.
# Both tile hostname forms belong to "tiles": index.html uses the bare
# host and verify.html the older sharded one (see the img-src note
# above), so turning tiles off has to withdraw both.
CSP_MAP_SOURCES = {
    "tiles": ("https://tile.openstreetmap.org",
              "https://*.tile.openstreetmap.org"),
    "search": ("https://nominatim.openstreetmap.org",),
}


def csp_header():
    """The policy for THIS response, with any map source the install has
    switched off removed from it."""
    policy = CSP_TEMPLATE.format(nonce=_csp_nonce())
    # after_request only ever runs inside a request, so g is always
    # available here; a page that drew no map simply never set this.
    opts = g.get("map_opts")
    if not opts:
        return policy
    for field, sources in CSP_MAP_SOURCES.items():
        if opts.get(field):
            continue
        for source in sources:
            # Each appears once, with a single space either side of it in
            # the template above; dropping the leading space keeps the
            # directive from ending up with a double one.
            policy = policy.replace(" " + source, "")
    return policy


@app.before_request
def _force_https():
    """Only active when SERVE_TLS is on - this app is otherwise always
    loopback-only behind an external reverse proxy (see gunicorn.conf.py),
    which already terminates its own TLS; forcing a redirect there would
    break that proxy's own plain-HTTP connection to this app internally,
    not just be redundant. request.is_secure reflects the CURRENT
    connection's actual scheme (gunicorn/Flask's own TLS handshake in
    this mode, not a proxy-set header) - true or false, never guessed.
    302, not 301: this is an environment-dependent redirect, not a
    permanent one - a 301 would have browsers cache it past the point
    SERVE_TLS might later be turned back off."""
    if SERVE_TLS and not request.is_secure:
        # Built from a host this install expects, not from the one that
        # arrived. request.url embeds the Host header verbatim, so echoing
        # it back answers a request claiming `Host: evil.example` with a
        # redirect to https://evil.example/<same path>. Following that is
        # the caller's own problem - but a cache in front of this app would
        # key the redirect on the path and could then serve it to somebody
        # else. SERVE_TLS is documented as the no-proxy case, which makes
        # that unlikely; nothing in the code enforced it, and the host this
        # install actually answers to is already known. An unrecognised Host
        # is redirected to the expected one rather than refused, so a
        # misconfigured-but-honest request still lands somewhere usable.
        host = request.host or ""
        bare = host.rsplit(":", 1)[0] if (":" in host and not host.endswith("]")) else host
        if bare.strip("[]").lower() not in TLS_EXPECTED_HOSTS:
            # Keep the port so the redirect stays reachable, but only if it
            # really is one. It comes from the same untrusted header as the
            # host, and there is no reason to carry an arbitrary fragment
            # into a Location we are otherwise rebuilding from known values.
            port = host.rsplit(":", 1)[1] if (":" in host and not host.endswith("]")) else ""
            host = TLS_PREFERRED_HOST + (":" + port if port.isdigit() else "")
        path = request.full_path
        if path.endswith("?") and not request.query_string:
            path = path[:-1]
        return redirect("https://" + host + path, code=302)


def _csp_nonce():
    """This request's script nonce - minted on first use, so the template
    and the response header always agree. 128 bits, base64url."""
    nonce = getattr(g, "csp_nonce", None)
    if not nonce:
        nonce = g.csp_nonce = secrets.token_urlsafe(16)
    return nonce


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = csp_header()
    # This app doesn't use any of these browser features itself, and
    # denying them outright means an embedded/framed context (already
    # blocked by frame-ancestors 'none' above, but defense in depth) can't
    # invoke them either.
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    )
    # Only when the connection is genuinely HTTPS right now - matches
    # request.is_secure's own reasoning in _force_https() above (the real
    # negotiated scheme, never guessed from a header). Behind a reverse
    # proxy (the common case, SERVE_TLS off), that proxy already owns HSTS
    # for its own domain - this app sending it too over the PLAIN http://
    # connection it actually has to that proxy would be meaningless at
    # best. Only SERVE_TLS mode ever has a real, direct HTTPS connection
    # to send this on.
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # gunicorn's own Server header (e.g. "gunicorn/23.0.0") discloses its
    # exact version to anyone scanning this from outside - checked directly
    # against gunicorn 23.0.0's own source (http/wsgi.py's
    # Response.default_headers()) rather than assumed: it unconditionally
    # writes its OWN Server line before appending whatever this app sets,
    # so setting response.headers["Server"] here does NOT override it -
    # it would just add a second, confusing Server header while gunicorn's
    # real version stays in the response regardless. There's no clean way
    # to suppress this from application code (the SERVER constant is bound
    # into gunicorn's own wsgi module at import time; patching it would
    # mean depending on gunicorn's internal implementation, not a
    # documented interface, and could silently break across versions).
    # The standard, correct place to strip or rewrite this is the reverse
    # proxy - the default/recommended deployment here for exactly this
    # kind of reason. It's only a real, unavoidable-from-here exposure in
    # SERVE_TLS mode, where gunicorn faces the internet directly with no
    # proxy in front to fix it at.
    return response


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_setting(key, env_fallback=None, default=None):
    """A value from app_settings (admin-editable, no restart needed), then
    the .env-seeded fallback if nothing's been saved there yet, then
    `default` if that's unset too. `default` should only ever be something
    genuinely standard across nearly every real TAK Server install (the
    standard Postgres port, TAK Server's own standard database name) -
    never for host or user, where a wrong silent default could mean
    quietly connecting to nothing, or to the wrong database entirely."""
    con = sqlite3.connect(AUDIT_DB)
    row = con.execute("SELECT value FROM app_settings WHERE key = ?;", (key,)).fetchone()
    con.close()
    if row and row[0] not in (None, ""):
        return row[0]
    env_val = os.getenv(env_fallback) if env_fallback else None
    return env_val if env_val not in (None, "") else default


def map_options():
    """What the map may contact, for the two pages that draw one.

    Both default ON, which is what every install has done until now - this
    turns a documented caveat into a switch rather than changing anybody's
    behaviour. Off matters for a network where a request leaving the agency
    is the problem, not the latency:

    - search: whatever an operator types goes to OpenStreetMap's public
      Nominatim service. "123 Main St" is a lookup; a case address typed
      into it is a disclosure, and the operator cannot take it back.
    - tiles: each one is a request naming the area being looked at, so the
      pattern of them describes where an investigation is pointed even
      though no case data is sent. Off leaves the map blank but still
      drawable - the Selected area panel reports the coordinates either way.
    """
    return {
        "search": get_setting("map_search", "MAP_SEARCH", "true") == "true",
        "tiles": get_setting("map_tiles", "MAP_TILES", "true") == "true",
    }


def set_setting(key, value):
    con = sqlite3.connect(AUDIT_DB)
    con.execute(
        "INSERT INTO app_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        (key, value),
    )
    con.commit()
    con.close()


VALID_THEMES = {"light", "dark", "system"}


def get_theme():
    """This user's own light/dark preference, stored against their
    account - not a per-browser or site-wide setting. Falls back to
    'system' (no override at all - the page's own prefers-color-scheme
    media query decides) if nothing's been set yet, or if there's no
    logged-in user to look one up for at all (the login page itself,
    before authentication - g.username is only set by require_role(),
    which that one route doesn't use)."""
    username = getattr(g, "username", None)
    if not username:
        return "system"
    con = sqlite3.connect(AUDIT_DB)
    row = con.execute(
        "SELECT theme FROM users WHERE username = ? COLLATE NOCASE;", (username,)
    ).fetchone()
    con.close()
    if row and row[0] in VALID_THEMES:
        return row[0]
    return "system"


def get_connection():
    """Open a fresh connection to the TAK database, using whatever
    credentials are currently persisted in app_settings (falling back to
    the .env-seeded values on first run, before an admin has ever saved
    anything via the admin page). Deliberately not cached/pooled - a
    long-lived connection object would keep using stale credentials after
    an admin rotates them here, which is the whole point of storing them
    somewhere editable at runtime instead of only in .env.

    Port and database name default to TAK Server's own standard values
    (5432, 'cot') if nothing else is configured - true for both an
    all-in-one install and a split one where Postgres lives on its own
    box. Host has NO default (an all-in-one system's database is on
    127.0.0.1; a split system's is wherever that separate database server
    actually is - there's no single value that's correct for both, so
    this is left for an admin to set explicitly rather than guessing).
    User has no default either - a shared, unscoped default credential for
    a database connection is a real security anti-pattern to avoid, not
    a convenience worth baking in.

    Raises a plain RuntimeError (not psycopg2's own, much less readable
    connection-failure text) when host/user are still blank - the expected
    state right after a fresh install, before an admin has visited the
    System page yet. Every caller already catches this the same way it
    catches a real connection failure (see each /api/... route below), so
    this surfaces as a clear "not configured yet" message wherever it's
    tried, instead of psycopg2 failing to even resolve an empty hostname."""
    host = get_setting("db_host", "DB_HOST")
    user = get_setting("db_user", "DB_USER")
    if not host or not user:
        raise RuntimeError(
            "TAK Server database connection isn't configured yet - an admin "
            "needs to set it from the System page."
        )
    return psycopg2.connect(
        host=host,
        port=get_setting("db_port", "DB_PORT", default="5432"),
        dbname=get_setting("db_name", "DB_NAME", default="cot"),
        user=user,
        password=get_setting("db_password", "DB_PASSWORD"),
        connect_timeout=5,
    )


def get_db_timezone(conn):
    """The IANA zone name (e.g. "America/Chicago", or "UTC") this already-
    open connection's session is using - the same value /api/extent shows
    the operator as a hint next to Start/End, needed here so an export's
    audit row can record what window_start/window_end actually meant
    instead of leaving that implicit. Never raises: a timezone lookup
    failure must not break an export any more than an audit-logging
    failure should (see audit()) - None just means a later verification
    can't convert this row's window to UTC."""
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW timezone;")
            return cur.fetchone()[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def _restrict_audit_db_mode():
    """audit.sqlite owner-only, whatever the umask was.

    sqlite3 creates it 0666 & ~umask - 0644 under both systemd's default
    and the container's - and the file holds the TAK Server password in
    plaintext (app_settings), every account's password hash, and the
    hash-chained log itself. Measured at 644 on a real install, inside a
    directory the takextract group could traverse, which connect-database.sh
    puts the postgres account into so it can share the re-check folder.

    Done here rather than only in the installers because this is the one
    place that runs on every start of every install shape, so it also
    catches a database restored or copied in by hand. Best-effort: a
    filesystem without POSIX modes (a Windows dev box) must not stop the
    app booting.
    """
    try:
        if os.path.exists(AUDIT_DB):
            os.chmod(AUDIT_DB, 0o600)
    except OSError:
        pass


def init_audit():
    con = sqlite3.connect(AUDIT_DB)
    _restrict_audit_db_mode()
    con.execute("""
        CREATE TABLE IF NOT EXISTS export_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc          TEXT    NOT NULL,
            ts_local        TEXT,
            actor           TEXT,
            client_ip       TEXT,
            case_id         TEXT,
            export_kind     TEXT,
            window_start    TEXT,
            window_end      TEXT,
            north           REAL,
            south           REAL,
            west            REAL,
            east            REAL,
            record_count    INTEGER,
            package_sha256  TEXT,
            outcome         TEXT,
            detail          TEXT,
            files_excluded  TEXT,
            channels_excluded TEXT
        );
    """)
    # CREATE TABLE IF NOT EXISTS is a no-op against an audit.sqlite that
    # already exists from before a column was added. SQLite has no ADD
    # COLUMN IF NOT EXISTS, so migrate explicitly and treat "duplicate
    # column" as proof the migration already ran, not an error.
    for ddl in [
        "ALTER TABLE export_log ADD COLUMN files_excluded TEXT;",
        "ALTER TABLE export_log ADD COLUMN channels_excluded TEXT;",
        # window_start/window_end are the raw <input type="datetime-local">
        # values the operator typed in - timezone-NAIVE by browser design,
        # interpreted at export time using the TAK database's own session
        # timezone (see get_db_timezone()). That interpretation was never
        # actually recorded anywhere before this column existed - reading
        # an old row back later gave no way to know what timezone its
        # window_start/window_end meant. Rows written before this column
        # existed keep it NULL - there's no reliable way to backfill what
        # timezone was in effect for a past export after the fact.
        "ALTER TABLE export_log ADD COLUMN window_timezone TEXT;",
        # Who the export was run FOR, as typed by the operator - distinct
        # from `actor`, which is the verified logged-in account that ran it
        # (see identify()). In practice an admin runs exports on behalf of
        # other people, so "who asked for this" is a real fact about the
        # request that was previously not captured anywhere: the page used
        # to prompt for a name and then throw it away, because identify()
        # correctly prefers the authenticated session over anything typed
        # into a box. Self-declared and unverified by nature - it is a note
        # about who the operator says requested it, never an identity claim
        # the way `actor` is. NULL for rows written before this column, and
        # for requests with nothing typed in.
        "ALTER TABLE export_log ADD COLUMN requested_for TEXT;",
        # The version and commit of the code that wrote the row.
        "ALTER TABLE export_log ADD COLUMN tool_version TEXT;",
        # The hash chain: row_hash is SHA-256 over this row's own content
        # (as stored, read back after the insert) plus prev_hash, the
        # previous row's row_hash. Any later edit, deletion or insertion
        # breaks the chain from that point; verify_audit_chain() walks it.
        # Rows from before the chain existed keep NULL and are reported as
        # predating it, never as broken.
        "ALTER TABLE export_log ADD COLUMN prev_hash TEXT;",
        "ALTER TABLE export_log ADD COLUMN row_hash TEXT;",
    ]:
        try:
            con.execute(ddl)
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                raise
    # Re-check tokens: one per package, created when the package is built,
    # valid 48 hours. The token is what lets the TAK Server fetch the
    # package's queries.sql and post its re-check hashes back without a
    # login (see /recheck/<token>/...). The script text is stored here so
    # the served bytes are exactly the zip's - the same hash appears in
    # the package's SHA256SUMS.txt.
    # An audit.sqlite from before requested_for was stored here keeps its
    # table; the same "duplicate column means it already ran" rule as the
    # export_log migrations above.
    _RECHECK_TOKEN_MIGRATIONS = [
        "ALTER TABLE recheck_tokens ADD COLUMN requested_for TEXT;",
        # The case AS RECORDED, which is not always the case as spelled in
        # filenames: safe_case_id() strips whatever a filename cannot hold,
        # so "River Road" is filed in the log as "River Road" but names its
        # files "RiverRoad". Without this the re-check's own entries were
        # recorded under the file spelling and sat in the log as a separate
        # case from the export they check.
        "ALTER TABLE recheck_tokens ADD COLUMN case_id TEXT;",
    ]
    con.execute("""
        CREATE TABLE IF NOT EXISTS recheck_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            case_prefix TEXT NOT NULL,
            case_id TEXT,
            package_sha256 TEXT NOT NULL,
            raw_sha256 TEXT,
            queries_sql TEXT NOT NULL,
            created_by TEXT,
            requested_for TEXT,
            created_utc TEXT NOT NULL,
            expires_utc TEXT NOT NULL,
            fetch_count INTEGER NOT NULL DEFAULT 0,
            result_count INTEGER NOT NULL DEFAULT 0
        );
    """)
    for ddl in _RECHECK_TOKEN_MIGRATIONS:
        try:
            con.execute(ddl)
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                raise
    # The script a package was built with, kept beyond its token. A token
    # lasts 48 hours and is shown once, on the page that produced it; the
    # script itself is what a later re-check needs, and until this table
    # existed the only copy the server had went with the token. Nothing
    # here is evidence: queries.sql holds the statements, not the rows -
    # the same case reference, window, box and channel names the export's
    # own audit entry already records, and no location data. What makes it
    # safe to run later is that the export entry records the script's
    # SHA-256, so this copy is checked against the chained log before a
    # token is ever minted from it (see /api/audit/recheck/<hash>).
    con.execute("""
        CREATE TABLE IF NOT EXISTS recheck_scripts (
            package_sha256 TEXT PRIMARY KEY,
            case_prefix TEXT NOT NULL,
            case_id TEXT,
            raw_sha256 TEXT,
            queries_sql TEXT NOT NULL,
            created_by TEXT,
            requested_for TEXT,
            created_utc TEXT NOT NULL
        );
    """)
    con.commit()
    con.close()


# Runs at import time, not just under `if __name__ == "__main__"` - a
# gunicorn deployment imports this module without ever executing that
# block (`gunicorn app:app` never sets __name__ to "__main__"), so the
# table would never get created on a fresh server and the very first
# export would crash trying to write to it. Idempotent either way
# (CREATE TABLE IF NOT EXISTS), so calling it here doesn't change
# behavior for `python app.py` - it just also covers gunicorn.
init_audit()


VALID_ROLES = {"admin", "viewer"}

# Failed-login lockout: local mode only (authentik mode has no password
# here to guess). Per-username, not per-IP - a small trusted-team tool,
# and IP-based tracking adds its own DoS surface (and complexity) without
# being asked for.
FAILED_LOGIN_LIMIT = 5
LOCKOUT_MINUTES = 15

# Length only, not composition rules - current guidance (NIST SP 800-63B)
# favors length over forced character-class complexity, which tends to
# push people toward predictable substitutions rather than actually
# stronger secrets.
MIN_PASSWORD_LENGTH = 10


def validate_password(password):
    """None if OK, else an error string."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    return None


def init_users_and_settings():
    """users: who can log in (or, in authentik mode, who has a role at all)
    and what they're allowed to do. app_settings: admin-editable config
    (currently just the TAK Postgres connection) that needs to change
    without a restart - see get_setting()/set_setting()."""
    con = sqlite3.connect(AUDIT_DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash   TEXT,
            role            TEXT NOT NULL,
            created_ts_utc  TEXT NOT NULL,
            updated_ts_utc  TEXT
        );
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    # Same idempotent-migration convention as init_audit(): CREATE TABLE IF
    # NOT EXISTS above is a no-op against a users table that already
    # existed before these two columns did, so migrate explicitly and
    # treat "duplicate column" as proof it already ran, not an error.
    for ddl in [
        "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;",
        "ALTER TABLE users ADD COLUMN locked_until TEXT;",
        "ALTER TABLE users ADD COLUMN theme TEXT;",
    ]:
        try:
            con.execute(ddl)
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                raise
    # theme used to be a single site-wide app_settings row before it became
    # per-user - that old value has no one clear owner to hand it to, so
    # it's just retired rather than migrated onto some particular account.
    con.execute("DELETE FROM app_settings WHERE key = 'theme';")
    con.commit()
    con.close()


init_users_and_settings()


def _hl(text):
    """Highlight a value in the startup banner (admin username, one-time
    password, login URL) so it stands out among gunicorn's own log lines -
    those are the three things someone scans this banner to find. Bright
    cyan via ANSI, unless NO_COLOR is set (the standard opt-out). Not gated
    on isatty(): this banner is normally read through `docker compose logs`,
    where stdout isn't a terminal but the viewer renders color fine; the
    NO_COLOR escape hatch covers a plain-text log viewer that wouldn't."""
    if os.getenv("NO_COLOR"):
        return str(text)
    return f"\033[1;36m{text}\033[0m"


def bootstrap_admin():
    """Ensure BOOTSTRAP_ADMIN_USERNAME (if set) is an admin whenever `users`
    currently has none. Runs on every startup, not just once - deliberate:
    if every admin is ever deleted, the next restart re-establishes this
    one instead of requiring direct sqlite surgery. Accepted tradeoff for a
    small trusted-team deployment: as long as the env var stays set, this
    is a standing recovery path, not a one-time setup step.

    BOOTSTRAP_ADMIN_PASSWORD, if explicitly set, is respected unchanged.
    Otherwise a random password is generated and printed to stdout ONCE -
    never stored in plaintext, never regenerated on a normal restart (this
    only runs when admin_count is 0), but a genuine lockout-recovery run
    correctly gets a fresh one, not the old.

    Gunicorn runs multiple worker processes (see gunicorn.conf.py), each
    independently importing this module - so this genuinely runs more than
    once, concurrently, on every real startup, not just hypothetically.
    Without an explicit lock here, two workers could both read admin_count
    as 0 before either writes, both generate their own random password,
    and both print a (different, now half-wrong) banner - whichever wrote
    last would silently win in the database while an installer might
    record the other one. BEGIN IMMEDIATE below closes that window: it
    takes SQLite's write lock before the read, so a second worker's own
    BEGIN IMMEDIATE blocks until the first one's transaction fully
    commits, and by the time it proceeds it correctly sees admin_count as
    1 and does nothing - confirmed by reproducing the double-banner
    failure first, then verifying this actually closes it."""
    admin_user = os.getenv("BOOTSTRAP_ADMIN_USERNAME")
    if not admin_user:
        return
    con = sqlite3.connect(AUDIT_DB, isolation_level=None)
    con.execute("BEGIN IMMEDIATE;")
    admin_count = con.execute(
        "SELECT count(*) FROM users WHERE role = 'admin';"
    ).fetchone()[0]
    generated_pw = None
    if admin_count == 0:
        pw = os.getenv("BOOTSTRAP_ADMIN_PASSWORD") or None
        if not pw and AUTH_MODE == "local":
            generated_pw = secrets.token_urlsafe(18)
            pw = generated_pw
        pw_hash = generate_password_hash(pw) if pw else None
        now = datetime.now(timezone.utc).isoformat()
        # COALESCE keeps whatever password hash the row already had if
        # neither BOOTSTRAP_ADMIN_PASSWORD nor a freshly generated one
        # applies this run (e.g. authentik mode, where passwords are never
        # used) - a recovery run must not silently wipe a working password.
        con.execute(
            """INSERT INTO users (username, password_hash, role, created_ts_utc)
               VALUES (?, ?, 'admin', ?)
               ON CONFLICT(username) DO UPDATE
                   SET role = 'admin',
                       password_hash = COALESCE(excluded.password_hash, users.password_hash),
                       updated_ts_utc = excluded.created_ts_utc;""",
            (admin_user, pw_hash, now),
        )
        con.commit()
    else:
        con.rollback()
    con.close()

    # Printed every time this runs, not just the one true first-boot event -
    # the address to log in at is useful on every restart (especially given
    # how often PORT itself can change - see setup.sh's own port-collision
    # handling), not something worth losing the moment the one-time
    # password banner stops applying. Each gunicorn worker calls
    # bootstrap_admin() independently (see the docstring above), so this
    # does print once per worker rather than truly once per container start
    # - harmless duplication of non-sensitive info, the same way gunicorn's
    # own "Booting worker" lines already appear once per worker with nobody
    # confused by it.
    # A command-line tool that imports this module for get_connection() and
    # audit() is not starting a server, so the "log in at" banner would be
    # a lie in its output. dbcheck.py sets this before importing.
    #
    # But NOT when a password was just generated. By this point the account
    # exists and the password has been hashed and committed, and this
    # banner is the only place the plaintext ever appears - suppressing it
    # would create an admin account whose password nobody can ever know,
    # and admin_count is now 1 so no later start regenerates it. Reachable:
    # connect-database.sh records the schema baseline by running dbcheck,
    # which on a bare-metal install can be the first process to import this
    # module. Found in the pre-push security review.
    if os.getenv("TAKX_NO_BANNER") and not generated_pw:
        return

    port = LISTEN_PORT
    scheme = "https" if SERVE_TLS else "http"
    print("", flush=True)
    print("=" * 70, flush=True)
    if generated_pw:
        print("TAK-Extract: first admin account created", flush=True)
        print(f"  Username: {_hl(admin_user)}", flush=True)
        print(f"  Password: {_hl(generated_pw)}", flush=True)
        print("  This password was generated automatically and is shown only", flush=True)
        print("  this once - it is not stored anywhere in plaintext. Log in now", flush=True)
        print("  and record it, or change it from the System page afterward.", flush=True)
        if not get_setting("db_host", "DB_HOST") or not get_setting("db_user", "DB_USER"):
            print("", flush=True)
            print("  The TAK Server database isn't connected yet - nothing that reads", flush=True)
            print("  position data will work until you set it. After logging in, go", flush=True)
            print("  to System -> TAK Server connection and fill it in (see README.md's", flush=True)
            print("  'Creating the least-privilege database account' section if that", flush=True)
            print("  account doesn't exist yet).", flush=True)
    else:
        print("TAK-Extract is running", flush=True)
    # Whoever's reading this is almost never sitting at this machine's own
    # console with a browser open - in practice it's nearly always a
    # headless VM (Docker or bare metal alike), administered remotely. So
    # whichever address is ACTUALLY reachable from elsewhere leads, with
    # 127.0.0.1 only ever a secondary "if you happen to be on this box
    # directly" note - never the other way around, and never printed as if
    # it were the real answer when it isn't (a reverse-proxy-only setup, or
    # a container where no LAN address is even knowable from in here,
    # genuinely has no better answer to give than 127.0.0.1).
    if SERVE_TLS:
        # BIND_ADDR=0.0.0.0 (Docker) / gunicorn.conf.py's own 0.0.0.0 bind
        # (bare metal) is a hard requirement of SERVE_TLS actually reaching
        # anyone - see README. Bare metal: the detected LAN IP is the real
        # answer. In a container, detect_local_ip() returns the container's
        # own bridge address - reachable from nowhere - which is exactly
        # what this used to print (contradicting tls.py's own contract that
        # it's never called for that in a container). setup.sh writes the
        # host's real address into TLS_CERT_HOST; use that, and if it's
        # missing in a container, say so rather than print a wrong URL.
        ip = os.getenv("TLS_CERT_HOST") or ("" if running_in_container() else detect_local_ip())
        if not ip:
            print(f"  Log in at: {scheme}://<this host's IP or hostname>:{port}/login", flush=True)
            print(f"  (or {scheme}://127.0.0.1:{port}/login from this machine itself; set", flush=True)
            print("  TLS_CERT_HOST in .env to this host's address to print it here)", flush=True)
        elif ip != "127.0.0.1":
            print(f"  Log in at: {_hl(f'{scheme}://{ip}:{port}/login')}", flush=True)
            print(f"  (or {scheme}://127.0.0.1:{port}/login if you're on this machine directly)", flush=True)
        else:
            print(f"  Log in at: {_hl(f'{scheme}://127.0.0.1:{port}/login')}", flush=True)
        print("  This uses a self-signed certificate - your browser will show", flush=True)
        print("  a security warning the first time. That's expected; click", flush=True)
        print("  through it (\"Proceed\"/\"Accept the Risk\") once per device.", flush=True)
    elif running_in_container():
        # No reverse proxy's address is knowable from inside this
        # container, and the un-mapped internal IP would be actively wrong
        # to print - 127.0.0.1 is genuinely the best answer available here
        # (SSH tunnel, or the reverse proxy's own address, which only
        # whoever set that up would know).
        print(f"  Log in at: {_hl(f'{scheme}://127.0.0.1:{port}/login')}", flush=True)
        print("  If this is reachable from other devices through a reverse", flush=True)
        print("  proxy, use that proxy's own address instead.", flush=True)
    else:
        print(f"  Log in at: {_hl(f'{scheme}://127.0.0.1:{port}/login')}", flush=True)
        ip = detect_local_ip()
        if ip != "127.0.0.1":
            print("  If a reverse proxy forwards this port from elsewhere, it", flush=True)
            print(f"  may also be reachable at: http://{ip}:{port}/login", flush=True)
    print("=" * 70, flush=True)
    print("", flush=True)


bootstrap_admin()


# The audit log's hash chain. Every column of a row goes into its hash
# except id (the position), the two hash columns themselves, and the
# delivery confirmation: /api/confirm appends " / delivered" to `outcome`
# once the browser reports the download complete, and that is the one
# change a row may legitimately receive after it is written, so it is
# excluded rather than allowed to break the chain. Values are hashed as
# SQLite returns them, so verification reproduces creation exactly.
CHAIN_FIELDS = (
    "ts_utc", "ts_local", "actor", "client_ip", "case_id", "export_kind",
    "window_start", "window_end", "north", "south", "west", "east",
    "record_count", "package_sha256", "outcome", "detail", "files_excluded",
    "channels_excluded", "window_timezone", "requested_for", "tool_version",
)


def _canon(v):
    if v is None:
        return ""
    if isinstance(v, float):
        return repr(v)
    return str(v)


def _row_hash(row):
    """SHA-256 over prev_hash + every chained field, each as text, joined
    with a separator that cannot occur in the fields (a NUL)."""
    keys = row.keys()
    parts = [_canon(row["prev_hash"]) if "prev_hash" in keys else ""]
    for f in CHAIN_FIELDS:
        v = row[f] if f in keys else None
        if f == "outcome" and v:
            v = str(v).replace(" / delivered", "")
        parts.append(_canon(v))
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def verify_audit_chain():
    """Walk the log in id order and recompute every chained row. Returns
    what a reader needs to state plainly: how many rows were checked, how
    many predate the chain, and the first row that fails, with why."""
    con = sqlite3.connect(AUDIT_DB)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM export_log ORDER BY id ASC;").fetchall()
    con.close()
    result = {"ok": True, "total": len(rows), "checked": 0, "unchained": 0,
              "first_chained_id": None, "last_id": rows[-1]["id"] if rows else None,
              "broken_id": None, "reason": None}
    expected_prev = ""
    for r in rows:
        if r["row_hash"] is None:
            result["unchained"] += 1
            continue
        if result["first_chained_id"] is None:
            result["first_chained_id"] = r["id"]
        if (r["prev_hash"] or "") != expected_prev:
            result.update(ok=False, broken_id=r["id"],
                          reason="prev_hash does not match the previous chained row (a row was "
                                 "removed, inserted or reordered before this one)")
            return result
        if _row_hash(r) != r["row_hash"]:
            result.update(ok=False, broken_id=r["id"],
                          reason="row content does not match its recorded hash (the row was edited)")
            return result
        result["checked"] += 1
        expected_prev = r["row_hash"]
    return result


def detail_safe(value, limit=200):
    """A caller-supplied fragment, ready to be interpolated into an audit
    entry's detail.

    A detail is clauses joined with "; ", and the audit page reads it back
    on that separator and labels what it finds - so a fragment carrying
    the separator could make the log display a clause nobody wrote, a
    verdict among them. The separator and control characters are removed;
    everything else is kept as supplied, and the whole is truncated."""
    text = "".join(
        c for c in str(value or "")
        if c != ";" and (c == "	" or ord(c) >= 32)
    )
    return text[:limit]


def audit(actor, client_ip, params, kind, record_count,
          outcome, package_hash=None, detail="", files_excluded=None,
          channels_excluded=None, window_timezone=None, requested_for=None):
    """Write one line to the audit log and return its row id.

    actor vs requested_for: `actor` is WHO RAN IT - the verified logged-in
    account, resolved by identify(), never something typed into a box.
    `requested_for` is WHO IT WAS RUN FOR, typed by the operator at export
    time, because in practice an admin runs exports on other people's
    behalf. The second is self-declared and unverified by nature; the two
    are kept in separate columns precisely so the log never presents a
    typed note and a verified identity as the same kind of fact.

    files_excluded: for a "package" export, the optional files the operator
    deliberately left out of it (comma-joined), or None when nothing was
    excluded. channels_excluded: same idea, for channels present in the
    window/area that the operator deliberately left out. Both are kept
    separate from `detail`, which is reserved for query failures, so "what
    broke" and "what the operator chose" don't blur together in the log.

    window_timezone: the IANA zone (e.g. "America/Chicago") the TAK
    database's session was using when window_start/window_end - themselves
    timezone-naive <input type="datetime-local"> values - were interpreted
    for the query. Recorded so a later verification can convert them to UTC
    correctly instead of guessing. None when the export never touched the
    database with a window at all (e.g. a failed/validation-error row).

    Never raises - a logging failure must not break an export - but a
    failure is printed rather than swallowed silently.
    """
    now = datetime.now(timezone.utc)
    try:
        con = sqlite3.connect(AUDIT_DB)
        con.row_factory = sqlite3.Row
        # BEGIN IMMEDIATE: one writer at a time, so two entries written at
        # the same moment cannot both chain onto the same previous row.
        con.execute("BEGIN IMMEDIATE;")
        prev = con.execute(
            "SELECT row_hash FROM export_log WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1;"
        ).fetchone()
        prev_hash = prev["row_hash"] if prev else ""
        cur = con.execute(
            """INSERT INTO export_log
               (ts_utc, ts_local, actor, client_ip, case_id, export_kind,
                window_start, window_end, north, south, west, east,
                record_count, package_sha256, outcome, detail, files_excluded,
                channels_excluded, window_timezone, requested_for, tool_version, prev_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                now.isoformat(),
                now.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
                actor,
                client_ip,
                params.get("case_id"),
                kind,
                params.get("start"),
                params.get("end"),
                params.get("north"),
                params.get("south"),
                params.get("west"),
                params.get("east"),
                record_count,
                package_hash,
                outcome,
                detail,
                files_excluded,
                channels_excluded,
                window_timezone,
                requested_for,
                TOOL_VERSION,
                prev_hash,
            ),
        )
        row_id = cur.lastrowid
        # Hash the row as STORED (read back), not as passed in, so that
        # verification - which can only read back - reproduces it exactly.
        stored = con.execute("SELECT * FROM export_log WHERE id = ?;", (row_id,)).fetchone()
        con.execute("UPDATE export_log SET row_hash = ? WHERE id = ?;", (_row_hash(stored), row_id))
        con.commit()
        con.close()
        return row_id
    except Exception as e:
        print(f"AUDIT LOG FAILURE: {type(e).__name__}: {e}")
        return None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def lookup_role(username):
    """This user's role, or None if they have no row in `users` at all - a
    verified identity (Authentik header, or a valid local-mode session)
    with no role assigned is treated the same as no identity: Authentik
    vouching for who someone is never by itself grants them anything here."""
    con = sqlite3.connect(AUDIT_DB)
    row = con.execute(
        "SELECT role FROM users WHERE username = ? COLLATE NOCASE;", (username,)
    ).fetchone()
    con.close()
    return row[0] if row else None


def current_identity():
    """(username, role) for this request, or (None, None) with no verified
    identity at all."""
    if AUTH_MODE == "authentik":
        username = request.headers.get("X-authentik-username")
        if not username:
            return None, None  # missing header = deny, never a fallback to anonymous
    else:
        username = session.get("username")
        if not username:
            return None, None
    return username, lookup_role(username)


# CSRF applies in BOTH auth modes. This used to be local-mode only, on the
# reasoning that authentik mode's identity comes from a header the proxy
# sets rather than an ambient cookie a cross-site page could ride along.
# That reasoning was incomplete: the proxy sets that header BECAUSE it
# just validated the Authentik session cookie on the victim's browser, so
# a cross-site POST that carries that cookie is authenticated on arrival
# and reaches this app with the header attached. Every JSON route was
# incidentally safe (a cross-site form can't send application/json, and
# a fetch() that does triggers a CORS preflight) - but /api/admin/restore
# takes a multipart upload, which a plain form CAN submit, and a
# successful one replaces this app's entire user table and audit log.
#
# The token mechanism costs nothing in authentik mode - SECRET_KEY is
# already required there and every template already sends the header -
# and it stacks with the session cookie's SameSite=Lax, so a cross-site
# POST fails on both counts: no cookie, therefore no token to match.
CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _get_csrf_token():
    """Per-session CSRF token, generated on first use and exposed to every
    template as a Jinja global (see the context_processor below) - mirrors
    Flask-WTF's own csrf_token() naming even though this app has no such
    dependency. Issued in both auth modes - see the note above."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def _inject_csrf_token():
    # app_version: the running version, shown in small print under the
    # Export and System page headings as an at-a-glance reference (the
    # same string that goes into every package and audit entry).
    return {"csrf_token": _get_csrf_token, "app_version": APP_VERSION,
            "csp_nonce": _csp_nonce}


def _check_csrf():
    """None if OK, else an error string. Applies to every state-changing
    request in both auth modes, not just the admin API - every route
    already sits behind the same require_role gate, so protecting only
    part of it would just leave the rest exploitable the same way."""
    if request.method in CSRF_SAFE_METHODS:
        return None
    expected = session.get("csrf_token")
    got = request.headers.get("X-CSRFToken")
    if not expected or not got or not secrets.compare_digest(expected, got):
        return "invalid or missing CSRF token"
    return None


def require_role(*roles, api=False):
    """Gate a route to only the given role(s). Sets g.username/g.role for
    the view to use (identify() below reads g.username) when access is
    granted. api=True returns a JSON {"error": ...} body with 401/403,
    matching every other API route's error convention in this file, instead
    of a redirect/plain-text page."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            username, role = current_identity()
            if username is None:
                if api:
                    return jsonify({"error": "authentication required"}), 401
                if AUTH_MODE == "local":
                    return redirect(url_for("login_page", next=request.path))
                return Response("Access denied - no verified identity.", status=403,
                                mimetype="text/plain")
            if role not in roles:
                msg = (f"{username} is signed in but has no role granting access "
                       f"to this page. Contact an admin.")
                if api:
                    return jsonify({"error": msg}), 403
                # text/plain, not Flask's default text/html: msg carries the
                # username, and nothing validates what characters a username
                # may hold - an admin creates them, and in authentik mode the
                # proxy asserts them. Neither is a reason to render markup
                # from one. Served as text, any markup in it is inert.
                return Response(msg, status=403, mimetype="text/plain")
            g.username, g.role = username, role
            # Checked only after auth/role succeed, so an unauthenticated
            # or wrong-role caller still gets the same 401/403 as before -
            # this is a second gate for someone already properly signed in.
            csrf_error = _check_csrf()
            if csrf_error:
                if api:
                    return jsonify({"error": csrf_error}), 403
                return Response(csrf_error, status=403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# Request handling helpers
# ---------------------------------------------------------------------------

def parse_params(data):
    """Validate incoming query parameters. Returns (params, error_message)."""
    try:
        params = {
            "north": float(data["north"]),
            "south": float(data["south"]),
            "west": float(data["west"]),
            "east": float(data["east"]),
            "start": data["start"],
            "end": data["end"],
            # Quotes and control characters out: a case reference has no
            # use for either, and the audit log's case corrections quote
            # the name inside their own text (see _load_case_corrections).
            # A name carrying `" -> "` would otherwise make a later
            # correction parse as a different mapping than the one its
            # text states.
            "case_id": "".join(
                c for c in (data.get("case_id") or "").strip()
                if c not in '";' and (c == "	" or ord(c) >= 32)
            ),
        }
    except (KeyError, TypeError, ValueError):
        return None, "missing or invalid parameters"

    if params["north"] <= params["south"]:
        return None, "north edge must be above south edge"
    if params["east"] <= params["west"]:
        return None, "east edge must be right of west edge"
    if not params["start"] or not params["end"]:
        return None, "start and end times are both required"
    if params["start"] >= params["end"]:
        return None, "start time must be before end time"

    return params, None


def parse_included(data):
    """Which optional files go into the full evidence package.

    Absent key -> None, meaning "all" - unchanged behaviour for any caller
    that doesn't send this. An explicit list, including an empty one, is
    the operator's authoritative choice, but only for filenames exports.py
    actually knows about; anything else is dropped rather than rejected,
    since this only gates which queries run and is never used to build SQL.
    A malformed (non-list) value also falls back to "all" - failing open
    toward full disclosure rather than silently narrowing on a client bug,
    matching this app's subtractive-filtering default elsewhere.
    """
    if "included" not in data:
        return None
    raw = data.get("included")
    if not isinstance(raw, list):
        return None
    return {name for name in raw if name in exports.OPTIONAL_FILES}


def parse_channels(data):
    """Which channels to restrict channel-filterable files to.

    Absent key -> None, meaning "every channel" - unchanged behaviour for
    any caller that doesn't send this. An explicit list, including an empty
    one, is the operator's authoritative choice: an empty list means "no
    channels selected", which matches zero rows in filterable files rather
    than silently behaving like no filter at all - subtractive filtering
    only works if excluding everything is actually honored. Non-integer
    entries are dropped rather than rejecting the whole request, since a
    channel bitpos is just an int used to build a SQL clause, never
    interpolated as text.
    """
    if "channels" not in data:
        return None
    raw = data.get("channels")
    if not isinstance(raw, list):
        return None
    result = set()
    for v in raw:
        try:
            result.add(int(v))
        except (TypeError, ValueError):
            continue
    return result


def identify(data):
    """Work out who is asking, and whether that is verified or self-declared.

    A name typed into a box is a claim, not proof of identity, and the log
    must not present the two as equivalent.

    g.username is set by require_role() once every route carries one (see
    Auth, above) - the actual verified identity for THIS request, whether
    that came from Authentik's header or a local-mode session. Checked
    first, and takes priority over a client-supplied `actor` field: without
    this, a logged-in local-mode user could put an arbitrary name in a
    POST body and have the audit log attribute their export to someone
    else, which would defeat the entire point of adding real login. The
    header/self-declared/unidentified branches below are dead code at
    every current call site now that all of them sit behind require_role,
    but are kept as a defensive fallback for any route that calls
    identify() without that decorator in the future.
    """
    if getattr(g, "username", None):
        return f"authenticated: {g.username}"
    header_user = request.headers.get("X-authentik-username")
    if header_user:
        return f"authenticated: {header_user}"
    declared = (data.get("actor") or "").strip()
    if declared:
        return f"self-declared: {declared}"
    return "unidentified"


def requested_for(data):
    """Who the operator says this export was run FOR, or None.

    The counterpart to identify(): that answers "who ran this" from the
    verified session and deliberately ignores anything typed in, which is
    right for an identity claim but left "who asked for it" uncaptured.
    An admin running an export on someone else's behalf is the normal
    case here, not the exception, so it gets its own field rather than
    being smuggled into the actor string where it would look verified.

    Returns None rather than "" for an empty box, so the log distinguishes
    "nothing was entered" from a real value at the column level.
    """
    return (data.get("requested_for") or "").strip() or None


def safe_case_id(params):
    case = params["case_id"] or datetime.now().strftime("cot-%Y%m%d-%H%M%S")
    cleaned = "".join(c for c in case if c.isalnum() or c in "._-")
    return cleaned or "export"


# The filter shared by the preview and the single-CSV export, so the number
# shown and the number exported come from identical criteria. Defined in
# exports.py with the rest of the query text - the schema check executes
# these statements, and it reads them from the query module rather than
# importing the web app. Aliased here so every call site below is unchanged.
POSITION_FILTER = exports.POSITION_FILTER
filter_args = exports.filter_args


def available_channels(conn, p):
    """Channels actually present among matching positions in this window and
    area, as (bitpos, name) pairs - offered as the channel checklist, and
    used to compute which channels a filter excluded for audit disclosure.

    One EXISTS check per defined channel rather than an aggregate bitwise
    OR: only the per-row substring comparison used elsewhere in this app has
    actually been verified against a live server (see NOTES.md on the
    bitpos-direction bug it once caught) - typical channel counts are small
    enough that this stays cheap.
    """
    sql = f"""
        SELECT gg.bitpos, gg.name
        FROM groups gg
        WHERE EXISTS (
            SELECT 1 FROM cot_router r
            WHERE {POSITION_FILTER}
              AND substring(r.groups from (length(r.groups) - gg.bitpos) for 1) = B'1'
        )
        ORDER BY gg.bitpos;
    """
    with conn.cursor() as cur:
        cur.execute(sql, filter_args(p))
        return cur.fetchall()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
@require_role("admin")
def index():
    # Kept on g so csp_header() can narrow the policy to whatever
    # this page was actually built with, without reading it twice.
    g.map_opts = map_options()
    return render_template("index.html", role=g.role, username=g.username, auth_mode=AUTH_MODE,
                            theme=get_theme(), map_opts=g.map_opts)

@app.route("/audit")
@require_role("admin")
def audit_page():
    return render_template("audit.html", role=g.role, username=g.username, auth_mode=AUTH_MODE,
                            theme=get_theme())

@app.route("/verify")
@require_role("admin", "viewer")
def verify_page():
    # Kept on g so csp_header() can narrow the policy to whatever
    # this page was actually built with, without reading it twice.
    g.map_opts = map_options()
    return render_template("verify.html", role=g.role, username=g.username, auth_mode=AUTH_MODE,
                            theme=get_theme(), map_opts=g.map_opts)


@app.route("/admin")
@require_role("admin")
def admin_page():
    return render_template("admin.html", role=g.role, username=g.username, auth_mode=AUTH_MODE,
                            theme=get_theme())


@app.route("/guide")
@require_role("admin", "viewer")
def guide_page():
    # A standalone, page-by-page user guide, opened in a new tab from each
    # page's "Guide" nav button at its top - the guide's own table of
    # contents links to each section (the buttons originally deep-linked
    # to /guide#<page>; the user preferred landing on the overview). Admin+viewer, same as verify_page: a viewer can only
    # reach the Verify page, but the guide is just reference text, so
    # showing them the whole thing is harmless and simpler than gating
    # sections by role. It documents orientation ("what each area is for");
    # the per-element info/About buttons on each page remain the source of
    # truth for specifics, so the guide doesn't have to be re-touched every
    # time a detail changes.
    # username/auth_mode like every other page: the guide's header now
    # carries the same account block, so that its nav lines up with theirs
    # instead of sitting flush right where theirs are pushed left.
    return render_template("guide.html", role=g.role, username=g.username,
                           auth_mode=AUTH_MODE, theme=get_theme())


@app.route("/guide/img/<path:name>")
@require_role("admin", "viewer")
def guide_image(name):
    # Screenshots embedded in the guide, generated from synthetic data (see
    # docs/guide-images/README.txt). Served through the same login gate as the
    # guide rather than Flask's default /static handler, which would answer
    # without a session - nothing sensitive is in them, but every URL this
    # app serves sitting behind the same gate is simpler to reason about
    # than one exception. send_from_directory refuses paths that escape the
    # directory.
    if not name.lower().endswith(".png"):
        abort(404)
    return send_from_directory(os.path.join(app.root_path, "docs", "guide-images"), name,
                               max_age=3600)


# A device that traveled far from normal operations (training, a
# conference) is a real point, not bad data - but min/max would let that
# one point drag the box across the country. Percentiles trim the extreme
# 10% on each edge instead, so one outlier gets discarded rather than
# controlling the whole view. If the trimmed box is still too wide, that
# means a bigger cluster of far-flung points, not just one outlier - fall
# back to a small fixed box around the median. Either way this only needs
# to be a good guess; manual address search is the escape hatch.
EXTENT_MAX_SPAN_DEGREES = 2.0
EXTENT_FALLBACK_HALF_SPAN = 0.15


@app.route("/api/extent")
@require_role("admin", api=True)
def extent():
    """Bounding box of recent position data (percentile-trimmed - see
    EXTENT_MAX_SPAN_DEGREES above), plus the database session's timezone,
    so the map opens where this server actually operates and the Start/End
    inputs can state which timezone they're interpreted in instead of
    leaving that implicit (the browser's clock and the DB session's
    timezone are not necessarily the same one)."""
    for window in ["7 days", "90 days", None]:
        time_filter = f"AND servertime > now() - interval '{window}'" if window else ""
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SHOW timezone;")
                    db_timezone = cur.fetchone()[0]
                    cur.execute(f"""
                        SELECT
                            percentile_cont(0.1) WITHIN GROUP (ORDER BY ST_Y(event_pt)) AS south,
                            percentile_cont(0.9) WITHIN GROUP (ORDER BY ST_Y(event_pt)) AS north,
                            percentile_cont(0.1) WITHIN GROUP (ORDER BY ST_X(event_pt)) AS west,
                            percentile_cont(0.9) WITHIN GROUP (ORDER BY ST_X(event_pt)) AS east,
                            percentile_cont(0.5) WITHIN GROUP (ORDER BY ST_Y(event_pt)) AS median_lat,
                            percentile_cont(0.5) WITHIN GROUP (ORDER BY ST_X(event_pt)) AS median_lon
                        FROM cot_router
                        WHERE event_pt IS NOT NULL
                          AND NOT (ST_Y(event_pt) = 0 AND ST_X(event_pt) = 0)
                          {time_filter};
                    """)
                    row = cur.fetchone()
                    if row and row[0] is not None:
                        south, north, west, east, median_lat, median_lon = row
                        basis = window or "all data"
                        if (north - south) > EXTENT_MAX_SPAN_DEGREES or \
                           (east - west) > EXTENT_MAX_SPAN_DEGREES:
                            south = median_lat - EXTENT_FALLBACK_HALF_SPAN
                            north = median_lat + EXTENT_FALLBACK_HALF_SPAN
                            west = median_lon - EXTENT_FALLBACK_HALF_SPAN
                            east = median_lon + EXTENT_FALLBACK_HALF_SPAN
                            basis += ", further narrowed - matching data was too spread out to fit"
                        return jsonify({
                            "south": south, "north": north,
                            "west": west, "east": east,
                            "basis": basis,
                            "db_timezone": db_timezone,
                        })
        except Exception as e:
            return jsonify({"error": f"{type(e).__name__}: {e}"})

    return jsonify({"error": "no position data found"})


@app.route("/api/optional-files")
@require_role("admin", api=True)
def optional_files():
    """Every file the operator can individually select, for the unified
    checklist: the KMZ track map (a synthetic entry - it isn't one of
    exports.py's package files, it's the separate /api/locations pipeline)
    plus the 12 optional package files. `group` tells the frontend which
    download endpoint a file belongs to: "kmz" goes through /api/locations,
    "package" goes through /api/package's `included` list. Sourced from
    exports.OPTIONAL_FILES/FILE_INFO so labels can't drift out of sync
    between this list and the README's own descriptions.
    """
    items = [{
        "filename": "locations.kmz",
        "label": "Positions — KMZ map",
        "contains": "A map file for Google Earth - colored tracks and points per device, grouped by category, plus drawn shapes (when shapes.csv is selected) as real geometry that changes on the time slider as they were redrawn.",
        "narrowed_by": "time window, area, and channel selection (same rows as cot.csv).",
        "note": "Same position data as cot.csv, just formatted for viewing rather than spreadsheets.",
        "channel_filterable": True,
        "group": "kmz",
    }]
    for name, label in exports.OPTIONAL_FILES.items():
        info = exports.FILE_INFO.get(name, {})
        items.append({
            "filename": name,
            "label": label,
            "contains": info.get("contains", ""),
            "narrowed_by": info.get("narrowed_by", ""),
            "note": info.get("note", ""),
            "channel_filterable": name in exports.CHANNEL_FILTERABLE_FILES,
            "group": "package",
            # shapes.csv is derived: its rows come from parsing geometry out
            # of raw XML and applying the box rule in Python, so a LIMIT 5 of
            # its SQL would show unfiltered XML blobs that look nothing like
            # the file. Its About note describes the file instead.
            "previewable": name not in exports.NON_PREVIEWABLE_FILES,
        })
    return jsonify(items)


@app.route("/api/channels", methods=["POST"])
@require_role("admin", api=True)
def channels_available():
    """Channels seen among matching positions in the current time window and
    area, for the channel-filter checklist. A preview only, like /api/count -
    runs no export and writes no audit entry."""
    params, err = parse_params(request.get_json() or {})
    if err:
        return jsonify({"error": err})

    try:
        with get_connection() as conn:
            rows = available_channels(conn, params)
        return jsonify([{"bitpos": bitpos, "name": name} for bitpos, name in rows])
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"})


@app.route("/api/count", methods=["POST"])
@require_role("admin", api=True)
def count():
    """How many records match, broken down by kind. A preview only - runs no
    export and writes no audit entry. Honors the channel filter, if any, so
    the preview matches what an export would actually produce."""
    data = request.get_json() or {}
    params, err = parse_params(data)
    if err:
        return jsonify({"error": err})
    channels = parse_channels(data)
    chan_and, chan_params = exports.channel_where_clause("groups", channels, prefix="AND")

    sql = exports.count_sql(chan_and)

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, filter_args(params) + tuple(chan_params))
                total, uids, personnel, equipment, infra, objects = cur.fetchone()

        return jsonify({
            "records": total,
            "uids": uids,
            "personnel": personnel,
            "equipment": equipment,
            "infrastructure": infra,
            "map_objects": objects,
        })
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"})


@app.route("/api/preview", methods=["POST"])
@require_role("admin", api=True)
def preview_file():
    """Header + first 5 rows of what a given optional file (or the KMZ)
    would actually contain right now, using its EXACT real query -
    exports.build_queries() for package files, single_csv_sql() for the
    KMZ - never a hand-written approximation, so a preview can't silently
    diverge from a real export (the same principle single_csv_sql() was
    itself refactored around, to stop duplicating channel-decode logic).

    Unlike /api/count / /api/channels / /api/trails (aggregate or de-
    identified, no audit entry), this one shows real individual row
    content - so it DOES write an audit entry, the same as a real export,
    including on a rejected or failed attempt."""
    data = request.get_json() or {}
    filename = data.get("filename")
    params, err = parse_params(data)
    channels = parse_channels(data)
    client_ip = request.remote_addr
    actor = identify(data)

    if err:
        audit(actor, client_ip, params or {}, "preview", 0, "rejected", detail=err)
        return jsonify({"error": err}), 400

    try:
        if filename == "locations.kmz":
            chan_and, chan_params = exports.channel_where_clause("r.groups", channels, prefix="AND")
            sql = exports.with_limit(single_csv_sql(chan_and), 5)
            query_params = filter_args(params) + tuple(chan_params)
        elif filename in exports.NON_PREVIEWABLE_FILES:
            audit(actor, client_ip, params, "preview", 0, "rejected",
                  detail=f"not previewable: {detail_safe(filename)}")
            return jsonify({"error": f"{filename} is built from parsed geometry, not "
                                     "a direct query, so it has no row preview - "
                                     "see its About note for what it contains"}), 400
        elif filename in exports.OPTIONAL_FILES:
            queries = exports.build_queries(params, channels=channels, included=[filename])
            match = next((q for q in queries if q[0] == filename), None)
            if not match:
                audit(actor, client_ip, params, "preview", 0, "rejected",
                      detail=f"no query for {detail_safe(filename)}")
                return jsonify({"error": f"no query for {filename}"}), 400
            _, base_sql, query_params = match
            sql = exports.with_limit(base_sql, 5)
        else:
            audit(actor, client_ip, params, "preview", 0, "rejected",
                  detail=f"unknown filename: {detail_safe(filename)}")
            return jsonify({"error": "unknown or non-previewable filename"}), 400

        with get_connection() as conn:
            window_timezone = get_db_timezone(conn)
            with conn.cursor() as cur:
                cur.execute(sql, query_params)
                columns = [d[0] for d in cur.description]
                rows = cur.fetchmany(5)
    except Exception as e:
        audit(actor, client_ip, params, "preview", 0, "error", detail=f"{type(e).__name__}: {e}")
        return jsonify({"error": f"{type(e).__name__}: {e}"})

    serializable_rows = [
        [v if v is None or isinstance(v, (str, int, float, bool)) else str(v) for v in row]
        for row in rows
    ]

    audit(actor, client_ip, params, "preview", len(serializable_rows), "ok",
          detail=f"file={detail_safe(filename)}", window_timezone=window_timezone)
    return jsonify({"columns": columns, "rows": serializable_rows})


# Mirrors EXTENT_MAX_SPAN_DEGREES's reasoning above - a defense-in-depth cap,
# not the primary control (the frontend already refuses to call this below a
# minimum zoom level - see index.html's TRAILS_MIN_ZOOM). If this is ever hit
# anyway, degrade gracefully (empty trails + a note) rather than error.
TRAILS_MAX_VIEWPORT_SPAN_DEGREES = 2.0


@app.route("/api/trails", methods=["POST"])
@require_role("admin", api=True)
def trails():
    """Faint, non-interactive device-motion lines for the CURRENT MAP
    VIEWPORT (not the drawn box - the whole point is to let an operator
    notice a moving device about to cross the box's edge from outside it,
    before they finalize the box) over the current time window. A preview
    only, like /api/count - no export, no audit entry, and no channel
    decoding (trails only need geometry, never channel names). Only
    devices that actually moved (at least two distinct positions) are
    included - a device that pinged twice from the same spot isn't a
    trail, matching kmz.py's own "at least 2 points" rule for drawing a
    track line at all."""
    data = request.get_json() or {}
    params, err = parse_params(data)
    if err:
        return jsonify({"error": err})
    include_feed_shapes = bool(data.get("include_feed_shapes", False))

    if (params["north"] - params["south"]) > TRAILS_MAX_VIEWPORT_SPAN_DEGREES or \
       (params["east"] - params["west"]) > TRAILS_MAX_VIEWPORT_SPAN_DEGREES:
        return jsonify({"trails": [], "note": "Zoom in further to see device trails."})

    sql = f"""
        SELECT uid, ST_Y(event_pt) AS latitude, ST_X(event_pt) AS longitude, servertime
        FROM cot_router
        WHERE {POSITION_FILTER}
        ORDER BY uid, servertime;
    """
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, filter_args(params))
                rows = cur.fetchall()
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"})

    devices = {}
    for uid, lat, lon, servertime in rows:
        devices.setdefault(uid, []).append(
            {"latitude": lat, "longitude": lon, "servertime": servertime}
        )

    # No uid in the response - trails are geometry only, never individually
    # identified (matches "not clickable" - there's nothing to click on).
    trail_segments = []
    for points in devices.values():
        if len({(p["latitude"], p["longitude"]) for p in points}) < 2:
            continue  # never actually moved - not a trail
        for seg in exports.split_segments(points):
            if len(seg) < 2:
                continue
            trail_segments.append([[p["latitude"], p["longitude"]] for p in seg])

    # Drawn shapes, same terms as the trails: outlines only, de-identified,
    # for the viewport, no audit entry. One row per object - its latest
    # version in the window - then the box test against the real geometry
    # in Python (see shapes.outlines for why, and what is deliberately left
    # out of the response). The type clause and box rule are the same ones
    # shapes.csv uses, so what an operator sees here while drawing is what
    # the export will contain.
    shape_outlines = []
    try:
        type_clause = " OR ".join("cot_type LIKE %s" for _ in exports.MAP_OBJECT_PATTERNS)
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"""
                    SELECT DISTINCT ON (uid) uid, cot_type,
                           ST_Y(event_pt) AS latitude, ST_X(event_pt) AS longitude,
                           detail AS raw_detail
                    FROM cot_router
                    WHERE servertime >= %s::timestamptz
                      AND servertime <  %s::timestamptz
                      AND ({type_clause})
                    ORDER BY uid, servertime DESC, id DESC;
                """, (params["start"], params["end"], *exports.MAP_OBJECT_PATTERNS))
                srows = cur.fetchall()
                sheaders = [d[0] for d in cur.description]
        shape_outlines = shapes.outlines(srows, sheaders, params["north"], params["south"],
                                         params["west"], params["east"],
                                         include_feed_shapes=include_feed_shapes)
    except Exception as e:
        # Reference overlay only - the trails still ship. Logged, not
        # returned, for the same reason the page fails quiet on this route.
        print(f"/api/trails shape outlines unavailable: {type(e).__name__}: {e}")

    return jsonify({"trails": trail_segments, "shapes": shape_outlines})


# Defined in exports.py with the rest of the query text, so the schema check
# can execute the real statement. Aliased so the routes below are unchanged.
single_csv_sql = exports.single_csv_sql

@app.route("/api/locations", methods=["POST"])
@require_role("admin", api=True)
def export_locations():
    """Locations package: a KMZ for Google Earth, plus the positional CSV.

    The quick look. Both files come from one query result, so the map view
    and the spreadsheet cannot disagree.
    """
    data = request.get_json() or {}
    params, err = parse_params(data)
    channels = parse_channels(data)
    client_ip = request.remote_addr
    actor = identify(data)

    req_for = requested_for(data)

    if err:
        audit(actor, client_ip, params or {}, "locations", 0, "rejected", detail=err,
              requested_for=req_for)
        return jsonify({"error": err}), 400

    chan_and, chan_params = exports.channel_where_clause("r.groups", channels, prefix="AND")

    try:
        with get_connection() as conn:
            window_timezone = get_db_timezone(conn)
            with conn.cursor() as cur:
                cur.execute(single_csv_sql(chan_and), filter_args(params) + tuple(chan_params))
                rows = cur.fetchall()
                columns = [d[0] for d in cur.description]

            channels_excluded_str = None
            if channels is not None:
                available = available_channels(conn, params)
                excluded_names = sorted(
                    name for bitpos, name in available if bitpos not in channels
                )
                if excluded_names:
                    channels_excluded_str = ", ".join(excluded_names)
    except Exception as e:
        audit(actor, client_ip, params, "locations", 0, "failed",
              detail=f"{type(e).__name__}: {e}", requested_for=req_for)
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500

    if not rows:
        audit(actor, client_ip, params, "locations", 0, "empty",
              channels_excluded=channels_excluded_str, window_timezone=window_timezone,
              requested_for=req_for)
        return jsonify({"error": "no records match those parameters"}), 400

    safe_case = safe_case_id(params)
    kmz_bytes = kmz.build_kmz(rows, columns, params, safe_case, actor, APP_VERSION,
                              requested_for=req_for)

    file_hash = hashlib.sha256(kmz_bytes).hexdigest()
    audit(actor, client_ip, params, "locations", len(rows),
          "generated", package_hash=file_hash, channels_excluded=channels_excluded_str,
          window_timezone=window_timezone, requested_for=req_for,
          detail=f"file: {safe_case}-locations.kmz")

    return Response(
        kmz_bytes,
        mimetype="application/vnd.google-earth.kmz",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_case}-locations.kmz"',
            "X-Package-SHA256": file_hash,
            "Access-Control-Expose-Headers": "X-Package-SHA256, Content-Disposition",
        },
    )


@app.route("/api/package", methods=["POST"])
@require_role("admin", api=True)
def export_package():
    """The full evidence package: every CSV, the README, and hashes, as a zip.

    Nothing is retained on the server. The package exists only for the
    duration of the download.
    """
    data = request.get_json() or {}
    params, err = parse_params(data)
    included = parse_included(data)
    channels = parse_channels(data)
    # Absent -> True, matching parse_included/parse_channels: a caller that
    # doesn't send it gets the long-standing default (KMZ bundled with
    # cot.csv). Only an explicit false from the Export page's deselected
    # KMZ tile turns it off. Coerced through bool() since it's only ever a
    # flag, never interpolated anywhere.
    include_kmz = bool(data.get("include_kmz", True))
    # Absent -> False: shapes pushed by an automated feed stay out unless
    # the operator ticked the box (see shapes.AUTOMATED_FEED_MARKS).
    include_feed_shapes = bool(data.get("include_feed_shapes", False))
    client_ip = request.remote_addr
    actor = identify(data)

    req_for = requested_for(data)

    if err:
        audit(actor, client_ip, params or {}, "package", 0, "rejected", detail=err,
              requested_for=req_for)
        return jsonify({"error": err}), 400

    safe_case = safe_case_id(params)

    # The recorded shape of the database, so this export can say whether it
    # still matched. Read before the connection opens: a missing or
    # unreadable baseline must never be the thing that stops an export.
    try:
        import dbcheck
        schema_baseline, _baseline_row = dbcheck.load_baseline(AUDIT_DB)
    except Exception:
        schema_baseline = None

    try:
        with get_connection() as conn:
            window_timezone = get_db_timezone(conn)
            zip_bytes, summary = exports.build_package(
                conn, params, safe_case, actor, APP_VERSION,
                included=included, channels=channels, include_kmz=include_kmz,
                requested_for=req_for, app_commit=APP_COMMIT,
                include_feed_shapes=include_feed_shapes,
                schema_baseline=schema_baseline,
            )
    except Exception as e:
        audit(actor, client_ip, params, "package", 0, "failed",
              detail=f"{type(e).__name__}: {e}", requested_for=req_for)
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500

    package_hash = hashlib.sha256(zip_bytes).hexdigest()

    # "generated" rather than "exported": at this point the package has been
    # built, but nothing yet confirms it reached the requester. The browser
    # calls /api/confirm once the transfer completes.
    outcome = "generated with errors" if summary["failures"] else "generated"
    detail = "; ".join(f"{k}: {v}" for k, v in summary["failures"].items())
    # The feed rule's effect on this package, in the audit row too: what
    # was left out (a count) or that the operator chose to include them.
    if summary.get("feed_shapes_included"):
        feed_note = "automated-feed shapes included at the operator's choice"
    elif summary.get("feed_shapes_left_out"):
        feed_note = f"automated-feed shapes left out: {summary['feed_shapes_left_out']} object(s)"
    else:
        feed_note = ""
    if feed_note:
        detail = f"{detail}; {feed_note}" if detail else feed_note
    files_excluded = summary.get("files_excluded") or []
    # channels_excluded is None (no filter applied) or a list (verified,
    # possibly empty) - both cases correctly log as blank below, same as
    # files_excluded's existing convention. channels_excluded_unknown is
    # the one state that must NOT log as blank: a blank audit row would
    # look identical to "nothing was excluded", when what actually happened
    # is the export couldn't tell whether anything was.
    channels_excluded = summary.get("channels_excluded")
    channels_excluded_unknown = summary.get("channels_excluded_unknown", False)
    if channels_excluded_unknown:
        channels_excluded_str = "UNVERIFIED - exclusion check failed, see README"
    elif channels_excluded:
        channels_excluded_str = ", ".join(channels_excluded)
    else:
        channels_excluded_str = None

    # Named first, so it reads before whatever the export had to report.
    detail = f"file: {safe_case}-package.zip" + (f"; {detail}" if detail else "")
    # Then every file in the package and its hash, as the package's own
    # SHA256SUMS.txt states them. Until now those hashes existed only inside
    # the zip: the log recorded the zip's hash and nothing about what was in
    # it. Recording them here is what lets a single CSV handed over later be
    # checked against the log without the package, and what lets a re-check
    # be read against what was exported. Last, because it is a reference
    # list rather than something to read first. About 2 KB.
    # Which database this came from, so two exports can be told apart and
    # so the System page can notice the connection being repointed. The
    # value is read from the server at export time (exports.source_identity)
    # and is a fact about the source, not a claim about it.
    if summary.get("source_identity"):
        detail += f"; source database: {summary['source_identity']}"
    # Whether the database was still shaped the way it was when this tool
    # was connected. A fact recorded with the package, so "the schema was as
    # expected when this was built" does not depend on anyone having
    # remembered to run a check that week.
    schema = summary.get("schema") or {}
    if schema.get("state"):
        detail += f"; database structure: {detail_safe(schema['state'])}"
        if schema.get("sha256"):
            detail += f"; schema fingerprint sha256 {schema['sha256']}"
        if schema.get("changes"):
            detail += ("; structure differences: "
                       + detail_safe(" | ".join(schema["changes"][:10])))
    file_hashes = summary.get("file_hashes") or []
    if file_hashes:
        detail += "; package files: " + ", ".join(f"{h} {n}" for n, h in file_hashes)
    audit(actor, client_ip, params, "package", summary["positional_records"],
          outcome, package_hash=package_hash, detail=detail,
          files_excluded=", ".join(files_excluded) if files_excluded else None,
          channels_excluded=channels_excluded_str, window_timezone=window_timezone,
          requested_for=req_for)

    # The re-check token for this package (see /recheck/<token>/...). A
    # failure here must not fail the export - the administrator still has
    # the manual re-check in the README.
    recheck_token = ""
    if summary.get("queries_sql"):
        try:
            recheck_token = create_recheck_token(safe_case, package_hash, summary.get("raw_sha256"),
                                                 summary["queries_sql"], actor,
                                                 requested_for=req_for,
                                                 case_id=params.get("case_id") or safe_case)
        except Exception as e:
            print(f"re-check token not created: {type(e).__name__}: {e}")
        # Kept past the token's 48 hours, so the Audit Log can offer this
        # export a re-check later. Same failure rule as the token: an
        # export that reached the requester must not fail over it.
        try:
            store_recheck_script(safe_case, package_hash, summary.get("raw_sha256"),
                                 summary["queries_sql"], actor,
                                 requested_for=req_for,
                                 case_id=params.get("case_id") or safe_case)
        except Exception as e:
            print(f"re-check script not stored: {type(e).__name__}: {e}")

    return Response(
        zip_bytes,
        mimetype="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_case}-package.zip"',
            "X-Package-SHA256": package_hash,
            "X-Recheck-Token": recheck_token,
            "X-Recheck-Prefix": safe_case,
            "Access-Control-Expose-Headers": "X-Package-SHA256, X-Recheck-Token, X-Recheck-Prefix, Content-Disposition",
        },
    )


@app.route("/api/confirm", methods=["POST"])
@require_role("admin", api=True)
def confirm_download():
    """Called by the browser once a transfer completes.

    This confirms the bytes finished arriving. It does not confirm that a
    usable file was written to disk, and the log should not be read as if
    it did.
    """
    data = request.get_json() or {}
    package_hash = (data.get("hash") or "").strip()
    if not package_hash:
        return jsonify({"error": "hash required"}), 400

    try:
        con = sqlite3.connect(AUDIT_DB)
        con.execute(
            """UPDATE export_log
               SET outcome = outcome || ' / delivered'
               WHERE id = (SELECT max(id) FROM export_log
                           WHERE package_sha256 = ?
                             AND outcome NOT LIKE '%delivered%')""",
            (package_hash,),
        )
        con.commit()
        con.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"})


# ---------------------------------------------------------------------------
# The administrator's re-check, without file transfers
# ---------------------------------------------------------------------------
# When a package is built, a token is minted for it. The Export page turns
# the token into one line the administrator pastes on the TAK Server: it
# fetches the package's queries.sql from here (GET below), runs it with
# psql into a per-case folder, hashes the results, tars them, and posts
# ONLY the hash file back (POST below). The tool never receives location
# data - a script goes out, a list of hashes comes back - and psql, not
# this tool, is what read the database. Both routes are token-
# authenticated and deliberately outside require_role: the server has no
# login here. Unknown, expired or mismatched tokens get a bare 404.

RECHECK_TOKEN_HOURS = 48
RECHECK_SUMS_MAX_BYTES = 64 * 1024
# A token is used a handful of times at most (a fetch and a post per run;
# a re-run or two). Beyond these it is dead, so a token that leaked cannot
# be used to fill the audit log with entries.
RECHECK_MAX_FETCHES = 20
RECHECK_MAX_RESULTS = 10
_SUMS_LINE = re.compile(r"^([0-9a-f]{64}) [ *](\S+)$")
# A file name as this tool writes them (see safe_case_id and the package's
# own names). The hash file is produced on the TAK Server and posted by
# whoever holds the token, so a name that is not shaped like one of ours is
# counted but not written into the audit detail.
_SUMS_NAME_OK = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
# A re-check produces about fifteen files. The cap is what stops an odd or
# hostile hash file from writing a very long list into one audit row.
RECHECK_MAX_LISTED = 60
_HOST_OK = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def _token_case_id(row):
    """The case the re-check's entries are filed under: the one the export
    recorded, falling back to the filename spelling for a token minted
    before that was stored."""
    try:
        return row["case_id"] or row["case_prefix"]
    except (IndexError, KeyError):
        return row["case_prefix"]


def _token_requested_for(row):
    """The token's requested_for, or None for a token minted before that
    column existed (sqlite3.Row raises on an absent key rather than
    returning None, and an old row simply has no such key)."""
    try:
        return row["requested_for"]
    except (IndexError, KeyError):
        return None


def create_recheck_token(case_prefix, package_sha256, raw_sha256, queries_sql, created_by,
                         requested_for=None, case_id=None):
    """Mint a token for one package and store what the two routes need.
    Expired tokens are purged on the way in.

    requested_for travels with the token so the re-check's own audit row
    carries the same "Exported For" the package did - the re-check is part
    of that request, not a separate errand. case_id travels for the same
    reason: case_prefix is the filename spelling, and filing the re-check
    under that would put it in the log as a case of its own whenever the
    two differ."""
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    con = sqlite3.connect(AUDIT_DB)
    con.execute("DELETE FROM recheck_tokens WHERE expires_utc < ?;", (now.isoformat(),))
    con.execute(
        """INSERT INTO recheck_tokens
           (token, case_prefix, case_id, package_sha256, raw_sha256, queries_sql, created_by,
            requested_for, created_utc, expires_utc)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (token, case_prefix, case_id or case_prefix, package_sha256, raw_sha256 or "", queries_sql,
         created_by, requested_for,
         now.isoformat(), (now + timedelta(hours=RECHECK_TOKEN_HOURS)).isoformat()),
    )
    con.commit()
    con.close()
    return token


def store_recheck_script(case_prefix, package_sha256, raw_sha256, queries_sql, created_by,
                         requested_for=None, case_id=None):
    """Keep one package's queries.sql, keyed by the package's own hash, so a
    re-check can be offered after the export page has been left. Re-running
    the same export writes the same bytes under the same hash, so this
    replaces rather than duplicates."""
    con = sqlite3.connect(AUDIT_DB)
    con.execute(
        """INSERT OR REPLACE INTO recheck_scripts
           (package_sha256, case_prefix, case_id, raw_sha256, queries_sql, created_by,
            requested_for, created_utc)
           VALUES (?,?,?,?,?,?,?,?)""",
        (package_sha256, case_prefix, case_id or case_prefix, raw_sha256 or "", queries_sql,
         created_by, requested_for, datetime.now(timezone.utc).isoformat()),
    )
    con.commit()
    con.close()


def recheck_command(base, prefix, token, tag="", insecure=False):
    """The one line the administrator pastes on the TAK Server.

    THIS IS THE SHAPE OF THAT COMMAND. The Export page builds the same
    string in JavaScript (recheckServerCmd() in templates/index.html),
    because it re-renders as the address field and the self-signed box
    change; a browser test compares the two so they cannot drift apart.
    Anywhere else that needs the line - the Audit Log's later re-check -
    asks for it here.
    """
    base = (base or "").rstrip("/")
    k = " -k" if insecure else ""
    sql = f"{prefix}-queries.sql"
    url = f"{base}/recheck/{token}/"
    return (
        f"D=/var/lib/takextract/recheck/{prefix}/$(date +%Y-%m-%dT%H-%M-%S){tag}"
        f" && mkdir -m 2770 -p \"$D\" && cd \"$D\""
        f" && curl -fsS{k} -o {sql} \"{url}{sql}\""
        f" && sudo -u postgres psql -d cot -f {sql}"
        f" && sha256sum {sql} {prefix}-recheck-*.csv {prefix}-recheck-snapshot.txt"
        f" > {prefix}-recheck-SHA256SUMS.txt"
        f" && tar czf {prefix}-recheck.tgz {sql} {prefix}-recheck-*.csv"
        f" {prefix}-recheck-snapshot.txt {prefix}-recheck-SHA256SUMS.txt"
        f" && curl -fsS{k} -F sums=@{prefix}-recheck-SHA256SUMS.txt"
        f" -F tgz_sha256=\"$(sha256sum {prefix}-recheck.tgz | cut -d' ' -f1)\""
        f" -F host=\"$(hostname)\" -F path=\"$D\" \"{url}result\" | tee RECHECK-INFO.txt"
    )


def _load_recheck_token(token):
    """The token's row, or None. Constant-time comparison on the token
    itself; the lookup by unique index is what finds the candidate."""
    if not token or len(token) > 100:
        return None
    con = sqlite3.connect(AUDIT_DB)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM recheck_tokens WHERE token = ?;", (token,)).fetchone()
    con.close()
    if row is None or not secrets.compare_digest(row["token"], token):
        return None
    if row["expires_utc"] < datetime.now(timezone.utc).isoformat():
        return None
    return row


def _bump_recheck_count(row_id, column):
    con = sqlite3.connect(AUDIT_DB)
    con.execute(f"UPDATE recheck_tokens SET {column} = {column} + 1 WHERE id = ?;", (row_id,))
    con.commit()
    con.close()


@app.route("/recheck/<token>/<name>")
def recheck_fetch(token, name):
    """Serve the package's queries.sql to the TAK Server, byte-exact."""
    row = _load_recheck_token(token)
    if row is None or name != f"{row['case_prefix']}-queries.sql" or row["fetch_count"] >= RECHECK_MAX_FETCHES:
        abort(404)
    _bump_recheck_count(row["id"], "fetch_count")
    audit(row["created_by"], request.remote_addr, {"case_id": _token_case_id(row)}, "recheck-fetch", 0, "ok",
          package_hash=row["package_sha256"], detail=f"queries.sql fetched by {request.remote_addr}",
          requested_for=_token_requested_for(row))
    return Response(
        row["queries_sql"].encode("utf-8"),
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"},
    )


@app.route("/recheck/<token>/result", methods=["POST"])
def recheck_result(token):
    """Record the re-check's hash file. Parses it, compares the raw file's
    line (and the script's) with what the package recorded, writes one
    chained audit entry, and answers with the RECHECK-INFO.txt text."""
    row = _load_recheck_token(token)
    if row is None or row["result_count"] >= RECHECK_MAX_RESULTS:
        abort(404)
    prefix = row["case_prefix"]

    # The whole request is a hash file and a few short fields; refuse
    # anything larger before the multipart body is read into memory.
    if (request.content_length or 0) > 4 * RECHECK_SUMS_MAX_BYTES:
        return Response("request too large", status=413, mimetype="text/plain")
    f = request.files.get("sums")
    if f is None:
        return Response("missing 'sums' file", status=400, mimetype="text/plain")
    data = f.read(RECHECK_SUMS_MAX_BYTES + 1)
    if len(data) > RECHECK_SUMS_MAX_BYTES:
        return Response("sums file too large", status=400, mimetype="text/plain")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Response("sums file is not UTF-8 text", status=400, mimetype="text/plain")
    hashes = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _SUMS_LINE.match(line.strip())
        if not m:
            return Response("sums file is not sha256sum output", status=400, mimetype="text/plain")
        hashes[m.group(2).split("/")[-1]] = m.group(1)
    if not hashes:
        return Response("sums file is empty", status=400, mimetype="text/plain")

    host = (request.form.get("host") or "").strip()
    path = (request.form.get("path") or "").strip()
    tgz = (request.form.get("tgz_sha256") or "").strip().lower()
    if host and not _HOST_OK.match(host):
        return Response("host is not a hostname", status=400, mimetype="text/plain")
    # The separator, refused outright. This field is posted by whoever holds
    # the token - the administrator this re-check is meant to be an
    # independent check ON - and it becomes the first clause of a chained
    # audit detail. A ";" in it would let them write further clauses,
    # verdicts among them, that the page reads back ahead of the ones this
    # route decided. The folder in the command this tool issues never
    # contains one. See detail_safe(), which says the same thing about
    # every other caller-supplied fragment.
    # No separator, and no spaces either. The ";" ban stops a clause being
    # forged; a space was enough to smuggle "hash file x sha256 <64 hex>"
    # into the FIRST clause, where anything reading the detail without
    # requiring a clause boundary would find it before the values this
    # route recorded. The folder this tool's own command builds never
    # contains a space (see recheck_command: the prefix is safe_case_id,
    # the rest is a timestamp and a hex fragment), so nothing legitimate
    # is refused here.
    if (len(path) > 300 or ";" in path or " " in path
            or any(ord(c) < 32 or ord(c) == 127 for c in path)):
        return Response("path is not a plain printable path without spaces",
                        status=400, mimetype="text/plain")
    if tgz and not re.fullmatch(r"[0-9a-f]{64}", tgz):
        return Response("tgz_sha256 is not a SHA-256", status=400, mimetype="text/plain")

    sums_sha256 = hashlib.sha256(data).hexdigest()
    script_sha256 = hashlib.sha256(row["queries_sql"].encode("utf-8")).hexdigest()
    raw_line = hashes.get(f"{prefix}-recheck-cot_router-raw.csv")
    script_line = hashes.get(f"{prefix}-queries.sql")
    if raw_line is None:
        raw_verdict, outcome = "MISSING - no line for the raw file", "raw file missing"
    elif row["raw_sha256"] and raw_line == row["raw_sha256"]:
        raw_verdict, outcome = "yes", "raw match"
    elif not row["raw_sha256"]:
        raw_verdict, outcome = "unknown - the package recorded no raw-file hash", "raw unverified"
    else:
        raw_verdict, outcome = "NO - the hashes differ", "raw MISMATCH"
    script_verdict = ("yes" if script_line == script_sha256 else
                      "MISSING" if script_line is None else "NO - a different script was run")
    # How many of the server's files a verdict was actually reached on. Two
    # at most - the script and the raw file - and the entry says so rather
    # than leaving "19 files hashed" beside two verdicts to be read as
    # nineteen comparisons. See the package README for why the others are
    # not compared by hash.
    compared = sum(1 for line in (script_line, raw_line) if line is not None)

    now = datetime.now(timezone.utc)
    # "host:path" when both were reported; just the one that was when only
    # one is, rather than a trailing colon with nothing after it.
    where = ":".join(detail_safe(x, limit=300) for x in (host, path) if x) or "(not reported)"
    # What the server hashed, name by name. The route used to parse these,
    # use two and discard the rest, so the entry could not say which files
    # the server produced or what it got for them; now the list is recorded
    # and the two verdicts are read against it.
    listed = sorted((n, h) for n, h in hashes.items() if _SUMS_NAME_OK.match(n))
    unnamed = len(hashes) - len(listed)
    over = max(0, len(listed) - RECHECK_MAX_LISTED)
    listed = listed[:RECHECK_MAX_LISTED]
    files_clause = ""
    if listed:
        files_clause = "; server files: " + ", ".join(f"{h} {n}" for n, h in listed)
        if over or unnamed:
            files_clause += f" (+{over + unnamed} not listed)"
    detail = (f"re-check at {where}; {len(hashes)} file(s) hashed on the server; "
              f"hash file {prefix}-recheck-SHA256SUMS.txt sha256 {sums_sha256}; "
              f"archive {prefix}-recheck.tgz sha256 {tgz or '(not reported)'}; "
              f"SQL query script match: {script_verdict}; "
              f"raw table rows match: {raw_verdict}; "
              f"compared: {compared} of {len(hashes)} file(s), the rest recorded not compared"
              + files_clause)
    audit(row["created_by"], request.remote_addr, {"case_id": _token_case_id(row)}, "recheck", len(hashes), outcome,
          package_hash=row["package_sha256"], detail=detail,
          requested_for=_token_requested_for(row))
    _bump_recheck_count(row["id"], "result_count")

    info = (
        f"recorded: {prefix} re-check, {len(hashes)} files, cot_router-raw.csv matches the package: {raw_verdict}\n"
        f"===============================================================================\n"
        f"RECHECK-INFO - written by TAK-Extract when this re-check was recorded\n"
        f"===============================================================================\n"
        f"Case / reference       : {prefix}\n"
        f"Re-check recorded      : {now.isoformat()} (UTC)\n"
        f"Recorded under         : {row['created_by']} (the account that exported the package)\n"
        f"Posted from            : {request.remote_addr}\n"
        f"Files at               : {where}\n"
        f"Package SHA-256        : {row['package_sha256']}\n"
        f"Hash file SHA-256      : {sums_sha256}\n"
        f"tgz SHA-256            : {tgz or '(not reported)'}\n"
        f"SQL query script       : {script_verdict}\n"
        f"  ({prefix}-queries.sql as the server ran it, against the same file in the\n"
        f"   package - the statements the export sent, for every file in it)\n"
        f"Raw table rows         : {raw_verdict}\n"
        f"  (the {prefix}-recheck-cot_router-raw.csv line in the hash file against the\n"
        f"   {prefix}-cot_router-raw.csv line in the package's SHA256SUMS.txt)\n"
        f"Files hashed on server : {len(hashes)}\n"
        f"Compared by hash       : {compared} of {len(hashes)} - the rest were recorded, not compared\n"
        f"  (see WHAT THE RE-CHECK COMPARES in the package README for why)\n"
        f"Recorded by            : {TOOL_VERSION}\n"
        f"===============================================================================\n"
        f"Every statement the re-check ran was a SELECT inside a read-only transaction.\n"
        f"These files were produced by psql on the server named above, not by TAK-Extract;\n"
        f"TAK-Extract received only this list of hashes. Keep this folder with the case.\n"
        f"\n"
        f"This file is written after {prefix}-recheck.tgz was built, so it is NOT inside\n"
        f"that archive - it sits beside it. Copy the whole folder, or copy this file\n"
        f"alongside the archive; the archive on its own does not carry the result. (The\n"
        f"archive's hash is recorded in the audit log, which is why it is not rebuilt\n"
        f"afterwards to include this.)\n"
    )
    return Response(info, mimetype="text/plain; charset=utf-8", headers={"Cache-Control": "no-store"})


@app.route("/api/admin/audit-chain")
@require_role("admin", api=True)
def audit_chain():
    """Verify the audit log's hash chain (see verify_audit_chain). Read-only."""
    try:
        return jsonify(verify_audit_chain())
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


# The address the command points back at. Whatever the operator's browser
# used is the right default - it is a name that reaches this install from
# where they are standing. It goes into a line they will paste into a
# shell, so nothing that is not a bare scheme and host is allowed near it.
_BASE_OK = re.compile(r"^https?://[A-Za-z0-9.\-]{1,253}(?::[0-9]{1,5})?$")


def _recorded_script_hash(detail, prefix):
    """The SHA-256 the export entry recorded for its own queries.sql, from
    the package file list (see the export route). None for an entry
    written before that list was recorded."""
    m = re.search(r"(?:^|; )package files: ([^;]+)", detail or "")
    if not m:
        return None
    for item in m.group(1).split(", "):
        parts = item.strip().split(" ", 1)
        if len(parts) == 2 and parts[1] == f"{prefix}-queries.sql":
            return parts[0]
    return None


@app.route("/api/audit/recheck/<package_sha256>", methods=["POST"])
@require_role("admin", api=True)
def audit_recheck(package_sha256):
    """Offer an export a re-check after the fact.

    A token is shown once, on the page that produced the package, and
    lasts 48 hours - so an export that was not re-checked at the time had
    no way back except running the statements by hand from the package.
    This mints a fresh token for an export already in the log, from the
    script that export was built with.

    The stored script is not taken on trust: the export's own entry
    records its SHA-256, and that entry is chained. If the two disagree,
    no token is minted and the disagreement is recorded.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", (package_sha256 or "").lower()):
        return jsonify({"error": "not a SHA-256"}), 400
    package_sha256 = package_sha256.lower()
    data = request.get_json(silent=True) or {}
    base = (data.get("base") or "").strip().rstrip("/")
    if base and not _BASE_OK.match(base):
        return jsonify({"error": "that address is not a plain http(s) host"}), 400
    base = base or request.url_root.rstrip("/")
    insecure = bool(data.get("insecure"))

    con = sqlite3.connect(AUDIT_DB)
    con.row_factory = sqlite3.Row
    try:
        export = con.execute(
            "SELECT * FROM export_log WHERE package_sha256 = ? AND export_kind = 'package'"
            " ORDER BY id DESC LIMIT 1;", (package_sha256,)).fetchone()
        script = con.execute(
            "SELECT * FROM recheck_scripts WHERE package_sha256 = ?;", (package_sha256,)).fetchone()
    finally:
        con.close()
    if export is None:
        return jsonify({"error": "no export in the log has that hash"}), 404
    if script is None:
        return jsonify({"error": "no-script",
                        "message": ("The script for this export was not kept. Exports made before "
                                    "this version stored it only with the token, which lasts 48 "
                                    "hours. The package's own queries.sql can still be run by "
                                    "hand - see THE ADMINISTRATOR'S RE-CHECK in its README.")}), 404

    prefix = script["case_prefix"]
    actual = hashlib.sha256(script["queries_sql"].encode("utf-8")).hexdigest()
    recorded = _recorded_script_hash(export["detail"], prefix)
    # identify(), as the export and the re-check rows use: the verified
    # identity for this request, written the same way they write it, so
    # the log does not show one operator under two spellings.
    actor = identify({})
    if recorded and recorded != actual:
        # Recorded, not swallowed: the stored copy disagreeing with the
        # chained log is the one thing this route exists to notice.
        audit(actor, request.remote_addr, {"case_id": script["case_id"] or prefix},
              "recheck-issued", 0, "script MISMATCH",
              package_hash=package_sha256,
              detail=(f"re-check NOT offered for package {package_sha256}; "
                      f"the kept {prefix}-queries.sql has sha256 {actual}; "
                      f"the export entry records {recorded}"),
              requested_for=script["requested_for"])
        return jsonify({"error": "script-mismatch",
                        "message": ("The kept copy of this export's queries.sql does not have the "
                                    "hash the export recorded for it. No re-check was offered. "
                                    "This is recorded in the log.")}), 409

    token = create_recheck_token(prefix, package_sha256, script["raw_sha256"],
                                 script["queries_sql"], script["created_by"] or actor,
                                 requested_for=script["requested_for"],
                                 case_id=script["case_id"] or prefix)
    checked = ("checked against the export entry: yes" if recorded else
               "checked against the export entry: the entry records no hash for it")
    audit(actor, request.remote_addr, {"case_id": script["case_id"] or prefix},
          "recheck-issued", 0, "issued", package_hash=package_sha256,
          detail=(f"re-check offered again for package {package_sha256}; "
                  f"script {prefix}-queries.sql sha256 {actual}; {checked}"),
          requested_for=script["requested_for"])
    return jsonify({
        "ok": True,
        "prefix": prefix,
        "token": token,
        "hours": RECHECK_TOKEN_HOURS,
        "checked": bool(recorded),
        "command": recheck_command(base, prefix, token,
                                   tag="-" + package_sha256[:8], insecure=insecure),
    })


def recent_source_identities(limit=50):
    """The distinct databases recent exports recorded reading, newest
    first. Separate from the route so it can be exercised without a live
    TAK Server - the route cannot answer at all without one, and this half
    is the half with logic in it."""
    con = sqlite3.connect(AUDIT_DB)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT ts_local, case_id, detail FROM export_log"
            " WHERE export_kind IN ('package', 'locations') AND detail LIKE '%source database: %'"
            " ORDER BY id DESC LIMIT ?;", (limit,)).fetchall()
    finally:
        con.close()
    seen = []
    for r in rows:
        m = re.search(r"(?:^|; )source database: ([^;]+)", r["detail"] or "")
        if not m:
            continue
        val = m.group(1).strip()
        if val not in [x["identity"] for x in seen]:
            seen.append({"identity": val, "when": r["ts_local"], "case_id": r["case_id"]})
    return seen


@app.route("/api/admin/source-identity")
@require_role("admin", api=True)
def source_identity_check():
    """Which database the connection currently points at, and whether that
    is the one recent exports were read from.

    The point is a specific, quiet failure: the TAK Server connection is
    editable from the System page, so an install can be repointed at
    another server between exports and nothing would have said so. A
    difference here is NOT an accusation - a rebuilt, upgraded or restored
    cluster reports a new identifier while holding the same data - which
    is why this reports both values and says what it cannot tell.
    """
    try:
        with get_connection() as conn:
            context = {}
            exports.read_source_identity(conn, context)
            now = exports.source_identity(context)
    except Exception as e:
        return jsonify({"checked": False, "error": f"{type(e).__name__}: {e}"})

    seen = recent_source_identities()
    newest = seen[0] if seen else None
    return jsonify({
        "checked": True,
        "current": now,
        "kind": "cluster" if context.get("db_cluster_id") else "catalog",
        "newest_export": newest,
        # More than one distinct value among recent exports: this install
        # has read from more than one database. Worth showing plainly.
        "distinct": seen,
        "matches": (newest is None or newest["identity"] == now),
    })


@app.route("/api/admin/recheck-setup")
@require_role("admin", api=True)
def recheck_setup():
    """What this install knows about the re-check folder on the TAK Server,
    for the System page's panel. The app runs in a container and cannot
    look at the host's folder, so it reports the two things it can know:
    the marker connect-database.sh writes into .env when the folder step
    completes (RECHECK_FOLDER_SETUP), and the newest re-check the server
    actually posted (a 'recheck' audit row - proof the folder works)."""
    marker = (os.getenv("RECHECK_FOLDER_SETUP") or "").strip()
    last = None
    try:
        con = sqlite3.connect(AUDIT_DB)
        con.row_factory = sqlite3.Row
        row = con.execute(
            "SELECT ts_utc, ts_local, actor, outcome, detail FROM export_log "
            "WHERE export_kind = 'recheck' ORDER BY id DESC LIMIT 1;").fetchone()
        con.close()
        if row is not None:
            # detail begins "re-check at host:path; ..." (see /recheck/<token>/result)
            where = ""
            d = row["detail"] or ""
            if d.startswith("re-check at "):
                where = d[len("re-check at "):].split(";", 1)[0]
            last = {"ts_utc": row["ts_utc"], "ts_local": row["ts_local"], "actor": row["actor"],
                    "outcome": row["outcome"], "where": where}
    except Exception as e:
        return jsonify({"marker": marker, "last": None, "error": f"{type(e).__name__}: {e}"})
    return jsonify({"marker": marker, "last": last})


@app.route("/api/admin/schema-check")
@require_role("admin", api=True)
def schema_check():
    """The cheap half of the database check, for the System page.

    Catalogue reads only - no table is touched - so this is a page load's
    worth of work. The full pass, which executes every statement an export
    sends, is ./check-database.sh on the server."""
    import dbcheck
    try:
        baseline, baseline_row = dbcheck.load_baseline(AUDIT_DB)
        with get_connection() as conn:
            fp = dbcheck.fingerprint(conn)
    except Exception as e:
        return jsonify({"checked": False, "error": f"{type(e).__name__}: {e}"})

    changes = dbcheck.diff_fingerprint(baseline, fp)
    verdict = dbcheck._worst([c["status"] for c in changes]) if changes else dbcheck.OK
    return jsonify({
        "checked": True,
        "has_baseline": baseline is not None,
        "baseline_when": (baseline_row or {}).get("created_utc"),
        "baseline_by": (baseline_row or {}).get("created_by"),
        "fingerprint_sha256": dbcheck.fingerprint_sha256(fp),
        "changes": changes,
        "verdict": verdict,
        "server_version": fp.get("server_version"),
        "table_count": len(fp.get("tables", {})),
        "cot_router_columns": len(fp.get("cot_router_columns", [])),
    })


@app.route("/api/admin/schema-check/approve-baseline", methods=["POST"])
@require_role("admin", api=True)
def schema_check_approve():
    """Accept the structure as it is now as the baseline future checks are
    measured against. Records who approved it, because this is someone
    deciding that a change is expected."""
    import dbcheck
    data = request.get_json() or {}
    who = (data.get("approved_by") or "").strip()[:120]
    if not who:
        return jsonify({"error": "say who is approving this"}), 400
    try:
        with get_connection() as conn:
            fp = dbcheck.fingerprint(conn)
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500

    # The page sends back the fingerprint it showed. If the schema moved
    # between the two, the person is approving something they did not see.
    seen = (data.get("fingerprint_sha256") or "").strip()
    current = dbcheck.fingerprint_sha256(fp)
    if seen and seen != current:
        return jsonify({"error": "the structure changed since this page read it - "
                                 "reload and look again before approving"}), 409

    old, _row = dbcheck.load_baseline(AUDIT_DB)
    changes = dbcheck.diff_fingerprint(old, fp) if old else []
    dbcheck.save_baseline(AUDIT_DB, fp, f"{session.get('username', 'admin')} / {who}",
                          "approved from the System page")
    detail = f"database structure baseline approved by {detail_safe(who)}"
    detail += f"; schema fingerprint sha256 {current}"
    if changes:
        detail += ("; accepted differences: "
                   + detail_safe(" | ".join(c["detail"] for c in changes[:10])))
    try:
        # {} not None - audit() reads the case and window off it with .get().
        audit(session.get("username", "admin"), request.remote_addr, {},
              "schema-check", 0, "baseline approved", detail=detail)
    except Exception as e:
        print(f"could not audit the baseline approval: {type(e).__name__}: {e}", flush=True)
    return jsonify({"ok": True, "fingerprint_sha256": current})


@app.route("/api/recheck-progress/<token>")
@require_role("admin", api=True)
def recheck_progress(token):
    """How far this package's re-check has got, for the Export page to
    report while the administrator is at the server.

    Whether the TAK Server can reach this app is not something this app
    can test - the connection runs the other way - but it knows the moment
    it happens, because the server's own curl fetches queries.sql through
    here. So the page watches this rather than guessing which method to
    offer, and only suggests the fallback once nothing has arrived."""
    row = _load_recheck_token(token)
    if row is None:
        return jsonify({"error": "unknown or expired token"}), 404
    out = {"fetched": row["fetch_count"], "results": row["result_count"],
           "outcome": None, "where": None, "when": None}
    if row["result_count"]:
        try:
            con = sqlite3.connect(AUDIT_DB)
            con.row_factory = sqlite3.Row
            r = con.execute(
                "SELECT ts_local, ts_utc, outcome, detail FROM export_log "
                "WHERE export_kind = 'recheck' AND package_sha256 = ? ORDER BY id DESC LIMIT 1;",
                (row["package_sha256"],)).fetchone()
            con.close()
            if r is not None:
                d = r["detail"] or ""
                out["outcome"] = r["outcome"]
                out["when"] = r["ts_local"] or r["ts_utc"]
                if d.startswith("re-check at "):
                    out["where"] = d[len("re-check at "):].split(";", 1)[0]
        except Exception as e:
            print(f"/api/recheck-progress lookup failed: {type(e).__name__}: {e}")
    return jsonify(out)


@app.route("/api/recheck-target")
@require_role("admin", api=True)
def recheck_target():
    """The saved connection's host, port, database and user, for the Export
    page to fill into the administrator's re-check command (form B). No
    password, ever; the same values the System page already shows."""
    return jsonify({
        "host": get_setting("db_host", "DB_HOST") or "",
        "port": get_setting("db_port", "DB_PORT", DB_SETTING_DEFAULTS.get("db_port")) or "5432",
        "dbname": get_setting("db_name", "DB_NAME", DB_SETTING_DEFAULTS.get("db_name")) or "cot",
        "user": get_setting("db_user", "DB_USER") or "",
    })


@app.route("/api/companion", methods=["POST"])
@require_role("admin", api=True)
def record_companion():
    """Record a companion file's SHA-256 in the audit log beside a
    package's - the administrator's own re-check output (recheck-*.csv from
    queries.sql run on the server), hashed in the browser like the package
    itself. The tool never produced or moved the file; this only witnesses
    its hash under the administrator's login, so a later reader loading the
    package and the file together sees both recorded. Stored in the same
    package_sha256 column under kind "companion", so /api/verify-hash finds
    it with the same lookup."""
    data = request.get_json() or {}
    pkg = str(data.get("package_hash") or "").strip().lower()
    comp = str(data.get("companion_hash") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", comp) or (pkg and not re.fullmatch(r"[0-9a-f]{64}", pkg)):
        return jsonify({"error": "a 64-character hex SHA-256 hash is required"}), 400
    filename = detail_safe(data.get("filename"))
    matched, total = data.get("matched"), data.get("total")
    try:
        matched, total = int(matched), int(total)
    except (TypeError, ValueError):
        matched, total = 0, 0
    case_id = detail_safe(data.get("case_id"))
    detail = (f"companion {filename} for package {pkg or '(package hash unavailable)'}; "
              f"{matched} of {total} package positions matched it")
    audit(identify({}), request.remote_addr, {"case_id": case_id}, "companion", matched, "recorded",
          package_hash=comp, detail=detail)
    return jsonify({"ok": True})


@app.route("/api/certification/<package_sha256>")
@require_role("admin", "viewer")
def certification(package_sha256):
    """The certification for a package, with the facts filled in.

    It used to ship inside the package as a blank form: the zip's own
    hash (which does not exist while the zip is being built) and the
    re-check's results (which happen afterwards, if at all) were left as
    underscores for someone to copy 64-character values into by hand.
    Both are in the audit log by the time anyone fills it in, so this
    reads them from there instead. Only the declaration and the signature
    are left for a person.

    Gated like /api/verify-hash - a viewer verifying a package is exactly
    who needs this - and reads nothing but this install's own log.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", (package_sha256 or "").lower()):
        abort(404)
    package_sha256 = package_sha256.lower()
    con = sqlite3.connect(AUDIT_DB)
    con.row_factory = sqlite3.Row
    try:
        export = con.execute(
            "SELECT * FROM export_log WHERE package_sha256 = ?"
            " AND export_kind IN ('package', 'locations') ORDER BY id DESC LIMIT 1;",
            (package_sha256,)).fetchone()
        # The newest re-check OF this package. None is an ordinary answer:
        # the certification then says no re-check is recorded, which is a
        # fact about the package, not a gap in it.
        recheck = con.execute(
            "SELECT * FROM export_log WHERE package_sha256 = ? AND export_kind = 'recheck'"
            " ORDER BY id DESC LIMIT 1;", (package_sha256,)).fetchone()
    finally:
        con.close()
    if export is None:
        abort(404)

    case_id = export["case_id"] or "export"
    safe_case = "".join(c for c in case_id if c.isalnum() or c in "._-") or "export"
    # Section 2 lists every file and its hash. Those were recorded with the
    # export from 1.17.0 on; an older entry has no list, and the section
    # says so rather than inventing one.
    contents = {}
    m = re.search(r"(?:^|; )package files: ([^;]+)", export["detail"] or "")
    if m:
        for item in m.group(1).split(", "):
            parts = item.strip().split(" ", 1)
            if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                contents[parts[1]] = parts[0]

    # Phrased here rather than in exports.py: these are readings of audit
    # columns, and the builder should not have to know what a row looks
    # like. The database account and the snapshot id are export-time facts
    # the log does not carry - they are in the package's own README, and
    # this says so instead of printing "unknown".
    window = ""
    if export["window_start"] or export["window_end"]:
        window = (f"; window {export['window_start']} to {export['window_end']}"
                  + (f" ({export['window_timezone']})" if export["window_timezone"] else ""))
    facts = {
        "produced_by": export["tool_version"],
        "exported": export["ts_local"] or export["ts_utc"],
        "exported_by": export["actor"],
        "requested_for": export["requested_for"],
        "source": ("the TAK Server PostgreSQL database, read in a REPEATABLE READ,\n"
                   "                        READ ONLY transaction" + window
                   + f"\n                        Recorded outcome: {export['outcome']}"
                   + "\n                        (the read-only account used and the database"
                   + "\n                        snapshot id are in the package's README)"),
    }
    text = exports.build_certification(
        safe_case, facts, sorted(contents.items()),
        package_sha256=package_sha256,
        recheck=(dict(recheck) if recheck is not None else None))
    return Response(text, mimetype="text/plain; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{safe_case}-certification.txt"',
        "Cache-Control": "no-store",
    })


@app.route("/api/verify-hash", methods=["POST"])
@require_role("admin", "viewer", api=True)
def verify_hash():
    """Look up a file's SHA-256 against the audit log.

    The read-only counterpart to /api/confirm's write, for the replay/verify
    page: the browser hashes a dropped file itself (Web Crypto), sends only
    the hash, and this checks it against every package_sha256 this server
    has ever logged - a KMZ, a full package, or an audit-log download all
    hash the same way, so this matches any of them. Never touches the TAK
    Postgres database, only the local audit.sqlite, so this works even when
    that server is unreachable.

    More than one match is possible (an export re-run against unchanged
    data can produce byte-identical output) and is not an error - all
    matches are returned, newest first, and the caller decides how to
    present that.
    """
    data = request.get_json() or {}
    file_hash = (data.get("hash") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", file_hash):
        return jsonify({"error": "a 64-character hex SHA-256 hash is required"}), 400

    try:
        con = sqlite3.connect(AUDIT_DB)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM export_log WHERE package_sha256 = ? ORDER BY id DESC;",
            (file_hash,),
        ).fetchall()
        con.close()
    except Exception as e:
        # Logged, not returned - this route is reachable by "viewer" too,
        # and the raw exception text (sqlite internals, file paths) isn't
        # this app's own information to hand out just because someone
        # dropped a file in wrong. Every OTHER admin-only route in this
        # file still returns the raw detail - that's a deliberate
        # difference in audience, not an inconsistency.
        print(f"/api/verify-hash lookup failed: {type(e).__name__}: {e}")
        return jsonify({"error": "lookup failed - see server log"}), 500

    # The row as recorded, minus what a verifier has no use for and should
    # not be handed: the exporting account's IP address, and the chain
    # hashes (System -> Audit log integrity verifies those; a viewer's
    # page never does). The admin-only /api/audit still returns everything.
    withheld = ("client_ip", "prev_hash", "row_hash")
    matches = [{k: v for k, v in dict(r).items() if k not in withheld} for r in rows]
    return jsonify({"matched": bool(matches), "matches": matches})


@app.route("/api/verify-window", methods=["POST"])
@require_role("admin", "viewer", api=True)
def verify_window():
    """For each audit-log row matching this hash, does the RECORDED export
    window actually contain the file's REAL data range?

    These are two related but genuinely different facts: window_start/end
    is what the operator typed in at export time (a request), while
    file_min_utc/file_max_utc (computed client-side from the file's own
    servertime values) is what the export actually contains. A request
    window is typically wider than the data it turns up, so the correct
    check is containment, not equality - two files can legitimately have
    different actual ranges while both being honest results of the same
    recorded window.

    window_start/window_end are timezone-naive by construction (see
    audit()'s docstring) - window_timezone (recorded at export time, see
    get_db_timezone()) says which IANA zone they were wall-clock time in,
    so they can be converted to UTC for a real comparison. A row with no
    window_timezone recorded (every export before that column existed)
    can't be verified after the fact - that comes back as null, not False,
    so the caller can tell "checked, and it didn't match" apart from
    "can't tell".
    """
    data = request.get_json() or {}
    file_hash = (data.get("hash") or "").strip().lower()
    file_min_utc = data.get("file_min_utc")
    file_max_utc = data.get("file_max_utc")
    if not re.fullmatch(r"[0-9a-f]{64}", file_hash):
        return jsonify({"error": "a 64-character hex SHA-256 hash is required"}), 400
    try:
        file_min = datetime.fromisoformat(file_min_utc.replace("Z", "+00:00"))
        file_max = datetime.fromisoformat(file_max_utc.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return jsonify({"error": "file_min_utc and file_max_utc must be ISO-8601 timestamps"}), 400

    try:
        con = sqlite3.connect(AUDIT_DB)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT id, window_start, window_end, window_timezone FROM export_log "
            "WHERE package_sha256 = ?;",
            (file_hash,),
        ).fetchall()
        con.close()
    except Exception as e:
        # See /api/verify-hash's identical except block just above -
        # same reasoning: this route is viewer-reachable too.
        print(f"/api/verify-window lookup failed: {type(e).__name__}: {e}")
        return jsonify({"error": "lookup failed - see server log"}), 500

    results = {}
    for row in rows:
        if not row["window_timezone"] or not row["window_start"] or not row["window_end"]:
            results[row["id"]] = None
            continue
        try:
            zone = ZoneInfo(row["window_timezone"])
            win_start = datetime.fromisoformat(row["window_start"]).replace(tzinfo=zone).astimezone(timezone.utc)
            win_end = datetime.fromisoformat(row["window_end"]).replace(tzinfo=zone).astimezone(timezone.utc)
            results[row["id"]] = win_start <= file_min and file_max <= win_end
        except Exception:
            results[row["id"]] = None

    return jsonify({"results": results})


AUDIT_PAGE_SIZE = 25

# Whitelisted, not interpolated from the request as-is: a column name can't
# be parameterized in SQL the way a value can, so this is the only thing
# standing between `sort` and a SQL-injection-via-identifier bug. Anything
# not in here (or no `sort` at all) falls back to the original id-DESC
# order, unchanged from before this existed.
AUDIT_SORT_COLUMNS = {
    "when": "ts_utc", "who": "actor", "case": "case_id",
    "kind": "export_kind", "records": "record_count", "outcome": "outcome",
    "for": "requested_for",
}


@app.route("/api/audit")
@require_role("admin", api=True)
def audit_view():
    """One page of export activity, newest first by default. Parameters
    only - no location data. `page` is 1-indexed; anything invalid falls
    back to page 1 rather than erroring, since a bad page number isn't
    worth a 400 on a page whose whole job is to be easy to check.

    `q`: an optional substring match against case_id, actor, or
    requested_for - the fields someone is actually likely to search this
    log by ("everything for case X", "everything I ran", "everything run
    on behalf of X"). Applied server-side, across the whole log, not just
    the current page - a client-side filter over one page of 25 rows would
    silently miss matches sitting on other pages.

    `sort`/`dir`: optional column to sort by (see AUDIT_SORT_COLUMNS) and
    direction ("asc" or "desc", anything else defaults to desc). Also
    applied across the whole log for the same reason.

    `group=case`: the page's default view. Answers with one entry per CASE
    (newest activity first), each carrying all of that case's entries -
    the unit someone actually works in, since one case is a package, the
    fetch of its script and the re-check that followed. A page is then 25
    cases rather than 25 entries, so a case's entries are never split
    across two pages. `sort`/`dir` do not apply in this mode: cases are
    ordered by their most recent entry, which is the only order that makes
    sense for a list of cases.
    """
    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    if page < 1:
        page = 1
    offset = (page - 1) * AUDIT_PAGE_SIZE

    q = (request.args.get("q") or "").strip()

    sort_key = request.args.get("sort", "")
    order_col = AUDIT_SORT_COLUMNS.get(sort_key, "id")
    order_dir = "ASC" if request.args.get("dir") == "asc" else "DESC"

    try:
        con = sqlite3.connect(AUDIT_DB)
        con.row_factory = sqlite3.Row
        # Corrections are applied on the way out (see _load_case_corrections):
        # the recorded case_id never changes, so every query that groups or
        # filters by case has to ask for the corrected value.
        by_entry, by_case = _load_case_corrections(con)
        eff_sql, eff_params = _effective_case_sql(by_entry, by_case)
        where = ""
        where_params = ()
        if q:
            # The corrected case AND the recorded one: a case someone
            # remembers by the name it was first filed under still finds it.
            where = (f"WHERE {eff_sql} LIKE ? OR case_id LIKE ? OR actor LIKE ? "
                     "OR COALESCE(requested_for, '') LIKE ?")
            like = f"%{q}%"
            where_params = tuple(eff_params) + (like, like, like, like)
        if request.args.get("group") == "case":
            return _audit_by_case(con, where, where_params, page, offset, eff_sql, eff_params)
        total = con.execute(
            f"SELECT count(*) FROM export_log {where};", where_params
        ).fetchone()[0]
        rows = con.execute(
            f"""SELECT *, {eff_sql} AS effective_case_id FROM export_log {where}
                ORDER BY {order_col} {order_dir} LIMIT ? OFFSET ?;""",
            tuple(eff_params) + where_params + (AUDIT_PAGE_SIZE, offset),
        ).fetchall()
        con.close()
        pages = max(1, -(-total // AUDIT_PAGE_SIZE))  # ceiling division
        return jsonify({
            "rows": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "pages": pages,
            "per_page": AUDIT_PAGE_SIZE,
        })
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"})


# A case typed wrong at export time repeats on everything that follows it
# (the package, the fetch of its script, its re-check), so it needs a way
# to be put right. The entry itself is never touched: case_id is one of
# CHAIN_FIELDS, so rewriting it would break that row's hash and every link
# after it - the log would report itself as tampered, which is the one
# alarm that has to keep meaning something. A correction is therefore an
# ordinary, chained entry of its own, and the page applies it on the way
# out: the recorded value stays visible beside the corrected one.
#
# The link back to what was corrected lives in `detail`, which is chained
# too, so it cannot be altered any more quietly than the rest of the row.
# These two patterns are what this app writes and reads back; anything
# else in a detail is left alone.
# No anchor after the corrected name: the detail carries on with how many
# entries were affected and the reason. A case reference cannot contain a
# quote (correct_case refuses one), so the non-greedy groups end exactly
# where the names do.
_CORRECT_ENTRY_RE = re.compile(r'^corrects entry (\d+): case "(.*?)" -> "(.*?)"')
_CORRECT_CASE_RE = re.compile(r'^corrects case "(.*?)" -> "(.*?)"')
CASE_ID_MAX = 120


def _unambiguous(detail, match):
    """Whether a correction entry means only what it appears to mean.

    The names are quoted inside the text, and the text carries on after
    them with the count and the reason. A case exported under a name
    containing `" -> "` would end the first quoted name early and make
    this read a mapping its own text does not state - so a detail whose
    remainder is not the expected continuation is left unapplied rather
    than trusted. Names written from now on cannot contain a quote at all
    (parse_params strips it, correct_case refuses it); this is for rows
    already in a log."""
    rest = detail[match.end():]
    return rest == "" or rest.startswith(" (") or rest.startswith(";")


def _load_case_corrections(con):
    """(by_entry, by_case) from the correction entries, oldest first.

    by_entry: {entry id: corrected case} - a single entry filed under the
    wrong case. by_case: {recorded case: corrected case}, resolved through
    later corrections of the same case, so a name corrected twice lands on
    the latest value rather than an intermediate one. An entry-level
    correction wins over a case-level one for that entry."""
    by_entry, by_case = {}, {}
    for r in con.execute("SELECT id, detail FROM export_log WHERE export_kind = 'case-correction' "
                         "ORDER BY id ASC;").fetchall():
        d = r["detail"] or ""
        m = _CORRECT_ENTRY_RE.match(d)
        if m and _unambiguous(d, m):
            by_entry[int(m.group(1))] = m.group(3)
            continue
        m = _CORRECT_CASE_RE.match(d)
        if m and _unambiguous(d, m):
            old, new = m.group(1), m.group(2)
            # Re-point anything that already landed on `old`, so A->B->C
            # leaves an entry recorded as A reading C, not B.
            for k, v in list(by_case.items()):
                if v == old:
                    by_case[k] = new
            for k, v in list(by_entry.items()):
                if v == old:
                    by_entry[k] = new
            by_case[old] = new
    return by_entry, by_case


def _effective_case_sql(by_entry, by_case):
    """A CASE expression giving each row its corrected case, and its
    parameters. Built from the corrections rather than applied row by row
    in Python so grouping, paging and filtering all stay in one query."""
    if not by_entry and not by_case:
        return "COALESCE(case_id, '')", []
    whens, params = [], []
    for entry_id, new in by_entry.items():        # entry-level wins
        whens.append("WHEN id = ? THEN ?")
        params += [entry_id, new]
    for old, new in by_case.items():
        whens.append("WHEN COALESCE(case_id, '') = ? THEN ?")
        params += [old, new]
    return "CASE " + " ".join(whens) + " ELSE COALESCE(case_id, '') END", params


@app.route("/api/audit/correct-case", methods=["POST"])
@require_role("admin", api=True)
def correct_case():
    """Record a correction to a case reference - for one entry, or for
    every entry recorded under one case.

    Writes a new chained entry; nothing already in the log changes. The
    entry names what was corrected, from what to what, and why, so a later
    reader sees the mistake and the correction rather than a tidy log that
    quietly disagrees with the package someone is holding."""
    data = request.get_json() or {}
    scope = data.get("scope")
    new_case = str(data.get("new_case") or "").strip()
    reason = " ".join(str(data.get("reason") or "").split())[:300]
    if not new_case or len(new_case) > CASE_ID_MAX:
        return jsonify({"error": f"a new case reference is required (up to {CASE_ID_MAX} characters)"}), 400
    if any(ch in new_case for ch in ('"', "\n", "\r", "\x00")):
        return jsonify({"error": 'a case reference cannot contain quotes or line breaks'}), 400

    con = sqlite3.connect(AUDIT_DB)
    con.row_factory = sqlite3.Row
    by_entry, by_case = _load_case_corrections(con)
    eff_sql, eff_params = _effective_case_sql(by_entry, by_case)

    if scope == "entry":
        try:
            entry_id = int(data.get("entry_id"))
        except (TypeError, ValueError):
            con.close()
            return jsonify({"error": "entry_id is required"}), 400
        row = con.execute(f"SELECT id, {eff_sql} AS eff FROM export_log WHERE id = ?;",
                          tuple(eff_params) + (entry_id,)).fetchone()
        con.close()
        if row is None:
            return jsonify({"error": "no such entry"}), 404
        old = row["eff"]
        if old == new_case:
            return jsonify({"error": "that entry already reads as that case"}), 400
        detail = f'corrects entry {entry_id}: case "{old}" -> "{new_case}"'
        affected = 1
    elif scope == "case":
        old = str(data.get("case_id") or "")
        rows = con.execute(f"SELECT count(*) AS n FROM export_log WHERE {eff_sql} = ?;",
                           tuple(eff_params) + (old,)).fetchone()
        con.close()
        if not rows["n"]:
            return jsonify({"error": "no entries are recorded under that case"}), 404
        if old == new_case:
            return jsonify({"error": "that case already reads as that name"}), 400
        affected = rows["n"]
        detail = f'corrects case "{old}" -> "{new_case}" ({affected} entr' + ("y" if affected == 1 else "ies") + ")"
    else:
        con.close()
        return jsonify({"error": 'scope must be "case" or "entry"'}), 400

    if reason:
        detail += f"; reason: {reason}"
    # case_id is the CORRECTED name, so the correction sits with the case
    # it puts right rather than with the name that was wrong.
    audit(identify({}), request.remote_addr, {"case_id": new_case}, "case-correction",
          affected, "recorded", detail=detail)
    return jsonify({"ok": True, "corrected": affected, "from": old, "to": new_case})


def _audit_by_case(con, where, where_params, page, offset, eff_sql, eff_params):
    """One page of CASES, each with its own entries (see audit_view's
    `group=case`). Two queries: which cases this page holds, then every
    entry belonging to them - rather than one query per case.

    Grouping is by the CORRECTED case (eff_sql, from _load_case_corrections),
    so a case put right keeps its entries together under the name it was
    corrected to, while each entry still carries the name it was recorded
    under.

    An entry with no case at all (an administrative action: a user added,
    a backup restored) is not a case and is not paged with them: it comes
    back separately as `app_wide`, so the page can give it a section of its
    own that is there on every page rather than on whichever page the
    empty key happened to sort to. The log still accounts for everything -
    it is only filed differently."""
    no_case = f"COALESCE({eff_sql}, '') = ''"
    has_case = f"COALESCE({eff_sql}, '') <> ''"
    # Both of these sit inside the caller's own WHERE, if it has one.
    case_where = (where + f" AND {has_case}") if where else f"WHERE {has_case}"
    case_where_params = where_params + tuple(eff_params)
    app_where = (where + f" AND {no_case}") if where else f"WHERE {no_case}"
    app_where_params = where_params + tuple(eff_params)
    total_cases = con.execute(
        f"SELECT count(*) FROM (SELECT {eff_sql} AS eff FROM export_log {case_where} GROUP BY eff);",
        tuple(eff_params) + case_where_params,
    ).fetchone()[0]
    total_entries = con.execute(
        f"SELECT count(*) FROM export_log {where};", where_params
    ).fetchone()[0]
    case_rows = con.execute(
        f"""SELECT {eff_sql} AS eff_case, count(*) AS entry_count, max(id) AS last_id
            FROM export_log {case_where}
            GROUP BY eff_case
            ORDER BY last_id DESC
            LIMIT ? OFFSET ?;""",
        tuple(eff_params) + case_where_params + (AUDIT_PAGE_SIZE, offset),
    ).fetchall()
    case_ids = [(r["eff_case"] or "") for r in case_rows]
    entries = []
    if case_ids:
        marks = ",".join("?" * len(case_ids))
        and_where = where.replace("WHERE", "AND", 1) if where else ""
        entries = con.execute(
            f"""SELECT *, {eff_sql} AS effective_case_id FROM export_log
                WHERE {eff_sql} IN ({marks}) {and_where}
                ORDER BY id DESC;""",
            tuple(eff_params) + tuple(eff_params) + tuple(case_ids) + where_params,
        ).fetchall()

    # The caseless entries, newest first and capped like a page of a case.
    app_entries = con.execute(
        f"""SELECT *, {eff_sql} AS effective_case_id FROM export_log {app_where}
            ORDER BY id DESC LIMIT ?;""",
        tuple(eff_params) + app_where_params + (AUDIT_PAGE_SIZE,),
    ).fetchall()
    app_total = con.execute(
        f"SELECT count(*) FROM export_log {app_where};", app_where_params
    ).fetchone()[0]
    con.close()

    app_rows = [dict(r) for r in app_entries]
    app_newest = app_rows[0] if app_rows else {}
    app_wide = {
        "entry_count": app_total,
        "last_ts_local": app_newest.get("ts_local"),
        "last_ts_utc": app_newest.get("ts_utc"),
        "last_outcome": app_newest.get("outcome"),
        "entries": app_rows,
    }

    by_case = {}
    for r in entries:
        by_case.setdefault(r["effective_case_id"] or "", []).append(dict(r))
    cases = []
    for c in case_rows:
        cid = c["eff_case"] or ""
        rows = by_case.get(cid, [])
        newest = rows[0] if rows else {}
        cases.append({
            "case_id": cid,
            "entry_count": c["entry_count"],
            "last_ts_local": newest.get("ts_local"),
            "last_ts_utc": newest.get("ts_utc"),
            "last_outcome": newest.get("outcome"),
            "last_kind": newest.get("export_kind"),
            "entries": rows,
        })
    return jsonify({
        "mode": "case",
        "cases": cases,
        "app_wide": app_wide,
        "total": total_entries,
        "total_cases": total_cases,
        "page": page,
        "pages": max(1, -(-total_cases // AUDIT_PAGE_SIZE)),
        "per_page": AUDIT_PAGE_SIZE,
    })


@app.route("/api/audit/download", methods=["POST"])
@require_role("admin", api=True)
def audit_download():
    """The audit log as a CSV - the accountability record's own record.

    `ids`: a list of row ids to include, from the checkboxes on the audit
    page - this is meant for "download the dozen rows relevant to this
    case," which is expected to be the common case, not "download
    everything." An empty list is rejected rather than silently downloading
    the whole table; omitting `ids` entirely (no caller in this app does)
    falls back to the full table, oldest first, for robustness.

    Downloading it is itself logged as an "audit-download" row, carrying the
    case reference and actor the page prompted for - who looked at the
    accountability record, when, and for what case is worth knowing too,
    the same reasoning that put an audit log here in the first place.
    Admin-only, same as the rest of this app's export/audit surface - see
    require_role() above and NOTES.md.
    """
    data = request.get_json() or {}
    case_id = (data.get("case_id") or "").strip()
    actor = identify(data)
    client_ip = request.remote_addr

    ids = None
    raw_ids = data.get("ids")
    if isinstance(raw_ids, list):
        ids = []
        for v in raw_ids:
            try:
                ids.append(int(v))
            except (TypeError, ValueError):
                continue
        if not ids:
            return jsonify({"error": "select at least one record to download"}), 400

    try:
        con = sqlite3.connect(AUDIT_DB)
        con.row_factory = sqlite3.Row
        if ids is not None:
            placeholders = ",".join("?" * len(ids))
            rows = con.execute(
                f"SELECT * FROM export_log WHERE id IN ({placeholders}) ORDER BY id ASC;",
                ids,
            ).fetchall()
        else:
            rows = con.execute("SELECT * FROM export_log ORDER BY id ASC;").fetchall()
        con.close()
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500

    columns = rows[0].keys() if rows else [
        "id", "ts_utc", "ts_local", "actor", "client_ip", "case_id",
        "export_kind", "window_start", "window_end", "north", "south",
        "west", "east", "record_count", "package_sha256", "outcome",
        "detail", "files_excluded", "channels_excluded", "window_timezone",
        "requested_for",
    ]
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(columns)
    # Same formula-injection guard as the evidence package (see
    # exports.neutralize_csv_cell): case_id is typed by the operator, and
    # in authentik mode `actor` comes from a header.
    for r in rows:
        writer.writerow([exports.neutralize_csv_cell(r[c]) for c in columns])
    body = buf.getvalue().encode("utf-8")

    file_hash = hashlib.sha256(body).hexdigest()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"audit-log-{stamp}.csv"

    audit(
        actor, client_ip,
        {"case_id": case_id, "start": None, "end": None,
         "north": None, "south": None, "west": None, "east": None},
        "audit-download", len(rows), "generated", package_hash=file_hash,
        requested_for=requested_for(data),
    )

    return Response(
        body,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Package-SHA256": file_hash,
            "Access-Control-Expose-Headers": "X-Package-SHA256, Content-Disposition",
        },
    )


# ---------------------------------------------------------------------------
# Login / logout (local mode only - see AUTH_MODE, above)
# ---------------------------------------------------------------------------

def _is_locked(locked_until_str):
    if not locked_until_str:
        return False
    try:
        return datetime.now(timezone.utc) < datetime.fromisoformat(locked_until_str)
    except ValueError:
        return False


def _record_failed_login(con, user_id, current_failed_attempts):
    new_count = current_failed_attempts + 1
    if new_count >= FAILED_LOGIN_LIMIT:
        locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        con.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?;",
                    (locked_until, user_id))
    else:
        con.execute("UPDATE users SET failed_attempts = ? WHERE id = ?;", (new_count, user_id))
    con.commit()


def _record_successful_login(con, user_id):
    con.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?;", (user_id,))
    con.commit()


def _auth_log_path():
    """Alongside AUDIT_DB - same reasoning as tls.py's cert-path default:
    whatever already persists AUDIT_DB (Docker's ./data bind mount)
    persists this too, with no extra configuration, and it's a real path
    on the HOST filesystem a fail2ban jail running there can point
    straight at."""
    d = os.path.dirname(os.path.abspath(AUDIT_DB)) or "."
    return os.path.join(d, "auth.log")


def _log_auth_event(outcome, username, ip):
    """One line per login attempt - success, failure, or against an
    already-locked account - in a plain, fail2ban-parseable format (see
    README.md's fail2ban section for a ready-made filter). A plain file,
    not the sqlite audit log: fail2ban (per infra-TAK's own convention,
    already used elsewhere in this ecosystem) tails a real file on the
    host, not a database.

    Logs EVERY attempt, including against usernames that don't exist at
    all - unlike the per-username account lockout above (which has no row
    to update for a made-up username, by design, to avoid a lockout-
    tracking DoS surface there), this is IP-based banning at the network
    layer, so it needs every attempt regardless of whether the username
    was ever real; that's the whole point of pairing the two.

    username is attacker-controlled input written into a line-oriented
    log file - stripped of newlines/control characters first, otherwise a
    crafted username could inject a fake extra log line (log injection),
    confusing both fail2ban's own regex and anyone reading this by hand.

    Best-effort: a logging failure here must never break an actual login,
    so any I/O error is swallowed (and noted to stdout) rather than
    raised."""
    safe_username = "".join(ch if ch.isprintable() else "?" for ch in (username or "-"))
    try:
        with open(_auth_log_path(), "a", encoding="utf-8") as f:
            ts = datetime.now(timezone.utc).isoformat()
            f.write(f"{ts} LOGIN_{outcome} user={safe_username} ip={ip}\n")
    except OSError as e:
        print(f"AUTH LOG FAILURE: {type(e).__name__}: {e}")


def _safe_next_path(raw):
    """Only ever redirect to a same-site relative path after login - never
    wherever an attacker's `next` value points. Without this, a link like
    "/login?next=https://evil.example" shows this app's own genuine login
    page (right domain, right cert) and only sends the victim elsewhere
    AFTER they've actually authenticated - a link that looks completely
    safe to click.

    Rejects anything that isn't a plain path starting with a single "/":
    an absolute URL (scheme and/or netloc, caught via urlparse), and the
    two tricks that turn a path into a scheme-relative absolute URL once a
    browser normalizes it even though it doesn't look like one here - a
    literal leading "//" and a leading "/\\" (some browsers silently
    rewrite a backslash to a forward slash before following it, so
    "/\\evil.example" can become "//evil.example" - scheme-relative to
    evil.example - despite passing a naive "starts with / not //" check)."""
    if not raw or not raw.startswith("/"):
        return url_for("index")
    if raw.startswith("//") or raw.startswith("/\\"):
        return url_for("index")
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        return url_for("index")
    return raw


# For the login timing guard above: a real hash of a random value, made
# once at start-up, so the no-such-user path does the same work as a real
# password check. Never matches anything.
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


@app.route("/login", methods=["GET", "POST"])
def login_page():
    """The only login surface this app has, and only in local mode - in
    authentik mode there's nothing to log into here at all, since the
    reverse proxy/Authentik already gated the request before Flask ever
    saw it."""
    if AUTH_MODE != "local":
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        # Login CSRF: /login has no session yet, so require_role's check
        # never runs here - the form carries its own token instead. Without
        # this, a hostile page could log a victim's browser into an account
        # the ATTACKER controls (the response's Set-Cookie is accepted on a
        # cross-site POST even though SameSite=Lax withholds cookies on the
        # way in), so the victim's later exports get audited under the
        # attacker's name. Nuisance-grade for access, real for the audit
        # trail. The token was seeded into the session when the form was
        # rendered (csrf_token() in login.html), same mechanism as the
        # X-CSRFToken header everywhere else.
        expected = session.get("csrf_token")
        got = request.form.get("csrf_token") or ""
        if not expected or not secrets.compare_digest(expected, got):
            _log_auth_event("FAILED", request.form.get("username") or "", request.remote_addr)
            return render_template("login.html",
                                   error="This sign-in form had expired. Please try again.",
                                   next=_safe_next_path(request.form.get("next")),
                                   theme=get_theme()), 403
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_path = _safe_next_path(request.form.get("next"))
        con = sqlite3.connect(AUDIT_DB)
        row = con.execute(
            "SELECT id, username, password_hash, failed_attempts, locked_until "
            "FROM users WHERE username = ? COLLATE NOCASE;",
            (username,),
        ).fetchone()

        if not row or not row[2]:
            # No such user (or no password set): still run one hash check,
            # against a throwaway hash, so this branch takes as long as a
            # wrong password for a real account does. Otherwise the
            # response time alone says whether a username exists.
            check_password_hash(_DUMMY_PASSWORD_HASH, password)

        if row and _is_locked(row[4]):
            con.close()
            _log_auth_event("FAILED", username, request.remote_addr)
            error = ("This account is temporarily locked after repeated failed sign-in "
                      "attempts. Try again in a few minutes.")
        elif row and row[2] and check_password_hash(row[2], password):
            _record_successful_login(con, row[0])
            con.close()
            _log_auth_event("SUCCESS", username, request.remote_addr)
            session.clear()
            session["username"] = row[1]
            session.permanent = True
            # A viewer's only allowed page is /verify (every other route's
            # require_role() rejects that role outright) - next_path
            # defaults to the Export page for everyone regardless of role,
            # which would otherwise land a viewer straight on a 403 the
            # instant login succeeds. Only overridden for viewer; admin's
            # own next_path (Export, or wherever they were headed) is
            # untouched.
            if lookup_role(row[1]) == "viewer" and not next_path.startswith("/verify"):
                next_path = url_for("verify_page")
            return redirect(next_path)
        else:
            # A nonexistent username never gets a row to update - no
            # lockout-tracking DoS surface against made-up usernames. Logged
            # to auth.log either way, though (see _log_auth_event) - that's
            # IP-based, not username-based, so a made-up username is exactly
            # the case it still needs to catch.
            if row:
                _record_failed_login(con, row[0], row[3])
            con.close()
            _log_auth_event("FAILED", username, request.remote_addr)
            # Generic message - confirming which part was wrong (username
            # vs. password) helps an attacker enumerate valid usernames.
            error = "Invalid username or password."
    else:
        next_path = _safe_next_path(request.args.get("next"))
    return render_template("login.html", error=error, next=next_path, theme=get_theme())


@app.route("/logout", methods=["POST"])
def logout():
    """POST only, with the session's CSRF token: a link on another site
    could otherwise sign a user out (SameSite=Lax already withholds the
    cookie on a cross-site POST; the token is the second lock, the same
    two every other state change here has). The header's "Log out" is a
    small form carrying the token."""
    expected = session.get("csrf_token")
    got = request.form.get("csrf_token") or request.headers.get("X-CSRFToken") or ""
    if expected and not secrets.compare_digest(expected, got):
        return Response("invalid or missing CSRF token", status=403)
    session.clear()
    return redirect(url_for("login_page") if AUTH_MODE == "local" else url_for("index"))


# ---------------------------------------------------------------------------
# Admin API (user manager + TAK Postgres connection settings)
# ---------------------------------------------------------------------------

# Maps each app_settings key to the .env var it falls back to before an
# admin has ever saved anything via the admin page - just field.upper(),
# named explicitly rather than computed so a typo here is a NameError at
# import time, not a silently-wrong env var looked up at request time.
DB_SETTING_ENV_FALLBACK = {
    "db_host": "DB_HOST", "db_port": "DB_PORT", "db_name": "DB_NAME",
    "db_user": "DB_USER", "db_password": "DB_PASSWORD",
}

# Same reasoning as get_connection()'s defaults, above: only for values
# that are genuinely standard across nearly every real TAK Server install.
# No entry for db_host or db_user - see get_connection().
DB_SETTING_DEFAULTS = {"db_port": "5432", "db_name": "cot"}


@app.route("/api/admin/users", methods=["GET", "POST"])
@require_role("admin", api=True)
def admin_users():
    if request.method == "GET":
        con = sqlite3.connect(AUDIT_DB)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """SELECT id, username, role, password_hash IS NOT NULL AS has_password,
                      created_ts_utc, updated_ts_utc
               FROM users ORDER BY username COLLATE NOCASE;"""
        ).fetchall()
        con.close()
        return jsonify([dict(r) for r in rows])

    # POST: add a new user, or update an existing one's role/password
    # (upsert by username) - one form serves both "add" and "edit" on the
    # admin page, same as this codebase's existing preset-button pattern
    # of recomputing state from what's actually there rather than tracking
    # add-vs-edit as a separate mode.
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    role = (data.get("role") or "").strip()
    password = data.get("password") or ""
    if not username:
        return jsonify({"error": "username is required"}), 400
    if role not in VALID_ROLES:
        return jsonify({"error": f"role must be one of {sorted(VALID_ROLES)}"}), 400
    if password and AUTH_MODE != "local":
        return jsonify({"error": "passwords are not used in authentik mode"}), 400
    if password:
        pw_err = validate_password(password)
        if pw_err:
            return jsonify({"error": pw_err}), 400

    con = sqlite3.connect(AUDIT_DB)
    existing = con.execute(
        "SELECT id, role, password_hash FROM users WHERE username = ? COLLATE NOCASE;",
        (username,),
    ).fetchone()
    now = datetime.now(timezone.utc).isoformat()
    # A blank password on an existing user means "leave it as-is," not
    # "clear it" - same reasoning as the settings password field below.
    pw_hash = generate_password_hash(password) if password else (existing[2] if existing else None)
    if existing:
        con.execute(
            "UPDATE users SET role = ?, password_hash = ?, updated_ts_utc = ? WHERE id = ?;",
            (role, pw_hash, now, existing[0]),
        )
        kind = "admin-role-change" if existing[1] != role else "admin-user-add"
        detail = f"{username}: role {existing[1]} -> {role}" if existing[1] != role else f"{username}: updated"
    else:
        con.execute(
            "INSERT INTO users (username, password_hash, role, created_ts_utc) VALUES (?, ?, ?, ?);",
            (username, pw_hash, role, now),
        )
        kind, detail = "admin-user-add", f"{username}: added as {role}"
    con.commit()
    con.close()

    audit(identify({}), request.remote_addr, {}, kind, 0, "ok", detail=detail)
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>/delete", methods=["POST"])
@require_role("admin", api=True)
def admin_delete_user(user_id):
    con = sqlite3.connect(AUDIT_DB)
    row = con.execute("SELECT username, role FROM users WHERE id = ?;", (user_id,)).fetchone()
    if not row:
        con.close()
        return jsonify({"error": "no such user"}), 404
    username, role = row
    # Two safety rails, both blocking rather than a warning-only prompt -
    # consistent with this feature's fail-closed approach throughout:
    # deleting your own account or the last admin would either lock you
    # out immediately or (if BOOTSTRAP_ADMIN_USERNAME isn't set) require
    # direct sqlite access to recover from.
    if username.lower() == g.username.lower():
        con.close()
        return jsonify({"error": "you cannot delete your own account"}), 400
    if role == "admin":
        admin_count = con.execute("SELECT count(*) FROM users WHERE role = 'admin';").fetchone()[0]
        if admin_count <= 1:
            con.close()
            return jsonify({"error": "cannot delete the last remaining admin"}), 400
    con.execute("DELETE FROM users WHERE id = ?;", (user_id,))
    con.commit()
    con.close()
    audit(identify({}), request.remote_addr, {}, "admin-user-delete", 0, "ok",
          detail=f"deleted {username} (was {role})")
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>/reset-password", methods=["POST"])
@require_role("admin", api=True)
def admin_reset_password(user_id):
    if AUTH_MODE != "local":
        return jsonify({"error": "passwords are not used in authentik mode"}), 400
    data = request.get_json() or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"error": "password is required"}), 400
    pw_err = validate_password(password)
    if pw_err:
        return jsonify({"error": pw_err}), 400

    con = sqlite3.connect(AUDIT_DB)
    row = con.execute("SELECT username FROM users WHERE id = ?;", (user_id,)).fetchone()
    if not row:
        con.close()
        return jsonify({"error": "no such user"}), 404
    now = datetime.now(timezone.utc).isoformat()
    con.execute(
        "UPDATE users SET password_hash = ?, updated_ts_utc = ? WHERE id = ?;",
        (generate_password_hash(password), now, user_id),
    )
    con.commit()
    con.close()
    audit(identify({}), request.remote_addr, {}, "admin-password-reset", 0, "ok",
          detail=f"password reset for {row[0]}")
    return jsonify({"ok": True})


@app.route("/api/admin/settings", methods=["GET", "POST"])
@require_role("admin", api=True)
def admin_settings():
    if request.method == "GET":
        return jsonify({
            "db_host": get_setting("db_host", "DB_HOST"),
            "db_port": get_setting("db_port", "DB_PORT", DB_SETTING_DEFAULTS.get("db_port")),
            "db_name": get_setting("db_name", "DB_NAME", DB_SETTING_DEFAULTS.get("db_name")),
            "db_user": get_setting("db_user", "DB_USER"),
            # The password itself is never sent back to the browser - only
            # whether one is currently set, so the admin page can honestly
            # show "leave blank to keep the current password."
            "db_password_set": bool(get_setting("db_password", "DB_PASSWORD")),
            "auth_mode": AUTH_MODE,
        })

    data = request.get_json() or {}
    changed = []
    for field in ("db_host", "db_port", "db_name", "db_user"):
        if data.get(field) is None:
            continue
        value = str(data[field]).strip()
        current = get_setting(field, DB_SETTING_ENV_FALLBACK[field], DB_SETTING_DEFAULTS.get(field))
        if value != (current or ""):
            changed.append(field)
        set_setting(field, value)
    # Password: only overwritten if a non-empty value was submitted -
    # leaving the field blank in the UI must not silently wipe a working
    # credential.
    password = data.get("db_password")
    if password:
        set_setting("db_password", password)
        changed.append("db_password (value not logged)")

    if changed:
        audit(identify({}), request.remote_addr, {}, "admin-settings-change", 0, "ok",
              detail="changed: " + ", ".join(changed))
    return jsonify({"ok": True})


@app.route("/api/theme", methods=["GET", "POST"])
@require_role("admin", "viewer", api=True)
def theme_setting():
    """Each logged-in user's own light/dark preference (see get_theme()) -
    a personal account setting, not a site-wide or per-browser one. Every
    role can set their own; nobody can set anyone else's. Not audited -
    this is cosmetic personal preference, the same category as display
    style or show-names-on-map, not an administrative action affecting
    other people."""
    if request.method == "GET":
        return jsonify({"theme": get_theme()})

    theme = (request.get_json() or {}).get("theme")
    if theme not in VALID_THEMES:
        return jsonify({"error": f"theme must be one of {sorted(VALID_THEMES)}"}), 400
    con = sqlite3.connect(AUDIT_DB)
    con.execute("UPDATE users SET theme = ? WHERE username = ? COLLATE NOCASE;", (theme, g.username))
    con.commit()
    con.close()
    return jsonify({"ok": True})


@app.route("/api/admin/map-settings", methods=["GET", "POST"])
@require_role("admin", api=True)
def map_settings():
    """Whether the maps may contact OpenStreetMap - see map_options().

    Site-wide, not per-account, and admin-only: this decides what leaves
    the network, which is not a personal preference the way the theme is.
    Audited for the same reason - turning the search back on is a change to
    what this install discloses, and the log should hold who did it."""
    if request.method == "GET":
        return jsonify(map_options())

    data = request.get_json() or {}
    before = map_options()

    # Only a real boolean counts. Python truthiness would read a typo or a
    # stray string as ON, which is the direction that turns a disclosure
    # back on - and the audit row would then say an admin asked for that
    # when they did not. Refuse instead of guessing.
    wanted = {}
    for key, field in (("map_search", "search"), ("map_tiles", "tiles")):
        if field not in data:
            continue
        value = data[field]
        if not isinstance(value, bool):
            return jsonify({"error": f"{field} must be true or false, "
                                     f"not {type(value).__name__}"}), 400
        wanted[key] = value
    for key, value in wanted.items():
        set_setting(key, "true" if value else "false")
    after = map_options()
    if after != before:
        changed = ", ".join(
            f"{k} {'on' if after[k] else 'off'}" for k in after if after[k] != before[k])
        audit(identify({}), request.remote_addr, {},
              "admin-map-settings", 0, "ok", detail=f"map: {changed}")
    return jsonify(after)


@app.route("/api/admin/test-connection", methods=["POST"])
@require_role("admin", api=True)
def admin_test_connection():
    """Try connecting with the CANDIDATE values from the admin page's form -
    not necessarily saved yet - falling back to whatever's currently
    persisted for any field left blank, so "test before save" reflects a
    partial edit correctly. Never writes to app_settings either way."""
    data = request.get_json() or {}

    def candidate(field):
        value = data.get(field)
        if value not in (None, ""):
            return str(value)
        return get_setting(field, DB_SETTING_ENV_FALLBACK[field], DB_SETTING_DEFAULTS.get(field))

    # The saved password is never shown to the browser (see admin_settings),
    # and it must not be handed to an arbitrary server either: with the
    # password box left blank and a host of their choosing typed in, this
    # route would otherwise send the stored password to that host. So the
    # stored password is only used to test the connection it was saved
    # for; any other host/port/database/user needs the password typed in.
    saved = {f: (get_setting(f, DB_SETTING_ENV_FALLBACK[f], DB_SETTING_DEFAULTS.get(f)) or "")
             for f in ("db_host", "db_port", "db_name", "db_user")}
    target_changed = any(candidate(f) != saved[f] for f in saved)
    if target_changed and not data.get("db_password"):
        return jsonify({"ok": False, "error": "enter the password to test a connection to a "
                                              "different host, port, database or user - the "
                                              "saved password is only used for the saved connection"})

    try:
        conn = psycopg2.connect(
            host=candidate("db_host"), port=candidate("db_port"),
            dbname=candidate("db_name"), user=candidate("db_user"),
            password=candidate("db_password"), connect_timeout=5,
        )
        # SELECT 1 proves the credentials and the route, and nothing else -
        # it would pass against an empty database, or one whose PostGIS is
        # gone. These three are what "connected" has to mean for a tool that
        # reads positions: the table is there, this account can read it, and
        # the spatial functions every map query needs exist. Each is
        # reported separately, because they fail for different reasons and
        # have different fixes. A candidate connection is tested here too,
        # so none of this may assume the target is the saved one.
        notes, ok = [], True
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            try:
                cur.execute("SELECT count(*) FROM pg_extension "
                            "WHERE extname LIKE 'postgis%';")
                if not cur.fetchone()[0]:
                    ok = False
                    notes.append("PostGIS is not installed on this database - every "
                                 "map-area query depends on it")
            except Exception as e:
                notes.append(f"could not check for PostGIS: {type(e).__name__}: {e}")
            try:
                cur.execute("SELECT to_regclass('public.cot_router') IS NOT NULL, "
                            "has_table_privilege(to_regclass('public.cot_router'), 'SELECT');")
                present, readable = cur.fetchone()
                if not present:
                    ok = False
                    notes.append("there is no cot_router table in this database - "
                                 "check the database name")
                elif not readable:
                    ok = False
                    notes.append("this account cannot SELECT from cot_router - "
                                 "connect-database.sh re-applies the grants")
            except Exception as e:
                notes.append(f"could not check cot_router: {type(e).__name__}: {e}")
        conn.close()
        return jsonify({"ok": ok, "error": "; ".join(notes) if notes and not ok else None,
                        "notes": notes})
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"})


def _parse_github_owner_repo(remote_url):
    """('owner', 'repo') from either URL form `git remote get-url` can
    return - https://github.com/owner/repo.git or git@github.com:owner/
    repo.git (SSH) - or (None, None) if it isn't a GitHub URL at all
    (self-hosted git, a fork elsewhere). Used only to build a browsable
    compare link; never a git remote name/URL this app connects with
    somewhere else."""
    m = re.search(r"github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?/?$", remote_url)
    return (m.group(1), m.group(2)) if m else (None, None)


@app.route("/api/admin/check-updates")
@require_role("admin", api=True)
def check_updates():
    """Compares this checkout's HEAD against its git remote. Read-only -
    runs `git fetch`, never anything that touches the working tree or
    restarts anything, and reports the commands an operator would run
    themselves rather than ever executing them here. Deliberately not a
    one-click "update and restart" button: actually applying an update
    from inside the running app would need either Docker socket access
    (to replace its own container) or loosening tak-extract.service's own
    filesystem sandboxing (ProtectSystem=strict) - a real jump in attack
    surface this check doesn't need to pay for.

    "checked": false (with an "error" string) covers every reason this
    can't answer - no .git directory at all (a release-zip install, not
    a git clone), no network route to the remote, no upstream branch
    configured - none of which are this app's own failures, so they're
    reported as "could not check", not a 500."""
    repo_dir = os.path.dirname(os.path.abspath(__file__))

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=repo_dir, check=True, capture_output=True,
            text=True, timeout=20,
        ).stdout.strip()

    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        return jsonify({"checked": False, "error": "not a git checkout - installed from a release zip?"})

    try:
        git("fetch", "--quiet")
        try:
            upstream = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
        except subprocess.CalledProcessError:
            # No upstream tracking branch configured (unusual for a plain
            # `git clone`, but not impossible) - master is this repo's
            # only real branch, so it's the reasonable assumption rather
            # than failing outright.
            upstream = "origin/master"
        local_commit = git("rev-parse", "HEAD")
        remote_commit = git("rev-parse", upstream)
        behind = int(git("rev-list", "--count", f"HEAD..{upstream}"))
        # Caught while testing this against this actual dev checkout,
        # which has local commits not yet pushed: behind==0 does NOT mean
        # "identical to upstream" - it only means "not missing anything
        # upstream has." A deployed install should never legitimately have
        # local commits of its own (nothing there should ever be hand-
        # edited and committed), but checking for it explicitly, rather
        # than assuming behind==0 implies identical, means this reports
        # that unusual state accurately instead of silently calling it
        # "up to date" when the commits actually differ.
        ahead = int(git("rev-list", "--count", f"{upstream}..HEAD"))
        owner, repo = _parse_github_owner_repo(git("remote", "get-url", "origin"))
        compare_url = (
            f"https://github.com/{owner}/{repo}/compare/{local_commit}...{remote_commit}"
            if owner and repo else None
        )
        return jsonify({
            "checked": True,
            "up_to_date": local_commit == remote_commit,
            "behind_count": behind,
            "ahead_count": ahead,
            "current_commit": local_commit[:8],
            "latest_commit": remote_commit[:8],
            "compare_url": compare_url,
            "in_container": running_in_container(),
            # Where `git pull` has to be run. Bare metal, the install is
            # wherever setup.sh put it (/opt/tak-extract by default), which
            # is almost never the admin's current directory - a bare
            # "git pull" in the update command would run in the wrong place
            # and report success for having done nothing.
            "install_dir": app.root_path,
            # Where the clone sits on the HOST, for a Docker install - the
            # one thing this process genuinely cannot work out, since it
            # only ever sees /app. setup.sh writes it into .env, which
            # docker-compose.yml passes in whole. Absent on an install made
            # before this, or one built by hand; the page then says so
            # rather than printing a command that assumes a directory.
            "host_install_dir": (os.getenv("HOST_INSTALL_DIR") or "").strip(),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"checked": False, "error": "timed out reaching the git remote"})
    except subprocess.CalledProcessError as e:
        return jsonify({"checked": False, "error": (e.stderr or str(e)).strip()})
    except Exception as e:
        return jsonify({"checked": False, "error": f"{type(e).__name__}: {e}"})


def _sqlite_backup_copy(dest_path):
    """A safe (sqlite online backup API, not a raw file copy) copy of the
    live AUDIT_DB to dest_path - no redaction. Shared by the downloadable
    backup (which redacts db_password afterward - see
    build_backup_snapshot()) and the internal, never-downloaded safety
    copy admin_restore() takes of the CURRENT database before replacing it
    with an upload, in case that upload turns out to be bad. A raw file
    copy could catch a concurrent write mid-flight (especially under WAL
    mode, where live data can be split across the main file and a
    separate -wal file) and produce a corrupt/inconsistent copy - sqlite's
    own backup API handles this correctly regardless."""
    src = sqlite3.connect(AUDIT_DB)
    dst = sqlite3.connect(dest_path)
    src.backup(dst)
    dst.close()
    src.close()


def build_backup_snapshot():
    """A safe, consistent snapshot of the whole AUDIT_DB (audit log, users,
    app_settings) - the users table and audit log so this installation's
    accounts/roles and its accountability record both move to a new
    machine intact; app_settings so the TAK DB host/port/name/user move
    too.

    The DB password is the one thing deliberately left out: it's real,
    live credential material, unlike a user's password (already a one-way
    hash) - the new machine supplies its own (via .env or the admin page),
    same as any other first-time setup. Returns a path to a temp file the
    caller must remove.
    """
    fd, tmp_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    _sqlite_backup_copy(tmp_path)
    dst = sqlite3.connect(tmp_path)
    # DELETE alone does NOT remove the bytes: sqlite unlinks the row from
    # the b-tree but leaves the cell sitting in a freed page, and
    # secure_delete is off by default - so `strings backup.sqlite` still
    # handed over the live TAK Postgres password. Verified directly: the
    # password was recoverable from the finished file after the DELETE,
    # and gone only after the VACUUM. All three steps are deliberate -
    # overwrite the value first, then delete the row, then VACUUM to
    # rewrite the database and drop the free pages.
    dst.execute("PRAGMA secure_delete = ON;")
    dst.execute("UPDATE app_settings SET value = '' WHERE key = 'db_password';")
    dst.execute("DELETE FROM app_settings WHERE key = 'db_password';")
    dst.commit()
    dst.execute("VACUUM;")
    dst.close()
    return tmp_path


def _validate_backup_file(path):
    """Best-effort check that an uploaded file actually looks like one of
    this app's own backups before it's ever allowed to touch the live
    database - a real sqlite file, with the tables this app expects.
    Table-existence only, not column-by-column: any newer column a backup
    predates (e.g. the lockout columns added after some installs already
    existed) gets backfilled by the same idempotent migrations
    (init_audit()/init_users_and_settings()) that already run at import
    time - admin_restore() re-runs them right after swapping the file in,
    so this check doesn't need to duplicate that. Returns an error string,
    or None if it looks OK."""
    # con.close() lives in `finally`, not right after the query - on a
    # genuinely invalid file the query raises before ever reaching a
    # close() placed after it, leaving the connection (and its file
    # handle) open. Harmless on Linux, but on Windows an unclosed handle
    # blocks the caller's very next os.remove() on this same path with a
    # PermissionError - caught by tests/test_auth.py, not just theoretical.
    con = None
    try:
        con = sqlite3.connect(path)
        tables = {row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table';"
        ).fetchall()}
    except sqlite3.DatabaseError as e:
        return f"not a valid sqlite database: {e}"
    finally:
        if con is not None:
            con.close()
    required = {"users", "app_settings", "export_log"}
    missing = required - tables
    if missing:
        return (f"missing expected table(s): {', '.join(sorted(missing))} - "
                f"this doesn't look like a TAK-Extract backup")
    return None


@app.route("/api/admin/backup")
@require_role("admin", api=True)
def admin_backup():
    """Download a full backup (audit log + users + non-secret settings -
    see build_backup_snapshot()) as a single sqlite file. See
    admin_restore() to bring one back in through the admin page itself -
    or, without using this app at all, stop it, put the file wherever
    AUDIT_DB points (Docker: the ./data volume), and start it back up;
    init_audit()/init_users_and_settings() are idempotent (CREATE TABLE IF
    NOT EXISTS / ADD COLUMN) and only ever add to what's already there,
    so that works too."""
    tmp_path = build_backup_snapshot()
    try:
        with open(tmp_path, "rb") as f:
            data = f.read()
    finally:
        os.remove(tmp_path)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"tak-extract-backup-{stamp}.sqlite"
    audit(identify({}), request.remote_addr, {}, "admin-backup-download", 0, "ok",
          detail=f"backup downloaded: {filename}")

    return Response(
        data,
        mimetype="application/x-sqlite3",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/admin/restore", methods=["POST"])
@require_role("admin", api=True)
def admin_restore():
    """Replace the live database with an uploaded backup (see
    admin_backup()/build_backup_snapshot() for what one contains).

    Order of operations matters here: validate the upload BEFORE it ever
    touches the live database, take a safety copy of what's currently
    live BEFORE replacing it, and roll back to that safety copy if
    anything past that point fails - a bad or incompatible upload should
    never leave this installation with no working database at all.
    """
    uploaded = request.files.get("backup")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "no file uploaded"}), 400

    fd, tmp_upload_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    uploaded.save(tmp_upload_path)

    err = _validate_backup_file(tmp_upload_path)
    if err:
        os.remove(tmp_upload_path)
        return jsonify({"error": err}), 400

    # Unredacted, internal-only, never sent anywhere - purely so a bad
    # upload can be undone. Removed once the restore below succeeds.
    fd, safety_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    _sqlite_backup_copy(safety_path)

    try:
        os.replace(tmp_upload_path, AUDIT_DB)
        # Backfill any table/column an older-schema upload predates - the
        # same idempotent migrations that already run at import time,
        # just re-run now against the newly-restored file.
        init_audit()
        init_users_and_settings()
    except Exception as e:
        # tmp_upload_path may or may not still exist as a separate file
        # depending on exactly where this failed (before or after the
        # os.replace() that turns it INTO AUDIT_DB) - clean it up either
        # way, without letting that get in the way of the rollback itself.
        if os.path.exists(tmp_upload_path):
            os.remove(tmp_upload_path)
        os.replace(safety_path, AUDIT_DB)
        return jsonify({
            "error": f"restore failed and was rolled back: {type(e).__name__}: {e}"
        }), 500

    audit(identify({}), request.remote_addr, {}, "admin-restore", 0, "ok",
          detail=f"restored from uploaded backup: {detail_safe(uploaded.filename)}")
    os.remove(safety_path)
    return jsonify({"ok": True})


if __name__ == "__main__":
    # Local dev only (`python app.py`). This whole block is never reached
    # under gunicorn (`gunicorn app:app`), which is the only thing that
    # should ever run this app with real users on the network.
    # init_audit() already ran above at import time either way.
    #
    # The debugger is OPT-IN. Werkzeug's debug mode serves an interactive
    # console on any traceback - useful while developing, and an obvious
    # thing to find pointed at a network. It used to be on unconditionally
    # here, which was safe enough in practice (neither install shape runs
    # this file) but wrong as the first thing somebody meets after cloning
    # the repo and typing the obvious command. Set FLASK_DEBUG=1 to get it.
    _debug = os.getenv("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes")
    if _debug:
        print("FLASK_DEBUG is set: the interactive debugger is ON. Never use "
              "this with real data or on a shared network.", flush=True)
    if SERVE_TLS:
        # Same cert-path derivation as gunicorn.conf.py, for the rare case
        # of testing SERVE_TLS against the dev server rather than
        # gunicorn - kept alongside AUDIT_DB so both paths land on the
        # same cert if pointed at the same AUDIT_DB.
        _tls_dir = os.path.dirname(os.path.abspath(AUDIT_DB)) or "."
        _cert = os.getenv("TLS_CERT_FILE") or os.path.join(_tls_dir, "tls_cert.pem")
        _key = os.getenv("TLS_KEY_FILE") or os.path.join(_tls_dir, "tls_key.pem")
        ensure_self_signed_cert(_cert, _key, detect_local_ip())
        app.run(debug=_debug, port=int(LISTEN_PORT), host="0.0.0.0",
                ssl_context=(_cert, _key))
    else:
        app.run(debug=_debug, port=int(LISTEN_PORT))