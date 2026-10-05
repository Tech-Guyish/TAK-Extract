"""Gunicorn configuration - shared by Docker (Dockerfile's CMD) and
bare-metal (tak-extract.service, README.md's Quick Start (bare metal)), so
the bind address and TLS cert paths are computed here once, from the
same env vars app.py itself reads (PORT, SERVE_TLS), instead of being
duplicated as literal command-line flags across three files that could
drift out of sync with each other.
"""
import os

from dotenv import load_dotenv

from tls import detect_local_ip, ensure_self_signed_cert, running_in_container

# Gunicorn evaluates THIS file before it imports app:app, so app.py's own
# load_dotenv() (which runs at import time) is far too late to affect the
# bind address, TLS settings or timeout decided below. Without this call,
# the documented bare-metal command - `gunicorn -c gunicorn.conf.py
# app:app`, see README's Quick Start (bare metal) - silently ignores
# everything in .env: it would bind 127.0.0.1:8080 plain HTTP while the
# app, once imported, reads SERVE_TLS=true and redirects every request to
# an https:// port gunicorn never opened.
#
# A no-op under Docker (env_file:) and systemd (EnvironmentFile=), which
# both put these in the real environment already - load_dotenv() does not
# override variables that are already set.
# Same guard as app.py's: unreadable is not an error, because the caller
# that cannot read it is the one that already has these in its environment.
try:
    load_dotenv()
except (PermissionError, OSError):
    pass

_serve_tls = os.getenv("SERVE_TLS", "false").strip().lower() in ("true", "1", "yes")
_in_container = running_in_container()

# Inside a container, the port gunicorn itself binds is a fixed internal
# implementation detail (8080, matching the Dockerfile's EXPOSE and
# docker-compose.yml's own hardcoded container-side port) - NOT the same
# thing as PORT, which there only chooses the HOST-side port Docker maps
# to it. Using PORT for gunicorn's own bind here too would silently break
# connectivity the moment someone sets a non-default PORT: docker-
# compose.yml's mapping would still point at container port 8080, but
# nothing would be listening there anymore. Outside a container (bare
# metal), there's no such translation layer - PORT IS the real bind port.
_bind_port = "8080" if _in_container else (os.getenv("PORT") or "8080")

# Loopback-only - today's default, a reverse proxy is expected to provide
# any real network exposure and its own TLS - UNLESS either of two things
# is true:
#   - Running inside a container: 0.0.0.0 here is just the container's OWN
#     internal interface, not a host-network exposure decision at all -
#     docker-compose.yml's port mapping is what actually controls that,
#     completely independently of this.
#   - SERVE_TLS is on: direct exposure (no proxy in front) is the whole
#     point of that mode, so binding loopback-only there would defeat it.
bind = f"0.0.0.0:{_bind_port}" if (_in_container or _serve_tls) else f"127.0.0.1:{_bind_port}"
workers = 2

# gunicorn's own default (30s) is tuned for typical request/response work,
# not this app's actual workload - building a KMZ or a full evidence
# package means querying potentially large amounts of position data,
# writing several files, and hashing/zipping them, which can genuinely
# take longer than 30 seconds against a real production TAK Server.
# Past this timeout gunicorn kills the worker mid-request and the
# connection just drops - a browser reports that as a generic "Failed to
# fetch", not a clear error, which is exactly what happened on a real
# install (confirmed via "[CRITICAL] WORKER TIMEOUT" in gunicorn's own
# log, not guessed). Configurable since how long is actually "long enough"
# depends on real data volume, which varies a lot by deployment.
# `or 300`, not a getenv default: .env.example teaches "leave it blank
# for the default" for DB_HOST/SECRET_KEY/TLS_CERT_FILE etc, so a blank
# GUNICORN_TIMEOUT= is a natural thing to write - and int("") is a
# ValueError out of gunicorn's config loader, before the app exists to
# report it.
timeout = int(os.getenv("GUNICORN_TIMEOUT") or 300)

if _serve_tls:
    # Same directory AUDIT_DB already lives in, so the cert rides along on
    # whatever persistent volume/path already holds the audit database -
    # no separate volume mount or path to configure for it under Docker.
    _default_dir = os.path.dirname(os.path.abspath(os.getenv("AUDIT_DB", "audit.sqlite"))) or "."
    certfile = os.getenv("TLS_CERT_FILE") or os.path.join(_default_dir, "tls_cert.pem")
    keyfile = os.getenv("TLS_KEY_FILE") or os.path.join(_default_dir, "tls_key.pem")
    # The name the certificate is issued for. Bare metal: this host's own
    # LAN address, detected directly. Inside a container that detection
    # returns the container's private bridge IP (172.x) - a name nobody
    # will ever type, so the browser reports a NAME MISMATCH on top of the
    # expected self-signed warning. setup.sh runs on the host and writes
    # the real address into TLS_CERT_HOST; if that's unset in a container,
    # fall back to 127.0.0.1 (which the SAN always includes anyway) rather
    # than baking in an address that's wrong by construction.
    _cert_host = os.getenv("TLS_CERT_HOST") or ("127.0.0.1" if _in_container else detect_local_ip())
    ensure_self_signed_cert(certfile, keyfile, _cert_host)
