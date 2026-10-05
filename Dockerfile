# Runs as a container's own internal process, same role gunicorn already
# plays on a bare-metal install (see NOTES.md's deployment section) -
# nothing about the app changes for Docker, only how it's started and
# what's allowed to reach it.
FROM python:3.12-slim

WORKDIR /app

# openssl: needed only if SERVE_TLS=true (see tls.py/gunicorn.conf.py) to
# generate a self-signed cert - harmless and unused otherwise. Not
# guaranteed present on Debian's own "slim" base image (the shared TLS
# library is, but the standalone CLI binary is a separate package), so
# installed explicitly rather than assumed. git: needed for the System
# page's "Check for updates" (see /api/admin/check-updates in app.py),
# which shells out to `git fetch`/`git rev-list` against the .git
# directory this image now deliberately includes (see the note further
# down, right before it's copied in) - also not present on the slim
# base by default.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl git \
    && rm -rf /var/lib/apt/lists/*

# requirements.txt is shared with local Windows dev (plain
# `pip install -r requirements.txt`) - gunicorn is installed as a separate
# step, here only, so it never has to go in that shared file. gunicorn
# doesn't run on Windows at all (relies on Unix fcntl/os.fork) - see
# NOTES.md's requirements.txt section.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn==23.0.0

# .git is deliberately NOT excluded here (see .dockerignore) - the
# "Check for updates" feature needs it to compare this build's own
# commit against its GitHub remote, and cannot work without it.
# Shipping the repository history inside the image is therefore a
# deliberate choice here, not an oversight.
COPY . .

# Non-root - a compromised app process shouldn't run as root inside its
# own container either. /app/data is where the persistent sqlite file
# (users, roles, connection settings, the audit log) lives - see
# docker-compose.yml's volume mount; owned by this user so it can
# actually write there.
RUN useradd --create-home --uid 1000 takextract \
    && mkdir -p /app/data \
    && chown -R takextract:takextract /app
USER takextract

# Documentation only - does not itself affect what's reachable. What
# actually is comes from gunicorn.conf.py's own bind decision (always
# 0.0.0.0 from inside a container - real host-level exposure is
# docker-compose.yml's port mapping to decide, not this) plus whatever
# port PORT resolves to (8080 if unset).
EXPOSE 8080

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
