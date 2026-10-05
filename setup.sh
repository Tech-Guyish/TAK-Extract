#!/usr/bin/env bash
# One-shot setup, for either install path - runs the same steps README.md
# otherwise has someone copy-paste by hand.
#
#   Docker        - the app in a container, talking to TAK Server's Postgres
#                   across the Docker bridge. What takserver runs.
#   Side-by-side  - the app installed straight onto the TAK Server's own
#                   machine, no Docker: a venv under /opt/tak-extract run by
#                   gunicorn under systemd, talking to Postgres over
#                   loopback. Everything else about the app is identical.
#
# The path is asked once and recorded as INSTALL_MODE in .env, so nothing -
# this script, connect-database.sh, or a later re-run - has to ask twice.
# Safe to re-run either way: skips anything already done instead of
# redoing/overwriting it (an existing .env is left untouched, ownership is
# only fixed if it is wrong). Run from the repo root: ./setup.sh
# -E (errtrace) matters as much as -e here: without it, bash does NOT run
# the ERR trap below for a failure inside a FUNCTION, so set_env_var /
# get_env_var - the most failure-prone things in this script, since they
# do file I/O on .env - would die completely silently. That's the exact
# "output just stopped dead, no error" symptom the trap was added to
# prevent, with a hole in the one place it's needed most (e.g. .env left
# root-owned by an earlier `sudo ./setup.sh`).
set -Eeuo pipefail
cd "$(dirname "$0")"

# Highlight color for the values an installer scans for (the reachable
# host/URL). Terminal-only, NO_COLOR-respecting - same as connect-database.sh.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then HL=$'\033[1;36m'; HL_OFF=$'\033[0m'; else HL=''; HL_OFF=''; fi

# Safety net for anything below that fails in a way nothing here
# specifically anticipated: `set -e` aborts silently otherwise, on
# whatever line happens to fail, with no indication why - exactly what
# happened twice on real installs before this existed (each time needing
# careful manual reasoning through the script to even find where it died).
# This won't replace a specific, better error message where one exists
# below, but it means an unanticipated failure is never completely silent.
# The temp file set_env_var writes is moved into place on success; a
# failure part-way leaves it behind holding the same values. Cleared here
# rather than left as litter beside the real .env.
cleanup_tmp() { [ -f .env.tmp ] && rm -f .env.tmp; return 0; }
trap 'cleanup_tmp; echo; echo "==> setup.sh failed at line $LINENO. Re-run as bash -x setup.sh for a full trace of what ran right before this." >&2' ERR
trap cleanup_tmp EXIT

# Replaces one KEY=... line in .env in place (preserving every comment and
# every other line) - used below for SECRET_KEY, PORT, INSTALL_MODE, and
# SERVE_TLS/BIND_ADDR if the direct-access question is answered yes.
# Portable across GNU and BSD awk, unlike sed -i's incompatible in-place
# flag on each.
#
# Appends when the key is not there at all, which is not a nicety: an .env
# created by an older version of this script has no INSTALL_MODE line, and
# a replace-only version would write nothing, report nothing, and ask which
# install path this is on every single re-run. connect-database.sh's own
# copy of this function has always appended - this one had not.
set_env_var() {
    if grep -qE "^$1=" .env 2>/dev/null; then
        awk -v line="$1=$2" -v pattern="^$1=" \
            '{ if ($0 ~ pattern) print line; else print $0 }' .env > .env.tmp \
            && chmod 600 .env.tmp && mv -f .env.tmp .env
    else
        printf '%s=%s\n' "$1" "$2" >> .env
    fi
}

# Reads one KEY=value out of .env (last match wins, like the app itself
# reading it) - "$2" is the default if the key is blank/missing. Used below
# to read PORT before deciding whether it needs to change.
get_env_var() {
    local val
    val="$(grep -E "^$1=" .env 2>/dev/null | tail -n1 | cut -d= -f2-)" || val=""
    if [ -n "$val" ]; then echo "$val"; else echo "$2"; fi
}

# Which install path. Asked once; after that .env carries the answer and
# this states it rather than asking again - the same look-before-asking
# rule the rest of this script and connect-database.sh follow. The default
# offered depends on what is actually on the host: Docker if the daemon
# answers, side-by-side if it does not, because being told "install Docker
# first" on a machine that is never going to run it is the wrong advice.
install_mode="$(get_env_var INSTALL_MODE "")"
if [ "$install_mode" = docker ] || [ "$install_mode" = baremetal ]; then
    if [ "$install_mode" = docker ]; then
        echo "==> .env says this is a Docker install - keeping that."
    else
        echo "==> .env says this is a side-by-side install - keeping that."
    fi
else
    if docker compose version >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        default_mode=docker
    else
        default_mode=baremetal
    fi
    echo "==> How should TAK-Extract be installed?"
    echo
    echo "      1) Docker        - in a container. Needs Docker Engine with the"
    echo "                         Compose v2 plugin."
    echo "      2) Side-by-side  - straight onto this machine, no Docker: a venv"
    echo "                         under /opt/tak-extract, run by gunicorn under"
    echo "                         systemd. Needs Python 3.10+ and systemd."
    echo
    if [ "$default_mode" = docker ]; then
        echo "    Docker answers on this host, so that is the default."
    else
        echo "    No working Docker was found on this host, so side-by-side is the"
        echo "    default. Choose 1 instead if you would rather install Docker first."
    fi
    printf '%s' "Which? [1/2, default $( [ "$default_mode" = docker ] && echo 1 || echo 2 )] "
    read -r mode_answer || mode_answer=""
    case "$mode_answer" in
        1|[Dd]*) install_mode=docker ;;
        2|[Ss]*|[Bb]*) install_mode=baremetal ;;
        *) install_mode="$default_mode" ;;
    esac
    if [ "$install_mode" = docker ]; then
        echo "    Installing with Docker."
    else
        echo "    Installing side-by-side, without Docker."
    fi
fi

# Where a side-by-side install lives, and the account that runs it. Both are
# what tak-extract.service already assumes; INSTALL_DIR is here for anyone
# who needs it somewhere else, not because it is expected to change.
install_dir="${INSTALL_DIR:-/opt/tak-extract}"
svc_user=takextract

if [ "$install_mode" = docker ]; then
    echo "==> Checking for Docker Compose v2 (docker compose, not docker-compose)..."
    if ! compose_version_err="$(docker compose version 2>&1 >/dev/null)"; then
        echo "docker compose (v2) not found. See README.md's Prerequisites section"
        echo "for how to install Docker Engine with the Compose v2 plugin."
        echo "  - Ubuntu: NOT 'apt install docker.io docker-compose' (that's the old"
        echo "    v1). Use Docker's own apt repo - see docs.docker.com/engine/install."
        echo "  - Rocky/RHEL: the default here is podman, which this installer does"
        echo "    NOT use. Install Docker Engine + docker-compose-plugin from Docker's"
        echo "    dnf repo (docs.docker.com/engine/install/rhel or .../centos)."
        if [ -n "$compose_version_err" ]; then
            echo "(docker's own error, in case that's not it: $compose_version_err)"
        fi
        exit 1
    fi

    # "v2 exists" isn't enough: `docker compose up --wait --wait-timeout` below
    # needs 2.20+ (--wait itself arrived in 2.17). Some distro packages still
    # ship 2.6-2.12, and on those the failure is `unknown flag: --wait` at the
    # very end of this script, after the image has already been built - and
    # the message above talks only about v1 vs v2, so someone on a too-old v2
    # would read it and conclude it doesn't apply to them.
    compose_ver="$(docker compose version --short 2>/dev/null | sed 's/^v//')" || compose_ver=""
    compose_major="${compose_ver%%.*}"
    compose_rest="${compose_ver#*.}"
    compose_minor="${compose_rest%%.*}"
    if [ -n "$compose_ver" ] && { [ "${compose_major:-0}" -lt 2 ] 2>/dev/null || { [ "${compose_major:-0}" -eq 2 ] && [ "${compose_minor:-0}" -lt 20 ]; } 2>/dev/null; }; then
        echo "Docker Compose $compose_ver is too old - this installer needs 2.20 or newer"
        echo "(for 'docker compose up --wait'). Upgrade the docker-compose-plugin:"
        echo "  - Ubuntu:      sudo apt-get install --only-upgrade docker-compose-plugin"
        echo "  - Rocky/RHEL:  sudo dnf upgrade docker-compose-plugin"
        echo "or see README.md's Prerequisites for installing from Docker's own repository."
        exit 1
    fi
    echo "    Docker Compose ${compose_ver:-(version unknown)} - OK."

    # `docker compose version` above only reports the installed CLI's own
    # version - it never actually talks to the daemon, so it passes even when
    # this user can't reach it. `docker info` does require daemon access, so it
    # catches the same "permission denied ... docker.sock" failure `docker
    # compose up` would otherwise hit later, but with an explanation instead of
    # just a raw socket error. Most common cause: this user was never added to
    # the 'docker' group (every `docker`/`docker compose` command up to now
    # would have needed `sudo` instead) - but the real error is shown too, in
    # case that guess is wrong (dockerd not actually running, say).
    echo "==> Checking that $(whoami) can actually reach the Docker daemon..."
    if ! docker_info_err="$(docker info 2>&1 >/dev/null)"; then
        echo "    Can't reach the Docker daemon as $(whoami) - most likely this user isn't"
        echo "    in the 'docker' group yet. Fix with:"
        echo "      sudo usermod -aG docker \$USER"
        echo "      newgrp docker"
        echo "    (newgrp activates the group in this shell immediately - no need to log"
        echo "    out. Then re-run ./setup.sh.)"
        if [ -n "$docker_info_err" ]; then
            echo "    (docker's own error, in case that's not it: $docker_info_err)"
        fi
        exit 1
    fi
else
    # The side-by-side path's prerequisites, checked HERE for the same reason
    # the Docker ones are: before anything is written or asked. They used to
    # sit further down, next to the work that needs them, and a real install
    # on Ubuntu 22.04 got all the way through creating .env, choosing a port,
    # setting a bootstrap username, generating a SECRET_KEY and answering the
    # TLS question before being told there is no usable Python - leaving a
    # half-configured .env behind from a run that could never have finished.
    echo "==> Looking for Python 3.10 or newer..."
    # Newest first, so the best interpreter present always wins: on Ubuntu
    # 24.04 this finds 3.12 without being told, and on a 22.04 box that
    # later gains a newer Python it switches to it by itself. Bare python3
    # stays last as the fallback. 3.10 is the floor because that is 22.04's
    # stock version - see the comment on app.py's own check.
    py=""
    for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" >/dev/null 2>&1 \
           && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
            py="$(command -v "$candidate")"
            break
        fi
    done
    if [ -z "$py" ]; then
        echo "    No Python 3.10 or newer on this host. TAK-Extract will not start"
        echo "    without one - app.py checks this before anything else and exits."
        echo "      - Ubuntu 22.04+:  python3 is already 3.10 or newer"
        echo "      - Rocky/RHEL 9:   sudo dnf install python3.12"
        echo
        echo "    If that cannot be changed, the Docker install needs no Python on"
        echo "    the host at all - its image carries its own. Re-run and choose 1."
        echo
        echo "    Nothing has been written yet - this stopped before touching .env."
        exit 1
    fi
    echo "    Using $py ($("$py" --version 2>&1))."

    # Having the interpreter is not the same as being able to build a venv.
    # Debian and Ubuntu split ensurepip into a separate package, so a stock
    # 22.04 has python3.10 but NOT python3.10-venv - and `python3 -m venv`
    # fails with "ensurepip is not available". Checked here rather than
    # discovered at the venv step further down, where it reads as a broken
    # installer rather than a missing package. Found on a real 22.04 host.
    echo "==> Checking that $(basename "$py") can build a virtual environment..."
    venv_probe="$(mktemp -d)"
    if "$py" -m venv "$venv_probe/probe" >/dev/null 2>&1; then
        echo "    Yes."
        rm -rf "$venv_probe"
    else
        # `|| true` is load-bearing: this pipeline FAILS by definition - that
        # is why we are in this branch - and under `set -Eeuo pipefail` the
        # failure propagates out of the command substitution. `set -e` is not
        # suspended inside an `if` BODY (only in its condition), so without
        # this the ERR trap fires here and the operator sees "failed at line
        # N" instead of the guidance below, which is the entire point of the
        # branch. Caught in the pre-push security review.
        venv_err="$("$py" -m venv "$venv_probe/probe" 2>&1 | tail -n 3 || true)"
        rm -rf "$venv_probe"
        echo "    No - the interpreter is there but its venv support is not."
        echo "    Debian and Ubuntu ship that separately:"
        echo "      - Ubuntu/Debian:  sudo apt-get install python3-venv"
        echo "                        (or python$("$py" -c 'import sys; print("%d.%d" % sys.version_info[:2])')-venv)"
        echo "      - Rocky/RHEL:     already included, nothing to install"
        echo
        echo "    Python's own error:"
        printf '%s\n' "$venv_err" | sed 's/^/      /'
        echo
        echo "    Nothing has been written yet - this stopped before touching .env."
        exit 1
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        echo "    systemd (systemctl) not found. This path installs a systemd service;"
        echo "    without it, follow README.md's manual gunicorn instructions instead."
        exit 1
    fi
fi

env_created=false
if [ ! -f .env ]; then
    cp .env.example .env
    # SECRET_KEY and DB_PASSWORD end up in here - readable by the owner only,
    # and the owner is the administrator who ran this (under sudo the copy
    # would otherwise be root's, and their later connect-database.sh and
    # docker compose runs could not read it).
    if [ -n "${SUDO_USER:-}" ]; then chown "$SUDO_USER" .env; fi
    chmod 600 .env
    echo "==> Created .env from .env.example."
    env_created=true
else
    echo "==> .env already exists, leaving it as-is."
fi

# So connect-database.sh knows which shape this install is - a Docker install
# needs a bridge subnet opened to Postgres, a side-by-side one connects over
# loopback and needs none of that - and so a re-run of this script does not
# ask again.
if [ "$(get_env_var INSTALL_MODE "")" != "$install_mode" ]; then
    set_env_var INSTALL_MODE "$install_mode"
fi


# Runs every time, not just on a fresh .env - a port that was free before
# can be taken by the time this re-runs. Docker's own failure here
# ("address already in use") gives no hint WHY, and only shows up after a
# full image build - this catches it first, with an actual explanation, and
# fixes it automatically rather than sending the installer to go figure out
# lsof/ss themselves. Most common real cause on a box that also runs TAK
# Server: its own Marti API defaults to this same port (8080).
echo "==> Checking that PORT isn't already taken on this host..."
port="$(get_env_var PORT 8080)"
# Not just "is a container from this project running at all" - it has to
# genuinely be bound to the SAME port .env currently asks for. Without
# that match, someone who manually changed PORT since the last run (to
# move off a real conflict, say) while the old container was still up on
# the OLD port would wrongly skip the check for the NEW one too.
#
# `docker compose port` exits non-zero when there's no running container
# for the service (the common case: nothing yet on a fresh install, or
# right after `docker compose down`) - under this script's own
# `set -euo pipefail`, that failure would otherwise silently kill the
# whole script right here with no error message at all (found on a real
# install: output just stopped dead after the line above, nothing after
# it). `|| true` tells the shell this particular failure is expected and
# fine - running_port just comes back empty, handled the same as "not
# found" below either way.
running_port=""
if [ "$install_mode" = docker ]; then
    running_port="$(docker compose port web 8080 2>/dev/null | sed -E 's/.*:([0-9]+)$/\1/')" || true
fi
if [ -n "$running_port" ] && [ "$running_port" = "$port" ]; then
    # This project's OWN container is what's currently on that port, not
    # something else - `docker compose up` below replaces it in place
    # (stops the old one, starts the new one), so the port genuinely isn't
    # a conflict. Without this check, every single re-run would otherwise
    # see its own not-yet-replaced container as "busy" and bump PORT again
    # - found on a real install where this had crept 8080 -> 8081 -> 8082
    # over three re-runs with nothing else ever actually involved.
    echo "    This project's own container is already running on port $port - it'll"
    echo "    be replaced in place by the build below, so that doesn't count as a"
    echo "    conflict."
elif command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":${port}\$"; then
        echo "    Port $port is already in use on this host (likely TAK Server's own"
        echo "    Marti API, if it's on this same machine)."
        new_port=""
        for candidate in $(seq $((port + 1)) $((port + 20))); do
            if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":${candidate}\$"; then
                new_port="$candidate"
                break
            fi
        done
        if [ -z "$new_port" ]; then
            echo "    Couldn't find a free port nearby either - set PORT in .env by hand"
            echo "    to something free and re-run."
            exit 1
        fi
        set_env_var PORT "$new_port"
        port="$new_port"
        echo "    Using PORT=$port instead. Change it in .env yourself first if you'd"
        echo "    rather pick a specific port."
    else
        echo "    Port $port is free."
    fi
else
    echo "    ('ss' not found on this host - skipping. If the build below fails with"
    echo "    'address already in use', set PORT in .env to something else and re-run.)"
fi

# Also checked every run, not just on a fresh .env, for the same reason as
# PORT above: an .env created before this check existed would otherwise
# stay silently broken forever, even after pulling the fix - unlike
# DB_HOST/DB_USER, a blank BOOTSTRAP_ADMIN_USERNAME isn't a safe "configure
# it later" gap. app.py's bootstrap_admin() returns immediately if it's
# unset, before creating any admin account or printing anything at all -
# no banner, no way to log in, ever. Harmless to keep checking after a
# real admin exists too - bootstrap_admin() only acts on this when the
# users table has zero admins, so this has no effect past that point.
#
# What counts as a SAFE default depends entirely on AUTH_MODE. In local
# mode "admin" is a fine placeholder - it's paired with a generated
# password on THIS app's own login page, renameable later from the System
# page. In authentik mode there is no local login page at all (see
# app.py's login_page()) - the only way anyone becomes the first admin is
# by passing the Authentik challenge AS this exact username, so silently
# defaulting to "admin" there would lock everyone out with no error at
# all: the app comes up fine, nobody can ever sign in as an admin. Also
# checked (not just blank) against the literal value "admin" specifically
# - the same default THIS script would have written on an earlier run
# while still in local mode, before AUTH_MODE was switched to authentik -
# so switching modes later doesn't leave that stale value silently
# uncaught.
auth_mode="$(get_env_var AUTH_MODE local)"
bootstrap_user="$(get_env_var BOOTSTRAP_ADMIN_USERNAME "")"

if [ "$auth_mode" = "authentik" ] && { [ -z "$bootstrap_user" ] || [ "$bootstrap_user" = "admin" ]; }; then
    echo
    echo "    AUTH_MODE=authentik - BOOTSTRAP_ADMIN_USERNAME must be a real username"
    echo "    that actually exists in Authentik. This app has no login page of its own"
    echo "    in this mode - the only way anyone becomes the first admin is by passing"
    echo "    the Authentik challenge AS this exact username. 'admin' is almost never a"
    echo "    real Authentik identity, so leaving it at that (the safe default for"
    echo "    local mode, not this one) would silently lock everyone out - the app"
    echo "    comes up fine, nobody can ever sign in as an admin."
    printf '%s' "    Authentik username to promote to admin [$bootstrap_user]: "
    read -r authentik_admin || authentik_admin=""
    if [ -n "$authentik_admin" ]; then
        set_env_var BOOTSTRAP_ADMIN_USERNAME "$authentik_admin"
        echo "    Set BOOTSTRAP_ADMIN_USERNAME=$authentik_admin."
    elif [ -z "$bootstrap_user" ]; then
        echo "    Left blank - no admin account will be created yet. Set"
        echo "    BOOTSTRAP_ADMIN_USERNAME in .env by hand once you know the right"
        echo "    Authentik username, then restart (docker compose up -d)."
    else
        echo "    Keeping BOOTSTRAP_ADMIN_USERNAME=admin - only fine if that's genuinely"
        echo "    a real Authentik username in your setup."
    fi
elif [ -z "$bootstrap_user" ]; then
    set_env_var BOOTSTRAP_ADMIN_USERNAME admin
    echo "    BOOTSTRAP_ADMIN_USERNAME was blank - set to 'admin'. Rename it from the"
    echo "    System page after logging in, if you'd like something else."
fi

# SECRET_KEY is the only value app.py refuses to start without (it signs
# the login session cookie) - generate one so the container comes up on the
# first try instead of crash-looping until someone edits it by hand.
# AUTH_MODE already defaults to 'local' in .env.example. DB_HOST/DB_USER/
# DB_PASSWORD are deliberately left blank - there's no safe default for a
# database credential, and the app already tolerates that: it comes up
# fine, an admin just configures the TAK Server connection from the System
# page after logging in.
#
# Checked on the VALUE, every run - deliberately NOT gated on "did this
# script create .env", for the same reason as BOOTSTRAP_ADMIN_USERNAME
# above. README's Quick Start opens with `cp .env.example .env`, and only
# afterwards mentions setup.sh does that step for you - so someone who
# reads top-to-bottom arrives here with an existing .env holding a BLANK
# SECRET_KEY, gets "leaving it as-is", and lands in a RuntimeError
# crash-loop. Same outcome if an earlier run was interrupted between
# creating .env and filling this in.
if [ -z "$(get_env_var SECRET_KEY "")" ]; then
    if command -v openssl >/dev/null 2>&1; then
        secret_key="$(openssl rand -hex 32)"
    else
        secret_key="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    set_env_var SECRET_KEY "$secret_key"
    echo "    Generated a random SECRET_KEY."
fi

if [ "$env_created" = true ]; then
    # Whoever runs this is almost never going to sit at this machine's own
    # console with a browser open - it's usually a headless VM, administered
    # remotely. Without SERVE_TLS+BIND_ADDR, the app comes up loopback-only
    # (see README's "Direct TLS" section) and is unreachable from anywhere
    # else, which looks like a bug rather than the secure-by-default
    # behavior it actually is. Ask, rather than silently deciding either
    # way - someone who already has a reverse proxy in front of this box
    # can say no and keep today's loopback-only default untouched.
    echo
    printf '%s' "Will this be reached directly, without a reverse proxy already in front of it? [Y/n] "
    read -r direct_answer || direct_answer=""
    case "$direct_answer" in
        [Nn]*)
            echo "    Leaving SERVE_TLS/BIND_ADDR at their defaults (loopback-only) -"
            echo "    point your reverse proxy at 127.0.0.1:${port} on this host."
            ;;
        *)
            set_env_var SERVE_TLS true
            set_env_var BIND_ADDR 0.0.0.0
            # The container can't know this host's real address - from inside
            # it only sees its own bridge IP (172.x), which is what the cert
            # and the printed login URL used to be built from: a URL reachable
            # from nowhere, and a certificate whose name never matches, so the
            # browser showed a scarier name-mismatch error instead of the
            # plain self-signed warning every doc prepares people for. This
            # script runs ON the host, so it can find the LAN address and hand
            # it in via TLS_CERT_HOST. Same UDP trick as tls.py's
            # detect_local_ip(): no packet is sent, it just asks the routing
            # table which interface would be used.
            host_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)" || host_ip=""
            if [ -z "$host_ip" ]; then
                host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || host_ip=""
            fi
            if [ -n "$host_ip" ]; then
                set_env_var TLS_CERT_HOST "$host_ip"
                echo "    Set SERVE_TLS=true, BIND_ADDR=0.0.0.0 and TLS_CERT_HOST=${HL}${host_ip}${HL_OFF} -"
                echo "    this app will terminate its own HTTPS and be reachable from other"
                echo "    devices at ${HL}https://${host_ip}:${port}/${HL_OFF}"
            else
                echo "    Set SERVE_TLS=true and BIND_ADDR=0.0.0.0 - this app will terminate"
                echo "    its own HTTPS and be reachable from other devices on the network."
                echo "    Couldn't detect this host's LAN address - set TLS_CERT_HOST in .env"
                echo "    to it (or a hostname) so the certificate is issued for the right name."
            fi
            echo "    Uses a self-signed certificate; your browser will show a security"
            echo "    warning the first time - that's expected, click through it."
            ;;
    esac
fi

if [ "$install_mode" = docker ]; then
    echo "==> Creating ./data (holds the audit database) with the right ownership..."
    mkdir -p data
    # uid 1000 is the non-root user the Dockerfile creates inside the container
    # (see Dockerfile) - the container needs write access to this bind-mounted
    # directory, which a freshly-created one otherwise isn't (root-owned on a
    # fresh Linux host - see README.md). `stat`'s flag differs between GNU
    # (Linux) and BSD (macOS) - try both rather than assuming one.
    current_owner="$(stat -c '%u' data 2>/dev/null || stat -f '%u' data 2>/dev/null || echo unknown)"
    if [ "$current_owner" != "1000" ]; then
        echo "    (needs sudo to change ./data's ownership to uid 1000)"
        # -R: a directory left over from an earlier failed attempt can hold
        # root-owned files (audit.sqlite, tls_cert.pem) that a top-level chown
        # doesn't touch - and then the container still can't write them.
        sudo chown -R 1000:1000 data
    else
        echo "    already owned by uid 1000, nothing to do."
    fi
    # Ownership was never the whole story. `mkdir` leaves this 755 under the
    # default umask and the container writes audit.sqlite at 644, so the
    # audit log - which holds the TAK Server password in plaintext in
    # app_settings, every account's password hash, and the hash-chained
    # record itself - was readable by any local account on the host.
    # Measured at 750/644 on a real side-by-side install; the Docker case is
    # worse because nothing narrowed the directory at all. uid 1000 owns
    # both, so 700/600 costs the container nothing. app.py re-applies the
    # file mode on every start, which covers a database restored by hand.
    sudo chmod 700 data
    sudo find data -type f -exec chmod 600 {} + 2>/dev/null || true

    echo "==> Building and starting..."
    # --wait (Compose v2.17+) is the documented way to solve this properly -
    # it blocks until the service's healthcheck actually reports healthy,
    # not just "container created". docker-compose.yml already defines a
    # real one (a genuine HTTP request to /login), so this is a much stronger
    # signal than guessing at a fixed delay: by the time this returns, the app
    # has definitely finished starting (including printing the one-time
    # bootstrap banner below), and a genuinely broken container fails loudly
    # here instead of silently leaving an empty-looking log for someone to
    # puzzle over. An earlier version of this script polled the log output on
    # a timer instead - replaced once this was checked against Compose's own
    # documented mechanism for exactly this, rather than guessing at timing.
    #
    # Wrapped in an `if` rather than left to `set -e`: when --wait fails, the
    # reason is in the container's own log - a RuntimeError about a blank
    # SECRET_KEY, an unwritable ./data, a port Docker couldn't bind - and the
    # ERR trap can only say "failed at line N", while `bash -x` shows the
    # same nothing. Without this, the installer was cut off one line short
    # of the exact output that would have told them what to fix.
    # --wait-timeout: a crash-looping container under restart:unless-stopped
    # keeps being recreated; without a ceiling --wait can sit there
    # indefinitely with no output at all.
    if ! docker compose up -d --build --wait --wait-timeout 180; then
        echo
        echo "==> The container did not come up healthy. Its own log follows - the"
        echo "    real reason is almost always in the last few lines:"
        echo
        docker compose logs --tail=60 web || true
        echo
        echo "    Fix what it reports, then re-run ./setup.sh (safe to repeat)."
        exit 1
    fi

    echo
    echo "==> Startup log - look for the one-time admin username/password below"
    echo "    (only printed on the very first start; copy it now if it's here):"
    docker compose logs web
    echo
else

    # ---- side by side, no Docker ------------------------------------------
    # Every step reports what it found before it changes anything, and does
    # nothing when the answer is "already right" - this script is re-run
    # after every update.

    # $py and the systemd check were settled in the prerequisites section at
    # the top, before anything was written or asked.

    # AUDIT_DB before anything is copied: .env is written HERE, in the
    # checkout, and the copy below carries it across. Writing it afterwards
    # would edit the wrong file.
    audit_db="$install_dir/data/audit.sqlite"
    if [ "$(get_env_var AUDIT_DB audit.sqlite)" = "$audit_db" ]; then
        echo "==> AUDIT_DB already points at $audit_db."
    else
        set_env_var AUDIT_DB "$audit_db"
        echo "==> Set AUDIT_DB=$audit_db (the audit log, and the TLS cert beside it)."
    fi

    echo "==> Checking the service account ($svc_user)..."
    if id -u "$svc_user" >/dev/null 2>&1; then
        echo "    Already exists."
    else
        echo "    Creating it - a system account with no login shell, which is what"
        echo "    runs the app. It is not the account you log in as."
        # --user-group explicitly: whether a system account otherwise gets a
        # group of its own depends on USERGROUPS_ENAB in /etc/login.defs, and
        # both the chown below and connect-database.sh's re-check folder step
        # assume a 'takextract' group exists.
        if [ -d "$install_dir" ]; then
            sudo useradd --system --user-group --home-dir "$install_dir" \
                 --shell /usr/sbin/nologin "$svc_user"
        else
            sudo useradd --system --user-group --create-home --home-dir "$install_dir" \
                 --shell /usr/sbin/nologin "$svc_user"
        fi
    fi

    # Who owns the installed copy. NOT the service account: the admin still
    # has to `git pull` here and run connect-database.sh, which writes .env,
    # and both are ordinary unprivileged work. The service account only ever
    # READS the code and .env (systemd reads EnvironmentFile as root before
    # dropping privileges), and writes one directory - data/ - below.
    admin_user="${SUDO_USER:-$(id -un)}"

    echo "==> Installing to $install_dir..."
    if [ "$(cd "$install_dir" 2>/dev/null && pwd -P || true)" = "$(pwd -P)" ]; then
        echo "    Already running from $install_dir - nothing to copy."
    else
        sudo mkdir -p "$install_dir"
        # -a keeps modes and carries .git, so `git pull` works there - which is
        # what the System page's update command tells an admin to run.
        sudo cp -a ./. "$install_dir"/
        # A venv copied from elsewhere has absolute paths baked into it and
        # would be wrong here; it is rebuilt below.
        sudo rm -rf "$install_dir/venv"
        sudo chown -R "$admin_user" "$install_dir"
        sudo chmod 755 "$install_dir"
        echo "    Copied. From here on $install_dir is the install - this checkout"
        echo "    is just where it came from."
    fi

    echo "==> Creating the virtual environment and installing dependencies..."
    if [ -x "$install_dir/venv/bin/gunicorn" ]; then
        echo "    Already present - upgrading its packages in place."
    else
        "$py" -m venv "$install_dir/venv"
    fi
    "$install_dir/venv/bin/pip" install --quiet --upgrade pip
    "$install_dir/venv/bin/pip" install --quiet -r "$install_dir/requirements.txt"
    # gunicorn is deliberately absent from requirements.txt - it does not run
    # on Windows, where this app is also developed. Bare metal needs it.
    "$install_dir/venv/bin/pip" install --quiet gunicorn==23.0.0
    # Run under `sudo ./setup.sh`, everything above ran as root and left a
    # root-owned venv inside an admin-owned install. Normalise either way.
    sudo chown -R "$admin_user" "$install_dir/venv"
    echo "    Done."

    echo "==> Creating $install_dir/data (holds the audit database)..."
    sudo mkdir -p "$install_dir/data"
    # The one directory the service account writes: the audit log, and the
    # self-signed certificate that gunicorn.conf.py puts beside it.
    #
    # -R, not just the directory: switching a Docker install to side-by-side
    # brings ./data across with an audit.sqlite already in it, owned by the
    # container's uid 1000. Chowning only the directory would leave the
    # service unable to write the one file it exists to write - and the
    # failure would look like a permissions bug in the app.
    sudo chown -R "$svc_user:$svc_user" "$install_dir/data"
    # 700, not 750. Nothing but the service has any business in here, and
    # the group is not a neutral party: connect-database.sh adds postgres
    # AND the administrator accounts to the takextract group so they can
    # share the re-check folder, which is a different path entirely
    # (/var/lib/takextract/recheck). At 750 that group could traverse this
    # directory, and audit.sqlite is created by Python's sqlite3 at
    # 0666 & ~umask - 0644 under systemd's default - so postgres could read
    # the audit log, the bootstrap admin's password hash, and the TAK
    # Server password, which app.py stores in app_settings in plaintext.
    # Found in the pre-push security review; see UMask in tak-extract.service
    # for the other half.
    sudo chmod 700 "$install_dir/data"
    # The directory mode only governs new traversal; anything already in
    # there from an earlier install keeps whatever mode it was created with.
    sudo find "$install_dir/data" -type f -exec chmod 600 {} + 2>/dev/null || true
    echo "    Owned by $svc_user - the only thing the service writes."

    echo "==> Installing the systemd service..."
    # tak-extract.service ships with /opt/tak-extract as a placeholder; fill
    # in the real path. ReadWritePaths is narrowed to data/ - with
    # ProtectSystem=strict the rest of the install stays read-only to the
    # service, which is all it needs.
    unit_tmp="$(mktemp)"
    sed -e "s#^WorkingDirectory=.*#WorkingDirectory=$install_dir#" \
        -e "s#^EnvironmentFile=.*#EnvironmentFile=$install_dir/.env#" \
        -e "s#^ExecStart=.*#ExecStart=$install_dir/venv/bin/gunicorn -c gunicorn.conf.py app:app#" \
        -e "s#^ReadWritePaths=.*#ReadWritePaths=$install_dir/data#" \
        -e "s#^User=.*#User=$svc_user#" \
        -e "s#^Group=.*#Group=$svc_user#" \
        "$install_dir/tak-extract.service" > "$unit_tmp"
    sudo install -m 644 "$unit_tmp" /etc/systemd/system/tak-extract.service
    rm -f "$unit_tmp"
    sudo systemctl daemon-reload
    sudo systemctl enable --quiet tak-extract 2>/dev/null || sudo systemctl enable tak-extract
    echo "    Installed and enabled (it will start on boot)."

    echo "==> Starting..."
    # NRestarts counts systemd's own automatic restarts, so a reading taken
    # before this one deliberate restart is the baseline for "has it been
    # crash-looping since?"
    restarts_before="$(systemctl show -p NRestarts --value tak-extract 2>/dev/null || echo 0)"
    sudo systemctl restart tak-extract
    # Confirm rather than assume: systemctl returns as soon as the process
    # has been forked, which is before a service that starts and then dies
    # has finished dying. The Docker branch waits on a real healthcheck
    # rather than a timer; this is the nearest equivalent - poll until it is
    # actually up, or until it has clearly failed.
    started=false
    for _ in $(seq 1 20); do
        if systemctl is-active --quiet tak-extract; then started=true; break; fi
        if systemctl is-failed --quiet tak-extract; then break; fi
        sleep 1
    done
    # One sighting of "active" is NOT enough. Under Restart= a service that
    # dies immediately is briefly active after every restart, and a
    # one-second poll lands in that window - so this reported "Running."
    # about an install that went on to crash-loop 159 times before anyone
    # noticed. It is never "failed" either, because systemd keeps putting it
    # back. So: wait, then require it to be BOTH still active and not to
    # have restarted itself in the meantime.
    if [ "$started" = true ]; then
        # Longer than the unit's RestartSec=5, or the NRestarts comparison
        # below is dead code: a service that starts and dies is still in
        # systemd's auto-restart wait at t+4 and has not been restarted yet,
        # so the counter has not moved. The is-active re-check catches the
        # crash loop either way, but only this makes both halves contribute.
        sleep 8
        restarts_after="$(systemctl show -p NRestarts --value tak-extract 2>/dev/null || echo 0)"
        # A non-integer (an older systemd not knowing the property prints an
        # empty line) would make `-gt` exit 2, and because that sits in an
        # `if` condition neither set -e nor the ERR trap would catch it - the
        # script would fall through and report the service as running, which
        # is the exact mis-report this check exists to prevent.
        case "$restarts_before" in ''|*[!0-9]*) restarts_before=0 ;; esac
        case "$restarts_after"  in ''|*[!0-9]*) restarts_after=0  ;; esac
        if ! systemctl is-active --quiet tak-extract \
           || [ "$restarts_after" -gt "$restarts_before" ]; then
            started=false
            echo "    It started and then restarted itself - that is a crash loop,"
            echo "    not a slow start."
        fi
    fi
    if [ "$started" = false ]; then
        echo
        echo "==> The service did not stay running. Its own log follows - the real"
        echo "    reason is almost always in the last few lines:"
        echo
        sudo journalctl -u tak-extract --no-pager -n 60 || true
        echo
        echo "    Fix what it reports, then re-run ./setup.sh (safe to repeat)."
        exit 1
    fi
    echo "    Running."

    echo
    echo "==> Startup log - look for the one-time admin username/password below"
    echo "    (only printed on the very first start; copy it now if it's here):"
    # Wait for the app's OWN output before printing the journal.
    # `systemctl is-active` above returns as soon as the process has forked,
    # which is before gunicorn's workers have imported app.py - so this used
    # to dump a journal containing nothing but "Started TAK-Extract." and
    # the one-time password, printed a second or two later, was never seen.
    # It is generated once and never regenerated while an admin exists, so
    # missing it means recovering the account rather than scrolling back.
    # The Docker branch does not need this: `--wait` blocks on a real
    # healthcheck, so by the time it logs, the app has definitely printed.
    # Match something only the APP prints, and only from this boot. The
    # first version grepped for "TAK-Extract", which systemd's own
    # "Started TAK-Extract." satisfies within milliseconds because that is
    # the unit's Description - so the wait broke on its first pass and
    # waited for nothing. --since because matching lines from every
    # previous start also counted. These two strings are app.py's only
    # startup output, and exactly one of them always appears.
    for _ in $(seq 1 30); do
        if sudo journalctl -u tak-extract --no-pager --since "2 min ago" 2>/dev/null \
           | grep -qE 'first admin account created|TAK-Extract is running'; then
            break
        fi
        sleep 1
    done
    sudo journalctl -u tak-extract --no-pager -n 80
    echo
    echo "    If no username/password appears above, the account already"
    echo "    existed - nothing was regenerated. Recover it by removing the"
    echo "    admin and restarting, which re-runs the one-time bootstrap:"
    echo "      sudo journalctl -u tak-extract --no-pager | grep -A6 'first admin'"
    echo

fi
# The app is up, but it can't read any position data until it's connected
# to TAK Server's Postgres - and that's a SEPARATE script. An earlier
# version of this message mentioned that script in a paragraph placed
# after "Log in at the URL shown above", which reads as "you're done";
# a real installer got as far as the login page and never saw it. So:
# detect the common same-host case the same way connect-database.sh
# does, and offer to run it right here, as the obvious next step.
# Which copy of connect-database.sh to offer: the one inside the install,
# which is this directory for a Docker install and /opt/tak-extract for a
# side-by-side one.
if [ "$install_mode" = docker ]; then
    connect_script=./connect-database.sh
else
    connect_script="$install_dir/connect-database.sh"
fi

echo "==> The app is running - but it can't read any position data yet."
echo "    It still needs to be connected to TAK Server's Postgres database."
echo
postgres_local=false
if command -v pg_isready >/dev/null 2>&1; then
    pg_isready -h 127.0.0.1 -p 5432 -t 2 >/dev/null 2>&1 && postgres_local=true
elif systemctl is-active --quiet postgresql 2>/dev/null; then
    postgres_local=true
fi
if [ "$postgres_local" = true ]; then
    echo "    TAK Server's Postgres appears to be running on THIS machine."
    echo "    ./connect-database.sh can connect to it: it finds the right address,"
    echo "    and then asks before each change - a pg_hba.conf line, a firewall"
    echo "    rule, and a least-privilege read-only database account. Decline any"
    echo "    step and it tells you exactly what to do by hand instead."
    echo
    printf '%s' "Run $connect_script now? [Y/n] "
    read -r connect_answer || connect_answer=""
    case "$connect_answer" in
        [Nn]*)
            echo "    Skipped. Run it whenever you're ready:"
            echo "      $connect_script"
            ;;
        *)
            echo
            # --skip-intro: it would otherwise open with its own overview and
            # a second "Continue? [Y/n]" straight after the one just answered.
            # Every per-step question inside it is still asked.
            #
            # `|| { ... }` so this stays non-fatal: connect-database.sh exits
            # non-zero on a legitimate "connection didn't verify - fix and
            # re-run" (not a setup.sh failure), and without this, setup.sh's
            # own `set -e` + ERR trap would fire and print a misleading
            # "setup.sh failed at line N / re-run bash -x setup.sh" - wrong
            # script, wrong advice. setup.sh's own work is already done and
            # committed by this point; connect-database.sh is re-runnable on
            # its own.
            # "$connect_script", not ./connect-database.sh: side by side, the
            # install is /opt/tak-extract and its .env is the one the service
            # reads. The checkout this was run from is not it, and writing
            # DB_HOST and a password into that copy would leave the app with
            # no database and no error to explain why.
            "$connect_script" --skip-intro || {
                echo
                echo "    connect-database.sh didn't finish (see its output above)."
                echo "    setup.sh itself is done - the app is installed and running."
                echo "    Re-run just the database step when ready: ./connect-database.sh"
            }
            ;;
    esac
else
    echo "    No Postgres detected running on this machine, so the database is"
    echo "    presumably on a separate server. See README.md's 'Creating the"
    echo "    least-privilege database account' section for the SQL to run there,"
    echo "    then enter the connection details on the System page after logging in."
fi
echo
echo "==> Log in at the URL shown in the startup log above."
if [ "$install_mode" = baremetal ]; then
    echo
    echo "    This install now lives in $install_dir, run by the '$svc_user'"
    echo "    account under systemd. That is where to pull updates and re-run"
    echo "    these scripts from - not the directory you cloned into:"
    echo "      cd $install_dir && git pull && sudo systemctl restart tak-extract"
    echo "      sudo systemctl status tak-extract      # is it running"
    echo "      sudo journalctl -u tak-extract -f      # follow its log"
fi
