#!/usr/bin/env bash
#
# Check that the TAK Server database still holds what an export needs.
# Run this after a TAK Server upgrade, a PostgreSQL upgrade, or any
# infra-TAK release that touches either.
#
# This is a wrapper, not the check. The check is dbcheck.py, and it has to
# be Python for two reasons that are not preferences:
#
#   - It executes the exporter's OWN statements, from exports.build_queries().
#     A shell script would have to keep its own copy of every table and
#     column, which is the drift it is meant to detect.
#   - The real database credentials live in audit.sqlite's app_settings
#     table, not in .env - .env is only a first-run seed (see get_setting()
#     in app.py). A shell script reading .env could test the wrong
#     connection, or a stale one, and report success.
#
# Everything it does is read-only: every statement is a SELECT, inside a
# READ ONLY transaction, under an account with no write privileges.
#
# Exit codes: 0 all well · 1 drift or warnings · 2 something is wrong
#             3 could not connect at all
#
set -Eeuo pipefail

cd "$(dirname "$0")"

get_env_var() {
    local val
    val="$(grep -E "^$1=" .env 2>/dev/null | tail -n1 | cut -d= -f2-)" || val=""
    if [ -n "$val" ]; then echo "$val"; else echo "$2"; fi
}

if [ ! -f .env ]; then
    echo "No .env here yet - run ./setup.sh first."
    exit 1
fi

# Which install this is. setup.sh asks once and records it; an .env written
# before INSTALL_MODE existed has no such line, and those installs are Docker.
install_mode="$(get_env_var INSTALL_MODE docker)"
case "$install_mode" in
    docker|baremetal) ;;
    *) install_mode=docker ;;
esac
install_dir="$(pwd -P)"

# A non-zero exit from the check is its RESULT, not a failure of this
# script - so it must not trip `set -e`. Captured, reported, passed on.
rc=0

if [ "$install_mode" = docker ]; then
    # Keep the error. Discarding it (2>/dev/null || true) made every
    # failure look like "the container isn't running" - including the
    # common one, which is that .env is root-owned 0600 so docker compose
    # cannot read it as an ordinary user. The advice that followed was
    # then wrong, and re-running the suggested command did not help.
    compose_err=""
    container_id=""
    if compose_err="$(docker compose ps -q web 2>&1)"; then
        container_id="$compose_err"
        compose_err=""
    fi
    if [ -n "$compose_err" ]; then
        echo "Could not ask Docker about the web container:"
        printf '%s\n' "$compose_err" | sed 's/^/    /'
        case "$compose_err" in
            *"permission denied"*|*"Permission denied"*)
                echo
                echo ".env is owner-only (it holds the database password), so"
                echo "docker compose cannot read it as $(id -un). Run this with sudo:"
                echo "    sudo ./check-database.sh${*:+ $*}"
                ;;
            *)
                echo
                echo "Check that Docker is running and that this account can use it."
                ;;
        esac
        exit 1
    fi
    if [ -z "$container_id" ]; then
        echo "The web container isn't running - start it with"
        echo "  sudo docker compose up -d --build"
        echo "then re-run this."
        exit 1
    fi
    docker compose exec -T web python dbcheck.py "$@" || rc=$?
else
    # As the service account, never as root: audit.sqlite is written here,
    # and a root-owned write would leave the service unable to open it.
    service_user="$(get_env_var SERVICE_USER takextract)"
    if [ ! -x "$install_dir/venv/bin/python" ]; then
        echo "No Python environment at $install_dir/venv - this looks like a"
        echo "side-by-side install that hasn't finished. Run ./setup.sh first."
        exit 1
    fi
    if [ "$(id -un)" = "$service_user" ]; then
        "$install_dir/venv/bin/python" dbcheck.py "$@" || rc=$?
    else
        # The settings have to be handed over explicitly. .env is owned by
        # the administrator and mode 600 - it holds SECRET_KEY and the
        # database password - and systemd gets them to the service by
        # reading it as root before dropping privileges. Dropping to the
        # service account here means .env is unreadable, so without this the
        # run dies on import with PermissionError. Seen on a real install.
        #
        # Deliberately NOT solved by widening .env's permissions:
        # connect-database.sh puts postgres AND the administrator accounts
        # in the takextract group so they can share the re-check folder, so
        # a group-readable .env would hand postgres the secret key and the
        # database password.
        #
        # And deliberately NOT passed as `env KEY=VALUE` arguments either,
        # which is how this was first written. Command-line arguments are
        # world-readable through /proc/<pid>/cmdline for as long as the sudo
        # process lives, and sudo additionally logs the full command it was
        # asked to run to the auth log - which is group-readable, kept for
        # weeks, and swept into backups. That would have handed postgres,
        # every other local account, and every reader of the auth log
        # exactly the two values the paragraph above refuses to share with
        # them. Caught in the pre-push security review.
        #
        # So: a file only the service account can read. The administrator
        # creates and writes it - no sudo anywhere near the CONTENT, because
        # `Defaults log_input` in sudoers records a command's stdin to
        # /var/log/sudo-io, which would reintroduce the same durable,
        # shipped-off-the-box copy the argv version was rejected for. sudo
        # appears only to hand the finished file over, where its log sees a
        # path and nothing else.
        # A directory the ADMINISTRATOR owns, with the file inside it. The
        # first version put the file straight in /tmp and chowned it to the
        # service account - which meant the administrator could no longer
        # unlink it, because /tmp is sticky, so cleanup depended entirely on
        # sudo still having a valid timestamp. With
        # `Defaults timestamp_timeout=0`, or simply a check that ran longer
        # than the timeout, the removal failed silently behind `|| true` and
        # the database password stayed in /tmp. Unlinking is governed by the
        # PARENT directory, so an admin-owned one makes cleanup unconditional
        # and drops sudo out of that path entirely.
        umask 077
        secrets_dir="$(mktemp -d)" || {
            echo "Could not create a temporary directory."; exit 1; }
        secrets_file="$secrets_dir/env"
        cleanup_secrets() { rm -rf "$secrets_dir" 2>/dev/null || true; }
        # Separate INT/TERM traps that exit: a bare `trap handler INT` would
        # run the handler and then resume at the next command.
        trap cleanup_secrets EXIT
        trap 'cleanup_secrets; exit 130' INT
        trap 'cleanup_secrets; exit 143' TERM

        # SECRET_KEY is NOT passed. dbcheck imports app only for
        # get_connection(), audit() and AUDIT_DB; it never signs or verifies
        # a session. app.py only requires the value to be non-empty, so a
        # placeholder satisfies it and the real key never leaves .env.
        {
            for key in AUDIT_DB DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD \
                       AUTH_MODE; do
                val="$(get_env_var "$key" "")"
                if [ -n "$val" ]; then
                    # Single-quoted with embedded quotes escaped, because
                    # this is sourced: a value containing a space or a glob
                    # character would otherwise split or expand.
                    esc="$(printf '%s' "$val" | sed "s/'/'\\\\''/g")"
                    printf "%s='%s'\n" "$key" "$esc"
                fi
            done
            printf "%s='%s'\n" SECRET_KEY "placeholder-schema-check-signs-nothing"
        } > "$secrets_file"
        # Handed over only now that it is written. umask 077 means the file
        # was owner-only from creation, so it was never readable by anyone
        # else at any point. 0711 on the directory lets the service account
        # traverse to a file it knows the name of without being able to list
        # what else is in there; the administrator keeps ownership of the
        # directory, which is what makes cleanup work without sudo.
        sudo chown "$service_user" "$secrets_file"
        chmod 0711 "$secrets_dir"

        sudo -u "$service_user" env TAKX_NO_BANNER=1 \
            sh -c 'set -a; . "$1"; set +a; shift; exec "$@"' sh "$secrets_file" \
            "$install_dir/venv/bin/python" dbcheck.py "$@" || rc=$?
        cleanup_secrets
        trap - EXIT INT TERM
    fi
fi

case "$rc" in
    0) ;;
    1) echo "Some things are worth reading above, but nothing is broken." ;;
    2) echo "Something is wrong - see the [FAIL] lines and 'What to do' above." ;;
    3) echo "The database could not be reached at all." ;;
esac
exit "$rc"
