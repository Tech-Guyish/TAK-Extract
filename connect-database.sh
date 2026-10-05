#!/usr/bin/env bash
# Automates connecting TAK-Extract to TAK Server's own Postgres. Reads
# INSTALL_MODE from .env (written by setup.sh) and does only the work that
# shape of install actually needs: a Docker install reaches Postgres across
# the bridge, so it needs the gateway discovered, a pg_hba.conf line for that
# subnet and a firewall rule; a side-by-side install reaches it over loopback
# and needs none of that. The database work - the least-privilege role, its
# grants, the re-check folder - is the same either way.
#
# Originally written only for the container path; that comment follows.
# Automates connecting TAK-Extract's Docker container to TAK Server's own
# Postgres database when that Postgres runs bare-metal on THIS SAME host -
# the common all-in-one case. Everything below mirrors, step by step, a
# real manual troubleshooting session: find the Docker bridge gateway IP,
# widen Postgres's listen_addresses, scope a pg_hba.conf rule to that one
# subnet, open a matching firewall rule (ufw or firewalld), create a
# least-privilege database role
# with a generated password, and wire the result into .env.
#
# The SQL below (role creation + GRANTs) mirrors README.md's "Creating the
# least-privilege database account" section exactly - keep both in sync if
# the table list ever changes (that list is built from every FROM/JOIN in
# exports.py, not guessed).
#
# Safe to re-run: idempotent throughout (see each section). Run from the
# repo root: ./connect-database.sh
# -E (errtrace) so the ERR trap below also fires for failures inside
# FUNCTIONS - without it bash skips the trap there, and set_env_var /
# get_env_var (file I/O on .env) would die with no message at all. Same
# reasoning as setup.sh.
set -Eeuo pipefail
cd "$(dirname "$0")"

# set_env_var writes .env via a temp file and moves it into place; a
# failure part-way leaves that temp behind holding the same values.
# The baseline step near the end writes the database password into a temp
# file so it can be handed to the service account. It removes it inline,
# but a Ctrl-C or a dropped SSH session during that run - which executes
# every exporter query and can take minutes - would otherwise leave a
# plaintext credential in /tmp, surviving into disk images and backups with
# nothing to say it is there. Hooked into the traps that already exist
# rather than adding competing ones. Found in the pre-push security review.
baseline_secrets_dir=""
cleanup_baseline_secrets() {
    # rm -rf on a directory the ADMINISTRATOR owns, so this never depends on
    # sudo still having a valid timestamp. The first version put the file in
    # /tmp and chowned it to the service account, which left the
    # administrator unable to unlink it (sticky bit) - cleanup then rested
    # entirely on sudo -n succeeding, and failed silently behind `|| true`
    # when it did not, leaving the database password on disk.
    if [ -n "${baseline_secrets_dir:-}" ]; then
        rm -rf "$baseline_secrets_dir" 2>/dev/null || true
        baseline_secrets_dir=""
    fi
    return 0
}
cleanup_tmp() { [ -f .env.tmp ] && rm -f .env.tmp; cleanup_baseline_secrets; return 0; }
trap 'cleanup_tmp; echo; echo "==> connect-database.sh failed at line $LINENO. Re-run as bash -x connect-database.sh for a full trace of what ran right before this." >&2' ERR
# INT and TERM must EXIT, not just clean up. A bare `trap handler INT` runs
# the handler and then RESUMES at the next command - and `confirm_step`'s
# `read -r a || a=""` returns non-zero when a trapped signal interrupts it,
# falling through to the `*)` branch, which means YES. So Ctrl-C at "create
# the role?" or "open the firewall?" would have performed the step and
# carried on to the next one. Caught in the pre-push security review, in
# code added earlier in the same session. cleanup_tmp is idempotent, so the
# EXIT trap firing again afterwards is harmless.
trap cleanup_tmp EXIT
trap 'cleanup_tmp; exit 130' INT
trap 'cleanup_tmp; exit 143' TERM

# Highlight color for the values an installer scans this output for - the
# connection IP and the generated password. Only when stdout is a real
# terminal (so it never lands in a piped/redirected capture) and NO_COLOR
# isn't set (the standard opt-out).
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then HL=$'\033[1;36m'; HL_OFF=$'\033[0m'; else HL=''; HL_OFF=''; fi

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
skip_gate=false      # --yes: auto-accept every non-disruptive per-step prompt
skip_intro=false     # --skip-intro: skip only the opening overview/Continue gate
allow_restart=false
dry_run=false
reset_password=false
role="takextract"
db=""

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y) skip_gate=true; skip_intro=true ;;
        # For setup.sh, which has just asked "run this now? [Y/n]" itself -
        # repeating an overview + "Continue?" right after that reads as a
        # double-prompt. Skips ONLY the intro; every per-step question
        # (pg_hba line, firewall rule, role) is still asked.
        --skip-intro) skip_intro=true ;;
        --yes-restart-postgres) allow_restart=true ;;
        --dry-run) dry_run=true ;;
        --reset-password) reset_password=true ;;
        # Value-taking flags: check the value is actually there. With --role
        # as the LAST argument, `shift` empties $@ and "$1" is unbound - which
        # under `set -u` is a bare "unbound variable" crash, not a usage hint.
        --role) [ $# -ge 2 ] || { echo "--role needs a value" >&2; exit 1; }; shift; role="$1" ;;
        --db)   [ $# -ge 2 ] || { echo "--db needs a value" >&2; exit 1; };   shift; db="$1" ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

run() {
    # Wraps every state-changing command so --dry-run can show exactly what
    # would happen without doing it - one place to check, not scattered
    # `if $dry_run` guards throughout every section below.
    if [ "$dry_run" = true ]; then
        echo "    [dry-run] $*"
    else
        "$@"
    fi
}

# Run psql as the postgres OS user, from a directory that user can enter.
# postgres can't chdir into this repo (home dirs are 0700), so a plain
# `sudo -u postgres` prints "could not change directory ... Permission
# denied" - harmless on its own, but a capture that merges stderr (2>&1,
# used below so a genuine connection error is still shown) pulls that
# warning INTO the value and corrupts it. Found on a real fresh install:
# it turned $hba_file into the warning text plus the path. Running from /
# removes the warning at the source; the subshell keeps the script's own
# cwd (needed for the .env writes) unchanged.
pg_psql() { ( cd / && sudo -u postgres psql "$@" ); }

# Every individual change to the HOST (a pg_hba.conf line, a firewall rule,
# a database role) is asked about on its own, not just covered by the one
# opt-in gate at the top - so someone can accept the parts they're
# comfortable with and do the rest by hand. Each declined step appends the
# exact manual commands to manual_steps, printed together at the end.
# --yes/-y answers all of these; the Postgres restart is deliberately NOT
# covered by it (it's the one disruptive step) and keeps its own
# --yes-restart-postgres.
manual_steps=""
confirm_step() {
    if [ "$skip_gate" = true ]; then return 0; fi
    printf '%s' "    $1 [Y/n] "
    local a
    read -r a || a=""
    case "$a" in
        [Nn]*) return 1 ;;
        *) return 0 ;;
    esac
}
add_manual_step() {
    manual_steps="$manual_steps
$1"
}
# Reminders that are NOT declined steps and do not block the connection
# (e.g. log out and back in for a group to apply). Printed under their own
# heading so they never read as "you chose to skip this".
notes=""
env_note=""
add_note() {
    notes="$notes
$1"
}

# ---------------------------------------------------------------------------
# Helpers - duplicated from setup.sh (not sourced: setup.sh runs top-level
# logic unconditionally, it isn't written to be safely sourced by another
# script). Keep both copies in sync if either changes.
# ---------------------------------------------------------------------------
set_env_var() {
    # -f: .env is root-owned after `sudo ./setup.sh`, and a plain mv then
    # stops to ask "replace .env, overriding mode?" - the directory is ours,
    # so the replace is allowed either way; -f only skips the question.
    awk -v line="$1=$2" -v pattern="^$1=" \
        '{ if ($0 ~ pattern) print line; else print $0 }' .env > .env.tmp \
        && chmod 600 .env.tmp && mv -f .env.tmp .env
}

# set_env_var only replaces a line that exists (so a key .env.example never
# had, from an older install, would silently not be written). This one
# appends it when it is missing.
set_or_add_env_var() {
    if grep -qE "^$1=" .env 2>/dev/null; then
        set_env_var "$1" "$2"
    else
        printf '%s=%s\n' "$1" "$2" >> .env
    fi
}

get_env_var() {
    local val
    val="$(grep -E "^$1=" .env 2>/dev/null | tail -n1 | cut -d= -f2-)" || val=""
    if [ -n "$val" ]; then echo "$val"; else echo "$2"; fi
}

gen_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

if [ -z "$db" ]; then
    db="$(get_env_var DB_NAME cot)"
fi

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
if [ ! -f .env ]; then
    echo "No .env here yet - run ./setup.sh first (or cp .env.example .env)."
    exit 1
fi

# Which install this is. setup.sh asks once and records it; this script
# never asks again. An .env written before INSTALL_MODE existed has no such
# line - treat that as Docker, which is what those installs are.
install_mode="$(get_env_var INSTALL_MODE docker)"
case "$install_mode" in
    docker|baremetal) ;;
    *) install_mode=docker ;;
esac

# Where the install is, for the side-by-side path: this script lives inside
# it and has already cd'd to its own directory, so there is nothing to guess
# and nothing to keep in step with setup.sh.
install_dir="$(pwd -P)"

container_id=""
if [ "$install_mode" = docker ]; then
    container_id="$(docker compose ps -q web 2>/dev/null)" || true
    if [ -z "$container_id" ]; then
        echo "The web container isn't running yet - run ./setup.sh (or"
        echo "docker compose up -d --build) first, then re-run this script."
        exit 1
    fi
elif ! systemctl list-unit-files tak-extract.service >/dev/null 2>&1; then
    echo "This is recorded as a side-by-side install, but tak-extract.service"
    echo "isn't installed yet - run ./setup.sh first, then re-run this script."
    exit 1
fi

# ---------------------------------------------------------------------------
# Detect local Postgres - not finding one is NOT an error, it just means
# this host isn't an all-in-one install, so there's nothing for this
# script to automate.
# ---------------------------------------------------------------------------
postgres_found=false
if command -v pg_isready >/dev/null 2>&1; then
    if pg_isready -h 127.0.0.1 -p 5432 -t 2 >/dev/null 2>&1; then
        postgres_found=true
    fi
else
    if systemctl is-active --quiet postgresql 2>/dev/null; then
        postgres_found=true
    elif systemctl list-units --type=service --all 2>/dev/null | grep -qi postgres; then
        postgres_found=true
    fi
fi

if [ "$postgres_found" = false ]; then
    echo "No Postgres detected running locally on this host - this script"
    echo "only automates the all-in-one case (TAK Server's database on the"
    echo "same machine as this container). If your database is on a"
    echo "separate server, see README.md's 'Creating the least-privilege"
    echo "database account' section for the SQL to run there by hand, then"
    echo "set DB_HOST/DB_USER/DB_PASSWORD from the System page."
    exit 0
fi

if [ "$install_mode" = docker ]; then
    echo "==> Detected Postgres running locally on this host, separate from"
    echo "    the Docker container."
else
    echo "==> Detected Postgres running locally on this host - the same machine"
    echo "    TAK-Extract is installed on, so the connection is over loopback."
fi
if [ "$skip_intro" = false ]; then
    echo
    echo "This script can automatically:"
    echo "  - create/update a least-privilege '$role' Postgres role"
    if [ "$install_mode" = docker ]; then
        echo "  - open pg_hba.conf to the Docker bridge subnet for that role+database only"
        echo "  - open a scoped firewall rule for port 5432 (ufw or firewalld, whichever"
        echo "    this host has)"
        echo "  - if needed, widen Postgres's listen_addresses (asked separately, since"
        echo "    that one requires a full Postgres restart)"
    else
        echo "  - add a pg_hba.conf line for that role+database over loopback, if one"
        echo "    isn't already there"
        echo "  - set up the re-check folder"
        echo "    (nothing is opened to the network: the connection never leaves this"
        echo "    machine, so there is no firewall rule and no listen_addresses change)"
    fi
    echo "Each of those is asked about individually as it comes up - decline any"
    echo "and you'll get the exact command to run yourself instead."
    printf '%s' "Continue? [Y/n] "
    read -r answer || answer=""
    case "$answer" in
        [Nn]*) echo "Nothing changed."; exit 0 ;;
    esac
fi

# ---------------------------------------------------------------------------
# Discover the Docker bridge gateway + subnet - container-inspect first
# (robust regardless of the Compose project name, which is NOT predictable
# from the directory name alone).
# ---------------------------------------------------------------------------
if [ "$install_mode" = docker ]; then
    echo "==> Finding the Docker bridge gateway..."
    gateway="$(docker inspect "$container_id" --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' 2>/dev/null)" || true
    network_name="$(docker inspect "$container_id" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)" || true
    subnet=""
    if [ -n "$network_name" ]; then
        subnet="$(docker network inspect "$network_name" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)" || true
    fi

    if [ -z "$gateway" ] || [ -z "$subnet" ]; then
        echo "    Couldn't determine the container's own network gateway/subnet -"
        echo "    this is unusual (an unexpected Docker network setup). Set"
        echo "    DB_HOST manually from the System page instead."
        exit 1
    fi
    echo "    Gateway: ${HL}${gateway}${HL_OFF}   Subnet: $subnet"
else
    # Nothing to discover: the app and Postgres are the same machine. Every
    # step below that takes an address takes these, so the pg_hba line is
    # scoped to loopback and the firewall is left alone entirely.
    gateway=127.0.0.1
    subnet=127.0.0.1/32
    echo "==> The app and Postgres are on the same machine - connecting over"
    echo "    ${HL}${gateway}${HL_OFF}. Nothing is opened to the network."
fi

# ---------------------------------------------------------------------------
# Locate Postgres's real config files - cross-distro (this project
# supports both Rocky 9 and Ubuntu 22.04), so use Postgres's own SHOW
# commands rather than a Debian-only tool like pg_lsclusters.
# ---------------------------------------------------------------------------
echo "==> Locating Postgres's configuration..."
hba_file="$(pg_psql -tAc "SHOW hba_file;" 2>&1)" || {
    echo "    Couldn't query Postgres as the 'postgres' OS user: $hba_file"
    exit 1
}
config_file="$(pg_psql -tAc "SHOW config_file;" 2>&1)" || {
    echo "    Couldn't query Postgres as the 'postgres' OS user: $config_file"
    exit 1
}
echo "    pg_hba.conf: $hba_file"
echo "    postgresql.conf: $config_file"

# ---------------------------------------------------------------------------
# listen_addresses - the one step that needs a full restart, so it gets
# its own explicit, separately-gated confirmation.
# ---------------------------------------------------------------------------
echo "==> Checking listen_addresses..."
current_listen="$(pg_psql -tAc "SHOW listen_addresses;" 2>/dev/null | tr -d ' ')" || current_listen=""
listen_ok=false
case "$current_listen" in
    "*"|"0.0.0.0"*) listen_ok=true ;;
    *"$gateway"*) listen_ok=true ;;
esac
# Side-by-side: the connection is loopback, which Postgres listens on out of
# the box under the name "localhost" - a string the gateway match above
# cannot see. Without this the script would offer to widen listen_addresses
# and restart Postgres to reach an address it can already reach.
if [ "$install_mode" = baremetal ]; then
    case "$current_listen" in
        *localhost*|*127.0.0.1*) listen_ok=true ;;
    esac
fi

restarted=false
if [ "$listen_ok" = true ]; then
    echo "    Already listening broadly enough ('$current_listen') - no restart needed."
else
    echo "    Currently: '$current_listen' - too narrow to reach from the container."
    do_restart=false
    if [ "$allow_restart" = true ]; then
        do_restart=true
    else
        echo
        echo "    Postgres currently only listens on localhost. Making it reachable"
        echo "    from the Docker container requires changing listen_addresses, which"
        echo "    needs a FULL RESTART of Postgres (not just a reload) - this will"
        echo "    briefly drop TAK Server's own connection to its database while it"
        echo "    restarts."
        printf '%s' "    Restart Postgres now to apply this? [y/N] "
        read -r restart_answer || restart_answer=""
        case "$restart_answer" in
            [Yy]*) do_restart=true ;;
        esac
    fi

    if [ "$do_restart" = true ]; then
        run pg_psql -c "ALTER SYSTEM SET listen_addresses = '*';"
        restart_err=""
        if [ "$dry_run" = false ]; then
            # Tracked explicitly. The previous shape - a nested `if ! ... &&
            # ! ...` - had a gap: when the plain `postgresql` unit failed AND
            # the version lookup came back empty, the inner test was false,
            # nothing exited, and control fell straight through to the
            # readiness poll. Which then PASSED, because Postgres had never
            # actually restarted and was still serving happily with the old
            # listen_addresses. The script then reported "Restarted and
            # confirmed reachable" and wrote .env - three false statements,
            # and a connection that fails later from the UI for no visible
            # reason. ALTER SYSTEM above had written the setting to
            # postgresql.auto.conf, but it was not in effect.
            restart_ok=false
            if restart_err="$(sudo systemctl restart postgresql 2>&1)"; then
                restart_ok=true
            else
                # Rocky/RHEL name the unit by major version. SHOW gives e.g.
                # 150004 for 15.4 - the first two characters are the major.
                major="$(pg_psql -tAc "SHOW server_version_num;" 2>/dev/null | cut -c1-2)" || major=""
                if [ -n "$major" ] && restart_err="$(sudo systemctl restart "postgresql-$major" 2>&1)"; then
                    restart_ok=true
                fi
            fi
            if [ "$restart_ok" = false ]; then
                echo "    Couldn't restart Postgres (tried units 'postgresql' and"
                echo "    'postgresql-${major:-<major>}'): $restart_err"
                echo "    Find the right unit name with:"
                echo "      systemctl list-units --type=service | grep -i postgres"
                echo "    then restart it yourself and re-run this script."
                exit 1
            fi
            # pg_isready is the clean check, but it lives in the postgresql-
            # client package and isn't guaranteed on PATH - the detection at
            # the top of this script already falls back to systemctl for that
            # reason, and this poll has to as well. Without the fallback, a
            # host without pg_isready got "Postgres did not come back up" ten
            # times over - a genuinely alarming message to hand county IT
            # staff who just restarted the database TAK Server depends on,
            # when in fact it was fine.
            ready=false
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                if command -v pg_isready >/dev/null 2>&1; then
                    if pg_isready -h 127.0.0.1 -p 5432 -t 2 >/dev/null 2>&1; then
                        ready=true; break
                    fi
                elif pg_psql -tAc "SELECT 1;" >/dev/null 2>&1; then
                    ready=true; break
                fi
                sleep 1
            done
            if [ "$ready" = false ]; then
                echo "    Postgres did not come back up after restarting - this is"
                echo "    serious (TAK Server depends on it too). Check:"
                echo "      sudo systemctl status postgresql"
                echo "      sudo journalctl -u postgresql -n 50"
                exit 1
            fi
        fi
        restarted=true
        echo "    Restarted and confirmed reachable."
    else
        echo "    Skipping the restart - pg_hba.conf/role/ufw will still be set up"
        echo "    below, but the connection won't actually work until you run:"
        echo "      sudo -u postgres psql -c \"ALTER SYSTEM SET listen_addresses = '*';\""
        echo "      sudo systemctl restart postgresql"
    fi
fi

# ---------------------------------------------------------------------------
# pg_hba.conf - idempotent, no hand-editing.
# ---------------------------------------------------------------------------
echo "==> Checking pg_hba.conf..."
method="$(sudo grep -E '^host[[:space:]]+\S+[[:space:]]+\S+[[:space:]]+127\.0\.0\.1/32[[:space:]]+' "$hba_file" 2>/dev/null | awk '{print $NF}' | tail -n1)" || true
if [ -z "$method" ]; then
    method="scram-sha-256"
    echo "    Couldn't find an existing 127.0.0.1/32 rule to match its auth method"
    echo "    against - defaulting to '$method'. Check $hba_file if this is wrong."
fi
hba_line="host    $db             $role       $subnet          $method"
hba_note="checked/updated ($hba_file)"
if sudo grep -qE "^host[[:space:]]+$db[[:space:]]+$role[[:space:]]+$subnet[[:space:]]+" "$hba_file" 2>/dev/null; then
    echo "    Already present, nothing to add."
elif confirm_step "Add this line to $hba_file and reload Postgres?  ($hba_line)"; then
    echo "    Adding: $hba_line"
    if [ "$dry_run" = true ]; then
        echo "    [dry-run] append to $hba_file"
    else
        echo "$hba_line" | sudo tee -a "$hba_file" >/dev/null
        run pg_psql -c "SELECT pg_reload_conf();"
    fi
else
    hba_note="SKIPPED at your request"
    echo "    Skipped."
    add_manual_step "pg_hba.conf - append this line to $hba_file, then reload:
    $hba_line
    sudo -u postgres psql -c \"SELECT pg_reload_conf();\""
fi

# ---------------------------------------------------------------------------
# Host firewall - ufw on Ubuntu, firewalld on Rocky/RHEL (this project's
# other supported platform, which ships firewalld and NOT ufw - so the
# firewalld branch is the normal path there, not an edge case). Neither
# being present isn't fatal: some hosts use raw nftables or a cloud
# security group instead. Recorded in firewall_note for the summary, so
# the summary can't claim "rule added" for a firewall that wasn't touched.
# ---------------------------------------------------------------------------
echo "==> Checking the host firewall..."
firewall_note="none found - open TCP 5432 from $subnet yourself"
if [ "$install_mode" = baremetal ]; then
    # A loopback connection never reaches a firewall. Opening 5432 here would
    # be a hole for no reason at all.
    firewall_note="not needed - the connection never leaves this machine"
    echo "    Not needed: the app connects over loopback, which no host firewall"
    echo "    sees. Nothing changed."
elif command -v ufw >/dev/null 2>&1; then
    # Look before asking, like the pg_hba/role/folder steps: a rule for
    # 5432 from this subnet already in `ufw status` means nothing to do.
    # (Rule lines read "5432/tcp   ALLOW IN   172.24.0.0/16".)
    ufw_existing="$(sudo ufw status 2>/dev/null | grep -E "^5432(/tcp)?[[:space:]]+ALLOW([[:space:]]+IN)?[[:space:]]+$subnet([[:space:]]|$)" || true)"
    if [ -n "$ufw_existing" ]; then
        echo "    Already present in ufw: $ufw_existing"
        firewall_note="ufw rule already present"
    elif confirm_step "Open TCP 5432 from $subnet in ufw?"; then
        # ufw answers "Skipping adding existing rule" for one already there;
        # the summary should say that rather than "added".
        if [ "$dry_run" = true ]; then
            run sudo ufw allow from "$subnet" to any port 5432 proto tcp
            firewall_note="ufw rule would be added (dry-run)"
        elif ufw_out="$(sudo ufw allow from "$subnet" to any port 5432 proto tcp 2>&1)"; then
            echo "$ufw_out"
            case "$ufw_out" in
                *"existing rule"*) firewall_note="ufw rule already present" ;;
                *) firewall_note="ufw rule added" ;;
            esac
        else
            echo "$ufw_out"
            firewall_note="ufw command failed - check the output above"
        fi
    else
        firewall_note="SKIPPED at your request"
        echo "    Skipped."
        add_manual_step "firewall (ufw) - allow the Docker subnet in to Postgres:
    sudo ufw allow from $subnet to any port 5432 proto tcp"
    fi
elif command -v firewall-cmd >/dev/null 2>&1 && fwd_existing="$(sudo firewall-cmd --list-rich-rules 2>/dev/null | grep -F "source address=\"$subnet\"" | grep -F 'port port="5432"' || true)" && [ -n "$fwd_existing" ]; then
    # Same look-first as ufw: a rich rule for 5432 from this subnet is
    # already there, so nothing to ask.
    echo "    Already present in firewalld: $fwd_existing"
    firewall_note="firewalld rich rule already present"
elif command -v firewall-cmd >/dev/null 2>&1 && ! confirm_step "Open TCP 5432 from $subnet in firewalld?"; then
    firewall_note="SKIPPED at your request"
    echo "    Skipped."
    add_manual_step "firewall (firewalld) - allow the Docker subnet in to Postgres:
    sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=\"$subnet\" port port=5432 protocol=tcp accept'
    sudo firewall-cmd --reload"
elif command -v firewall-cmd >/dev/null 2>&1; then
    # A rich rule scoped to the Docker subnet, same intent as the ufw line
    # above. --permanent writes it; --reload applies it without dropping
    # existing connections. Both run through run(), so --dry-run shows them.
    run sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=\"$subnet\" port port=5432 protocol=tcp accept"
    run sudo firewall-cmd --reload
    firewall_note="firewalld rich rule added"
else
    echo "    Neither ufw nor firewalld found - if this host uses a different"
    echo "    firewall (raw iptables/nftables, a cloud security group), open TCP"
    echo "    5432 from $subnet manually."
fi

# ---------------------------------------------------------------------------
# Role creation/update - idempotent, password never silently rotated.
# ---------------------------------------------------------------------------
echo "==> Checking the '$role' database role..."
role_exists="$(pg_psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$role';" 2>/dev/null | tr -d ' ')"
password=""
role_skipped=false
if [ -z "$role_exists" ]; then
    if confirm_step "Create a read-only Postgres role '$role' (generated password) and grant it SELECT on the tables this tool reads?"; then
        password="$(gen_password)"
        echo "    Creating role '$role'..."
        run pg_psql -c "CREATE ROLE $role WITH LOGIN PASSWORD '$password';"
    else
        role_skipped=true
        echo "    Skipped."
        add_manual_step "database role - as a Postgres superuser, run (pick your own password):
    sudo -u postgres psql -c \"CREATE ROLE $role WITH LOGIN PASSWORD 'choose-a-strong-password';\"
    sudo -u postgres psql -c \"GRANT CONNECT ON DATABASE $db TO $role;\"
    sudo -u postgres psql -d $db -c \"GRANT USAGE ON SCHEMA public TO $role;\"
    then GRANT SELECT on each table - the full list is in README.md under
    'Creating the least-privilege database account'. Afterwards set
    DB_USER=$role and DB_PASSWORD from the System page (or in .env)."
    fi
elif [ "$reset_password" = true ]; then
    password="$(gen_password)"
    echo "    Role already exists - rotating its password (--reset-password)..."
    run pg_psql -c "ALTER ROLE $role WITH PASSWORD '$password';"
else
    echo "    Role already exists - leaving its password unchanged"
    echo "    (use --reset-password to rotate it)."
fi
# Printed NOW, not only in the final summary: everything after this point
# (the grants, the live check) can still fail, and if it does the role
# already exists with this password - which nobody would ever have seen.
# A re-run then takes the "leaving its password unchanged" branch above,
# so the second attempt can't write DB_PASSWORD either, and the only way
# out is --reset-password. Showing it here means an abort lower down is
# recoverable by hand instead of a dead end.
if [ -n "$password" ] && [ "$dry_run" != true ]; then
    echo "    Password for '$role' (also written to .env at the end if the live"
    echo "    check passes - copy it now in case something below fails): ${HL}${password}${HL_OFF}"
fi

# The tables the role needs SELECT on. One GRANT per table, not one
# statement for all 25: a single statement is all-or-nothing, so one table
# missing from this TAK Server's schema version would reject the whole
# thing, `set -e` would abort, and the installer would get a raw "relation
# does not exist" with the role already created and no .env written.
# Per-table, a missing table is skipped and named, and every table that IS
# there gets its grant - which is what a least-privilege read-only role
# needs anyway. The list must stay in sync with README.md's manual SQL block.
grant_tables="cot_router cot_router_chat cot_image cot_link cot_thumbnail
    groups client_endpoint client_endpoint_event connection_event_type
    mission mission_change mission_subscription mission_uid
    mission_resource mission_external_data mission_log mission_invitation
    resource video_connections video_connections_v2
    data_feed data_feed_cot data_feed_type_pl
    fed_event fed_event_kind_pl properties_uid"

# Grants ride along with the role decision above: a freshly created role
# gets them as part of "create with minimal access". A pre-existing role
# is looked at first - which of those tables (of the ones that exist here)
# it cannot SELECT, and whether it has CONNECT and USAGE - and only asked
# about when something is missing, since re-applying grants is still a
# change to someone else's database: harmless and idempotent, but theirs
# to decline. "ok" from the query means nothing is missing; an empty
# answer means the check itself failed, and the old ask-anyway path runs.
grants_note=""
grants_lacking=""
if [ -n "$role_exists" ] && [ "$role_skipped" = false ]; then
    tbl_list="$(printf "'%s'," $grant_tables)"; tbl_list="${tbl_list%,}"
    grants_lacking="$(pg_psql -d "$db" -tAc "
        SELECT coalesce(string_agg(x, ' ' ORDER BY x), 'ok') FROM (
            SELECT c.relname AS x FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind IN ('r','v','p','m')
              AND c.relname = ANY (ARRAY[$tbl_list])
              AND NOT has_table_privilege('$role', c.oid, 'SELECT')
            UNION ALL SELECT 'CONNECT-on-database' WHERE NOT has_database_privilege('$role', '$db', 'CONNECT')
            UNION ALL SELECT 'USAGE-on-schema-public' WHERE NOT has_schema_privilege('$role', 'public', 'USAGE')
        ) q;" 2>/dev/null | tr -d '\r' || true)"
fi
apply_grants=true
if [ "$role_skipped" = true ]; then
    apply_grants=false
elif [ "$grants_lacking" = "ok" ]; then
    apply_grants=false
    echo "    Already granted: SELECT on every table this tool reads that exists here, plus CONNECT and USAGE."
    grants_note="already in place"
elif [ -n "$role_exists" ] && [ -n "$grants_lacking" ] && ! confirm_step "Grant '$role' what it is missing ($grants_lacking)?"; then
    apply_grants=false
    echo "    Skipped."
    grants_note="SKIPPED at your request - missing: $grants_lacking"
    add_manual_step "grants - '$role' is missing: $grants_lacking; the
    table list and statements are in README.md under 'Creating the least-privilege database account'."
elif [ -n "$role_exists" ] && [ -z "$grants_lacking" ] && ! confirm_step "Re-apply the read-only SELECT grants to the existing role '$role'? (could not check what it has)"; then
    apply_grants=false
    echo "    Skipped."
    grants_note="SKIPPED at your request"
    add_manual_step "grants - re-apply SELECT to '$role' if it's missing any; the
    table list is in README.md under 'Creating the least-privilege database account'."
fi
if [ "$apply_grants" = true ]; then
echo "    Applying grants..."
run pg_psql -c "GRANT CONNECT ON DATABASE $db TO $role;"
run pg_psql -d "$db" -c "GRANT USAGE ON SCHEMA public TO $role;"
grant_missing=""
for t in $grant_tables; do
    if [ "$dry_run" = true ]; then
        echo "    [dry-run] sudo -u postgres psql -d $db -c \"GRANT SELECT ON $t TO $role;\""
    elif ! pg_psql -d "$db" -qc "GRANT SELECT ON $t TO $role;" >/dev/null 2>&1; then
        grant_missing="$grant_missing $t"
    fi
done
if [ -n "$grant_missing" ]; then
    echo "    Not present on this server's schema (skipped, not an error):$grant_missing"
    echo "    The matching export file(s) will simply come back empty/unavailable."
fi
grants_note="$([ "$dry_run" = true ] && echo 'would be applied (dry-run)' || echo 'applied')"
fi  # apply_grants

# ---------------------------------------------------------------------------
# One optional EXECUTE grant: pg_control_system(), which returns the
# cluster's system_identifier - a value fixed when the cluster was created
# and unchanged by restarts, address changes or TAK Server upgrades. Each
# export records it, so a package can be told apart from one produced
# against a different database, and the System page can notice this install
# being repointed at another server.
#
# Read-only and tiny: the function returns the control file's own fields
# (identifier, catalog version, and when it was last written). It grants no
# access to any data.
#
# This step usually grants nothing, because the privilege is usually already
# there: pg_control_system() carries no privilege list of its own on a stock
# cluster - pg_proc.proacl is NULL for it on PostgreSQL 18, checked on two
# clusters - so Postgres's default applies and any role can call it. The
# documentation names a superuser restriction for the server-signalling and
# recovery-control functions and says nothing of the kind for the control-data
# ones. This comment used to claim the opposite, and the step was described as
# existing only because of that restriction.
#
# It stays because the privilege can be revoked, so it has to be checked
# rather than assumed - which is what the has_function_privilege call below
# does, reporting 'Already granted' on the clusters where nothing is needed.
#
# Declining is a real option - without it the export falls back to catalog
# identifiers (database name and OIDs) which any role can read, and says in
# the package that it did. Looked at before asking, like every other step.
# ---------------------------------------------------------------------------
identity_note="not granted - exports use the weaker catalog fingerprint"
# `role_skipped` alone, NOT `-n "$role_exists"`: role_exists is captured
# before the role is created, so testing it meant this step only ran when
# the role ALREADY existed - i.e. on a re-run. A fresh install, which is
# exactly when you want the cluster identifier recorded from the first
# export onward, silently skipped it and reported "not granted" without
# ever asking. Found on the first complete side-by-side install.
if [ "$role_skipped" = false ]; then
    echo "==> Checking whether '$role' can read the cluster's own identifier..."
    has_exec="$(pg_psql -d "$db" -tAc \
        "SELECT has_function_privilege('$role', 'pg_control_system()', 'EXECUTE');" \
        2>/dev/null | tr -d '\r ' || true)"
    if [ "$has_exec" = "t" ]; then
        echo "    Already granted."
        identity_note="already granted"
    elif confirm_step "Grant '$role' EXECUTE on pg_control_system()? (read-only; lets each export record which database cluster it came from)"; then
        if run pg_psql -d "$db" -c "GRANT EXECUTE ON FUNCTION pg_control_system() TO $role;"; then
            identity_note="$([ "$dry_run" = true ] && echo 'would be granted (dry-run)' || echo 'granted')"
        else
            # Not fatal: the export degrades to the catalog fingerprint.
            identity_note="could not be granted - exports use the weaker catalog fingerprint"
            echo "    Could not grant it. Exports will record the catalog fingerprint instead,"
            echo "    and will say so. Nothing else is affected."
        fi
    else
        echo "    Skipped. Exports will record the weaker catalog fingerprint and say so."
        identity_note="SKIPPED at your request"
        add_manual_step "cluster identifier - to let each export record which database it
    came from, run:
    sudo -u postgres psql -d $db -c \"GRANT EXECUTE ON FUNCTION pg_control_system() TO $role;\""
    fi
fi

# ---------------------------------------------------------------------------
# The re-check folder. After an export, the Export page shows the
# administrator one line to paste on this host: it re-runs the package's
# statements with psql and keeps the results, per case, under
#   /var/lib/takextract/recheck/<case>/<date-time>/
# psql runs as the postgres account and must be able to write there; the
# administrator must be able to read, move and archive the files without
# sudo. Hence: the folder owned by postgres, group takextract (an OS group,
# no login of its own) holding postgres and the admin accounts, mode 2770 -
# the setgid bit makes every case folder and file inherit the group. This
# is file-system permission only; it has nothing to do with the database
# role above or its privileges. Idempotent: re-running reports what is
# already in place.
# ---------------------------------------------------------------------------
recheck_dir=/var/lib/takextract/recheck
recheck_group=takextract
recheck_setup_marker=""   # written to .env as RECHECK_FOLDER_SETUP when the folder is in place
admin_user="${SUDO_USER:-${USER:-}}"
echo "==> Checking the re-check folder ($recheck_dir)..."
folder_state="$(stat -c '%U:%G %a' "$recheck_dir" 2>/dev/null || true)"
# getent exits 2 when the group does not exist yet - the normal answer on a
# first run, not a failure - so it must not trip pipefail/the ERR trap.
group_exists="$(getent group "$recheck_group" 2>/dev/null | cut -d: -f1 || true)"
pg_in_group="$(id -nG postgres 2>/dev/null | tr ' ' '\n' | grep -x "$recheck_group" || true)"
admin_in_group="$(id -nG "$admin_user" 2>/dev/null | tr ' ' '\n' | grep -x "$recheck_group" || true)"
if [ "$folder_state" = "postgres:$recheck_group 2770" ] && [ -n "$group_exists" ] && [ -n "$pg_in_group" ] && [ -n "$admin_in_group" ]; then
    echo "    Already in place: $recheck_dir is postgres:$recheck_group 2770; postgres and $admin_user are in '$recheck_group'."
    recheck_note="already in place"
    recheck_setup_marker="$(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname) by ${admin_user:-unknown} (connect-database.sh, already in place)"
elif confirm_step "Create the re-check folder $recheck_dir and the '$recheck_group' group (postgres writes, admins read and manage; no new logins)?"; then
    [ -n "$group_exists" ] && echo "    Group '$recheck_group' exists." || run sudo groupadd -f "$recheck_group"
    [ -n "$pg_in_group" ] && echo "    postgres is already in '$recheck_group'." || run sudo usermod -aG "$recheck_group" postgres
    if [ -z "$admin_user" ]; then
        add_manual_step "Add each administrator account to the '$recheck_group' group: sudo usermod -aG $recheck_group <account> (this run could not tell which account you are)."
    elif [ -n "$admin_in_group" ]; then
        echo "    $admin_user is already in '$recheck_group'."
    else
        run sudo usermod -aG "$recheck_group" "$admin_user"
    fi
    run sudo mkdir -p "$recheck_dir"
    run sudo chown "postgres:$recheck_group" "$recheck_dir"
    run sudo chmod 2770 "$recheck_dir"
    if [ -n "$admin_user" ] && { [ -z "$admin_in_group" ] || [ -z "$pg_in_group" ]; }; then
        add_note "Log out and back in (or 'newgrp $recheck_group') so the '$recheck_group' group membership applies; then the re-check line from the Export page can be pasted here."
    fi
    echo "    Done: $recheck_dir is postgres:$recheck_group 2770."
    recheck_note="$([ "$dry_run" = true ] && echo 'would be created (dry-run)' || echo "created: postgres:$recheck_group 2770")"
    recheck_setup_marker="$(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname) by ${admin_user:-unknown} (connect-database.sh)"
else
    echo "    Skipped. The Export page's re-check line needs this folder; the one-time"
    echo "    setup line is also shown on the System page (Re-check folder)."
    recheck_note="SKIPPED at your request"
fi

# ---------------------------------------------------------------------------
# End-to-end verification - only possible when we actually know the
# password (a fresh create or an explicit --reset-password).
# ---------------------------------------------------------------------------
if [ "$dry_run" = true ]; then
    echo "==> Skipping live verification (--dry-run)."
elif [ "$role_skipped" = true ]; then
    echo "==> Skipping live verification (no role was created to test with)."
elif [ -n "$password" ]; then
    # Verify from INSIDE the container, not from the host. The pg_hba rule
    # we just added is scoped to the Docker subnet ($subnet) - which is
    # correct, that's where the container lives - but the host's own
    # connection to the gateway IP arrives at Postgres from the host's LAN
    # address, which is NOT in that subnet, so a host-side psql check fails
    # ("no pg_hba.conf entry for host <LAN-IP>") even though the real setup
    # is fine. The container's connection comes from inside $subnet and
    # matches. So test the path the app actually uses: the container's own
    # python/psycopg2, password passed via env (not argv, so it isn't
    # visible in the container's process list).
    echo "==> Verifying the connection the way the app makes it..."
    verify_err=""
    verify_py="import os, psycopg2; psycopg2.connect(host='$gateway', port=5432, user='$role', password=os.environ['VERIFY_PW'], dbname='$db', connect_timeout=5).close(); print('ok')"
    if [ "$install_mode" = docker ]; then
        # From inside the container: its connection comes from $subnet, and
        # that is the path the pg_hba line above was written for. The
        # password goes by env, not argv, so it is not in the process list.
        verify_ok=true
        verify_err="$(docker compose exec -T -e VERIFY_PW="$password" web python -c "$verify_py" 2>&1)" || verify_ok=false
    else
        # Same idea, the installed venv's own python - the interpreter
        # gunicorn will be running under. Checked for first: run from the
        # checkout rather than from the install, the failure would otherwise
        # read as a database problem when it is a wrong-directory problem.
        if [ ! -x "$install_dir/venv/bin/python" ]; then
            echo "    No virtual environment at $install_dir/venv."
            echo "    This script verifies the connection with the interpreter the app runs"
            echo "    under, so run it from the install itself:"
            echo "      cd /opt/tak-extract && sudo ./connect-database.sh"
            echo "    .env was NOT updated."
            exit 1
        fi
        verify_ok=true
        verify_err="$(VERIFY_PW="$password" "$install_dir/venv/bin/python" -c "$verify_py" 2>&1)" || verify_ok=false
    fi
    if [ "$verify_ok" = true ]; then
        echo "    Connected successfully."
    else
        echo "    Connection failed: $verify_err"
        echo "    .env was NOT updated - fix the above and re-run."
        exit 1
    fi
else
    echo "==> Skipping live verification (role already existed, password unknown)"
    echo "    - use tests/test_db.py to verify manually, or re-run with --reset-password."
fi

# ---------------------------------------------------------------------------
# Write .env and apply it.
# ---------------------------------------------------------------------------
if [ "$dry_run" = true ]; then
    if [ "$role_skipped" = true ]; then
        echo "==> [dry-run] Would write DB_HOST=$gateway DB_PORT=5432 DB_NAME=$db to .env"
        echo "    (DB_USER/DB_PASSWORD left for you, since the role was skipped), and"
        echo "    apply it ($([ "$install_mode" = docker ] && echo 'docker compose up -d' || echo 'systemctl restart tak-extract'))."
    else
        echo "==> [dry-run] Would write DB_HOST=$gateway DB_PORT=5432 DB_NAME=$db DB_USER=$role"
        echo "    to .env, and apply it ($([ "$install_mode" = docker ] && echo 'docker compose up -d' || echo 'systemctl restart tak-extract'))."
    fi
else
    echo "==> Updating .env..."
    # set_or_add_env_var throughout: set_env_var only REPLACES a line that
    # already exists, so against a hand-built .env missing any of these keys
    # it silently writes nothing - the run would print the generated password
    # and then fail to persist it. Noted in the pre-push security review.
    set_or_add_env_var DB_HOST "$gateway"
    set_or_add_env_var DB_PORT 5432
    set_or_add_env_var DB_NAME "$db"
    # DB_HOST/PORT/NAME are just facts about where the database is - always
    # worth writing. DB_USER only if the role actually exists (created now,
    # or found already there); writing a username for a role that was
    # declined would point the app at an account that doesn't exist.
    if [ "$role_skipped" = false ]; then
        set_or_add_env_var DB_USER "$role"
    fi
    if [ -n "$password" ]; then
        set_or_add_env_var DB_PASSWORD "$password"
        echo "    Password (shown once): $password"
    fi
    # An existing role's password cannot be read back, so a run that finds
    # the role already there has nothing to write - and if .env was recreated
    # in the meantime (setup.sh builds a fresh one from .env.example when
    # there is none), DB_PASSWORD is left EMPTY and the app cannot connect at
    # all. The summary used to report ".env: updated" either way, which reads
    # as success; the only hint was a "skipping live verification" line
    # several steps earlier. Seen on a real install after the operator
    # deleted .env and re-ran.
    if [ "$role_skipped" = false ] && [ -z "$(get_env_var DB_PASSWORD "")" ]; then
        # Carefully NOT phrased as "the app cannot connect". .env is not the
        # live source: app.py's get_setting() reads app_settings in
        # audit.sqlite FIRST and falls back to the environment only when
        # nothing is stored there. So on an install where anyone has saved
        # the connection on the System page, the app is connecting fine and
        # an empty DB_PASSWORD means nothing. Telling that operator to run
        # --reset-password would rotate the role, invalidate the password
        # app_settings still holds, and write the new one where it is
        # ignored - breaking a working evidence tool, with the System page
        # still reporting the password as set. Caught in the pre-push
        # security review, in wording added an hour earlier.
        env_note="DB_PASSWORD is empty in .env"
        echo
        echo "    !! DB_PASSWORD is empty in .env. The role already existed, and an"
        echo "       existing role's password cannot be read back, so this run had"
        echo "       none to write."
        echo
        echo "       Check System -> TAK Server connection FIRST. A password saved"
        echo "       there lives in the audit database and takes priority over .env,"
        echo "       so the app may already be connecting perfectly well."
        echo
        echo "       If it is not connecting, rotate the password:"
        echo "         cd $install_dir && sudo ./connect-database.sh --reset-password"
        echo "       and then re-save it on the System page too - otherwise a"
        echo "       previously saved value keeps winning and the new one is ignored."
        add_note "DB_PASSWORD is empty in .env. Check System -> TAK Server connection
first: a password saved there takes priority over .env, so the app may already
be working. If it is not, run 'sudo ./connect-database.sh --reset-password' and
re-save the new password on the System page as well."
    fi
    # The System page's "Re-check folder" panel shows this as the sign that
    # the one-time setup has been done on this host (the app runs in a
    # container and cannot look at the host's folder itself).
    if [ -n "$recheck_setup_marker" ]; then
        set_or_add_env_var RECHECK_FOLDER_SETUP "$recheck_setup_marker"
    fi

    echo "==> Applying the change..."
    if [ "$install_mode" = docker ]; then
        docker compose up -d >/dev/null
    else
        sudo systemctl restart tak-extract
    fi

    echo
    echo "    If you'd already configured a TAK Server connection manually via"
    echo "    the System page before running this script, that saved setting"
    echo "    takes priority over what was just written to .env. Open"
    echo "    System -> TAK Server connection and click Save there too (with"
    echo "    these same values) to make sure it's actually using them."

    # ---------------------------------------------------------------------
    # Record what the database looks like right now, so a later upgrade can
    # be compared against it. Seeded HERE rather than on the first manual
    # run, because otherwise the first run after an upgrade would quietly
    # baseline the upgraded state and there would be nothing to notice.
    # Looks before it asks, like every other step: an existing baseline is
    # reported and left alone.
    # ---------------------------------------------------------------------
    echo
    echo "==> Recording the database's structure as the baseline..."
    baseline_note="recorded"
    if [ "$install_mode" = docker ]; then
        baseline_out="$(docker compose exec -T web python dbcheck.py --quick --no-audit 2>&1)" || true
    else
        # The settings go across in a file only the service account can
        # read, NOT as `env KEY=VALUE` arguments: argv is world-readable via
        # /proc/<pid>/cmdline and sudo logs the whole command line to the
        # auth log, so arguments would publish the database password to
        # every local account and every log reader. See the longer note in
        # check-database.sh. SECRET_KEY is not passed at all - dbcheck signs
        # nothing, and app.py only needs the value to be non-empty.
        baseline_user="$(get_env_var SERVICE_USER takextract)"
        # Written by the administrator, never through sudo: `Defaults
        # log_input` records a sudo'd command's stdin to /var/log/sudo-io,
        # which would put the database password straight back into a
        # durable, shipped-off-the-box log. sudo only hands the finished
        # file over and removes it, where its own log sees a path.
        umask 077
        baseline_secrets_dir="$(mktemp -d)" || baseline_secrets_dir=""
        baseline_secrets="$baseline_secrets_dir/env"
        if [ -n "$baseline_secrets_dir" ]; then
            {
                for key in AUDIT_DB DB_HOST DB_PORT DB_NAME DB_USER \
                           DB_PASSWORD AUTH_MODE; do
                    val="$(get_env_var "$key" "")"
                    if [ -n "$val" ]; then
                        esc="$(printf '%s' "$val" | sed "s/'/'\\\\''/g")"
                        printf "%s='%s'\n" "$key" "$esc"
                    fi
                done
                printf "%s='%s'\n" SECRET_KEY "placeholder-schema-check-signs-nothing"
            } > "$baseline_secrets"
            sudo chown "$baseline_user" "$baseline_secrets"
            chmod 0711 "$baseline_secrets_dir"
            baseline_out="$(sudo -u "$baseline_user" env TAKX_NO_BANNER=1 \
                sh -c 'set -a; . "$1"; set +a; shift; exec "$@"' sh "$baseline_secrets" \
                "$install_dir/venv/bin/python" dbcheck.py --quick --no-audit 2>&1)" || true
            cleanup_baseline_secrets
        else
            baseline_out="could not create a temporary file"
        fi
    fi
    if printf '%s' "$baseline_out" | grep -q "seeding from it"; then
        echo "    Recorded. A later upgrade will be compared against this."
    elif printf '%s' "$baseline_out" | grep -q "nothing changed"; then
        echo "    A baseline was already recorded, and the structure still matches it."
        baseline_note="already recorded, unchanged"
    elif printf '%s' "$baseline_out" | grep -q "Drift since"; then
        echo "    A baseline was already recorded and the structure has changed since."
        echo "    Run ./check-database.sh to see what, then approve it there or on"
        echo "    the System page if the change is expected."
        baseline_note="already recorded, DIFFERS - see ./check-database.sh"
    else
        echo "    Could not record it: $(printf '%s' "$baseline_out" | tail -n 2)"
        echo "    Not fatal - ./check-database.sh records it on its first run."
        baseline_note="not recorded - run ./check-database.sh"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "==> Summary"
if [ "$install_mode" = docker ]; then
    echo "    Gateway/subnet: ${HL}${gateway}${HL_OFF} / $subnet"
else
    echo "    Connecting over: ${HL}${gateway}${HL_OFF} (loopback, same machine)"
fi
echo "    listen_addresses: $([ "$listen_ok" = true ] && echo 'already sufficient' || { [ "$restarted" = true ] && echo 'widened, restarted' || echo 'still needs manual widening'; })"
echo "    pg_hba.conf: $hba_note"
echo "    firewall: $firewall_note"
echo "    re-check folder: $recheck_note"
echo "    cluster identifier: $identity_note"
echo "    structure baseline: ${baseline_note:-not recorded (dry-run)}"
# "would be" phrasing under --dry-run: these describe actions that were
# only printed, not taken, and the summary shouldn't read as if they were.
if [ "$role_skipped" = true ]; then
    echo "    Role '$role': SKIPPED at your request"
elif [ "$dry_run" = true ]; then
    echo "    Role '$role': $([ -z "$role_exists" ] && echo 'would be created' || { [ "$reset_password" = true ] && echo 'password would be rotated' || echo 'already exists, would be left unchanged'; }) (dry-run)"
else
    echo "    Role '$role': $([ -z "$role_exists" ] && echo 'created' || { [ "$reset_password" = true ] && echo 'password rotated' || echo 'already existed, unchanged'; })"
fi
echo "    Grants: ${grants_note:-n/a (role skipped)}"
applied="$([ "$install_mode" = docker ] && echo 'container recreated' || echo 'service restarted')"
echo "    .env: $([ "$dry_run" = true ] && echo 'not written (dry-run)' || { [ "$role_skipped" = true ] && echo 'DB_HOST/PORT/NAME written; DB_USER/DB_PASSWORD left for you to set' || echo "updated, $applied${env_note:+ - $env_note}"; })"

# Everything declined above, in one place, with the exact commands. This is
# the "what still needs to happen to get it working" list - the connection
# won't work until each of these is done by hand.
if [ -n "$manual_steps" ]; then
    echo
    echo "==> Still to do by hand (you chose to skip these):"
    echo "$manual_steps" | sed 's/^/    /'
    echo
    echo "    The database connection will not work until the above is done."
fi
if [ -n "$notes" ]; then
    echo
    echo "==> One more thing:"
    echo "$notes" | sed 's/^/    /'
fi
