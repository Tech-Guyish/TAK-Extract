# TAK-Extract

A self-hosted tool for pulling defensible, auditable location-data exports out of a TAK Server — built for records requests and after-action review, not analytics.

For any team that may have to say where a unit was, months later: search and rescue, fire, law enforcement, emergency management.

---

## What it is

TAK Server accumulates CoT (Cursor-on-Target) position reports in its own Postgres database, but has no built-in way to hand a slice of that data to a requester as a self-contained, verifiable package. TAK-Extract sits alongside an existing TAK Server, reads its database directly (read-only), and turns a case ID + time window + map area into:

- a **locations KMZ** for Google Earth, or
- a **full evidence package** — every relevant CSV, a plain-language README, and SHA-256 hashes, zipped

Every export is logged to a local audit trail (who, when, what parameters — never the location data itself), and a companion page lets anyone re-verify a package's hash against that log and replay its tracks on a map, entirely offline in the browser.

---

## Core components

- **TAK Server** – the source of truth; TAK-Extract only ever reads from its Postgres database
- **Postgres** (TAK Server's own) – queried directly with a dedicated, least-privilege account
- **Authentik** *(optional)* – if a reverse proxy in front of this app already does forward-auth, TAK-Extract trusts its identity header instead of running its own login

---

## What's in this repository

The three scripts at the top are the only things an administrator runs by hand; everything else is either the application, its pages, or the files that describe how it is deployed.

| | |
|---|---|
| `setup.sh` | **Start here.** Installs TAK-Extract — in Docker, or side by side with TAK Server — and writes `.env` |
| `connect-database.sh` | Creates the read-only Postgres role, applies the grants, opens the one network path the app needs, sets up the re-check folder, and records the schema baseline |
| `check-database.sh` | Run after any TAK Server or Postgres update: proves the exporter's own statements still resolve and reports what shifted underneath them |
| `app.py` | The application — every route and page, the audit log and its hash chain, users, roles and sessions |
| `exports.py` | Every SQL statement an export sends, and the assembly of the evidence package |
| `dbcheck.py` | The schema check that `check-database.sh` runs |
| `kmz.py`, `shapes.py` | The locations KMZ, and drawn map objects read out of a record's CoT detail |
| `tls.py` | The optional self-signed certificate, for an install with no reverse proxy in front of it |
| `templates/` | The pages themselves — Export, Verify & Replay, Audit Log, System, Guide, Login |
| `tests/` | Every regression suite, run one file at a time (`python tests/test_exports.py`). `tests/test_db.py` is the only one that needs a live database |
| `docs/` | The security policy, the evidence standards this design was measured against, third-party notices, and the User Guide's screenshots |
| `Dockerfile`, `docker-compose.yml` | The Docker install |
| `tak-extract.service`, `gunicorn.conf.py` | The side-by-side install: the systemd unit, and the server configuration both installs share |
| `requirements.txt` | What the app needs. `requirements-dev.txt` is Playwright, for the browser tests and the Guide's screenshots only |
| `.env.example` | Every setting there is, with what it does and what happens if it is left alone — `setup.sh` copies it to `.env` |
| `CHANGELOG.md` | What changed in each version, and why |

---

## Features

- **Export** — draw an area on a map, set a time window, preview record counts by category before committing to anything, filter by channel, then download. Shapes pushed to the server by software (an imported map layer; the record carries a `__nodered` element) are left out of the map outlines, `shapes.csv` and the KMZ unless the operator ticks the box; the package README states what was found and what was done either way
- **Verify & Replay** — drop a previously-exported file back in and get one verdict: whether the package matches an export recorded in the audit log (and when, by whom, for whom), whether every file inside it matches the hash list built with it (each one hashed in the browser — nothing is uploaded), whether its records fall inside the window originally requested, and whether an administrator's re-check was recorded. A button produces the certification with those facts filled in. Underneath, its tracks and drawn shapes replay on a map with per-device, per-channel playback controls, and a re-check file can be compared exactly by row id. A KMZ from TAK Server itself replays too, marked as not produced by this tool
- **Evidence package** — beside the CSVs, README and per-file hashes: `cot_router-raw.csv` (every column of the server's own rows, unmodified, written the way psql writes CSV), `queries.sql` (every statement as sent) and `VERIFY.txt` (one page on checking the package, for whoever receives it without access to this tool). The README prints the snapshot id, the database account and its write privileges as the database reports them, both clocks, the code's version and commit, and which database cluster the export was read from
- **The administrator's re-check** (optional corroboration, over and above what is required) — after an export, one line to paste on the TAK Server: it fetches the package's `queries.sql` from TAK-Extract, re-runs every statement with psql in one read-only snapshot into `/var/lib/takextract/recheck/<case>/<date-time>-<package>/` (one folder per re-check, so several exports under one case never overwrite each other), hashes and tars the results, and posts only the list of hashes back; TAK-Extract records it in the audit log and the raw file's hash is expected to equal the package's. No location data travels either way; the folder outlives the server's retention purge
- **Which database an export came from** — every export records the source database's own identity, so a package can be told apart from one produced against a different server and the System page can say whether the connection still points where recent exports were read from. Where the read-only account has been granted `EXECUTE` on `pg_control_system()` (offered by `connect-database.sh`) that is the cluster's identifier, fixed when the cluster was created; otherwise a weaker catalog fingerprint, which the package says it used and why. A difference is not in itself a sign that anything is wrong — a rebuilt or restored cluster reports a new identifier while holding the same data
- **User Guide** — built in, per role, with screenshots from synthetic data; includes a reference grid of what each file carries and a section on using an export as evidence
- **Audit Log** — every export request ever made: who, when, what was asked for, and the outcome — searchable, sortable, and itself exportable; hash-chained, so a later edit, deletion or insertion is detectable (verified from the System page or from the downloaded log)
- **System** — users and roles, TAK Server connection settings, database backup/restore, what the maps are allowed to contact, per-account display preferences, and a read-only check against GitHub for available updates (shows the commands to run — never applies anything on its own)

---

## Prerequisites

- An existing TAK Server with its Postgres database reachable from wherever TAK-Extract runs
- A dedicated, read-only Postgres account for TAK-Extract to connect with (not TAK Server's own internal database user) — see below for the exact SQL to create one
- Docker, **or** Python 3.10+ for a bare-metal install
- *(optional)* Authentik and a reverse proxy, if you want single sign-on instead of this app's own login

### Creating the least-privilege database account

There's no safe default for `DB_USER`/`DB_PASSWORD` — unlike a value like
`SECRET_KEY`, which this app can generate for itself, a database credential
has to already exist as a real role on TAK Server's own Postgres before
TAK-Extract can use it. Run this once, on the TAK Server's database host, as
a Postgres superuser (or whichever account owns the `cot` database):

```sql
-- Adjust the database name below if this deployment doesn't use the
-- standard "cot" (see DB_NAME in .env.example).
CREATE ROLE takextract WITH LOGIN PASSWORD 'replace-with-a-strong-password';
GRANT CONNECT ON DATABASE cot TO takextract;
GRANT USAGE ON SCHEMA public TO takextract;
GRANT SELECT ON
    cot_router, cot_router_chat, cot_image, cot_link, cot_thumbnail,
    groups, client_endpoint, client_endpoint_event, connection_event_type,
    mission, mission_change, mission_subscription, mission_uid,
    mission_resource, mission_external_data, mission_log, mission_invitation,
    resource, video_connections, video_connections_v2,
    data_feed, data_feed_cot, data_feed_type_pl,
    fed_event, fed_event_kind_pl, properties_uid
TO takextract;
```

That table list is exactly what TAK-Extract reads today (checked against
every `FROM`/`JOIN` in `exports.py`, including the census counts) — no
`INSERT`/`UPDATE`/`DELETE` grants anywhere, and no access to tables this
tool doesn't touch (TAK Server's own user/auth tables included). If a
future version starts reading a new table, this list — and the role's
grants on a live server — needs updating to match; see `CHANGELOG.md` for
anything that changes what gets queried.

**One optional extra grant.** Each export records which database it was
read from, so a package can be told apart from one produced against a
different server. The strong form of that is the cluster's own
`system_identifier`. On a stock cluster any role can already read it —
`pg_control_system()` carries no privilege list of its own, so Postgres's
default applies (checked on PostgreSQL 18; the documentation names a
superuser restriction for its signalling and recovery-control functions
and says nothing of the kind for the control-data ones). It can be
revoked, though, and this tool never assumes it. Where it has been:

```sql
GRANT EXECUTE ON FUNCTION pg_control_system() TO takextract;
```

It is read-only and returns only control-file fields (the identifier, the
catalog version, and when the control file was last written) — no access to
any data.
`connect-database.sh` checks first and says what it found — on most
clusters it finds the privilege already there and grants nothing. Without
it nothing breaks: the export falls back to catalog identifiers (the
database name and two OIDs, readable by any role) and states in the
package that it used the weaker fingerprint and why. Those are small
numbers that two unrelated servers could match by chance, which is the
only reason the grant is worth having.

### Connecting to Postgres on the same host

Running the SQL above by hand, plus figuring out the right `DB_HOST` and —
for a Docker install — widening Postgres's `listen_addresses`, adding a
`pg_hba.conf` rule and opening a firewall port, is what
`./connect-database.sh` automates. It reads `INSTALL_MODE` from `.env`
(written by `setup.sh`) and does only what that shape of install needs:

- **Docker** — the container reaches Postgres across the Docker bridge, so
  the gateway has to be discovered and `pg_hba.conf` and the host firewall
  opened to that subnet.
- **Side by side** — the app is on the same machine and reaches Postgres
  over loopback, so there is no gateway to find, no firewall rule to add
  and no `listen_addresses` to widen. The script says so rather than
  offering them.

The read-only role, its grants and the re-check folder are the same work
either way:

```bash
./connect-database.sh
```

It detects whether Postgres is running locally, finds the real address to
reach it at (the Docker bridge gateway — `127.0.0.1` from inside a
container is the container's own loopback, not the host's), and then
**asks before each individual change to the host**: the `pg_hba.conf`
rule, the firewall rule (ufw or firewalld), and the least-privilege role
above, each scoped to just that one Docker subnet — plus widening
`listen_addresses` only if needed (the one step that requires a full
Postgres restart, so it's confirmed on its own and never covered by
`--yes`). Decline any of them and the script finishes with a "still to do
by hand" list giving the exact commands, so you can accept the parts
you're comfortable automating and do the rest yourself. Safe to re-run
later if TAK Server's database ever moves or gets reinstalled —
`--dry-run` shows what it would do without changing anything, `--yes`
accepts every non-disruptive step, `--reset-password` rotates the role's
password. Its generated SQL mirrors the block above exactly; keep both in
sync if the table list ever changes.

If TAK Server's database is on a **separate** server, this script has
nothing to automate — use the manual SQL above, and see the System page's
own "TAK Server connection" panel for the equivalent `listen_addresses`/
`pg_hba.conf`/firewall guidance for that case.

**The minimum is Python 3.10, which Ubuntu 22.04 and 24.04 both ship as
their stock `python3`** (3.10 and 3.12 respectively). Rocky Linux 9 ships
3.9, which is *below* the floor — but 3.12 is one `dnf install` away from
its normal repositories, with no third-party source involved.

No third-party repository is needed on Ubuntu, and that is the point of the
floor being 3.10 rather than 3.12: the `deadsnakes` PPA a 3.12 requirement
would force is unreachable on some agency networks, and that alone can make
a bare-metal install impossible.

- **Ubuntu 22.04 / 24.04**: the stock `python3` qualifies (3.10 and 3.12
  respectively). Install the venv package, which Debian and Ubuntu ship
  separately: `sudo apt-get install python3-venv`
- **Rocky Linux 9.4+ / RHEL 9.4+**: `sudo dnf install -y python3.12`

> **Having the interpreter is not the same as being able to build a venv.**
> A stock Ubuntu 22.04 has `python3.10` but not `python3.10-venv`, and
> `python3 -m venv` then fails with *"ensurepip is not available"*.
> `setup.sh` checks for this up front and names the package to install, but
> it is worth knowing before you start.

`setup.sh` picks the newest interpreter it finds — it tries `python3.14`
down through `python3.10` by name before falling back to bare `python3` — so
a host with a newer Python installed alongside the system one uses the newer
one automatically, and nothing here needs revisiting as later releases ship.

The Docker image deliberately runs a newer Python than the floor requires
(`python:3.12-slim`), and the container needs no Python on the host at all.
CI runs the test suites on both 3.10 and 3.12 so the floor cannot quietly
stop being true.

**Installing Docker itself** — this project uses the Docker Engine CLI and
the Compose **v2** plugin (`docker compose`, a space, not the hyphenated v1
`docker-compose`). `setup.sh` refuses to run without them.

- **Ubuntu 22.04**: don't use `apt install docker.io docker-compose` — that
  pulls Compose v1. Install from [Docker's own apt repository](https://docs.docker.com/engine/install/ubuntu/),
  which includes `docker-compose-plugin` (v2) alongside Docker Engine.
- **Rocky Linux 9 / RHEL 9**: the distro default container engine here is
  **Podman, not Docker** — and this project's scripts call `docker compose`
  specifically, which Podman does not provide (its equivalent is the
  separate `podman-compose`, which is *not* a drop-in). Install real Docker
  Engine + the Compose v2 plugin from [Docker's own dnf repository](https://docs.docker.com/engine/install/rhel/)
  (or the [CentOS instructions](https://docs.docker.com/engine/install/centos/)
  for RHEL variants Docker doesn't list directly), then `sudo systemctl
  enable --now docker`. Podman *can* run this app, but none of the helper
  scripts (`setup.sh`, `connect-database.sh`) will work against it as-is.

SELinux (enforcing by default on Rocky/RHEL) is already accounted for — the
container's data volume is mounted with a `:z` relabel (see
`docker-compose.yml`), so the audit database and TLS cert persist without a
manual `chcon` or setting SELinux permissive.

---

### Checking the database after a TAK Server or Postgres update

```bash
sudo ./check-database.sh
```

Run this after a TAK Server upgrade, a PostgreSQL upgrade, or any change to
the server underneath. It is **read-only**: every statement is a `SELECT`,
inside a `READ ONLY` transaction, under an account with no write privileges.

`sudo` is for Docker, not for the database: `connect-database.sh` leaves
`.env` root-owned and `0600` because it holds the database password, so
`docker compose` cannot read it as an ordinary account. The same applies to
updating — `sudo docker compose up -d --build`, or the pull succeeds and
nothing is rebuilt.

It answers a different question from the System page's *Test connection*,
which proves the credentials and the route and nothing more. This runs
**every statement an export actually sends** — from the same code that
builds a package, so it cannot drift from it — and then checks the handful
of things that resolve perfectly well while returning the wrong answer:

- **`event_pt` is still a geometry in SRID 4326.** The map-area filter
  compares against an envelope built in 4326. A column in a different SRID
  does not raise; it returns **nothing**, so an export looks clean and is
  empty.
- **The channel bitmask still decodes to channel names.** If it stops,
  channel filtering silently matches nothing.
- **Callsigns still come out of the `detail` XML.**
- **The account still cannot write** — `INSERT`, `UPDATE`, `DELETE` and
  `TRUNCATE` are checked on every granted table, not just `cot_router`.

It also compares the structure — tables, columns, types, geometry columns —
against the baseline recorded when `connect-database.sh` connected this
tool. A removed, retyped or reordered column is reported as a failure,
because it changes what an evidence file contains; an added one is a
warning, naming where it landed and what it does to
`<case>-cot_router-raw.csv`. **A difference is not in itself a sign that
anything is wrong** — an upgrade changes structure legitimately. It is
reported so that it is known rather than assumed.

Exit codes: `0` all well · `1` drift or warnings · `2` something is wrong ·
`3` could not connect at all. A connection failure names what it usually is
— a `pg_hba.conf` line that a major-version upgrade did not carry across, a
role that did not survive, a cluster on a different port, or
`listen_addresses` back at `localhost` where a container on the Docker
bridge cannot reach it.

Once you have looked at a difference and it is expected, accept it as the
new baseline:

```bash
sudo ./check-database.sh --approve-baseline --approved-by "your name"
```

The same comparison runs inside **every export**, and its result goes into
that package's README and its audit entry — so what the structure was when
a package was built is recorded with the package, not only when someone
remembers to run this. The System page has the same summary and the same
Approve button, under **Database structure**.

---

## Quick start (either way)

```bash
git clone https://github.com/Tech-Guyish/TAK-Extract.git
cd TAK-Extract
./setup.sh
```

`setup.sh` asks which of two installs this is, once, and records the answer
in `.env` so nothing asks again:

- **Docker** — the app in a container, reaching TAK Server's Postgres across
  the Docker bridge. Needs Docker Engine with the Compose v2 plugin (2.20+).
- **Side-by-side** — the app installed straight onto the TAK Server's own
  machine, no Docker: a virtual environment under `/opt/tak-extract`, run by
  `gunicorn` under `systemd`, reaching Postgres over loopback. Needs Python
  3.10+ and systemd. Everything else about the app is identical.

Either way it creates `.env`, generates `SECRET_KEY`, moves off a port
something else already holds (TAK Server's own API commonly has 8080), asks
whether this install is reached directly or through a reverse proxy, brings
the app up, and offers to run `./connect-database.sh` straight afterwards.
It is safe to re-run: every step reports what it found and skips whatever is
already done.

**A note on the side-by-side install.** Putting TAK-Extract on the TAK
Server's own machine means the audit log lives on the same host as the data
it is evidence about, under one root account. That is a normal thing to do
and nothing about the app depends on it being otherwise — but it is the
reason to keep a copy of the audit log somewhere that host's accounts cannot
reach (download it from the Audit Log page, or note the newest row's hash
from the System page). A re-generated hash chain disagrees with a copy held
elsewhere, and that disagreement is the point.

The sections below are what those two paths do by hand, for anyone who would
rather run the steps themselves or needs to understand what the script did.

---

## Quick start (Docker)

```bash
# Confirms Docker Engine and the Compose plugin are both actually
# installed before anything else - a missing/too-old Docker otherwise
# fails on `docker compose up` several steps later with a less obvious
# error (or, on some systems, "docker: command not found").
docker compose version

git clone https://github.com/Tech-Guyish/TAK-Extract.git
cd TAK-Extract
cp .env.example .env
# edit .env: at minimum set SECRET_KEY and BOOTSTRAP_ADMIN_USERNAME (both
# blank by default - AUTH_MODE already defaults to 'local'). Without
# BOOTSTRAP_ADMIN_USERNAME specifically, no admin account is ever created
# and there is no way to log in at all. If you're instead running
# AUTH_MODE=authentik, BOOTSTRAP_ADMIN_USERNAME must be a real username
# that already exists in Authentik, not a placeholder - this app has no
# login page of its own in that mode, so becoming the first admin means
# passing the Authentik challenge AS this exact username (setup.sh below
# asks for this explicitly rather than guessing). DB_HOST/DB_USER/
# DB_PASSWORD can stay blank for now - the app starts and logs in fine
# without them; connect it to TAK Server's database from the System page
# after first login instead (see "Creating the least-privilege database
# account" above).
# Running a second instance on this same host (e.g. against a different
# TAK Server)? Also set a different PORT here - docker-compose.yml reads
# it directly, so there's no port collision with the first instance and
# no compose-file editing needed.

# The container runs as a non-root user (uid 1000) and needs write access
# to this bind-mounted directory for its audit database - on a fresh Linux
# host, letting `docker compose up` create ./data itself leaves it
# root-owned, which the container can't write to. Create and hand it over
# first instead:
mkdir -p data && sudo chown 1000:1000 data

docker compose up -d --build
docker compose logs web
```

Or, once cloned, `./setup.sh` does the `.env`/`data` steps above automatically (safe to re-run — it skips whatever's already done), generates `SECRET_KEY` itself, asks whether this install will be reached directly over the network (see "Direct TLS" below), and then runs `docker compose up -d --build` itself.

The first startup creates the initial admin account and prints its username, a one-time generated password, and the actual URL to log in at (varies depending on whether direct access was set up) to the log above — copy the password now, it's never shown again. `docker compose ps` reports `healthy` once the app is actually answering requests, not just once its process has started.

## Quick start (side-by-side, by hand)

This is what `setup.sh` does for you when the side-by-side path is chosen —
creating the `takextract` service account, copying the checkout to
`/opt/tak-extract`, building the venv, pointing `AUDIT_DB` at
`/opt/tak-extract/data`, filling in `tak-extract.service` and enabling it.
Run it yourself only if you want to place things differently.


```bash
python --version             # Confirm 3.10+ before anything else. The app checks this
                              # on startup and fails with a clear message if it is too
                              # old, but catching it here first is cheaper.
python -m venv venv          # Linux/macOS: python3 -m venv venv. Needs python3-venv
                              # installed on Debian/Ubuntu (see Prerequisites above)
venv\Scripts\activate        # Windows; source venv/bin/activate on Linux/macOS
pip install -r requirements.txt
cp .env.example .env
# edit .env the same way as above - AND, for this plain-http dev server
# only, also set SESSION_COOKIE_SECURE=false (see .env.example: the
# secure-by-default cookie is silently never sent back over http://,
# which makes login look like it worked and then immediately forget you)
python app.py
```

This runs Flask's own dev server on `http://127.0.0.1:5000` — fine for local development, but not for production use. For a real deployment on **Linux** bare metal, install and run it behind `gunicorn` instead (deliberately left out of `requirements.txt` since it doesn't run on Windows at all — see the Dockerfile's own comment on this):

```bash
pip install gunicorn==23.0.0
gunicorn -c gunicorn.conf.py app:app
```

`gunicorn.conf.py` reads `PORT` (and, if set, `SERVE_TLS` — see below) from `.env` for its bind address, so there's one setting to change, not a `--bind` flag to keep in sync with it by hand.

There's no equivalent production option on Windows bare metal — either use Docker there too, or deploy on Linux for anything beyond local development. `setup.sh`'s side-by-side path is Linux-only for the same reason.

Running the `gunicorn` command above directly in a terminal only lasts until that terminal closes. `tak-extract.service` is a starter [systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) unit that keeps it running instead — auto-restarts on failure, starts on boot, and uses the same `gunicorn.conf.py`. See the comments in that file for the rest of the setup (creating a dedicated service user, and pointing it at wherever this was actually installed).

---

## Configuration

Everything lives in `.env` (see `.env.example` for the full, commented list). The two choices that matter most:

- **`AUTH_MODE`** — `local` runs this app's own login form and session; `authentik` trusts an `X-authentik-username` header set by a reverse proxy in front of it, and skips local login entirely. With a forward-auth proxy, pass `/recheck/` through **without** authentication: the TAK Server's re-check line fetches a script and posts a hash file there, authenticated by a per-package token rather than a login, and it cannot answer a sign-in page
- **`DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD`** — TAK Server's Postgres connection. These only seed the very first startup; once an admin saves connection settings from the **System** page, those take over

- **`MAP_SEARCH` / `MAP_TILES`** — whether the Export and Verify maps may reach OpenStreetMap: the address-search box sends what is typed into it to the public Nominatim service, and the tiles are fetched as you pan. Both default to on. Like the database settings these only seed the first startup — the **Map and privacy** panel on the **System** page takes over once an administrator saves there, and records the change in the audit log. Set them here for an installation that must never reach OpenStreetMap even before anyone has logged in

Everything else (session timeout, failed-login lockout, CSRF, minimum password length) is on by default in `local` mode and needs no configuration.

### Direct TLS (optional)

By default this app is loopback-only everywhere (Docker, `tak-extract.service`, even `python app.py`) and expects a reverse proxy in front of it to provide any real network exposure and its own TLS — the common setup, matching infra-TAK's own Caddy or a standalone nginx. If there's no reverse proxy and this app should terminate its own HTTPS directly:

- **Docker (`setup.sh`)**: it asks this directly — *"Will this be reached directly, without a reverse proxy already in front of it?"* — the first time it creates `.env`. Answering yes (the default — Enter works) sets both `SERVE_TLS=true` and `BIND_ADDR=0.0.0.0` for you; answering no leaves both at today's loopback-only defaults. Installing by hand instead of through `setup.sh`, or changing your mind later, set them directly in `.env`:
- Set **`SERVE_TLS=true`** in `.env`. A self-signed certificate is generated automatically (needs `openssl` on `PATH` — already in the Docker image; virtually always already present on a real Linux install) and persists across restarts alongside `AUDIT_DB`, so it's only generated once.
- Every browser that connects will show a security warning the first time — expected for a self-signed cert. Click through it ("Proceed"/"Accept the Risk") once per device; the connection is genuinely encrypted either way, which is what actually matters for the Verify & Replay page's hash-check feature (browsers only allow that API over HTTPS or `localhost`).
- **Docker only**: also set **`BIND_ADDR=0.0.0.0`** (or a specific host IP) in `.env`. `SERVE_TLS` alone doesn't change `docker-compose.yml`'s own host-side port mapping — leaving `BIND_ADDR` at its loopback-only default would generate and serve a cert nobody outside the host could ever actually reach.

### fail2ban (optional)

This app already locks an *account* out after 5 failed attempts, but that only tracks usernames that actually exist — someone spraying made-up usernames, or a handful of guesses each against several real ones, never trips it. [fail2ban](https://github.com/fail2ban/fail2ban) (already used elsewhere in this ecosystem — see infra-TAK) bans the *source IP* at the firewall instead, which catches that gap regardless of which usernames were tried.

Every login attempt — success, failure, or against an already-locked account — is written to `auth.log`, alongside `AUDIT_DB` (Docker: `./data/auth.log`, same bind mount as the audit database). fail2ban runs on the **host**, not inside the container, and reads this file directly:

`/etc/fail2ban/filter.d/tak-extract.conf`:
```ini
[Definition]
failregex = ^\S+ LOGIN_FAILED user=\S* ip=<HOST>$
ignoreregex =
```

`/etc/fail2ban/jail.d/tak-extract.conf`:
```ini
[tak-extract]
enabled  = true
filter   = tak-extract
logpath  = /path/to/TAK-Extract/data/auth.log
maxretry = 10
findtime = 10m
bantime  = 1h
```

`maxretry` is deliberately higher than the in-app lockout's own 5 — every attempt against an already-locked account keeps getting logged too (by design, so those count for fail2ban even though the app itself stops re-checking the password), so a confused legitimate user retrying their own lockout a few times shouldn't get their IP banned on top of it. Adjust `logpath` to wherever this is actually installed, and `maxretry`/`findtime`/`bantime` to taste.

If this app sits behind a reverse proxy (the default — see "Direct TLS" above), `auth.log`'s IP is only correct because `ProxyFix` trusts exactly one hop of `X-Forwarded-For` in that mode; make sure nothing between the proxy and this app strips or rewrites that header.

---

## Uninstalling

Before removing anything, decide what happens to the audit log. It is the tool's accountability record — every user account, every setting, and every export ever run, with its SHA-256 — and it lives in the app's own data directory, not in TAK Server. Removing the app's data removes that record. Login attempts are in `auth.log` alongside it.

To keep it, either use **System → Download backup** while the app is still running (this deliberately leaves out the TAK Server password, so the file is safe to store), or copy the two files directly:

| Install | Files to preserve |
|---|---|
| Docker | `./data/audit.sqlite`, `./data/auth.log` (inside the clone directory) |
| Side by side | `audit.sqlite` and `auth.log` at the `AUDIT_DB` path in `.env` — `/opt/tak-extract/data/` for an install made by `setup.sh` |

### Docker

```bash
cd /path/to/TAK-Extract

# Stop and remove the container, its network, and the locally built image.
# (No --volumes: the app uses a bind mount, not a named volume - see below.)
docker compose down --rmi local --remove-orphans

# The audit database is a bind mount at ./data, so `down` leaves it on disk.
# Only once it is backed up (above):
sudo rm -rf ./data

# The clone itself - this also removes .env, which holds SECRET_KEY and the
# TAK Server database password.
cd .. && rm -rf TAK-Extract

# Optional, and daemon-wide: this clears the build cache of every project on
# the host, not only this app's. Skip it on a machine that also builds other
# containers, or keep the last week's with --filter until=168h.
docker builder prune -f
```

### Side by side (Linux, systemd)

What `./setup.sh` creates on that path: the clone, the venv and `.env` in `/opt/tak-extract` owned by the administrator who installed it, `/opt/tak-extract/data` owned by the `takextract` service account (the audit database, `auth.log`, and any self-signed TLS certificate), and the unit at `/etc/systemd/system/tak-extract.service`. Adjust the paths and username if the install used different ones.

```bash
sudo systemctl disable --now tak-extract
sudo rm /etc/systemd/system/tak-extract.service
sudo systemctl daemon-reload

# The install directory, explicitly. `userdel -r` is NOT enough on its own
# here: the service account's recorded home is this directory, but the
# files in it belong to the administrator who installed them, so userdel
# leaves most of it behind. Back up the audit files first (above).
sudo rm -rf /opt/tak-extract

# The service account. It owns nothing else and has no login shell.
sudo userdel takextract
```

If it was run under a personal account without systemd, there is nothing to unregister — deactivate the venv and delete the clone directory.

If fail2ban was configured (see above):

```bash
sudo rm /etc/fail2ban/jail.d/tak-extract.conf /etc/fail2ban/filter.d/tak-extract.conf
sudo systemctl reload fail2ban
```

### On the TAK Server host: remove the database role

Both install types use a dedicated read-only Postgres role (`takextract` by default; whatever `--role` was given to `connect-database.sh`, or whatever was created by hand from "Creating the least-privilege database account" above). It only ever received `GRANT`s and owns no objects, so dropping it does not touch any of TAK Server's data — but Postgres refuses to drop a role that still holds privileges, so revoke them first:

```bash
sudo -u postgres psql -d cot -c "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM takextract;"
sudo -u postgres psql -d cot -c "REVOKE USAGE ON SCHEMA public FROM takextract;"
# Only if the optional identifier grant above was ever applied; harmless either way.
sudo -u postgres psql -d cot -c "REVOKE EXECUTE ON FUNCTION pg_control_system() FROM takextract;"
sudo -u postgres psql       -c "REVOKE CONNECT ON DATABASE cot FROM takextract;"
sudo -u postgres psql       -c "DROP ROLE takextract;"
```

### Optional: undo the host changes made by `connect-database.sh`

These only apply to a **Docker** install where `connect-database.sh` opened a path to Postgres across the Docker bridge; a side-by-side install connects over loopback and the script makes none of these changes. It made up to three changes so the container could reach Postgres; each was confirmed individually at the time. Reverting them is hardening rather than a requirement — with the role dropped, none of them grants access to anything — and the third one **restarts Postgres, which interrupts TAK Server**. Skip any of them if something else now depends on remote Postgres access, such as a split or HA TAK Server install.

**1. The `pg_hba.conf` line.** Remove the line the script added — it has the form `host    cot    takextract    <docker-subnet>    <method>` — then reload:

```bash
sudo systemctl reload postgresql        # Rocky/RHEL: postgresql-<major>
```

**2. The firewall rule** opening TCP 5432 to the Docker subnet:

```bash
# ufw (Ubuntu): list the rules with numbers, then delete the 5432 one
sudo ufw status numbered
sudo ufw delete <number>

# firewalld (Rocky/RHEL) - use the exact subnet the script reported
sudo firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address="<docker-subnet>" port port=5432 protocol=tcp accept'
sudo firewall-cmd --reload
```

**3. `listen_addresses`** — only if the script widened it to `*` (it asks separately, since this is the one disruptive step). Reverting requires a full Postgres restart, so do it in a maintenance window:

```bash
sudo -u postgres psql -c "ALTER SYSTEM RESET listen_addresses;"
sudo systemctl restart postgresql       # Rocky/RHEL: postgresql-<major>
```

---

## Documentation

- **[CHANGELOG.md](CHANGELOG.md)** — what changed, by date

---

## License

[AGPL-3.0](LICENSE) — the same license infra-TAK, CloudTAK, and TAK-Portal already use. Anyone given a copy can run and modify it, but anyone who runs a modified version as a network service must make their modifications available to that service's users too.

Third-party dependencies (all permissive, except one - see [docs/THIRD-PARTY-NOTICES.md](docs/THIRD-PARTY-NOTICES.md)) are compatible with this license and don't require anything additional.

---

## Status

**Beta.** In production use at the agency that built it, and released publicly in case it is useful to others running TAK Server. Every release is marked pre-release deliberately: it is working software with real users, not a finished product with a support contract behind it.

### What it is, and what it is not

It reads a TAK Server's PostgreSQL database with a **read-only** account, over a window and a map area an operator chooses, and writes what it found to a zip with the hash of every file recorded in its own audit log. It re-states what the server stored. **It does not attest that what the server stored is complete or accurate**, and nothing it produces is a substitute for someone who can speak to how the data got there.

It makes no claim about any compliance regime. **Which regimes a deployment falls under — and whether this tool's handling of the data satisfies them — is the deploying agency's determination, not this tool's.** The same goes for retention, disclosure and whatever a particular court expects of evidence put in front of it. Read [docs/EVIDENCE-REFERENCES.md](docs/EVIDENCE-REFERENCES.md) for the standards the design was measured against and the decisions that followed from them, then decide for yourself.

### What it does not do

- **No telemetry.** It never contacts anything but the TAK Server database you point it at and, from the browser, OpenStreetMap — for the map imagery, and for whatever is typed into the map's address-search box, which is sent there to be looked up. Both can be turned off from the **System** page, or before first login with `MAP_TILES` and `MAP_SEARCH` in `.env`. It does not phone home, check in, or report usage anywhere.
- **It never writes to TAK Server.** The database account it uses has `SELECT` and nothing else, in a `READ ONLY` transaction, and the package README prints the account's write privileges as the database itself reports them.
- **Location data never leaves your machine on the Verify page.** Files dropped there are read and hashed in the browser; only a 64-character hash is sent, to look up in the audit log.

As with any AGPL-3.0 software, it comes **with no warranty** — see sections 15 and 16 of the [LICENSE](LICENSE). If you run it, you are the one accountable for what it produces.
