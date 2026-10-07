"""Regression tests for dbcheck.py - the post-upgrade schema check.

No live Postgres needed. The two halves that carry the real risk are both
pure: collect_statements() assembles the statements an export sends, and
diff_fingerprint() classifies what changed between two schema snapshots.
Everything below tests one of those, plus the one duplicate that cannot be
removed - the granted-table list, which shell cannot import from Python.

The rule this file exists to enforce: a statement is ALWAYS executed with
the parameter tuple its builder returned, including an empty one, never
None. psycopg2 only runs its own %-interpolation when vars is not None,
and several statements carry a deliberately doubled '%%'. Pass None and
that doubling reaches Postgres literally - which is the outage recorded
above QUALITY_CHECKS in exports.py, in a new disguise.

Run with: python tests/test_dbcheck.py
"""
import json
import os
import re
import sys

# This file lives in tests/; dbcheck.py and exports.py are in the checkout above.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import dbcheck
import exports

failures = []


def check(label, cond):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}")
    if not cond:
        failures.append(label)


STATEMENTS = dbcheck.collect_statements(probe_bitpos=3,
                                        columns=["id", "uid", "servertime", "detail"])

# ---------------------------------------------------------------------------
# How the statements are executed
# ---------------------------------------------------------------------------

check("collect_statements: covers every file query, both channel passes, "
      "and the statements that live outside build_queries",
      len(STATEMENTS) > 40)

check("every statement carries a params tuple - never None, which would let "
      "psycopg2 skip interpolation and send a doubled %% to Postgres",
      all(p is not None for _l, _s, p in STATEMENTS))

check("every statement is verified with LIMIT 0 appended",
      all(dbcheck.exports.with_limit(s, 0).rstrip().endswith("LIMIT 0;")
          for _l, s, _p in STATEMENTS))

# LIMIT is appended, not wrapped: two of these end in a positional ORDER BY
# over a UNION ALL, and wrapping is a second place the text sent could
# differ from the text the exporter sends.
check("with_limit appends rather than wrapping in a sub-select",
      not dbcheck.exports.with_limit("SELECT 1;", 0).lstrip().startswith("SELECT * FROM ("))

# The scan that caught the original outage, now over every statement this
# module will actually execute rather than over one list in the source.
BARE_PERCENT = re.compile(r"(?<!%)%(?![%s(])")
bare = [label for label, sql, _p in STATEMENTS if BARE_PERCENT.search(sql)]
check("no statement carries a bare '%' that psycopg2 would read as a placeholder",
      not bare)
for label in bare:
    print(f"       {label}")

survived = []
for label, sql, params in STATEMENTS:
    try:
        if params:
            dbcheck.exports.with_limit(sql, 0) % tuple("x" for _ in params)
    except Exception as e:
        survived.append(f"{label}: {type(e).__name__}: {e}")
check("every statement survives %-interpolation with its own parameters",
      not survived)
for line in survived[:5]:
    print(f"       {line}")

check("the raw-rows statement is verified with the real column list, not the "
      "r.* fallback",
      any('r."detail"::text' in s for l, s, _p in STATEMENTS if l.startswith("cot_router-raw")))

# ---------------------------------------------------------------------------
# The fingerprint and what a diff makes of it
# ---------------------------------------------------------------------------

BASE = {
    "taken_utc": "2026-09-28 00:00:00Z",
    "server_version": "15.8", "server_version_num": "150008",
    "timezone": "UTC", "datestyle": "ISO, MDY",
    "db_user": "takextract", "db_name": "cot",
    "extensions": {"postgis": "3.4.2"},
    "tables": {"cot_router": ["id bigint", "uid text", "event_pt geometry"],
               "groups": ["bitpos integer", "name text"]},
    "cot_router_columns": ["id bigint", "uid text", "event_pt geometry"],
    "geometry_columns": {"cot_router.event_pt": "POINT srid=4326"},
    "channel_mask_bits": [32768],
    "output_headers": {"cot.csv": ["id", "uid"]},
}


def variant(**changes):
    fp = json.loads(json.dumps(BASE))
    for key, value in changes.items():
        fp[key] = value
    return fp


def details(fp_a, fp_b):
    return dbcheck.diff_fingerprint(fp_a, fp_b)


check("an unchanged schema produces no changes at all", not details(BASE, variant()))

check("the fingerprint hash ignores when it was taken, so two runs of an "
      "unchanged schema agree",
      dbcheck.fingerprint_sha256(BASE)
      == dbcheck.fingerprint_sha256(variant(taken_utc="2027-01-01 12:00:00Z")))

check("the fingerprint hash changes when the schema does",
      dbcheck.fingerprint_sha256(BASE)
      != dbcheck.fingerprint_sha256(variant(cot_router_columns=["id bigint"])))

# An export takes the cheap fingerprint and never runs the statement pass,
# so it has no output_headers. If those were hashed, a package could never
# record a fingerprint equal to the baseline's even on an unchanged schema
# - which would make the number printed in an evidence package worthless.
no_headers = variant()
del no_headers["output_headers"]
check("a fingerprint taken during an export hashes the same as the baseline's, "
      "so the value a package records is comparable to it",
      dbcheck.fingerprint_sha256(BASE) == dbcheck.fingerprint_sha256(no_headers))

added = details(BASE, variant(
    tables={"cot_router": ["id bigint", "uid text", "event_pt geometry", "foo text"],
            "groups": ["bitpos integer", "name text"]}))
check("a new column is a warning, not a failure - nothing breaks",
      added and all(c["status"] == dbcheck.WARN for c in added))
check("a new column says where it landed and what it does to the raw file",
      any("column 4 of 4" in c["detail"] and "raw.csv now has 4 columns" in c["detail"]
          for c in added))

removed = details(BASE, variant(
    tables={"cot_router": ["id bigint", "event_pt geometry"],
            "groups": ["bitpos integer", "name text"]}))
check("a removed column is a failure",
      any(c["status"] == dbcheck.FAIL and "cot_router.uid was removed" in c["detail"]
          for c in removed))

retyped = details(BASE, variant(
    tables={"cot_router": ["id bigint", "uid character varying(255)", "event_pt geometry"],
            "groups": ["bitpos integer", "name text"]}))
check("a retyped column is a failure and names both types",
      any(c["status"] == dbcheck.FAIL and "was text" in c["detail"]
          and "character varying(255)" in c["detail"] for c in retyped))

reordered = details(BASE, variant(
    tables={"cot_router": ["uid text", "id bigint", "event_pt geometry"],
            "groups": ["bitpos integer", "name text"]}))
check("a reordered table is a failure - it changes what the raw file contains",
      any(c["status"] == dbcheck.FAIL and "column order changed" in c["detail"]
          for c in reordered))

dropped_table = details(BASE, variant(tables={"cot_router": BASE["tables"]["cot_router"]}))
check("a dropped table is a failure",
      any(c["status"] == dbcheck.FAIL and "table groups is gone" in c["detail"]
          for c in dropped_table))

srid = details(BASE, variant(geometry_columns={"cot_router.event_pt": "POINT srid=3857"}))
check("an SRID change is a failure - the box filter would return nothing",
      any(c["status"] == dbcheck.FAIL and "srid=3857" in c["detail"] for c in srid))

gone = details(BASE, variant(extensions={}))
check("PostGIS disappearing is a failure",
      any(c["status"] == dbcheck.FAIL and "postgis" in c["detail"] for c in gone))

major = details(BASE, variant(server_version="18.0", server_version_num="180000"))
check("a major PostgreSQL version change is called out by name, with what it "
      "usually takes with it",
      any("major version changed" in c["detail"] and "pg_hba.conf" in c["detail"]
          for c in major))

# A statement's output columns are classified the same way as the table's
# own: gaining one is benign (an upgrade does that), losing or reordering
# one is not. Getting this wrong made a harmless added column report as
# "something is wrong" - caught by breaking a real database, not by
# reading the code.
gained_col = details(BASE, variant(output_headers={"cot.csv": ["id", "uid", "extra"]}))
check("a statement producing an EXTRA column is a warning, not a failure",
      gained_col and all(c["status"] == dbcheck.WARN for c in gained_col)
      and "now also produces: extra" in gained_col[0]["detail"])

lost_col = details(BASE, variant(output_headers={"cot.csv": ["id"]}))
check("a statement that stopped producing a column is a failure, and names it",
      any(c["status"] == dbcheck.FAIL and "no longer produces: uid" in c["detail"]
          for c in lost_col))

swapped = details(BASE, variant(output_headers={"cot.csv": ["uid", "id"]}))
check("a statement whose column order changed is a failure",
      any(c["status"] == dbcheck.FAIL and "order of its columns changed" in c["detail"]
          for c in swapped))

check("with no baseline there is nothing to diff against, and no changes are invented",
      dbcheck.diff_fingerprint(None, BASE) == [])

# app.recent_source_identities() returns DICTS, not strings. Treating them
# as strings raised "unhashable type: 'dict'" and took the whole check down
# - but only on an install that had recorded an export, because a fresh
# audit log returns an empty list. Every test box missed it; the production
# one failed on the first run.
# Both fixtures carry the KIND prefix, because that is what an export
# actually writes into the log - exports.source_identity() returns
# "cluster <n>" or "catalog <db>/<oid>/<oid>", never a bare id. An earlier
# version of this fixture mixed the two spellings, which is how a
# comparison against the unprefixed value shipped unnoticed.
rows = [{"identity": "cluster 7690", "when": "2026-10-03", "case_id": "X"},
        {"identity": "catalog cot/16384/16407", "when": "2026-09-01", "case_id": None}]
check("the identity set accepts what app.recent_source_identities() actually "
      "returns - a list of dicts",
      dbcheck._known_identities(rows) == {"cluster 7690", "catalog cot/16384/16407"})
check("and still accepts plain strings, which is what it was written for",
      dbcheck._known_identities(["a", "b"]) == {"a", "b"})
check("an empty or absent list yields nothing to compare against",
      dbcheck._known_identities([]) == set()
      and dbcheck._known_identities(None) == set())
check("entries with no identity are dropped rather than compared as None",
      dbcheck._known_identities([{"when": "x"}, None, ""]) == set())

# The comparison itself, driven through the SAME formatter an export logs
# with. Checking _known_identities alone could never have caught the real
# defect: the set was right, and what it was compared against was wrong.
# An unchanged database must report a match, or this item WARNs forever on
# a correct install and writes a non-OK verdict into the chained log.
logged = dbcheck._known_identities([{"identity": "cluster 7690", "when": "x"}])
check("an unchanged database matches what the log recorded",
      exports.source_identity({"db_cluster_id": "7690"}) in logged)
check("a different cluster does not match",
      exports.source_identity({"db_cluster_id": "7691"}) not in logged)
# The kind is part of the compared value on purpose: a catalog fingerprint
# and a cluster identifier are not worth the same, so an identical number
# under a different kind must NOT read as the same database.
check("a catalog fingerprint never matches a cluster identifier of the same number",
      exports.source_identity({"db_catalog_id": "7690"}) not in logged)

# Change strings carry text the DATABASE supplies - table and column names,
# format_type() output, server error messages. A quoted Postgres identifier
# may hold a newline or a semicolon, and these strings are spliced into the
# package README's fixed-width header block (which states the source
# database and the account's write privileges) and into the audit log's
# "; "-joined clauses. Sanitised where they are built, so all three sinks
# are covered at once.
hostile = "evil\nDB account       : nobody; write privilege on cot_router:\n  none"
injected = details(BASE, variant(
    tables={"cot_router": BASE["tables"]["cot_router"] + [hostile + " text"],
            "groups": BASE["tables"]["groups"]}))
check("a column name cannot carry a newline into a change string",
      injected and all("\n" not in c["detail"] and "\r" not in c["detail"]
                       for c in injected))
check("a column name cannot carry an audit-clause separator either",
      all(";" not in c["detail"] for c in injected))
check("a single enormous identifier cannot push the rest off the page",
      all(len(c["detail"]) <= 300 for c in details(BASE, variant(
          tables={"cot_router": BASE["tables"]["cot_router"] + ["x" * 5000 + " text"],
                  "groups": BASE["tables"]["groups"]}))))

check("the README's 'could not be compared' line is flattened to one line",
      "\n" not in exports._schema_text(
          {"state": "unavailable",
           "detail": 'syntax error\nLINE 1: SELECT\n               ^'}))

check("a different database name is a failure, not a warning - it means the "
      "install was repointed",
      any(c["status"] == dbcheck.FAIL for c in details(BASE, variant(db_name="other"))))

# ---------------------------------------------------------------------------
# The one duplicate that cannot be removed
# ---------------------------------------------------------------------------
# connect-database.sh applies the grants and cannot import Python, so the
# table list exists in both languages. It is a tested duplicate rather than
# a remembered one.
shell = open(os.path.join(REPO, "connect-database.sh"), encoding="utf-8").read()
block = shell[shell.index("grant_tables=\""):]
block = block[len("grant_tables=\""):block.index("\"", len("grant_tables=\""))]
installer_tables = tuple(sorted(block.split()))
# ---------------------------------------------------------------------------
# The installers have to be runnable from a fresh clone
# ---------------------------------------------------------------------------
# All three were committed 100644 because this repo is authored on Windows,
# where core.filemode is false and the execute bit is never captured. A
# fresh clone on Linux then answers "Permission denied" to the ./setup.sh
# the README tells people to run - and `sudo ./setup.sh` reports the even
# less helpful "command not found". Caught on a real install.
import subprocess as _sp
_modes = {}
try:
    _out = _sp.run(["git", "ls-files", "-s", "--", "*.sh"], cwd=REPO,
                   capture_output=True, text=True, timeout=30)
    for _line in _out.stdout.splitlines():
        _mode, _rest = _line.split(" ", 1)
        _modes[_rest.split(chr(9))[-1]] = _mode
except Exception as _e:          # no git available - say so rather than pass
    _modes = {"<git unavailable>": str(_e)}

for _script in ("setup.sh", "connect-database.sh", "check-database.sh"):
    check(f"{_script} is committed executable (100755), so a fresh clone can run it",
          _modes.get(_script) == "100755")
if any(v != "100755" for v in _modes.values()):
    print(f"       modes: {_modes}")

# Shell scripts must be stored with LF. A CRLF one dies on Linux with
# "$'\r': command not found", which names no file and reads like a
# corrupted install. The working copy here is CRLF (core.autocrlf), so this
# checks what git actually STORES, not what is on disk.
for _script in ("setup.sh", "connect-database.sh", "check-database.sh"):
    try:
        _blob = _sp.run(["git", "cat-file", "-p", ":" + _script], cwd=REPO,
                        capture_output=True, timeout=30).stdout
        _crlf = _blob.count(b"\r\n")
    except Exception:
        _crlf = -1
    check(f"{_script} is stored with LF endings, not CRLF", _crlf == 0)

# The one that sent a real user to re-run setup.sh against a healthy
# install: `docker compose ps -q web 2>/dev/null` threw away the reason it
# failed, so a daemon that refused us was reported as "the container isn't
# running". Each branch must now name what actually happened.
_cdb = open(os.path.join(REPO, "connect-database.sh"), encoding="utf-8").read()
check("connect-database.sh keeps Docker's own error instead of discarding it",
      'docker_err="$(docker compose ps -q web 2>&1 >/dev/null)"' in _cdb)
check("connect-database.sh tells you to re-run with sudo when Docker refuses it",
      "Cannot reach the Docker daemon" in _cdb and "sudo bash ./$(basename" in _cdb)
check("connect-database.sh still reports a genuinely stopped container as such",
      "The web container isn't running yet" in _cdb)
check("connect-database.sh separates 'docker is absent' from the other two",
      "docker isn't on PATH" in _cdb)


check("connect-database.sh grants exactly the tables exports.GRANTED_TABLES names",
      installer_tables == tuple(sorted(exports.GRANTED_TABLES)))
if installer_tables != tuple(sorted(exports.GRANTED_TABLES)):
    print(f"       only in installer: {set(installer_tables) - set(exports.GRANTED_TABLES)}")
    print(f"       only in exports.py: {set(exports.GRANTED_TABLES) - set(installer_tables)}")

# Every table the census counts should be one the role can actually read.
check("every census table is a granted table",
      all(t in exports.GRANTED_TABLES for t, _label in exports.CENSUS_TABLES))

# ---------------------------------------------------------------------------
# What an export's README says about it
# ---------------------------------------------------------------------------
# Four states, and each has to read as a fact rather than a verdict. A
# structure difference is not evidence that the package is wrong - an
# upgrade changes structure legitimately - and the wording has to say so
# without overstating what a match proves either.

matched = exports._schema_text({"state": "matches baseline"})
check("README: an unchanged structure says what was compared",
      "unchanged" in matched and "geometry columns" in matched)

differs = exports._schema_text(
    {"state": "differs from baseline", "changes": ["cot_router.foo was added"]})
check("README: a difference lists what differed",
      "cot_router.foo was added" in differs)
check("README: a difference is not reported as proof that anything is wrong",
      "not by itself a sign" in differs)

many = exports._schema_text(
    {"state": "differs from baseline", "changes": [f"change {n}" for n in range(25)]})
check("README: a long list of differences is capped and says how many more",
      "and 15 more" in many)

check("README: no baseline says there was nothing to compare against, not that "
      "the check passed",
      "no earlier record" in exports._schema_text({"state": "no baseline"}))

check("README: a failed comparison gives the reason",
      "boom" in exports._schema_text({"state": "unavailable", "detail": "boom"}))

check("README: an absent schema result still renders rather than raising",
      isinstance(exports._schema_text(None), str))


class _NoCatalogue:
    """A connection whose catalogue cannot be read - the state that used to
    pass silently."""

    def cursor(self):
        raise RuntimeError("no catalogue here")

    def rollback(self):
        pass


unavailable = exports.schema_check_result(_NoCatalogue(), BASE)
check("an export never fails because the structure could not be checked",
      unavailable["state"] == "unavailable" and "no catalogue here" in unavailable["detail"])

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

report = {
    "checked_utc": "2026-09-28 00:00:00Z",
    "sections": [{"name": "Connection", "items": [
        dbcheck._item("x", "something failed", dbcheck.FAIL, "because of a reason")]}],
    "changes": [], "verdict": dbcheck.FAIL,
    "fingerprint_sha256": "a" * 64, "baseline_seeded": False,
}
text = dbcheck.render_text(report)
check("a failing report says so in its verdict", "VERDICT: something is wrong" in text)
check("a failing report ends with what to do about it", "What to do" in text)

seeded = dict(report, verdict=dbcheck.OK, baseline_seeded=True,
              sections=[{"name": "Connection", "items": []}])
check("a first run says plainly that its baseline is not verified against anything",
      "verified against anything earlier" in dbcheck.render_text(seeded))

print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for f in failures:
        print(f"  - {f}")
    raise SystemExit(1)
print("ALL DBCHECK TESTS PASSED")
