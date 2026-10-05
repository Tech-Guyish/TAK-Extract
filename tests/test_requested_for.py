"""Regression tests for requested_for - who an export was run FOR.

Distinct from `actor` (who ran it), which identify() resolves from the
verified session and deliberately ignores anything typed in. Before this
column existed the Export page prompted for a name and the server threw it
away; an admin running exports on someone else's behalf is the normal case
here, so it now gets its own field.

No live Postgres needed - the audit log is local sqlite. Covers the
migration path against a PRE-EXISTING audit.sqlite, which is what every
real install already has. Run with: python tests/test_requested_for.py
"""
import os, sqlite3, sys, tempfile

DB = tempfile.mktemp(suffix=".sqlite")

# --- Simulate a PRE-EXISTING audit.sqlite from before this column existed.
# This is the path that matters: a real install already has one of these.
con = sqlite3.connect(DB)
con.execute("""CREATE TABLE export_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts_utc TEXT NOT NULL, ts_local TEXT,
    actor TEXT, client_ip TEXT, case_id TEXT, export_kind TEXT,
    window_start TEXT, window_end TEXT, north REAL, south REAL, west REAL,
    east REAL, record_count INTEGER, package_sha256 TEXT, outcome TEXT,
    detail TEXT);""")
con.execute("INSERT INTO export_log (ts_utc, actor, case_id, export_kind, "
            "package_sha256, outcome) VALUES (?,?,?,?,?,?)",
            ("2026-01-01T00:00:00+00:00", "authenticated: olduser", "OLD-1",
             "package", "a" * 64, "generated"))
con.commit(); con.close()

os.environ.update({
    "AUDIT_DB": DB, "AUTH_MODE": "local", "SECRET_KEY": "t",
    "BOOTSTRAP_ADMIN_USERNAME": "admin", "BOOTSTRAP_ADMIN_PASSWORD": "adminpass12345",
    "DB_HOST": "unused", "DB_PORT": "5432", "DB_NAME": "unused",
    "DB_USER": "unused", "DB_PASSWORD": "unused", "NO_COLOR": "1",
})
# This file lives in tests/; app.py is in the checkout above it. test_support
# is beside this file, which sys.path[0] already covers.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app
from test_support import login

fails = []
def check(label, cond, extra=""):
    print(("[PASS] " if cond else "[FAIL] ") + label + ("" if cond else f"  {extra}"))
    if not cond: fails.append(label)

# 1. Migration added the column to the pre-existing table, old row preserved.
con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
cols = [r[1] for r in con.execute("PRAGMA table_info(export_log);")]
check("migration adds requested_for to an existing audit.sqlite",
      "requested_for" in cols, cols)
old = con.execute("SELECT * FROM export_log WHERE case_id='OLD-1';").fetchone()
check("pre-existing row survives migration, new column NULL",
      old is not None and old["requested_for"] is None)
con.close()

# 2. audit() writes both identity fields, and they stay distinct.
rid = app.audit("authenticated: admin", "1.2.3.4",
                {"case_id": "CASE-9", "start": "2026-01-01T00:00",
                 "end": "2026-01-02T00:00", "north": 1, "south": 0,
                 "west": 0, "east": 1},
                "package", 42, "generated", package_hash="b" * 64,
                requested_for="Sgt. Alice Nguyen")
con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
row = con.execute("SELECT * FROM export_log WHERE id=?;", (rid,)).fetchone()
con.close()
check("audit() stores requested_for", row["requested_for"] == "Sgt. Alice Nguyen",
      repr(dict(row)))
check("actor still the verified account, not the typed name",
      row["actor"] == "authenticated: admin")

# 3. The helper: blank/whitespace -> None (not ""), so "not entered" is distinct.
check("requested_for() blank -> None", app.requested_for({}) is None)
check("requested_for() whitespace -> None", app.requested_for({"requested_for": "   "}) is None)
check("requested_for() trims", app.requested_for({"requested_for": " Bob "}) == "Bob")

c = app.app.test_client()
login(c, data={"username": "admin", "password": "adminpass12345"})
# API POSTs carry CSRF the same way the real pages do.
import re as _re
_html = c.get("/admin").data.decode()
HDR = {"X-CSRFToken": _re.search(r'name="csrf-token" content="([^"]+)"', _html).group(1)}

# 4. Audit listing exposes it; filter finds "everything run for X".
j = c.get("/api/audit").get_json()
check("/api/audit exposes requested_for",
      any(r.get("requested_for") == "Sgt. Alice Nguyen" for r in j["rows"]))
j = c.get("/api/audit?q=Nguyen").get_json()
check("filter matches on requested_for", j["total"] == 1 and
      j["rows"][0]["requested_for"] == "Sgt. Alice Nguyen", j)
j = c.get("/api/audit?q=olduser").get_json()
check("filter still matches on actor", j["total"] == 1, j)
j = c.get("/api/audit?sort=for&dir=asc").get_json()
check("sort=for is a registered column", "error" not in j and len(j["rows"]) == 2, j)

# 5. Verify page's lookup carries it through.
j = c.post("/api/verify-hash", json={"hash": "b" * 64}, headers=HDR).get_json()
check("/api/verify-hash returns requested_for",
      j["matched"] and j["matches"][0]["requested_for"] == "Sgt. Alice Nguyen", j)
j = c.post("/api/verify-hash", json={"hash": "a" * 64}, headers=HDR).get_json()
check("old row verifies fine, requested_for None",
      j["matched"] and j["matches"][0]["requested_for"] is None, j)

# 6. CSV download includes the column, and logs its own row with it.
r = c.post("/api/audit/download", json={"ids": [rid], "case_id": "CASE-9",
                                        "requested_for": "Lt. Bob Ortiz"}, headers=HDR)
body = r.data.decode()
check("CSV header includes requested_for", "requested_for" in body.splitlines()[0], body[:200])
check("CSV row carries the value", "Sgt. Alice Nguyen" in body)
con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
dl = con.execute("SELECT * FROM export_log WHERE export_kind='audit-download' "
                 "ORDER BY id DESC LIMIT 1;").fetchone()
con.close()
check("audit-download row records who it was for",
      dl["requested_for"] == "Lt. Bob Ortiz", repr(dict(dl)) if dl else None)

# --- The hash chain. The pre-existing row above predates chaining (no
# hash); everything written since is chained. Then tamper, and the walk
# must name the first bad row and why.
r = app.verify_audit_chain()
check("chain intact after normal writes; the pre-chain row is reported as predating, not broken",
      r["ok"] and r["unchained"] == 1 and r["checked"] >= 2 and r["first_chained_id"] == 2, r)
con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
first = con.execute("SELECT id, tool_version FROM export_log WHERE row_hash IS NOT NULL ORDER BY id LIMIT 1;").fetchone()
check("chained rows record the tool version and commit", first["tool_version"].startswith("TAK-Extract"), first["tool_version"])
# the one legitimate later change: the delivery note
con.execute("UPDATE export_log SET outcome = outcome || ' / delivered' WHERE id = ?;", (first["id"],)); con.commit()
check("the delivery note added later does not break the chain", app.verify_audit_chain()["ok"])
# an edit behind the tool's back
con.execute("UPDATE export_log SET case_id = 'TAMPERED' WHERE id = ?;", (first["id"],)); con.commit()
r = app.verify_audit_chain()
check("an edited row is named, with the reason", not r["ok"] and r["broken_id"] == first["id"] and "edited" in r["reason"], r)
con.close()
# delete that row outright: the next chained row's prev_hash no longer matches
con = sqlite3.connect(DB)
ids = [x[0] for x in con.execute("SELECT id FROM export_log WHERE row_hash IS NOT NULL ORDER BY id;").fetchall()]
con.execute("DELETE FROM export_log WHERE id = ?;", (ids[0],)); con.commit(); con.close()
r = app.verify_audit_chain()
check("a deleted row is detected at the next row, with the reason",
      not r["ok"] and r["broken_id"] == ids[1] and "removed" in r["reason"], r)

print()
print("FAILURES: " + (", ".join(fails) if fails else "none"))
sys.exit(1 if fails else 0)
