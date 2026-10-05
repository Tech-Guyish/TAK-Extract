"""Browser-level regression tests: the Verify & Replay page's JavaScript,
driven in a real headless Chromium against a throwaway dev server.

The first tests in this project that execute the page's own JavaScript
rather than reasoning about it. Needs the dev-only Playwright install
(see requirements-dev.txt); skips cleanly - exit 0 with a message - when
it is not installed, so the other suites and CI-style runs are unaffected.

Covers: drawn shapes parsed from a generated KMZ, drawn as a step function
of playback time (appear when begun, change when redrawn, vanish when the
server recorded their deletion), stacked beneath device dots, clickable
for a version popup, toggleable from the legend; a KMZ with no shapes
still loads; a KMZ shaped like TAK Server's own export replays through the
generic reader and is labelled as foreign and unverifiable; and no page
overflows sideways at phone width.

Interaction rule learned the hard way: use REAL mouse clicks
(page.mouse.click at bounding-box coordinates), never a synthetic
dispatch_event('click'). A synthetic MouseEvent carries client
coordinates of (0,0); Leaflet derives a map location from that and
auto-pans off into nowhere, which looks exactly like a rendering bug and
is not one.

Run with: venv/Scripts/python tests/test_browser.py
"""
import datetime as dt
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("SKIPPED: playwright is not installed (dev-only; see requirements-dev.txt)")
    sys.exit(0)

# This file lives in tests/; the modules it drives are in the checkout
# above it, and so is the app the dev server imports.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import exports
import kmz
import shapes
failures = []


def check(label, cond, extra=""):
    # The page's own text can carry glyphs the Windows console codepage has
    # no room for (the list's open/close caret, for one). A failing check
    # must print its evidence, not die trying.
    line = ("[PASS] " if cond else "[FAIL] ") + label + ("" if cond else f"  {extra}")
    print(line.encode(sys.stdout.encoding or "utf-8", "replace").decode(sys.stdout.encoding or "utf-8"))
    if not cond:
        failures.append(label)


# ---------------------------------------------------------------------------
# Fixture KMZ: one device, four drawn shapes with version history + a deletion.
# Timezone-aware times, as psycopg2 delivers them - a naive time would be
# read as the browser's local zone and drift an hour against the device.
# ---------------------------------------------------------------------------
TZ = dt.timezone(dt.timedelta(hours=-4))
T = lambda h, m: dt.datetime(2026, 1, 1, h, m, 0, tzinfo=TZ)


def _poly(name, pts, stroke="-2737863", fill="2144745785"):
    return (f'<detail><contact callsign="{name}"/><creator uid="c1" callsign="Drawer"/>'
            f'<strokeColor value="{stroke}"/><fillColor value="{fill}"/>'
            + "".join(f'<link point="{la},{lo}"/>' for la, lo in pts) + "</detail>")


SH = ["id", "uid", "servertime", "event_time", "cot_type", "how", "callsign",
      "latitude", "longitude", "channels", "channel_numbers", "raw_detail"]


def _srow(i, uid, t, ct, xml, la, lo):
    return (i, uid, t, t, ct, "h-g-i-g-o", "", la, lo, "Admin", "6", xml)


PER1 = _poly("Perimeter", [(39.800, -98.500), (39.800, -98.480), (39.812, -98.480), (39.812, -98.500), (39.800, -98.500)])
PER2 = _poly("Perimeter", [(39.800, -98.500), (39.800, -98.470), (39.816, -98.470), (39.816, -98.500), (39.800, -98.500)])
HAZ = _poly("Hazard", [(39.803, -98.495), (39.803, -98.490), (39.806, -98.490), (39.806, -98.495), (39.803, -98.495)],
            stroke="-16776961", fill="1073807104")
FIRE = ('<detail><contact callsign="Fire line"/><creator uid="c2" callsign="Ops"/><strokeColor value="-65536"/>'
        '<strokeWeight value="4"/><link point="39.798,-98.505"/><link point="39.805,-98.492"/><link point="39.814,-98.478"/></detail>')
STG = ('<detail><contact callsign="Staging"/><strokeColor value="-16711936"/><fillColor value="1090453504"/>'
       '<shape><ellipse major="250" minor="250" angle="360"/></shape></detail>')
SHAPE_ROWS = [
    _srow(1, "per", T(10, 0), "u-d-f", PER1, 39.806, -98.490),
    _srow(2, "per", T(10, 10), "u-d-f", PER2, 39.808, -98.485),
    _srow(3, "haz", T(10, 2), "u-d-f", HAZ, 39.8045, -98.4925),
    _srow(4, "stg", T(10, 3), "u-d-c-c", STG, 39.809, -98.483),
    _srow(5, "fire", T(10, 4), "u-d-f", FIRE, 39.805, -98.492),
]
DELETIONS = [(T(10, 40), "haz", "", 43)]
PARAMS = {"north": 39.85, "south": 39.75, "west": -98.55, "east": -98.45, "start": "x", "end": "y"}

DEV_COLS = ["id", "uid", "callsign", "servertime", "event_time", "latitude", "longitude", "ce_m", "how",
            "cot_type", "channels", "reported_team", "reported_role", "course_deg", "speed_ms",
            "battery_pct", "device_model", "tak_platform", "tak_version"]


def _drow(i, t, la, lo):
    return (i, "DEV-1", "ALPHA", t, t, la, lo, 5.0, "m-g", "a-f-G-U-C", "Admin", "Cyan",
            "Team Member", 90, 1.5, 80, "Pixel", "ATAK", "5.2")


DEV_ROWS = [_drow(1, T(10, 0), 39.801, -98.498), _drow(2, T(10, 20), 39.806, -98.488), _drow(3, T(10, 45), 39.811, -98.481)]

tmp = tempfile.mkdtemp(prefix="takx-browser-")
coll = shapes.collect(SHAPE_ROWS, SH, DELETIONS, PARAMS)
WITH = os.path.join(tmp, "with_shapes.kmz")
WITHOUT = os.path.join(tmp, "no_shapes.kmz")
open(WITH, "wb").write(kmz.build_kmz(DEV_ROWS, DEV_COLS, PARAMS, "t", "tester", "TEST", shape_collection=coll))
open(WITHOUT, "wb").write(kmz.build_kmz(DEV_ROWS, DEV_COLS, PARAMS, "t", "tester", "TEST"))

# A KMZ shaped exactly like TAK Server's own export, per its KmlUtils.java:
# one Placemark per device with id=uid and name=callsign, a gx:MultiTrack of
# gx:Tracks pairing <when> with <gx:coord>, aligned speed/ce arrays; plus a
# timed Point, an untimed Point, and a LineString - which cannot be replayed.
def _tak_style_kmz(path, rows, extra_uid=None, shift_index=None):
    """A KMZ in TAK Server's own shape (KmlUtils.buildTrack: <when> is
    servertime, written in UTC) from this suite's device rows, so Compare
    mode can be checked against a file whose positions are known to be
    identical. extra_uid adds a device the first file does not have (TAK
    Server's export has no bounding box, so that is the normal case);
    shift_index moves one position by ~50 m so a disagreement is present."""
    by_uid = {}
    for i, r in enumerate(rows):
        la, lo = r[5], r[6]
        if shift_index == i:
            la += 0.00045
        by_uid.setdefault((r[1], r[2]), []).append((r[3], la, lo))
    if extra_uid:
        by_uid[(extra_uid, extra_uid)] = [(T(10, 5), 40.0, -98.9), (T(10, 6), 40.0, -98.89)]
    pms = []
    for (uid, cs), pts in by_uid.items():
        whens = "".join(f"<when>{t.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')}</when>" for t, _, _ in pts)
        coords = "".join(f"<gx:coord>{lo} {la} 0</gx:coord>" for _, la, lo in pts)
        pms.append(f'<Placemark id="{uid}"><name>{cs}</name><gx:MultiTrack><gx:Track>{whens}{coords}</gx:Track></gx:MultiTrack></Placemark>')
    doc = ('<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2" '
           'xmlns:gx="http://www.google.com/kml/ext/2.2"><Document>' + "".join(pms) + '</Document></kml>')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("doc.kml", doc)
    return path


TAK_SAME = _tak_style_kmz(os.path.join(tmp, "tak_same.kmz"), DEV_ROWS, extra_uid="ANDROID-far")

# Our KMZ with a stationary repeat (two reports at the same spot, 2 min
# apart), and TAK-shaped files that (a) omit the repeat - what Optimize
# export does, (b) cover only the first half hour, (c) call the device by
# its uid instead of its callsign.
REPEAT_ROWS = [_drow(1, T(10, 0), 39.801, -98.498), _drow(2, T(10, 2), 39.801, -98.498),
               _drow(3, T(10, 20), 39.806, -98.488), _drow(4, T(10, 45), 39.811, -98.481)]
OURS_REPEAT = os.path.join(tmp, "ours_repeat.kmz")
open(OURS_REPEAT, "wb").write(kmz.build_kmz(REPEAT_ROWS, DEV_COLS, PARAMS, "t", "tester", "TEST"))
TAK_THINNED = _tak_style_kmz(os.path.join(tmp, "tak_thinned.kmz"), [REPEAT_ROWS[0], REPEAT_ROWS[2], REPEAT_ROWS[3]])
TAK_SHORT = _tak_style_kmz(os.path.join(tmp, "tak_short.kmz"), [REPEAT_ROWS[0], REPEAT_ROWS[1], REPEAT_ROWS[2]])
TAK_RENAMED = _tak_style_kmz(os.path.join(tmp, "tak_renamed.kmz"),
                             [tuple(list(r[:2]) + ["DEV-1"] + list(r[3:])) for r in REPEAT_ROWS])
TAK_SHIFTED = _tak_style_kmz(os.path.join(tmp, "tak_shifted.kmz"), DEV_ROWS, shift_index=1)

# A full package as the tool now writes it: locations.kmz, cot.csv (with
# the spreadsheet guard, Python spelling) and cot_router-raw.csv written the
# way psql writes CSV with every value in the server's text form. RECHECK_RAW
# is what the administrator's re-run produces for the raw statement - the
# same bytes - and RECHECK_PLAIN the plain query's psql output ("+HH"
# offsets, one extra device the package's box does not cover).
def _raw_rows(rows, shift_index=None):
    out = []
    for i, r in enumerate(rows):
        la = r[5] + (0.00045 if shift_index == i else 0)
        out.append([str(r[0]), r[1], r[3].strftime("%Y-%m-%d %H:%M:%S-04"), '<detail><contact callsign="' + r[2] + '"/></detail>',
                    str(la), str(r[6])])
    return out

def _raw_csv(rows, shift_index=None):
    return exports.psql_csv(["id", "uid", "servertime", "detail", "latitude", "longitude"], _raw_rows(rows, shift_index))

def _plain_csv(rows, shift_index=None, psql=False):
    out = ["id,uid,callsign,servertime,latitude,longitude"]
    for i, r in enumerate(rows):
        la = r[5] + (0.00045 if shift_index == i else 0)
        t = r[3].strftime("%Y-%m-%d %H:%M:%S-04") if psql else str(r[3])
        out.append(f"{r[0]},{r[1]},{r[2]},{t},{la},{r[6]}")
    return chr(10).join(out) + chr(10)

def _package_zip(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("t-locations.kmz", open(WITHOUT, "rb").read())
        z.writestr("t-cot.csv", _plain_csv(DEV_ROWS))
        z.writestr("t-cot_router-raw.csv", _raw_csv(DEV_ROWS))
    return path

PKG = _package_zip(os.path.join(tmp, "t-package.zip"))


def _package_with_sums(path, tamper=None):
    """A package carrying its own SHA256SUMS.txt, the way a real one does.
    tamper: a member name to alter AFTER the list was written, i.e. the
    file someone changed after the package was built."""
    members = {
        "t-locations.kmz": open(WITHOUT, "rb").read(),
        "t-cot.csv": _plain_csv(DEV_ROWS).encode(),
        "t-cot_router-raw.csv": _raw_csv(DEV_ROWS).encode(),
        "t-README.txt": b"README\n",
    }
    sums = "".join(f"{hashlib.sha256(v).hexdigest()}  {k}\n" for k, v in sorted(members.items()))
    if tamper:
        members[tamper] = members[tamper] + b"\n# added after the list was written\n"
    with zipfile.ZipFile(path, "w") as z:
        for k, v in sorted(members.items()):
            z.writestr(k, v)
        z.writestr("t-SHA256SUMS.txt", sums)
    return path


PKG_SUMS = _package_with_sums(os.path.join(tmp, "t-sums.zip"))
PKG_TAMPERED = _package_with_sums(os.path.join(tmp, "t-tampered.zip"), tamper="t-cot.csv")
RECHECK_RAW = os.path.join(tmp, "recheck-cot_router-raw.csv")
open(RECHECK_RAW, "w", newline="").write(_raw_csv(DEV_ROWS))
RECHECK_RAW_BAD = os.path.join(tmp, "recheck-cot_router-raw-bad.csv")   # row 2 moved ~50 m
open(RECHECK_RAW_BAD, "w", newline="").write(_raw_csv(DEV_ROWS, shift_index=1))
RECHECK_PLAIN = os.path.join(tmp, "recheck-positions-plain.csv")
open(RECHECK_PLAIN, "w", newline="").write(_plain_csv(DEV_ROWS, psql=True) +
                                             "99,ANDROID-far,FAR-1,2026-01-01 10:05:00-04,40.0,-98.9" + chr(10))

FOREIGN = os.path.join(tmp, "takserver_style.kmz")
_kml = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2"><Document>
<Placemark id="ANDROID-unit-one"><name>UNIT-1</name><styleUrl>#a-f-G-U-C-Cyan</styleUrl>
 <gx:MultiTrack><gx:Track>
  <ExtendedData><SchemaData schemaUrl="#trackschema">
   <gx:SimpleArrayData name="speed"><gx:value>1.2</gx:value><gx:value>1.4</gx:value><gx:value></gx:value></gx:SimpleArrayData>
   <gx:SimpleArrayData name="ce"><gx:value>5.0</gx:value><gx:value>4.5</gx:value><gx:value>6.0</gx:value></gx:SimpleArrayData>
  </SchemaData></ExtendedData>
  <when>2026-01-01T14:00:00Z</when><when>2026-01-01T14:05:00Z</when><when>2026-01-01T14:10:00Z</when>
  <gx:coord>-98.500 40.900 0</gx:coord><gx:coord>-98.495 40.903 0</gx:coord><gx:coord>-98.490 40.906 0</gx:coord>
 </gx:Track><gx:Track>
  <when>2026-01-01T15:00:00Z</when><when>2026-01-01T15:05:00Z</when>
  <gx:coord>-98.480 40.910 0</gx:coord><gx:coord>-98.475 40.912 0</gx:coord>
 </gx:Track></gx:MultiTrack></Placemark>
<Placemark id="ANDROID-unit-two"><name>UNIT-2</name><gx:MultiTrack><gx:Track>
  <when>2026-01-01T14:02:00Z</when><when>2026-01-01T14:07:00Z</when>
  <gx:coord>-98.510 40.895 0</gx:coord><gx:coord>-98.505 40.897 0</gx:coord>
 </gx:Track></gx:MultiTrack></Placemark>
<Placemark id="marker-1"><name>Timed marker</name><TimeStamp><when>2026-01-01T14:30:00Z</when></TimeStamp>
 <Point><coordinates>-98.502,40.901,0</coordinates></Point></Placemark>
<Placemark id="marker-2"><name>Untimed marker</name><Point><coordinates>-98.503,40.902,0</coordinates></Point></Placemark>
<Placemark id="route-1"><name>A route</name><LineString><coordinates>-98.5,40.9,0 -98.49,40.91,0</coordinates></LineString></Placemark>
</Document></kml>"""
import zipfile as _zf
with _zf.ZipFile(FOREIGN, "w", _zf.ZIP_DEFLATED) as _z:
    _z.writestr("doc.kml", _kml)

# ---------------------------------------------------------------------------
# Throwaway dev server on a free port, local auth, dummy DB settings.
# ---------------------------------------------------------------------------
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    PORT = s.getsockname()[1]
env = dict(os.environ)
env.update({
    "AUDIT_DB": os.path.join(tmp, "audit.sqlite"), "AUTH_MODE": "local", "SECRET_KEY": "browser-test",
    "BOOTSTRAP_ADMIN_USERNAME": "admin", "BOOTSTRAP_ADMIN_PASSWORD": "browsertest12345",
    "DB_HOST": "unused", "DB_PORT": "5432", "DB_NAME": "unused", "DB_USER": "unused", "DB_PASSWORD": "unused",
    "NO_COLOR": "1", "PORT": str(PORT), "SESSION_COOKIE_SECURE": "false",
})
# gunicorn.conf.py/app.py read PORT; the Flask dev server hard-codes 5000, so
# run it through a tiny launcher that binds where we want.
launcher = f"import app; app.app.run(port={PORT}, debug=False, use_reloader=False)"
server = subprocess.Popen([sys.executable, "-c", launcher], cwd=REPO, env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
BASE = f"http://127.0.0.1:{PORT}"
for _ in range(60):
    try:
        urllib.request.urlopen(BASE + "/login", timeout=1)
        break
    except Exception:
        time.sleep(0.25)
else:
    server.kill()
    print("FAIL: dev server did not come up")
    sys.exit(1)

SEL = ".leaflet-shapes-pane path"


def paths(pg, sel=SEL):
    return pg.evaluate("sel => [...document.querySelectorAll(sel)].map(p => (p.getAttribute('d')||'').length)", sel)


def scrub_to(pg, frac):
    pg.evaluate("f => { var s = document.getElementById('scrubber'); s.value = Math.round(s.max * f);"
                " s.dispatchEvent(new Event('input', {bubbles: true})); }", frac)
    pg.wait_for_timeout(150)


def login(pg):
    pg.goto(BASE + "/login")
    pg.fill("input[name=username]", "admin")
    pg.fill("input[name=password]", "browsertest12345")
    pg.click("button[type=submit]")
    pg.wait_for_load_state("networkidle")


def load(pg, path):
    pg.goto(BASE + "/verify")
    pg.wait_for_load_state("networkidle")
    pg.set_input_files("#fileInput", path)
    pg.wait_for_selector("#summaryBox", state="visible", timeout=20000)
    pg.wait_for_timeout(1000)


try:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        errors = []
        pg = browser.new_page(viewport={"width": 1200, "height": 1000})
        pg.on("pageerror", lambda e: errors.append(str(e)))
        login(pg)

        # ---- drawn shapes -------------------------------------------------
        load(pg, WITH)
        check("summary counts the drawn shapes",
              "4 drawn shapes" in pg.locator("#summaryBox").inner_text())
        legend = [t.replace("\n", " ") for t in pg.locator("#shapeLegend button").all_inner_texts()]
        check("legend lists every shape with kind and version count, largest first",
              len(legend) == 4 and legend[0].startswith("Perimeter (polygon, 2 versions)")
              and any("Hazard (polygon, 1 version, deleted)" in t for t in legend))
        check("shapes pane sits beneath the overlay pane (z 350 < 400)",
              pg.evaluate("() => getComputedStyle(document.querySelector('.leaflet-shapes-pane')).zIndex") == "350")

        # 45-minute window (10:00 -> 10:45): per v1@0m, haz@2m, stg@3m, fire@4m,
        # per v2@10m, haz deleted@40m.
        scrub_to(pg, 0.0)
        check("t=0: only the first shape (perimeter v1) is drawn", len(paths(pg)) == 1)
        v1 = paths(pg)[0]
        scrub_to(pg, 0.06)
        check("t=2.7m: perimeter + hazard", len(paths(pg)) == 2)
        scrub_to(pg, 0.10)
        check("t=4.5m: all four drawn", len(paths(pg)) == 4)
        scrub_to(pg, 0.30)
        check("t=13.5m: still four", len(paths(pg)) == 4)
        check("perimeter geometry changed at version 2", paths(pg)[0] != v1)
        scrub_to(pg, 0.95)
        check("t=42.8m: hazard gone after its 40m deletion -> three", len(paths(pg)) == 3)
        check("device dot still drawn alongside the shapes", len(paths(pg, ".leaflet-overlay-pane path")) >= 1)

        # Real mouse click on a shape -> version popup. Never dispatch_event.
        scrub_to(pg, 0.30)
        box = pg.locator(SEL).first.bounding_box()
        pg.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
        pg.wait_for_timeout(800)
        pop = pg.locator(".leaflet-popup-content")
        text = pop.first.inner_text() if pop.count() else ""
        check("clicking a shape opens its popup with version detail",
              pop.count() > 0 and "Version" in text and "of" in text and "Kind" in text)
        check("popup did not disturb the map (paths intact)", not all(x == 4 for x in paths(pg)))
        pg.locator(".leaflet-popup-close-button").click()
        pg.wait_for_timeout(200)

        n0 = len(paths(pg))
        pg.locator("#shapeLegend button").first.click()
        pg.wait_for_timeout(200)
        check("legend toggle hides that shape", len(paths(pg)) == n0 - 1)
        pg.locator("#shapesAllNoneBtn").click()
        pg.wait_for_timeout(200)
        check("Select none hides every shape", len(paths(pg)) == 0)
        pg.locator("#shapesAllNoneBtn").click()
        pg.wait_for_timeout(200)
        check("Select all brings them back", len(paths(pg)) == n0)

        # ---- a KMZ without shapes is unaffected ---------------------------
        load(pg, WITHOUT)
        check("no-shapes KMZ: legend section hidden",
              pg.locator("#shapeLegendSection").evaluate("e => e.hidden"))
        check("no-shapes KMZ: device parsed", "1 people/entities, 3 positions" in pg.locator("#summaryBox").inner_text())
        check("no JavaScript errors across the Verify page checks", not errors, errors)

        # ---- a KMZ exported by TAK Server itself: replays, says it is foreign --
        load(pg, FOREIGN)
        head = pg.locator("#summaryBoxSummary").inner_text()
        check("TAK Server KMZ: summary leads with NOT PRODUCED BY THIS TOOL", head.startswith("NOT PRODUCED BY THIS TOOL"))
        check("TAK Server KMZ: 3 devices, 8 positions read from MultiTrack/Track + a timed point",
              "3 people/entities, 8 positions" in head, head)
        pg.locator("#summaryBox").click(); pg.wait_for_timeout(200)
        body = pg.locator("#summaryBoxBody").inner_text()
        check("TAK Server KMZ: the 2 untimed placemarks are counted as not shown, not silently dropped",
              "2 placemark(s) without a timestamped position" in body)
        check("TAK Server KMZ: verification stated as not possible, with the reason", "Not possible" in body and "audit-log entry" in body)
        check("TAK Server KMZ: hash box is red (no matching export)",
              "No matching export" in pg.locator("#hashResultSummary").inner_text())
        check("TAK Server KMZ: legend uses the file's own callsigns",
              set(pg.locator("#deviceLegend button").all_inner_texts()) == {"UNIT-1", "UNIT-2", "Timed marker"})
        box = pg.locator(".leaflet-overlay-pane path").first.bounding_box()
        pg.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2); pg.wait_for_timeout(600)
        pop = pg.locator(".leaflet-popup-content")
        ptext = pop.first.inner_text() if pop.count() else ""
        check("TAK Server KMZ: a point's popup shows the file's own speed/ce and a not-verified note",
              "speed" in ptext and "ce" in ptext and "not verified" in ptext, ptext[:120])
        pg.locator(".leaflet-popup-close-button").click(); pg.wait_for_timeout(200)
        # Our own KMZ with positions must never be reported as foreign.
        load(pg, WITHOUT)
        check("our own KMZ is still read by the strict reader, never flagged foreign",
              not pg.locator("#summaryBoxSummary").inner_text().startswith("NOT PRODUCED"))
        check("no JavaScript errors across the foreign-file checks", not errors, errors)

        # ---- a hostile file: a callsign carrying markup must never run --------
        # Every file this page opens was handed over by someone else. Popups
        # go through sanitizePopupHtml(); the name label on the map goes to
        # Leaflet's tooltip, which renders a string as HTML, so it is escaped.
        import html as _html
        HOSTILE = _tak_style_kmz(os.path.join(tmp, "tak_hostile.kmz"),
                                 [tuple(list(r[:2]) + [_html.escape('<img src=x onerror="window.__xss=1">', quote=True)] + list(r[3:])) for r in REPEAT_ROWS])
        load(pg, HOSTILE)
        pg.evaluate("() => { var t = document.getElementById('showNamesToggle'); t.checked = true; t.dispatchEvent(new Event('change')); }")
        pg.wait_for_timeout(800)
        tip = pg.locator(".leaflet-tooltip")
        check("hostile callsign: the name tooltip shows the markup as text and runs nothing",
              tip.count() >= 1 and '<img src=x onerror="window.__xss=1">' in tip.first.inner_text()
              and pg.evaluate("() => window.__xss") is None
              and pg.evaluate("() => document.querySelectorAll('.leaflet-tooltip img').length") == 0)
        check("hostile callsign: the legend shows it as text too",
              '<img src=x onerror="window.__xss=1">' in pg.locator("#deviceLegend").inner_text())
        pg.evaluate("() => { var t = document.getElementById('showNamesToggle'); t.checked = false; t.dispatchEvent(new Event('change')); }")
        check("no JavaScript errors across the hostile-file checks", not errors, errors)

        # ---- Compare mode ------------------------------------------------------
        def compare_with(path):
            pg.set_input_files("#compareInput", path)
            pg.wait_for_timeout(1200)
            return pg.locator("#compareResult").inner_text()

        load(pg, WITHOUT)
        check("Compare box appears once a file with positions has loaded",
              pg.evaluate("() => !document.getElementById('compareBox').hidden"))
        txt = compare_with(WITHOUT)
        check("Compare: our KMZ against itself matches every position",
              "Every one of the 3 positions" in txt and "hashOk" in pg.get_attribute("#compareBox", "class"), txt[:160])
        txt = compare_with(TAK_SAME)
        check("Compare: a TAK-Server-shaped export of the same rows (UTC times) matches every position",
              "Every one of the 3 positions" in txt and "hashOk" in pg.get_attribute("#compareBox", "class"), txt[:200])
        check("Compare: the server file's extra device is reported as expected, not as a disagreement",
              "holds 2 position(s) that are not in" in txt and "ANDROID-far" in txt, txt[:300])
        txt = compare_with(TAK_SHIFTED)
        check("Compare: one moved position is flagged, the box turns red",
              "2 of 3 positions" in txt and "1 do not" in txt and "hashBad" in pg.get_attribute("#compareBox", "class"), txt[:200])
        load(pg, WITHOUT)
        check("a KMZ alone: the Compare tab is neutral and says a re-check can only match by callsign and position",
              pg.locator("#compareSummary").inner_text() == "Compare" and
              "not exactly by row id" in pg.locator("#compareNote").inner_text() and
              "hashOk" not in pg.get_attribute("#compareBox", "class"))

        # ---- a package: neutral until the administrator's file is chosen ---------
        load(pg, PKG)
        check("a package loads with the Compare tab neutral and asks for the administrator's re-check file",
              pg.locator("#compareSummary").inner_text() == "Compare" and
              "No re-check file compared yet" in pg.locator("#compareNote").inner_text() and
              "hashOk" not in pg.get_attribute("#compareBox", "class"))
        # the byte-identical raw file: exact by id against the package's own raw file
        check("the package's raw file and the re-check raw file are byte-identical (the hand check)",
              open(RECHECK_RAW, "rb").read() == zipfile.ZipFile(PKG).read("t-cot_router-raw.csv"))
        txt = compare_with(RECHECK_RAW); pg.wait_for_timeout(800)
        check("recheck-cot_router-raw.csv: exact by row id against the package's cot_router-raw.csv, tab green",
              "Exact check by row id - t-cot_router-raw.csv against recheck-cot_router-raw.csv" in txt and
              "all 3 rows present with identical" in txt and "hashOk" in pg.get_attribute("#compareBox", "class") and
              "matches exactly by row id" in pg.locator("#compareSummary").inner_text(), txt[:400])
        comp = pg.locator("#companionBox").inner_text()
        check("companion: hashed in the browser, not yet in the audit log, admin offered Record",
              "SHA-256 of recheck-cot_router-raw.csv" in comp and "Not in the audit log" in comp and
              pg.locator("#recordCompanionBtn").count() == 1, comp[:200])
        pg.locator("#recordCompanionBtn").click(); pg.wait_for_timeout(1200)
        comp = pg.locator("#companionBox").inner_text()
        check("companion: Record writes it to the audit log; the box now shows who and when",
              "Recorded in the audit log" in comp and "by admin" in comp and "3 of 3 package positions matched" in comp,
              comp[:300])
        txt_bad = compare_with(RECHECK_RAW_BAD)
        check("a re-check raw file with one moved row: the exact check names the id and field, tab red",
              "id 2: latitude" in txt_bad and "1 differ" in txt_bad and "hashBad" in pg.get_attribute("#compareBox", "class") and
              "differs by row id" in pg.locator("#compareSummary").inner_text(), txt_bad[:400])
        txt = compare_with(RECHECK_PLAIN)
        check("recheck-positions-plain.csv (psql offsets): exact by id against the package's cot.csv, extra row noted",
              "against recheck-positions-plain.csv" in txt and "all 3 rows present with identical" in txt and
              "1 further row(s) only in recheck-positions-plain.csv" in txt, txt[:400])
        load(pg, PKG)
        compare_with(RECHECK_RAW); pg.wait_for_timeout(800)
        check("companion: loading the same file again finds the record without any action",
              "Recorded in the audit log" in pg.locator("#companionBox").inner_text())

        # ---- a re-check posted by the server (token route) shows on the Compare tab on load
        # Mint a token in the test server's own audit DB, post the hash file
        # the way the pasted line does, then load the package: no file to
        # choose, the verdict is already there.
        import sqlite3 as _sq, urllib.request as _ur, uuid as _uu
        pkg_hash = hashlib.sha256(open(PKG, "rb").read()).hexdigest()
        raw_hash = hashlib.sha256(zipfile.ZipFile(PKG).read("t-cot_router-raw.csv")).hexdigest()
        tok = "browser-test-token-" + _uu.uuid4().hex
        con = _sq.connect(env["AUDIT_DB"])
        con.execute("INSERT INTO recheck_tokens (token, case_prefix, package_sha256, raw_sha256, queries_sql, created_by, created_utc, expires_utc)"
                    " VALUES (?,?,?,?,?,?,?,?)", (tok, "t", pkg_hash, raw_hash, "SELECT 1;", "authenticated: admin",
                                                  "2026-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00"))
        con.commit(); con.close()
        sums = (raw_hash + "  t-recheck-cot_router-raw.csv" + chr(10)).encode()
        boundary = "----takx" + _uu.uuid4().hex
        body = (("--" + boundary + chr(13) + chr(10) + 'Content-Disposition: form-data; name="host"' + chr(13) + chr(10) + chr(13) + chr(10) + "takserver" + chr(13) + chr(10) +
                 "--" + boundary + chr(13) + chr(10) + 'Content-Disposition: form-data; name="path"' + chr(13) + chr(10) + chr(13) + chr(10) + "/var/lib/takextract/recheck/t/2026-09-19T14-02" + chr(13) + chr(10) +
                 "--" + boundary + chr(13) + chr(10) + 'Content-Disposition: form-data; name="sums"; filename="t-recheck-SHA256SUMS.txt"' + chr(13) + chr(10) +
                 "Content-Type: text/plain" + chr(13) + chr(10) + chr(13) + chr(10)).encode() + sums +
                (chr(13) + chr(10) + "--" + boundary + "--" + chr(13) + chr(10)).encode())
        req = _ur.Request(BASE + "/recheck/" + tok + "/result", data=body, method="POST",
                          headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
        info = _ur.urlopen(req, timeout=10).read().decode()
        # The Export page's watch, end to end: with this token showing, a
        # posted result turns the line green without a reload.
        pg.goto(BASE + "/"); pg.wait_for_load_state("networkidle")
        pg.evaluate("(t) => showRecheck('t', t)", tok); pg.wait_for_timeout(400)
        check("token route: the posted hash file is recorded and answered with the INFO text, verdict first",
              info.startswith("recorded: t re-check, 1 files, cot_router-raw.csv matches the package: yes") and "RECHECK-INFO" in info, info[:160])
        pg.wait_for_timeout(4000)
        check("Export page: the watch reports the recorded verdict on its own, no reload",
              "Re-check recorded" in pg.locator("#recheckStatus").inner_text()
              and pg.get_attribute("#recheckStatus", "class") == "statusOk",
              pg.locator("#recheckStatus").inner_text()[:120])

        load(pg, PKG); pg.wait_for_timeout(800)
        check("Verify: the recorded re-check shows on the Compare tab on load - green, who, when, where - with nothing to choose",
              "hashOk" in pg.get_attribute("#compareBox", "class") and
              "re-check recorded, raw file matches" in pg.locator("#compareSummary").inner_text() and
              "takserver:/var/lib/takextract/recheck/t/2026-09-19T14-02" in pg.locator("#compareNote").inner_text() and
              "authenticated: admin" in pg.locator("#compareNote").inner_text(),
              pg.locator("#compareNote").inner_text()[:300])
        check("Verify: the hash panel still shows only the export match, not the re-check row",
              "recheck" not in pg.locator("#hashResultBody").inner_text().lower() or
              "No matching export" in pg.locator("#hashResultSummary").inner_text())

        # Diagnostics.
        load(pg, OURS_REPEAT)
        txt = compare_with(TAK_THINNED)
        check("Diagnose: a missing stationary repeat is attributed to Remove Identical Position Reports",
              "3 of 4 positions" in txt and "repeat the same device's previous report" in txt and "Remove Identical Position Reports" in txt, txt[-700:])
        txt = compare_with(TAK_SHORT)
        check("Diagnose: a position beyond the second file's range is attributed to its window",
              "outside the time range" in txt and "Start / End" in txt, txt[-700:])
        txt = compare_with(TAK_RENAMED)
        check("Diagnose: the same track under another name is reported as a rename, not a disagreement",
              "ALPHA in ours_repeat.kmz is DEV-1 in tak_renamed.kmz" in txt and "Not a data disagreement" in txt, txt[-700:])
        check("no JavaScript errors across the Compare checks", not errors, errors)

        # ---- Export map: shape outlines from /api/trails ----------------------
        # The route needs a database; stub its response and check the page
        # draws what it is given as outlines in the trails layer. The layer
        # only draws at zoom >= 11 and the map opens at zoom 4, so zoom in
        # first with the map's own +/- control (7 clicks), which fires the
        # same moveend/zoomend refresh a user's scroll-wheel would.
        pg.set_viewport_size({"width": 1200, "height": 1000})
        stub = ('{"trails": [[[40.90,-98.50],[40.91,-98.49]]], "shapes": ['
                '{"kind":"polygon","latlngs":[[40.900,-98.500],[40.900,-98.480],[40.912,-98.480],[40.912,-98.500],[40.900,-98.500]]},'
                '{"kind":"line","latlngs":[[40.898,-98.505],[40.914,-98.478]]},'
                '{"kind":"circle","center":[40.909,-98.483],"radius_m":250}]}')
        trails_sent = []
        def _trails(r):
            trails_sent.append(json.loads(r.request.post_data or "{}"))
            r.fulfill(status=200, body=stub, headers={"Content-Type": "application/json"})
        pg.route("**/api/trails", _trails)
        pg.route("**/api/count", lambda r: r.fulfill(status=200, body='{"positional_records":0}', headers={"Content-Type": "application/json"}))
        pg.route("**/api/channels", lambda r: r.fulfill(status=200, body='{"channels":[]}', headers={"Content-Type": "application/json"}))
        pg.goto(BASE + "/")
        pg.wait_for_load_state("networkidle")
        before = pg.evaluate("() => document.querySelectorAll('.leaflet-overlay-pane path').length")
        check("Export map at its opening zoom draws no overlay (too far out)", before == 0, f"paths={before}")
        for _ in range(7):
            pg.locator(".leaflet-control-zoom-in").click()
            pg.wait_for_timeout(450)   # let each zoom animation finish, or clicks are dropped
        pg.wait_for_timeout(1200)
        n_paths = pg.evaluate("() => document.querySelectorAll('.leaflet-overlay-pane path').length")
        check("zoomed in, Export map draws the stubbed trail + 3 shape outlines (4 paths)", n_paths == 4, f"paths={n_paths}")
        fills = pg.evaluate("() => [...document.querySelectorAll('.leaflet-overlay-pane path')].map(p => p.getAttribute('fill'))")
        check("outlines are unfilled and non-interactive (a drawing aid, not a layer to click)",
              all(f in (None, "none") for f in fills) and
              pg.evaluate("() => document.querySelectorAll('.leaflet-overlay-pane path.leaflet-interactive').length") == 0, fills)
        # ---- automated-feed shapes: the box is off by default, the overlay
        # request says so, and ticking it re-requests the overlay with the flag.
        check("feed shapes box: present, unticked by default, with an About",
              not pg.is_checked("#includeFeedShapes") and pg.locator("#feedShapesAboutBox").is_hidden())
        check("feed shapes box: the overlay request carries include_feed_shapes=false by default",
              trails_sent and trails_sent[-1].get("include_feed_shapes") is False, trails_sent[-1:] )
        n_before = len(trails_sent)
        pg.locator("#includeFeedShapes").check(); pg.wait_for_timeout(1200)
        check("feed shapes box: ticking it refreshes the overlay with include_feed_shapes=true",
              len(trails_sent) > n_before and trails_sent[-1].get("include_feed_shapes") is True, trails_sent[-1:])
        pg.locator("#feedShapesAboutBtn").click(); pg.wait_for_timeout(100)
        check("feed shapes box: About opens and names the mark and the README",
              pg.locator("#feedShapesAboutBox").is_visible() and "__nodered" in pg.locator("#feedShapesAboutBox").inner_text()
              and "README" in pg.locator("#feedShapesAboutBox").inner_text())
        pg.locator("#feedShapesAboutBtn").click()
        # ---- the re-check block: the one-line server command, the -k toggle, the workstation form
        pg.goto(BASE + "/"); pg.wait_for_load_state("networkidle")
        pg.evaluate("() => showRecheck('CASE-7', 'tok-abc', 'abcdef1234567890' + '0'.repeat(48))"); pg.wait_for_timeout(600)
        a_cmd = pg.locator("#recheckCmdA").inner_text(); b_cmd = pg.locator("#recheckCmdB").text_content()   # B sits in a collapsed <details>
        # The folder carries seconds and the package's short hash: one case can
        # hold several exports, and two re-checks a minute apart would
        # otherwise share a folder and overwrite each other's files.
        check("re-check server line: a folder of its own per package, fetch by token from this page's origin, psql, hashes, tgz, post back, INFO saved",
              a_cmd.startswith('D=/var/lib/takextract/recheck/CASE-7/$(date +%Y-%m-%dT%H-%M-%S)-abcdef12 && mkdir -m 2770 -p "$D" && cd "$D" && curl -fsS -o CASE-7-queries.sql "' + BASE + '/recheck/tok-abc/CASE-7-queries.sql" && sudo -u postgres psql -d cot -f CASE-7-queries.sql && sha256sum CASE-7-queries.sql CASE-7-recheck-*.csv CASE-7-recheck-snapshot.txt > CASE-7-recheck-SHA256SUMS.txt && tar czf CASE-7-recheck.tgz')
              and a_cmd.endswith('-F host="$(hostname)" -F path="$D" "' + BASE + '/recheck/tok-abc/result" | tee RECHECK-INFO.txt')
              and " -k" not in a_cmd, a_cmd)
        pg.locator("#recheckInsecure").check(); pg.wait_for_timeout(200)
        check("re-check server line: the self-signed box adds -k to both curl calls",
              pg.locator("#recheckCmdA").inner_text().count("curl -fsS -k") == 2)
        pg.fill("#recheckBase", "https://takextract.example/"); pg.wait_for_timeout(200)
        check("re-check server line: the base address is editable and a trailing slash is dropped",
              '"https://takextract.example/recheck/tok-abc/CASE-7-queries.sql"' in pg.locator("#recheckCmdA").inner_text())
        check("re-check workstation form: plain psql with the saved host, port, user and database filled in",
              b_cmd.startswith("psql -h unused -p 5432 -U unused -d unused -f CASE-7-queries.sql && sha256sum CASE-7-queries.sql CASE-7-recheck-*.csv"), b_cmd)
        # The fallback is behind a button, and the page watches what actually
        # reaches it rather than asking the operator to choose a method.
        check("re-check: the other-methods form is behind a button, closed to begin with",
              pg.locator("#recheckOtherBox").is_hidden()
              and "Other ways to run it" in pg.locator("#recheckOtherBtn").inner_text())
        pg.locator("#recheckOtherBtn").click(); pg.wait_for_timeout(200)
        check("re-check: the button opens the psql-from-anywhere form and says nothing is posted back",
              pg.locator("#recheckOtherBox").is_visible()
              and "Nothing is posted back" in pg.locator("#recheckOtherBox").inner_text())
        check("re-check: the page starts watching for the server to fetch the script",
              "Waiting for the server" in pg.locator("#recheckStatus").inner_text(),
              pg.locator("#recheckStatus").inner_text())

        check("re-check block names the one line that must match and the one-time setup",
              "CASE-7-recheck-cot_router-raw.csv" in pg.locator("#recheckBox").inner_text() and
              "one-time setup" in pg.locator("#recheckBox").inner_text() and
              pg.get_attribute("#recheckCopyA", "data-copy") == pg.locator("#recheckCmdA").inner_text())

        # ---- Generate: Case / Incident and Exported For are required ----------
        # Still zoomed in with the stubs in place. Draw a rectangle with the
        # draw tool (real mouse, see above); every file tile starts selected. Click
        # Generate with the fields empty: no export request may leave the
        # page, and the message must name the missing field. Then fill both
        # and check the request that does go out carries them. /api/package
        # is stubbed too - there is no database behind this server.
        pg.route("**/api/package", lambda r: r.fulfill(status=400, body='{"error":"stubbed"}', headers={"Content-Type": "application/json"}))
        sent = []
        pg.on("request", lambda req: sent.append(req) if req.url.endswith("/api/package") else None)
        pg.locator(".leaflet-draw-draw-rectangle").click(); pg.wait_for_timeout(200)
        m = pg.locator("#map").bounding_box()
        x0, y0 = m["x"] + m["width"] * 0.3, m["y"] + m["height"] * 0.3
        pg.mouse.move(x0, y0); pg.mouse.down(); pg.mouse.move(x0 + 200, y0 + 120, steps=6); pg.mouse.up()
        pg.wait_for_timeout(500)
        pg.locator("#generateBtn").click(); pg.wait_for_timeout(300)
        msg = pg.locator("#exportResult").inner_text()
        check("Generate with an empty Case / Incident sends nothing and names the field",
              not sent and "Case / Incident" in msg and
              pg.evaluate("() => document.activeElement.id") == "caseId" and
              pg.evaluate("() => document.getElementById('caseId').classList.contains('missing')"), msg)
        pg.fill("#caseId", "CASE-0001")
        pg.locator("#generateBtn").click(); pg.wait_for_timeout(300)
        msg = pg.locator("#exportResult").inner_text()
        check("Generate with an empty Exported For sends nothing and names that field",
              not sent and "Exported For" in msg and
              pg.evaluate("() => document.activeElement.id") == "exportedFor" and
              not pg.evaluate("() => document.getElementById('caseId').classList.contains('missing')"), msg)
        pg.fill("#exportedFor", "Det. Example")
        pg.keyboard.press("Enter"); pg.wait_for_timeout(300)
        check("Enter in a field does not start the export (the pointer-hiding sequence)", not sent, len(sent))
        pg.locator("#generateBtn").click(); pg.wait_for_timeout(800)
        body = json.loads(sent[0].post_data) if sent else {}
        check("with both filled, the export request carries case_id and requested_for",
              len(sent) == 1 and body.get("case_id") == "CASE-0001" and body.get("requested_for") == "Det. Example", body)
        check("the export request carries include_feed_shapes as the box stands (unticked after the reload)",
              body.get("include_feed_shapes") is False, body.get("include_feed_shapes"))
        check("the fields keep their values after an export attempt",
              pg.input_value("#caseId") == "CASE-0001" and pg.input_value("#exportedFor") == "Det. Example")
        check("no JavaScript errors across the Generate checks", not errors, errors)
        pg.unroute("**/api/package")
        pg.unroute("**/api/trails"); pg.unroute("**/api/count"); pg.unroute("**/api/channels")

        # ---- Audit page: the download fields are required too ----------------
        pg.set_viewport_size({"width": 1200, "height": 1000})
        pg.route("**/api/audit/download", lambda r: r.fulfill(status=400, body='{"error":"stubbed"}', headers={"Content-Type": "application/json"}))
        dl = []
        pg.on("request", lambda req: dl.append(req) if req.url.endswith("/api/audit/download") else None)
        pg.goto(BASE + "/audit"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(500)
        pg.locator("#downloadAllBtn").click(); pg.wait_for_timeout(300)
        hint = pg.locator("#downloadHint").inner_text()
        check("Audit: Download entire log with empty fields sends nothing and names Case / Incident",
              not dl and "Case / Incident" in hint and pg.evaluate("() => document.activeElement.id") == "caseId", hint)
        pg.fill("#caseId", "CASE-0002"); pg.fill("#exportedFor", "Sgt. Sample")
        pg.keyboard.press("Enter"); pg.wait_for_timeout(300)
        check("Audit: Enter in a field does not start the download", not dl, len(dl))
        pg.locator("#downloadAllBtn").click(); pg.wait_for_timeout(800)
        body = json.loads(dl[0].post_data) if dl else {}
        check("Audit: with both filled, the download request carries case_id and requested_for",
              len(dl) == 1 and body.get("case_id") == "CASE-0002" and body.get("requested_for") == "Sgt. Sample", body)
        pg.unroute("**/api/audit/download")

        # ---- Audit page: cases open to show their entries ---------------------
        # The log reads as a list of cases, each opening to its own entries
        # (package, the fetch of its script, the re-check that followed) -
        # so seed one case with the shape a real one has, plus the other
        # three verdicts, and an entry with no case at all.
        import sqlite3 as _sq3
        _con = _sq3.connect(env["AUDIT_DB"])
        def _entry(case, kind, outcome, pkg, when, detail, count=19, forwhom="Det. Example"):
            _con.execute("INSERT INTO export_log (ts_utc, ts_local, actor, client_ip, case_id, export_kind,"
                         " record_count, outcome, package_sha256, detail, requested_for)"
                         " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         (when + "+00:00", when.replace("T", " ") + " UTC", "authenticated: admin",
                          "10.0.0.1", case, kind, count, outcome, pkg, detail, forwhom))
        # Inserted oldest first: the log orders by id, which ascends with
        # time on a real server, so a fixture written newest-first would
        # order backwards and prove nothing about what the page shows.
        _entry("UnverifiedCase", "recheck", "raw unverified", "4d" * 32, "2026-09-20T13:00:00", "x")
        _entry("MissingCase", "recheck", "raw file missing", "3c" * 32, "2026-09-20T14:00:00", "x")
        _entry("BadCase", "recheck", "raw MISMATCH", "2b" * 32, "2026-09-20T15:00:00", "x")
        _entry("OldStyle", "recheck", "raw match", "5e" * 32, "2026-09-20T15:30:00",
               "re-check at takserver:/var/lib/takextract/recheck/OldStyle/2026-09-19T14-02; "
               "19 file(s) hashed; hash file OldStyle-recheck-SHA256SUMS.txt sha256 " + "ee" * 32 + "; "
               "archive OldStyle-recheck.tgz sha256 " + "dd" * 32 + "; "
               "script match: yes; cot_router-raw.csv match: yes")
        _entry("RowTest", "package", "generated / delivered", "0d" * 32, "2026-09-20T16:05:00",
               "file: RowTest-package.zip", count=11)
        # The package's own file list, as an export records it: every file
        # with the hash calculated when the package was built.
        _pkg_files = ["cot.csv", "shapes.csv", "chat.csv", "connections.csv", "missions.csv",
                      "mission-subs.csv", "mission-contents.csv", "mission-changes.csv",
                      "files.csv", "attachments.csv", "video.csv", "datafeeds.csv",
                      "federation.csv", "manifest.csv", "cot_router-raw.csv", "locations.kmz",
                      "README.txt", "certification-template.txt", "queries.sql"]
        _pkg_list = ", ".join(f"{i:02x}" * 32 + f" RowTest-{n}" for i, n in enumerate(_pkg_files))
        _entry("RowTest", "package", "generated / delivered", "1a" * 32, "2026-09-20T16:11:35",
               "file: RowTest-package.zip; package files: " + _pkg_list, count=5829)
        _entry("RowTest", "recheck-fetch", "ok", "1a" * 32, "2026-09-20T16:13:10",
               "queries.sql fetched by 10.0.0.9", count=0)
        # What the server hashed: the script, the raw file, the snapshot
        # record and one re-check CSV per file the export asked for. Only
        # the first two are ever compared by hash.
        _srv_files = (["RowTest-queries.sql", "RowTest-recheck-cot_router-raw.csv",
                       "RowTest-recheck-snapshot.txt"] +
                      [f"RowTest-recheck-{n}" for n in _pkg_files if n.endswith(".csv")
                       and n not in ("manifest.csv", "cot_router-raw.csv")])
        _srv_list = ", ".join(f"{i + 40:02x}" * 32 + f" {n}" for i, n in enumerate(_srv_files))
        _entry("RowTest", "recheck", "raw match", "1a" * 32, "2026-09-20T16:13:24",
               "re-check at takserver:/var/lib/takextract/recheck/RowTest/2026-09-20T16-13-24-1a1a1a1a; "
               f"{len(_srv_files)} file(s) hashed on the server; "
               "hash file RowTest-recheck-SHA256SUMS.txt sha256 " + "ee" * 32 + "; "
               "archive RowTest-recheck.tgz sha256 " + "dd" * 32 + "; "
               "SQL query script match: yes; raw table rows match: yes; "
               f"compared: 2 of {len(_srv_files)} file(s), the rest recorded not compared; "
               "server files: " + _srv_list, count=len(_srv_files))
        # A row that says the same thing twice. One like this cannot be
        # posted any more, but a log already holding one cannot be corrected
        # either - the chain is the point - so the page has to be safe on
        # its own account.
        _entry("Forged", "recheck", "raw match", "6f" * 32, "2026-09-20T15:45:00",
               "re-check at tak01:/var/lib/takextract/recheck; "
               "SQL query script match: yes; raw table rows match: yes; "
               "server files: " + "11" * 32 + " Forged-queries.sql; "
               "2 file(s) hashed on the server; "
               "SQL query script match: NO - a different script was run; "
               "raw table rows match: yes; "
               "server files: " + "22" * 32 + " Forged-queries.sql")
        _entry("RowTest", "preview", "ok", None, "2026-09-20T16:15:00", "file=cot.csv", count=5)
        import hashlib as _hl
        _script = "-- RowTest-queries.sql" + chr(10) + "SELECT 1;" + chr(10)
        _script_sha = _hl.sha256(_script.encode()).hexdigest()
        _con.execute("INSERT OR REPLACE INTO recheck_scripts (package_sha256, case_prefix, case_id,"
                     " raw_sha256, queries_sql, created_by, requested_for, created_utc)"
                     " VALUES (?,?,?,?,?,?,?,?)",
                     ("1a" * 32, "RowTest", "RowTest", "cc" * 32, _script,
                      "authenticated: admin", "Det. Example", "2026-09-20T16:11:35+00:00"))
        # the entry's recorded hash for that script, so the two agree
        _con.execute("UPDATE export_log SET detail = replace(detail, ?, ?)"
                     " WHERE package_sha256 = ? AND export_kind = 'package';",
                     ("12" * 32 + " RowTest-queries.sql",
                      _script_sha + " RowTest-queries.sql", "1a" * 32))
        _con.execute("UPDATE export_log SET north=39.6945, south=39.6922, west=-98.3444, east=-98.3415,"
                     " window_start='2026-09-09T12:09', window_end='2026-09-10T00:09'"
                     " WHERE case_id='RowTest' AND export_kind='package';")
        _con.commit(); _con.close()
        pg.set_viewport_size({"width": 1200, "height": 1000})
        pg.goto(BASE + "/audit"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(900)

        def _case(name):
            return pg.locator(".caseGroup", has=pg.locator(".caseName", has_text=name)).first
        check("Audit: opens as one line per case, counting its extractions and its events",
              pg.locator(".caseGroup").count() >= 4 and "case(s)" in pg.locator("#status").inner_text()
              and "2 extractions" in _case("RowTest").inner_text()
              and "5 events" in _case("RowTest").inner_text()
              and _case("RowTest").locator(".caseBody").is_hidden(), _case("RowTest").inner_text()[:120])
        cls = pg.evaluate("""() => {
            var out = {};
            document.querySelectorAll('.caseToggle').forEach(function (t) {
                out[t.querySelector('.caseName').textContent.trim()] = t.lastElementChild.className;
            });
            return out;
        }""")
        check("Audit: each verdict colours by what it means, a pass apart from every failure",
              cls.get("RowTest") == "ok" and cls.get("BadCase") == "bad"
              and cls.get("MissingCase") == "bad" and cls.get("UnverifiedCase") == "warn", cls)
        check("Audit: entries with no case are their own section, not a case with a missing name",
              pg.locator(".appWide").count() == 1
              and "Application-wide activity" in pg.locator(".appWideHead").inner_text()
              and pg.locator(".caseName", has_text="no case").count() == 0)

        # ---- a case is its extractions, each holding what was done to it ------
        _case("RowTest").locator(".caseToggle").click(); pg.wait_for_timeout(400)
        rt = _case("RowTest")
        xs = rt.locator(".extraction")
        check("Audit: a case opens to its extractions, oldest first, numbered",
              xs.count() == 2
              and "Extraction 1" in xs.nth(0).locator(".extractionToggle").inner_text()
              and "Extraction 2" in xs.nth(1).locator(".extractionToggle").inner_text()
              and "16:05:00" in xs.nth(0).locator(".extractionToggle").inner_text()
              and "16:11:35" in xs.nth(1).locator(".extractionToggle").inner_text(),
              xs.nth(0).locator(".extractionToggle").inner_text().encode("ascii", "replace").decode())
        # The re-check belongs to the export it checked, not to the case.
        x2 = xs.nth(1)
        kids = x2.locator(".extractionChildren > .entry")
        check("Audit: the fetch and the re-check sit under the extraction they belong to, in order",
              kids.count() == 2
              and "TAK Server fetched the script" in kids.nth(0).inner_text()
              and "Re-check on the TAK Server" in kids.nth(1).inner_text()
              and xs.nth(0).locator(".extractionChildren > .entry").count() == 0,
              str(kids.count()))
        check("Audit: an extraction's own events are visible as soon as the case opens",
              kids.nth(1).is_visible() and x2.locator(".extractionBody").is_hidden())
        check("Audit: a case's other activity is grouped apart from its extractions",
              rt.locator(".otherToggle").count() == 1
              and "Other activity for this case" in rt.locator(".otherToggle").inner_text())

        # ---- an entry says in words what it was, and opens to its record -----
        check("Audit: an entry says in words what it was, keeping the recorded kind",
              "Re-check on the TAK Server" in rt.inner_text()
              and "TAK Server fetched the script" in rt.inner_text()
              and "Evidence package exported" in rt.inner_text()
              and "recheck-fetch" not in kids.nth(0).locator(".entryToggle").inner_text(),
              kids.nth(0).locator(".entryToggle").inner_text().encode("ascii", "replace").decode())
        x2.locator(".extractionToggle").click(); pg.wait_for_timeout(300)
        opened = x2.locator(".extractionBody").inner_text()
        check("Audit: an opened extraction lists what it recorded as labelled lines, no sideways scrolling",
              "For" in opened and "Det. Example" in opened and "Window" in opened
              and "2026-09-09T12:09" in opened and "Area" in opened and "39.6945" in opened
              and "Records" in opened and "5829" in opened and "1a1a1a" in opened,
              opened[:200].encode("ascii", "replace").decode())
        rc = kids.nth(1)
        rc.locator(".entryToggle").click(); pg.wait_for_timeout(300)
        rcb = rc.locator(".entryBody").inner_text()
        check("Audit: a re-check entry says its count is files, and what its hash is the hash OF",
              "Files hashed" in rcb and "SHA-256 of" in rcb
              and "the export this entry refers to" in rcb
              and "recorded as: recheck" in rcb, rcb[:200].encode("ascii", "replace").decode())
        # The detail is one recorded string, shown as recorded - but read as
        # clauses, so the hashes are not inside sentences and the verdicts
        # are not the same colour as the rest.
        det = rc.evaluate("""el => {
            var g = el.querySelector('.entryBody .detailGrid');
            if (!g) { return null; }
            var out = [];
            g.querySelectorAll('.dKey').forEach(function (k) {
                out.push([k.textContent.trim(), k.nextElementSibling.textContent.trim(),
                          k.nextElementSibling.className]);
            });
            return { pairs: out, sentences: [].map.call(g.querySelectorAll('.dSay'), function (e) { return e.textContent.trim(); }) };
        }""")
        pairs = {k: (v, c) for k, v, c in (det or {}).get("pairs", [])}
        check("Audit: the detail's clauses read as key and value, hashes in their own column",
              "list of hashes" in pairs and pairs["list of hashes"][0].endswith("e" * 16)
              and "re-check at" in pairs and pairs["re-check at"][0].startswith("takserver:/var/lib")
              and "mono" in pairs["re-check at"][1], pairs)
        check("Audit: what is stated plainly above is not repeated inside the detail",
              not any(k.endswith("match") or "file(s) hashed" in k or k == "compared"
                      for k in pairs), pairs)
        check("Audit: a named hash in the detail shows its file beside the value",
              "list of hashes" in pairs
              and "RowTest-recheck-SHA256SUMS.txt" in pairs.get("list of hashes", ("", ""))[0]
              and "archive" in pairs and "RowTest-recheck.tgz" in pairs.get("archive", ("",""))[0], pairs)


        # ---- what was compared, and what was only recorded -------------------
        # The point of this block: an entry that hashed sixteen files and
        # compared two must not read as sixteen comparisons.
        cmp_txt = rc.locator(".compared").inner_text()
        check("Audit: the re-check names the two files it compared, each with its own verdict",
              "the SQL query script" in cmp_txt and "RowTest-queries.sql" in cmp_txt
              and "the raw table rows" in cmp_txt
              and "RowTest-recheck-cot_router-raw.csv" in cmp_txt
              and cmp_txt.count("compared") >= 2 and "same hash" in cmp_txt,
              cmp_txt.encode("ascii", "replace").decode())
        check("Audit: the files that were not compared say so, in their own words, and are counted",
              "14 other file(s)" in cmp_txt and "recorded, not compared" in cmp_txt,
              cmp_txt.encode("ascii", "replace").decode())
        states = rc.evaluate("""(el) => {
            var out = {};
            el.querySelectorAll('.compared .cFile').forEach(function (f) {
                out[f.textContent.trim()] = f.nextElementSibling.className;
            });
            return out;
        }""")
        check("Audit: a file that was compared and matched is the only thing coloured as a pass",
              states.get("RowTest-queries.sql", "").endswith("ok")
              and states.get("RowTest-recheck-cot_router-raw.csv", "").endswith("ok")
              and len(states) == 2, states)
        check("Audit: the entry says why most of the files are not compared",
              "not limited by time" in rc.locator(".fileNote").inner_text()
              and "row by row" in rc.locator(".fileNote").inner_text(),
              rc.locator(".fileNote").inner_text()[:160].encode("ascii", "replace").decode())
        check("Audit: the server's full list is there but folded away until asked for",
              rc.locator(".fileList").is_hidden()
              and "Show all 16 file(s)" in rc.locator(".filesToggle").inner_text(),
              rc.locator(".filesToggle").inner_text())
        rc.locator(".filesToggle").click(); pg.wait_for_timeout(300)
        open_list = rc.locator(".fileList").inner_text()
        check("Audit: the opened list gives every file the server hashed, with its hash",
              rc.locator(".fileList .fileRow").count() == 16
              and "RowTest-recheck-snapshot.txt" in open_list
              and "RowTest-recheck-federation.csv" in open_list
              and ("37" * 32) in open_list
              and "Hide all 16 file(s)" in rc.locator(".filesToggle").inner_text(),
              open_list[:160].encode("ascii", "replace").decode())
        rc.locator(".filesToggle").click(); pg.wait_for_timeout(200)

        # The export's own list: what was in the package, with the hash each
        # file had when it was built - the SQL script among them, which
        # until now was asserted by the re-check and shown nowhere.
        check("Audit: the export lists the files the package held, folded away",
              "Files in the package" in opened
              and x2.locator(".extractionBody .filesToggle").count() == 1
              and "Show the 19 file(s)" in x2.locator(".extractionBody .filesToggle").inner_text(),
              x2.locator(".extractionBody .filesToggle").inner_text())
        x2.locator(".extractionBody .filesToggle").click(); pg.wait_for_timeout(300)
        pkg_list = x2.locator(".extractionBody .fileList").inner_text()
        check("Audit: the package's list names the SQL query script and gives its hash",
              "RowTest-queries.sql" in pkg_list and _script_sha in pkg_list
              and "RowTest-cot_router-raw.csv" in pkg_list
              and x2.locator(".extractionBody .fileRow").count() == 19, pkg_list[:160])
        check("Audit: nothing in the package's list is coloured as compared",
              x2.locator(".extractionBody .fileList .fState").count() == 19
              and x2.locator(".extractionBody .fileList .fState").all_inner_texts() == [""] * 19
              and x2.locator(".extractionBody .fileList .ok, .extractionBody .fileList .bad").count() == 0)

        # ---- an entry recorded before any of this still reads ----------------
        _case("OldStyle").locator(".caseToggle").click(); pg.wait_for_timeout(400)
        _case("OldStyle").locator(".otherToggle").click(); pg.wait_for_timeout(300)
        old = _case("OldStyle").locator(".otherBody .entry").first
        old.locator(".entryToggle").click(); pg.wait_for_timeout(300)
        old_det = old.evaluate("""(el) => {
            var g = el.querySelector('.entryBody .detailGrid');
            var out = [];
            (g ? g.querySelectorAll('.dKey') : []).forEach(function (k) {
                out.push([k.textContent.trim(), k.nextElementSibling.className]);
            });
            return { keys: out, says: [].map.call((g ? g.querySelectorAll('.dSay') : []),
                                                  function (e) { return e.textContent.trim(); }) };
        }""")
        old_keys = {k: c for k, c in old_det["keys"]}
        check("Audit: an entry recorded before the file lists keeps its verdicts in the detail",
              old_keys.get("script match", "").endswith("ok")
              and old_keys.get("cot_router-raw.csv match", "").endswith("ok"), old_keys)
        check("Audit: a clause that is a sentence stays a sentence",
              any("19 file(s) hashed" in x for x in old_det["says"]), old_det)
        check("Audit: an entry with no recorded list offers none",
              old.locator(".filesToggle").count() == 0 and old.locator(".compared").count() == 0)
        _case("OldStyle").locator(".caseToggle").click(); pg.wait_for_timeout(300)

        # ---- an entry that says the same thing twice is not read as a pass ---
        _case("Forged").locator(".caseToggle").click(); pg.wait_for_timeout(400)
        _case("Forged").locator(".otherToggle").click(); pg.wait_for_timeout(300)
        forged = _case("Forged").locator(".otherBody .entry").first
        forged.locator(".entryToggle").click(); pg.wait_for_timeout(400)
        ftxt = forged.locator(".entryBody").inner_text()
        check("Audit: an entry recording the same statement twice shows no result at all",
              "same statement more than once" in ftxt
              and forged.locator(".compared").count() == 0
              and forged.locator(".fileList").count() == 0
              and "same hash" not in ftxt and "recorded, not compared" not in ftxt,
              ftxt[:300].replace(chr(10)," | ").encode("ascii","replace").decode())
        check("Audit: and it still shows everything that was recorded, unaltered",
              "NO - a different script was run" in ftxt and "11" * 32 in ftxt
              and "22" * 32 in ftxt, ftxt[:300].replace(chr(10)," | ").encode("ascii","replace").decode())
        _case("Forged").locator(".caseToggle").click(); pg.wait_for_timeout(300)

        # ---- asking the log for a re-check of an export made earlier ---------
        # The token the Export page shows lasts 48 hours and is shown once,
        # so without this an export not re-checked at the time had no way
        # back except running the statements by hand.
        x2.locator(".recheckBtn").click()
        x2.locator(".recheckCmd").wait_for(timeout=15000)
        cmd = x2.locator(".recheckCmd").inner_text()
        check("Audit: an export can be offered a re-check from the log, with the line to paste",
              cmd.startswith("D=/var/lib/takextract/recheck/RowTest/")
              and "/recheck/" in cmd and "RowTest-queries.sql" in cmd
              and "-1a1a1a1a" in cmd and "| tee RECHECK-INFO.txt" in cmd, cmd[:120])
        check("Audit: the offer says how long it is good for, and that the kept script matches the log",
              "48 hours" in x2.locator(".recheckNote").inner_text()
              and "hash this export recorded" in x2.locator(".recheckNote").inner_text(),
              x2.locator(".recheckNote").inner_text())
        check("Audit: the line is offered with a Copy button and a place for the verdict",
              x2.locator(".recheckBox .copyBtn").count() == 1
              and "Waiting for the server" in x2.locator(".recheckStatus").inner_text(),
              x2.locator(".recheckStatus").inner_text())
        server_cmd = cmd      # compared with the Export page's own builder below

        # ---- ticking at each level -------------------------------------------
        x2.locator(".extractionChk").check(); pg.wait_for_timeout(300)
        check("Audit: ticking an extraction takes it and everything done to it",
              "3 row(s) selected" in pg.locator("#selectionCount").inner_text(),
              pg.locator("#selectionCount").inner_text())
        x2.locator(".extractionChk").uncheck(); pg.wait_for_timeout(200)
        _case("RowTest").locator(".caseChk").check(); pg.wait_for_timeout(300)
        check("Audit: ticking a case takes every entry in it, for the download",
              "5 row(s) selected" in pg.locator("#selectionCount").inner_text(),
              pg.locator("#selectionCount").inner_text())
        _case("RowTest").locator(".caseChk").uncheck(); pg.wait_for_timeout(200)

        pg.locator("#flatBtn").click(); pg.wait_for_timeout(900)
        check("Audit: Flat list switches to one line per entry across every case, with the sort controls",
              pg.locator(".caseGroup").count() == 0 and pg.locator(".entry").count() >= 6
              and pg.locator("#sortCells").is_visible()
              and "export requests" in pg.locator("#status").inner_text())
        check("Audit: a flat line names the case it belongs to",
              "RowTest" in pg.locator(".entryToggle").first.inner_text(),
              pg.locator(".entryToggle").first.inner_text())
        pg.locator(".sortCell[data-sort='case']").click(); pg.wait_for_timeout(900)
        check("Audit: sorting still works in the flat view",
              pg.locator(".sortCell[data-sort='case']").get_attribute("class").find("activeSort") != -1
              and pg.locator(".entry").count() >= 6)
        pg.locator("#byCaseBtn").click(); pg.wait_for_timeout(900)
        check("Audit: By case returns to the case list", pg.locator(".caseGroup").count() >= 4)
        # ---- correcting a case: appended, never rewritten ---------------------
        # A case typed wrong repeats on everything that follows it. The entry
        # is never altered (case_id is chained), so this records a correction
        # of its own and the page applies it when it reads the log back.
        _case("RowTest").locator(".correctBtn[data-scope='case']").click(); pg.wait_for_timeout(300)
        form = _case("RowTest").locator(".correctForm")
        check("Audit: the correction form says the original entry is not changed",
              form.is_visible() and "never changed" in form.inner_text())
        form.locator(".newCase").fill("RowTest-2026-14")
        form.locator(".reason").fill("case typed wrong at export time")
        form.locator(".saveCorrection").click(); pg.wait_for_timeout(1400)
        # Exact names: has_text matches substrings, and "RowTest" is one of
        # "RowTest-2026-14" - which would pass while proving nothing.
        names = [t.inner_text().strip() for t in pg.locator(".caseName").all()]
        check("Audit: the case now reads under its corrected name, carrying its entries and the correction",
              "RowTest-2026-14" in names and "RowTest" not in names
              and "7 events" in _case("RowTest-2026-14").inner_text(), names)
        g = _case("RowTest-2026-14")
        g.locator(".caseToggle").click(); pg.wait_for_timeout(400)
        check("Audit: the correction is itself an entry, filed under the case's other activity",
              g.locator(".otherToggle").count() == 1
              and "Case reference corrected" in g.locator(".otherBody").inner_text(),
              g.locator(".otherBody").inner_text()[:120].encode("ascii", "replace").decode())
        g.locator(".extraction").first.locator(".extractionToggle").click(); pg.wait_for_timeout(400)
        opened = g.locator(".extraction").first.locator(".extractionBody").inner_text()
        check("Audit: a corrected extraction still shows the case it was recorded under",
              "Case recorded as" in opened and "RowTest" in opened and "corrected to RowTest-2026-14" in opened,
              opened[:200].encode("ascii", "replace").decode())
        pg.fill("#filterInput", "RowTest"); pg.wait_for_timeout(1200)
        check("Audit: the case is still found under the name it was first recorded under",
              pg.locator(".caseGroup").count() >= 1)
        pg.fill("#filterInput", ""); pg.wait_for_timeout(1200)
        check("no JavaScript errors across the audit-log checks", not errors, errors)

        def _first_diff(x, y):
            """Where two commands stop agreeing, with a window either side -
            a failure that only says they differ is no use on a 600-character
            line."""
            for i in range(min(len(x), len(y))):
                if x[i] != y[i]:
                    return (i, x[max(0, i - 30):i + 40], y[max(0, i - 30):i + 40])
            return ("lengths", len(x), len(y), x[min(len(x), len(y)):][:60] or y[min(len(x), len(y)):][:60])

        # ---- one command, two builders ---------------------------------------
        # The server builds the line for the Audit Log (recheck_command in
        # app.py); the Export page builds it in JavaScript, because it
        # re-renders as the address field and the self-signed box change.
        # They have to produce the same thing, and nothing but a test will
        # keep them that way.
        pg.goto(BASE + "/"); pg.wait_for_load_state("networkidle")
        js_cmd = pg.evaluate("""(a) => {
            recheck.prefix = a.prefix; recheck.token = a.token; recheck.tag = a.tag;
            document.getElementById('recheckBase').value = a.base;
            document.getElementById('recheckInsecure').checked = false;
            return recheckServerCmd();
        }""", {"prefix": "RowTest", "tag": "-1a1a1a1a", "base": BASE,
               # the FIRST /recheck/ in the line is the folder it writes
               # into, not the URL - the token is in the curl that follows
               "token": re.search(r"/recheck/([A-Za-z0-9_-]{20,})/", server_cmd).group(1)})
        check("The Export page's builder and the server's produce the same command",
              js_cmd == server_cmd, _first_diff(js_cmd, server_cmd))

        # ---- the verdict: one answer, before the tabs ----------------------
        # The page had every piece of this and made a reader assemble it from
        # three tabs; and it never checked the files inside at all.
        load(pg, PKG_SUMS)
        pg.wait_for_timeout(1200)
        vtext = pg.locator("#verdict").inner_text()
        check("Verify: the verdict says whether the package is in the log, before the tabs",
              pg.locator("#verdict").is_visible()
              and ("matches an export recorded" in vtext or "No export in this tool" in vtext),
              vtext[:160].encode("ascii", "replace").decode())
        check("Verify: every file inside is checked against the package's own list",
              "All 4 files inside match the list built with this package" in vtext,
              vtext[:300].encode("ascii", "replace").decode())
        # The per-file check is worth different things depending on the line
        # above it. This package is not in the log, so the list inside it is
        # tied to nothing - and the page has to say that, not the stronger
        # sentence it uses when the package DOES match.
        check("Verify: with the package unmatched, the file check does not claim a tie it lacks",
              "t-SHA256SUMS.txt" in vtext
              and "nothing here ties that list to the tool that built it" in vtext
              and "covered by the package hash above" not in vtext,
              vtext[:300].encode("ascii", "replace").decode())
        check("Verify: a package with no re-check says so as a fact, not a failure",
              "No re-check was run" in vtext and "not deficient" in vtext,
              vtext[:400].encode("ascii", "replace").decode())
        marks = pg.evaluate("""() => [].map.call(
            document.querySelectorAll('#verdictLines .vMark'), function (e) { return e.className; })""")
        check("Verify: the files line is the only thing coloured as a pass on an unlogged package",
              any("ok" in m for m in marks) and len(marks) >= 3, marks)

        # a member altered after the list was written
        load(pg, PKG_TAMPERED)
        pg.wait_for_timeout(1200)
        vt = pg.locator("#verdict").inner_text()
        check("Verify: an altered file is caught and named",
              "3 of 4 files match" in vt and "1 differ: t-cot.csv" in vt,
              vt[:300].encode("ascii", "replace").decode())
        bad = pg.evaluate("""() => {
            var out = [];
            document.querySelectorAll('#verdictLines .vLine').forEach(function (l) {
                out.push([l.querySelector('.vMark').className, l.querySelector('.vSay').textContent.slice(0, 40)]);
            });
            return out;
        }""")
        check("Verify: that line is coloured as a failure",
              any(m[0].endswith("bad") and "files match" in m[1] for m in bad), bad)

        # ---- which database exports came from --------------------------------
        # The route cannot answer without a live TAK Server, so the states
        # worth seeing are stubbed: what the panel SAYS is the part that has
        # to be right, and a mismatch must not read as an accusation.
        def _src(payload):
            pg.route("**/api/admin/source-identity",
                     lambda r: r.fulfill(status=200, body=payload,
                                         headers={"Content-Type": "application/json"}))

        _src(json.dumps({"checked": True, "current": "cluster 7412345678901234567",
                         "kind": "cluster", "matches": True,
                         "newest_export": {"identity": "cluster 7412345678901234567",
                                           "when": "2026-09-25 10:00:00 UTC", "case_id": "SRC-A"},
                         "distinct": [{"identity": "cluster 7412345678901234567",
                                       "when": "2026-09-25 10:00:00 UTC", "case_id": "SRC-A"}]}))
        pg.goto(BASE + "/admin"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(900)
        same = pg.locator("#sourceIdentityStatus")
        check("System: when the connection matches what exports recorded, it says so plainly",
              "reports: cluster 7412345678901234567" in same.inner_text()
              and "read the same database" in same.inner_text()
              and "muted" in (same.get_attribute("class") or ""),
              same.inner_text()[:160])

        pg.unroute("**/api/admin/source-identity")
        _src(json.dumps({"checked": True, "current": "cluster 7412345678901234567",
                         "kind": "cluster", "matches": False,
                         "newest_export": {"identity": "cluster 9998887776665554443",
                                           "when": "2026-09-25 10:00:00 UTC", "case_id": "SRC-B"},
                         "distinct": [{"identity": "cluster 9998887776665554443",
                                       "when": "2026-09-25 10:00:00 UTC", "case_id": "SRC-B"},
                                      {"identity": "cluster 7412345678901234567",
                                       "when": "2026-09-20 10:00:00 UTC", "case_id": "SRC-A"}]}))
        pg.goto(BASE + "/admin"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(900)
        diff = pg.locator("#sourceIdentityStatus")
        dt = diff.inner_text()
        check("System: a different database is named, counted, and flagged",
              "DIFFERENT database" in dt and "cluster 9998887776665554443" in dt
              and "SRC-B" in dt and "2 different databases" in dt
              and "warn" in (diff.get_attribute("class") or ""), dt[:200])
        check("System: and it is not worded as an accusation",
              "rebuilt, upgraded or restored" in dt
              and "not by itself a sign that anything is wrong" in dt, dt[:240])

        pg.unroute("**/api/admin/source-identity")
        _src(json.dumps({"checked": True, "current": "catalog cot/16384/16512",
                         "kind": "catalog", "matches": True, "newest_export": None, "distinct": []}))
        pg.goto(BASE + "/admin"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(900)
        weak = pg.locator("#sourceIdentityStatus").inner_text()
        check("System: the weaker fingerprint says it is the weaker one, and how to get the other",
              "catalog cot/16384/16512" in weak and "weaker catalog fingerprint" in weak
              and "connect-database.sh" in weak
              and "nothing to compare it with" in weak, weak[:200])
        pg.unroute("**/api/admin/source-identity")

        # ---- blocks line up with each other at desktop width ---------------
        # The overflow check below only catches a page that scrolls
        # sideways. It cannot see a block that is merely WIDER than its
        # neighbours, which is what happened to the verdict: body is 1200px
        # and everything inside it is capped at --content-width, but that
        # rule was missing from #verdict, so it alone ran full width. Found
        # by eye, which is not a repeatable way to find it.
        pg.set_viewport_size({"width": 1400, "height": 1000})
        pg.goto(BASE + "/verify")
        pg.wait_for_load_state("networkidle")
        pg.set_input_files("#fileInput", PKG_SUMS)
        pg.wait_for_selector("#verdict", state="visible", timeout=20000)
        pg.wait_for_timeout(1500)
        edges = pg.evaluate("""() => {
            var out = {};
            ['verdict', 'resultRow', 'dropZone'].forEach(function (id) {
                var el = document.getElementById(id);
                if (!el || el.hidden) { return; }
                var r = el.getBoundingClientRect();
                out[id] = { left: Math.round(r.left), width: Math.round(r.width) };
            });
            return out;
        }""")
        check("Verify: the verdict is the same width as the tabs, and starts at the same edge",
              "verdict" in edges and "resultRow" in edges
              and edges["verdict"]["width"] == edges["resultRow"]["width"]
              and edges["verdict"]["left"] == edges["resultRow"]["left"], edges)

        # ---- the nav does not move between pages ---------------------------
        # It used to, by 87px, because the header inherited each page's own
        # content width - 1100px on Export and Verify, 1200px on Audit and
        # System, 1068px on the Guide - and the nav is right-aligned inside
        # it. Two smaller causes on top: .logoutLink reset padding and border
        # but not margin, so a page whose generic `button` rule carried a
        # margin-right made the account block 8px wider; and the Guide had no
        # account block at all. Reported by the owner as the buttons
        # "floating around", found by measuring rather than by reading.
        pg.set_viewport_size({"width": 1400, "height": 900})
        navs = {}
        for path in ("/", "/verify", "/audit", "/admin", "/guide"):
            pg.goto(BASE + path)
            pg.wait_for_load_state("networkidle")
            navs[path] = pg.evaluate("""() => {
                var n = document.querySelector('nav.siteNav');
                if (!n) { return null; }
                var r = n.getBoundingClientRect();
                var h = [...n.children].map(function (e) {
                    return Math.round(e.getBoundingClientRect().height);
                });
                return { right: Math.round(r.right), width: Math.round(r.width),
                         heights: [...new Set(h)] };
            }""")
        placed = [v for v in navs.values() if v]
        check("the nav sits in the same place and is the same size on every page",
              len(placed) == 5
              and len({v["right"] for v in placed}) == 1
              and len({v["width"] for v in placed}) == 1
              and len({tuple(v["heights"]) for v in placed}) == 1,
              {p: v for p, v in navs.items()})

        # ---- no horizontal overflow at phone width, every page -------------
        for path in ("/", "/verify", "/audit", "/admin", "/guide"):
            pg.set_viewport_size({"width": 400, "height": 800})
            pg.goto(BASE + path)
            pg.wait_for_load_state("networkidle")
            sw, cw = pg.evaluate("() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]")
            check(f"{path} does not overflow sideways at 400px", sw <= cw, f"scrollWidth={sw}")
        browser.close()
finally:
    server.kill()

print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("ALL BROWSER TESTS PASSED")
