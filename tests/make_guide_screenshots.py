"""Regenerates the User Guide's screenshots (docs/guide-images/*.png) from
SYNTHETIC data, against a dev server you start first.

Every name is invented (UNIT-1, "Perimeter", CASE-0001, "Det. Example"),
and the coordinates sit at the app's default map view - rural Kansas, the
geographic centre of the US - a place unrelated to any real deployment, so
the OpenStreetMap tiles that do appear identify nothing. The
audit-log and users screenshots show whatever the dev server's own
throwaway audit database holds - seed it with generic rows first (see the
SEED block below), never point this at a real installation.

Needs the dev-only Playwright install (requirements-dev.txt). Run from the
repo root with a dev server on port 5000 whose admin is admin /
guidepreview12345 (any throwaway AUDIT_DB and dummy DB_* settings):

    venv/Scripts/python tests/make_guide_screenshots.py
"""
import hashlib, os, sys, datetime as dt, tempfile, zipfile
from playwright.sync_api import sync_playwright
# This file lives in tests/; kmz.py and shapes.py are in the checkout above.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import kmz, shapes

OUT = os.path.join(REPO, "docs", "guide-images")
os.makedirs(OUT, exist_ok=True)
SC = tempfile.mkdtemp(prefix="takx-guide-")
BASE = os.environ.get("GUIDE_SHOTS_BASE", "http://127.0.0.1:5000")

# ---- synthetic KMZ: two units, four drawn shapes, one deletion --------------
TZ = dt.timezone(dt.timedelta(hours=-4))
T = lambda h, m: dt.datetime(2026, 3, 4, h, m, 0, tzinfo=TZ)
def poly(name, pts, stroke="-2737863", fill="2144745785"):
    return (f'<detail><contact callsign="{name}"/><creator uid="c1" callsign="Example Drawer"/>'
            f'<strokeColor value="{stroke}"/><fillColor value="{fill}"/>'
            + "".join(f'<link point="{la},{lo}"/>' for la, lo in pts) + "</detail>")
SH = ["id","uid","servertime","event_time","cot_type","how","callsign","latitude","longitude","channels","channel_numbers","raw_detail"]
def srow(i, uid, t, ct, xml, la, lo): return (i, uid, t, t, ct, "h-g-i-g-o", "", la, lo, "Patrol", "3", xml)
B = (39.800, -98.500)   # the app's default map view (rural Kansas): a place unrelated to any deployment
def off(dlat, dlon): return (round(B[0] + dlat, 6), round(B[1] + dlon, 6))
PER1 = poly("Perimeter", [off(0,0), off(0,0.02), off(0.012,0.02), off(0.012,0), off(0,0)])
PER2 = poly("Perimeter", [off(0,0), off(0,0.03), off(0.016,0.03), off(0.016,0), off(0,0)])
HAZ = poly("Hazard area", [off(0.003,0.005), off(0.003,0.010), off(0.006,0.010), off(0.006,0.005), off(0.003,0.005)], stroke="-16776961", fill="1073807104")
FIRE = ('<detail><contact callsign="Fire line"/><creator uid="c2" callsign="Ops Lead"/><strokeColor value="-65536"/><strokeWeight value="4"/>'
        + "".join(f'<link point="{la},{lo}"/>' for la, lo in [off(-0.002,-0.005), off(0.005,0.008), off(0.014,0.022)]) + "</detail>")
STG = ('<detail><contact callsign="Staging"/><strokeColor value="-16711936"/><fillColor value="1090453504"/>'
       '<shape><ellipse major="250" minor="250" angle="360"/></shape></detail>')
SROWS = [srow(1,"per",T(10,0),"u-d-f",PER1,*off(0.006,0.01)), srow(2,"per",T(10,10),"u-d-f",PER2,*off(0.008,0.015)),
         srow(3,"haz",T(10,2),"u-d-f",HAZ,*off(0.0045,0.0075)), srow(4,"stg",T(10,3),"u-d-c-c",STG,*off(0.009,0.017)),
         srow(5,"fire",T(10,4),"u-d-f",FIRE,*off(0.005,0.008))]
DELS = [(T(10,40), "haz", "", 43)]
P = {"north": B[0]+0.05, "south": B[0]-0.05, "west": B[1]-0.05, "east": B[1]+0.05, "start": "x", "end": "y"}
DC = ["id","uid","callsign","servertime","event_time","latitude","longitude","ce_m","how","cot_type","channels","reported_team","reported_role","course_deg","speed_ms","battery_pct","device_model","tak_platform","tak_version"]
def drow(i, uid, cs, t, la, lo, team): return (i, uid, cs, t, t, la, lo, 5.0, "m-g", "a-f-G-U-C", "Patrol", team, "Team Member", 90, 1.5, 80, "Handset", "ATAK", "5.2")
DROWS = []
n = 1
for k in range(0, 46, 5):
    DROWS.append(drow(n, "UNIT-1", "UNIT-1", T(10, k), *off(0.001 + k*0.00025, -0.002 + k*0.0005), "Cyan")); n += 1
    DROWS.append(drow(n, "UNIT-2", "UNIT-2", T(10, k), *off(0.014 - k*0.0002, 0.024 - k*0.0003), "Green")); n += 1
coll = shapes.collect(SROWS, SH, DELS, P)
KMZ = os.path.join(SC, "guide_sample.kmz")
open(KMZ, "wb").write(kmz.build_kmz(DROWS, DC, P, "CASE-0001", "authenticated: admin", "TAK-Extract", requested_for="Det. Example", shape_collection=coll))

# The full package the Verify shots load: the synthetic KMZ plus a
# positions-plain.csv of the same rows, so the built-in check runs; and
# the administrator's re-check file (psql-style CSV) with one unit the
# package's box does not cover, for the Compare shot.
def plain_csv(rows, psql=False, extra=None):
    out = ["id,uid,callsign,servertime,latitude,longitude"]
    for r in rows:
        t = r[3].strftime("%Y-%m-%d %H:%M:%S-04") if psql else str(r[3])
        out.append(f"{r[0]},{r[1]},{r[2]},{t},{r[5]},{r[6]}")
    if extra:
        la, lo = off(0.03, 0.04)
        out.append(f"999,{extra},{extra},{T(10, 5).strftime('%Y-%m-%d %H:%M:%S-04')},{la},{lo}")
    return chr(10).join(out) + chr(10)

def raw_csv(rows):
    # cot_router-raw.csv as the tool writes it: psql's CSV rules, every value in text form.
    import exports
    return exports.psql_csv(["id", "uid", "servertime", "detail", "latitude", "longitude"],
                            [[str(r[0]), r[1], r[3].strftime("%Y-%m-%d %H:%M:%S-04"),
                              '<detail><contact callsign="' + r[2] + '"/></detail>', str(r[5]), str(r[6])] for r in rows])

PKG = os.path.join(SC, "guide_sample.zip")
_members = {
    "CASE-0001-locations.kmz": open(KMZ, "rb").read(),
    "CASE-0001-cot.csv": plain_csv(DROWS).encode("utf-8"),
    "CASE-0001-cot_router-raw.csv": raw_csv(DROWS).encode("utf-8"),
}
# Its own SHA256SUMS.txt, the way build_package writes one - so Verify's
# per-file check has the list it is meant to check against.
_sums = "".join(f"{hashlib.sha256(v).hexdigest()}  {k}\n"
                for k, v in sorted(_members.items()))
with zipfile.ZipFile(PKG, "w") as z:
    for _k, _v in sorted(_members.items()):
        z.writestr(_k, _v)
    z.writestr("CASE-0001-SHA256SUMS.txt", _sums)
# The administrator's re-check of the raw statement: the same bytes.
RECHECK = os.path.join(SC, "recheck-cot_router-raw.csv")
open(RECHECK, "w", newline="").write(raw_csv(DROWS))
RECHECK_PLAIN = os.path.join(SC, "recheck-positions-plain.csv")
open(RECHECK_PLAIN, "w", newline="").write(plain_csv(DROWS, psql=True, extra="UNIT-3"))

def tiles_loaded(pg):
    """Wait until every map tile Leaflet asked for has actually painted, so
    a screenshot never catches a half-drawn map. Polled with evaluate()
    rather than wait_for_function(): the app's Content-Security-Policy
    forbids eval, which the string form of wait_for_function relies on."""
    for _ in range(100):
        done = pg.evaluate("() => { var t = document.querySelectorAll('.leaflet-tile'); "
                           "return t.length > 0 && [...t].every(e => e.classList.contains('leaflet-tile-loaded')); }")
        if done:
            break
        pg.wait_for_timeout(200)
    pg.wait_for_timeout(300)

def scrub_to(pg, frac):
    pg.evaluate("f => { var s = document.getElementById('scrubber'); s.value = Math.round(s.max * f); s.dispatchEvent(new Event('input', {bubbles:true})); }", frac)
    pg.wait_for_timeout(200)

def shot(pg, selector, name, pad=0):
    el = pg.locator(selector).first
    el.scroll_into_view_if_needed(); pg.wait_for_timeout(150)
    el.screenshot(path=os.path.join(OUT, name))
    print("  wrote", name)

with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    ctx = b.new_context(viewport={"width": 1000, "height": 900}, device_scale_factor=1)
    pg = ctx.new_page()
    pg.goto(BASE + "/login")
    pg.fill("input[name=username]", "admin"); pg.fill("input[name=password]", "guidepreview12345")
    pg.click("button[type=submit]"); pg.wait_for_load_state("networkidle")

    # ================= EXPORT =================
    pg.goto(BASE + "/"); pg.wait_for_load_state("networkidle")
    tiles_loaded(pg)
    # The page opens at a continental zoom; an operator zooms in before
    # drawing. Use the map's own + control, paced so Leaflet's zoom
    # animation finishes between clicks (it drops clicks mid-animation).
    for _ in range(8):
        pg.locator(".leaflet-control-zoom-in").click(); pg.wait_for_timeout(450)
    tiles_loaded(pg)
    # draw a rectangle with the leaflet-draw tool
    pg.locator(".leaflet-draw-draw-rectangle").click(); pg.wait_for_timeout(200)
    m = pg.locator("#map").bounding_box()
    x0, y0 = m["x"] + m["width"] * 0.30, m["y"] + m["height"] * 0.30
    pg.mouse.move(x0, y0); pg.mouse.down(); pg.mouse.move(x0 + 300, y0 + 180, steps=8); pg.mouse.up(); pg.wait_for_timeout(600)
    tiles_loaded(pg)
    shot(pg, "#map", "export-map.png")
    shot(pg, "#fileSelectionPanel", "export-files-closed.png")
    # open one About and show the file tiles
    pg.locator(".infoBtn[data-target]").first.click(); pg.wait_for_timeout(200)
    shot(pg, "#fileSelectionPanel", "export-files.png")
    shot(pg, "#timeWindowPanel", "export-time.png")
    pg.fill("#caseId", "CASE-0001"); pg.fill("#exportedFor", "Det. Example (Unit 12)")
    pg.evaluate("() => document.activeElement.blur()")
    shot(pg, "#generatePanel", "export-generate.png")
    # The re-check block as it appears once a package has downloaded (no
    # database behind the preview server, so it is shown directly).
    pg.evaluate("() => showRecheck('CASE-0001', 'example-token')"); pg.wait_for_timeout(600)
    shot(pg, "#recheckBox", "export-recheck.png")

    # ================= VERIFY =================
    pg.goto(BASE + "/verify"); pg.wait_for_load_state("networkidle")
    shot(pg, "#dropZone", "verify-drop.png")
    pg.set_input_files("#fileInput", PKG); pg.wait_for_selector("#summaryBox", state="visible", timeout=20000)
    pg.wait_for_timeout(800)
    # The tab row, then each tab opened - row and panel captured together.
    def shot_tab(tab, panel, name):
        pg.locator(tab).click(); pg.wait_for_timeout(200)
        pg.evaluate("() => window.scrollTo(0, 0)"); pg.wait_for_timeout(150)
        rr = pg.locator("#resultRow").bounding_box(); pb = pg.locator(panel).bounding_box()
        pg.screenshot(path=os.path.join(OUT, name), clip={"x": rr["x"] - 1, "y": rr["y"] - 1,
                      "width": rr["width"] + 2, "height": (pb["y"] + pb["height"]) - rr["y"] + 2})
        print("  wrote", name)
    shot(pg, "#resultRow", "verify-tabs.png")
    shot_tab("#hashResult", "#hashResultBody", "verify-hash.png")
    shot_tab("#summaryBox", "#summaryBoxBody", "verify-contents.png")
    pg.locator("#summaryBox").click(); pg.wait_for_timeout(150)   # close it again
    scrub_to(pg, 0.3)
    tiles_loaded(pg)
    shot(pg, "#map", "verify-map.png")
    # click the perimeter for its popup
    box = pg.locator(".leaflet-shapes-pane path").first.bounding_box()
    pg.mouse.click(box["x"] + box["width"] * 0.15, box["y"] + box["height"] * 0.85); pg.wait_for_timeout(600)
    shot(pg, "#map", "verify-shape-popup.png")
    pg.locator(".leaflet-popup-close-button").click(); pg.wait_for_timeout(200)
    pg.locator("#ribbonVisibilitySelect").select_option("show"); pg.wait_for_timeout(300)
    shot(pg, "#playbackPanel", "verify-playback.png")
    shot(pg, "#mapPanel .panel:has(.styleToggle)", "verify-style.png")
    shot(pg, "#mapPanel .panel:has(#deviceLegend)", "verify-legend.png")
    # A recorded re-check for the sample package, posted the way the pasted
    # line posts it: a token minted in the preview DB, then the hash file.
    import hashlib, sqlite3, urllib.request, uuid
    pkg_hash = hashlib.sha256(open(PKG, "rb").read()).hexdigest()
    raw_hash = hashlib.sha256(zipfile.ZipFile(PKG).read("CASE-0001-cot_router-raw.csv")).hexdigest()
    con = sqlite3.connect(os.environ["AUDIT_DB"]) if os.environ.get("AUDIT_DB") else None
    script = "-- CASE-0001-queries.sql (guide fixture)" + chr(10) + "SELECT 1;" + chr(10)
    if con is not None and not con.execute("SELECT 1 FROM export_log WHERE export_kind='recheck' AND package_sha256=?", (pkg_hash,)).fetchone():
        tok = "guide-" + uuid.uuid4().hex
        con.execute("INSERT INTO recheck_tokens (token, case_prefix, package_sha256, raw_sha256, queries_sql, created_by, created_utc, expires_utc)"
                    " VALUES (?,?,?,?,?,?,?,?)", (tok, "CASE-0001", pkg_hash, raw_hash, script, "authenticated: admin",
                                                  "2026-03-04T12:00:00+00:00", "2099-01-01T00:00:00+00:00"))
        con.commit()
        # A complete hash file, as the pasted line produces it: the script's
        # own hash (so the record reads "script match: yes"), the raw file,
        # and a few more results; a realistic-looking tgz hash.
        sums = (hashlib.sha256(script.encode()).hexdigest() + "  CASE-0001-queries.sql" + chr(10) +
                raw_hash + "  CASE-0001-recheck-cot_router-raw.csv" + chr(10) +
                hashlib.sha256(b"cot").hexdigest() + "  CASE-0001-recheck-cot.csv" + chr(10) +
                hashlib.sha256(b"manifest").hexdigest() + "  CASE-0001-recheck-manifest.csv" + chr(10) +
                hashlib.sha256(b"snapshot").hexdigest() + "  CASE-0001-recheck-snapshot.txt" + chr(10)).encode()
        tgz_hash = hashlib.sha256(b"CASE-0001-recheck.tgz").hexdigest()
        bd = "----guide" + uuid.uuid4().hex
        crlf = chr(13) + chr(10)
        body = (("--" + bd + crlf + 'Content-Disposition: form-data; name="host"' + crlf + crlf + "takserver" + crlf +
                 "--" + bd + crlf + 'Content-Disposition: form-data; name="path"' + crlf + crlf + "/var/lib/takextract/recheck/CASE-0001/2026-03-04T12-05" + crlf +
                 "--" + bd + crlf + 'Content-Disposition: form-data; name="tgz_sha256"' + crlf + crlf + tgz_hash + crlf +
                 "--" + bd + crlf + 'Content-Disposition: form-data; name="sums"; filename="s.txt"' + crlf + "Content-Type: text/plain" + crlf + crlf).encode()
                + sums + (crlf + "--" + bd + "--" + crlf).encode())
        urllib.request.urlopen(urllib.request.Request(BASE + "/recheck/" + tok + "/result", data=body, method="POST",
                               headers={"Content-Type": "multipart/form-data; boundary=" + bd}), timeout=10).read()
    # The export entry records the package's own file list, so the fixture
    # takes it from the sample package's SHA256SUMS.txt - the same place a
    # real export's list comes from.
    def _pkg_files():
        import hashlib as _h
        _z = zipfile.ZipFile(PKG)
        return ", ".join(_h.sha256(_z.read(n)).hexdigest() + " " + n for n in sorted(_z.namelist()))
    if os.environ.get("AUDIT_DB"):
        import sqlite3 as _s3
        _c = _s3.connect(os.environ["AUDIT_DB"])
        if not _c.execute("SELECT 1 FROM export_log WHERE export_kind='package' AND case_id='CASE-0001';").fetchone():
            # The window columns too: without them Verify can only say the
            # window "could not be checked", which is an honest state but not
            # the one to teach from.
            _c.execute("INSERT INTO export_log (ts_utc, ts_local, actor, client_ip, case_id, export_kind,"
                       " record_count, outcome, package_sha256, detail, requested_for,"
                       " window_start, window_end, window_timezone, north, south, west, east)"
                       " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       ("2026-03-04T11:58:00+00:00", "2026-03-04 11:58:00 UTC", "authenticated: admin",
                        "10.0.0.1", "CASE-0001", "package", 20, "generated / delivered",
                        pkg_hash, "file: CASE-0001-package.zip; package files: " + _pkg_files(),
                        "Det. Example",
                        "2026-03-04T09:00", "2026-03-04T12:00", "America/New_York",
                        B[0] + 0.05, B[0] - 0.05, B[1] - 0.05, B[1] + 0.05))
            _c.commit()
        _c.close()
    if con is not None: con.close()
    pg.reload(); pg.wait_for_load_state("networkidle")
    pg.set_input_files("#fileInput", PKG); pg.wait_for_selector("#summaryBox", state="visible", timeout=20000); pg.wait_for_timeout(1200)
    # The verdict, now that the package IS in the log and a re-check has
    # been recorded against it - which is what the guide describes. Taken
    # here rather than on the first load above, where neither was true yet.
    pg.wait_for_selector("#verdict", state="visible", timeout=20000)
    pg.wait_for_timeout(1500)   # the per-file hashing finishes in the browser
    pg.evaluate("() => window.scrollTo(0, 0)"); pg.wait_for_timeout(150)
    shot(pg, "#verdict", "verify-verdict.png")
    pg.locator("#compareBox").click(); pg.wait_for_timeout(300)
    pg.evaluate("() => window.scrollTo(0, 0)"); pg.wait_for_timeout(150)
    rr = pg.locator("#resultRow").bounding_box(); pb = pg.locator("#compareBody").bounding_box()
    pg.screenshot(path=os.path.join(OUT, "verify-compare.png"), clip={"x": rr["x"] - 1, "y": rr["y"] - 1,
                  "width": rr["width"] + 2, "height": (pb["y"] + pb["height"]) - rr["y"] + 2})
    print("  wrote verify-compare.png")

    # A chained entry, so the audit table and the integrity panel show one:
    # record a (synthetic) companion file against a (synthetic) package hash.
    pg.evaluate("""() => fetch('/api/verify-hash', {method: 'POST',
        headers: {'Content-Type': 'application/json',
                  'X-CSRFToken': document.querySelector('meta[name=csrf-token]').content},
        body: JSON.stringify({hash: 'cd'.repeat(32)})}).then(r => r.json()).then(d => d.matched ? null :
      fetch('/api/companion', {method: 'POST',
        headers: {'Content-Type': 'application/json',
                  'X-CSRFToken': document.querySelector('meta[name=csrf-token]').content},
        body: JSON.stringify({package_hash: 'ab'.repeat(32), companion_hash: 'cd'.repeat(32),
                              filename: 'recheck-positions-plain.csv', matched: 20, total: 20, case_id: 'CASE-0001'})}))""")
    pg.wait_for_timeout(600)

    # ================= AUDIT =================
    # The log is a tree - a case holds its extractions, each holding what was
    # done to check it - so the export's own entry is seeded above, beside
    # the re-check that refers to it, in the order a real install has them.
    pg.goto(BASE + "/audit"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(800)
    # Open the newest case and its extraction, so the shot shows the tree the
    # guide describes rather than a wall of collapsed lines.
    pg.locator(".caseToggle").first.click(); pg.wait_for_timeout(300)
    if pg.locator(".extractionToggle").count():
        pg.locator(".extractionToggle").first.click(); pg.wait_for_timeout(300)
    elif pg.locator(".otherToggle").count():
        pg.locator(".otherToggle").first.click(); pg.wait_for_timeout(300)
    shot(pg, "#rows", "audit-table.png")
    # The re-check, opened: what was compared against what, and what was
    # only recorded - the part of the log the guide spends most words on.
    _rc = pg.locator(".extractionChildren > .entry").filter(
        has=pg.locator(".eWhat", has_text="Re-check on the TAK Server")).first
    if _rc.count():
        _rc.locator(".entryToggle").click(); pg.wait_for_timeout(400)
        _rc.scroll_into_view_if_needed(); pg.wait_for_timeout(150)
        _rc.screenshot(path=os.path.join(OUT, "audit-recheck.png"))
        print("  wrote audit-recheck.png")

    # ================= SYSTEM =================
    pg.goto(BASE + "/admin"); pg.wait_for_load_state("networkidle")
    pg.wait_for_selector("#connStatus:not(.checking)", timeout=15000)
    # add a generic viewer so the users table shows both roles
    if pg.locator("#usersBody").inner_text().find("j.viewer") < 0:
        pg.fill("#newUsername", "j.viewer"); pg.select_option("#newRole", "viewer") if pg.locator("#newRole").count() else None
        pg.fill("#newPassword", "ViewerExample12345!"); pg.click("#addUserBtn"); pg.wait_for_timeout(800)
    shot(pg, ".panel:has(#usersBody)", "system-users.png")
    # the badge in each of its three states, by setting the element directly
    for cls, txt in (("ok", "Connected"), ("bad", "Disconnected"), ("warn", "Not configured")):
        pg.evaluate("a => { var e = document.getElementById('connStatus'); e.className = 'connStatus ' + a[0]; e.textContent = a[1]; }", [cls, txt])
        pg.wait_for_timeout(100)
        shot(pg, "#connStatus", f"system-badge-{cls}.png")
    shot(pg, ".panel:has(#dbHost)", "system-connection.png")
    pg.locator("#verifyChainBtn").click(); pg.wait_for_timeout(600)
    shot(pg, ".panel:has(#verifyChainBtn)", "system-chain.png")
    shot(pg, ".panel:has(#recheckSetupCmd)", "system-recheck.png")
    b.close()
print("done")
