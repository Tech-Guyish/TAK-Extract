"""Regression tests for shapes.py - drawn map objects as real geometry.

The XML fixtures below mirror the exact element/attribute layout observed
in real CloudTAK-drawn data on 2026-09-13 (see shapes.py's module
docstring), with made-up coordinates. No live database. Run with:
python tests/test_shapes.py
"""
import os
import sys

# This file lives in tests/; shapes.py is in the checkout above.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shapes

failures = []


def check(label, cond, extra=""):
    print(("[PASS] " if cond else "[FAIL] ") + label + ("" if cond else f"  {extra}"))
    if not cond:
        failures.append(label)


STYLE = ('<strokeColor value="-2737863"/><strokeWeight value="3"/>'
         '<strokeStyle value="solid"/><fillColor value="2144745785"/>')
CREATOR = ('<creator uid="ANDROID-CloudTAK-tester" type="a-f-G-E-V-C" '
           'callsign="Test Admin" time="2026-01-01T00:00:00.000Z"/>')


def detail(inner):
    return f'<detail><contact callsign="New Feature"/><archive/>{CREATOR}{inner}</detail>'


def links(pts):
    return "".join(f'<link point="{la},{lo}"/>' for la, lo in pts)


# A square polygon (closed: first == last) around (10, 20)
SQUARE = [(10.1, 19.9), (10.1, 20.1), (9.9, 20.1), (9.9, 19.9), (10.1, 19.9)]
POLY_XML = detail(STYLE + links(SQUARE) + '<labels_on value="false"/>')
# An open line: first != last, and nothing else marks it
LINE_XML = detail(STYLE + links([(10.0, 19.0), (10.0, 21.0)]))
# A circle: <shape><ellipse> plus the KmlStyle <link> that is NOT a vertex
CIRCLE_XML = detail(STYLE + (
    '<shape><ellipse major="500" minor="500" angle="360"/>'
    '<link uid="x.Style" type="b-x-KmlStyle" relation="p-c"><Style>'
    '<LineStyle><color>FFD63939</color></LineStyle></Style></link></shape>'))
POINT_XML = detail('<color argb="-16711936" value="-16711936"/>')

# ---------------------------------------------------------------------------
# parse_geometry
# ---------------------------------------------------------------------------
g = shapes.parse_geometry("u-d-f", POLY_XML, 10.0, 20.0)
check("closed link ring -> polygon", g["kind"] == "polygon" and g["closed"] is True)
check("polygon keeps every vertex as written (incl. closing repeat)", len(g["vertices"]) == 5)
check("stroke colour parsed from signed ARGB int", g["stroke_argb"] == -2737863)
check("fill colour parsed", g["fill_argb"] == 2144745785)
check("stroke weight parsed", g["stroke_weight"] == 3.0)
check("callsign and creator fields parsed",
      g["callsign"] == "New Feature" and g["creator_callsign"] == "Test Admin"
      and g["creator_uid"] == "ANDROID-CloudTAK-tester")

g = shapes.parse_geometry("u-d-f", LINE_XML, 10.0, 20.0)
check("open link chain -> line (first != last is the whole convention)",
      g["kind"] == "line" and g["closed"] is False and len(g["vertices"]) == 2)

g = shapes.parse_geometry("u-d-c-c", CIRCLE_XML, 10.0, 20.0)
check("ellipse with major == minor -> circle centred on the anchor",
      g["kind"] == "circle" and g["center"] == (10.0, 20.0) and g["radius_m"] == 500.0)
check("KmlStyle <link> is NOT mistaken for a vertex", g["vertices"] == [])

g = shapes.parse_geometry("u-d-c-e", detail('<shape><ellipse major="800" minor="300" angle="45"/></shape>'), 1.0, 2.0)
check("major != minor on a u-d-c-e -> ellipse, angle kept",
      g["kind"] == "ellipse" and g["minor_m"] == 300.0 and g["angle_deg"] == 45.0)

g = shapes.parse_geometry("u-d-p", POINT_XML, 10.0, 20.0)
check("dropped point -> point with its <color argb> as stroke",
      g["kind"] == "point" and g["center"] == (10.0, 20.0) and g["stroke_argb"] == -16711936)

check("no geometry at all -> None", shapes.parse_geometry("u-d-f", "<detail/>", None, None) is None)
check("unparseable detail with an anchor -> falls back to a point",
      shapes.parse_geometry("u-d-p", "<detail><broken", 1.0, 2.0)["kind"] == "point")
check("unparseable detail and no anchor -> None",
      shapes.parse_geometry("u-d-f", "<detail><broken", None, None) is None)
check("vertex with altitude 'lat,lon,hae' parses lat/lon",
      shapes.parse_geometry("u-d-f", detail(links([(1, 2), (3, 4)]).replace('"1,2"', '"1,2,55.5"')), None, None)["vertices"][0] == (1.0, 2.0))

# ---------------------------------------------------------------------------
# intersects_box - the inclusion rule
# ---------------------------------------------------------------------------
def box(n, s, w, e):
    return dict(north=n, south=s, west=w, east=e)

poly = shapes.parse_geometry("u-d-f", POLY_XML, 10.0, 20.0)
check("polygon: a vertex inside the box -> included",
      shapes.intersects_box(poly, **box(10.05, 9.95, 19.85, 19.95)))
check("polygon: box entirely INSIDE the shape (no vertex, no edge crossing) -> included",
      shapes.intersects_box(poly, **box(10.01, 9.99, 19.99, 20.01)))
check("polygon: an edge crosses the box, all vertices outside -> included",
      shapes.intersects_box(poly, **box(10.2, 10.05, 19.95, 20.05)))
check("polygon: entirely elsewhere -> excluded",
      not shapes.intersects_box(poly, **box(12.0, 11.0, 30.0, 31.0)))
check("polygon: anchor outside, shape crossing the box -> INCLUDED (the fire-line case)",
      shapes.intersects_box(poly, **box(9.95, 9.85, 19.95, 20.05)))

line = shapes.parse_geometry("u-d-f", LINE_XML, 10.0, 20.0)
check("open line crossing the box with both ends outside -> included",
      shapes.intersects_box(line, **box(10.1, 9.9, 19.9, 20.1)))
check("open line entirely outside -> excluded",
      not shapes.intersects_box(line, **box(11.0, 10.5, 19.0, 21.0)))
check("open line: a box inside the line's bounding rectangle but not touching it -> excluded",
      not shapes.intersects_box(line, **box(10.5, 10.1, 19.5, 20.5)))

circ = shapes.parse_geometry("u-d-c-c", CIRCLE_XML, 10.0, 20.0)
# 500 m radius; 1 degree of latitude is ~111 km, so 0.004 deg ~ 444 m
check("circle: centre inside -> included", shapes.intersects_box(circ, **box(10.1, 9.9, 19.9, 20.1)))
check("circle: centre outside but rim overlaps the box edge (444 m away) -> included",
      shapes.intersects_box(circ, **box(10.1, 10.004, 19.9, 20.1)))
check("circle: centre 1.1 km from the nearest box edge -> excluded",
      not shapes.intersects_box(circ, **box(10.1, 10.01, 19.9, 20.1)))

pt = shapes.parse_geometry("u-d-p", POINT_XML, 10.0, 20.0)
check("point inside -> included", shapes.intersects_box(pt, **box(10.1, 9.9, 19.9, 20.1)))
check("point outside -> excluded", not shapes.intersects_box(pt, **box(10.1, 10.05, 19.9, 20.1)))

# ---------------------------------------------------------------------------
# build_rows - versions, tie-break, deletions, creator pass-through
# ---------------------------------------------------------------------------
H = ["id", "uid", "servertime", "event_time", "cot_type", "how", "callsign",
     "latitude", "longitude", "channels", "channel_numbers", "raw_detail"]

def row(id_, uid, t, ctype, xml, lat, lon):
    return (id_, uid, t, t, ctype, "h-g-i-g-o", "New Feature", lat, lon, "Admin", "6", xml)

far = links([(50.0, 50.0), (50.0, 50.1), (50.1, 50.1), (50.1, 50.0), (50.0, 50.0)])
rows = [
    row(3, "poly", "2026-01-01 10:00:02", "u-d-f", POLY_XML, 10.0, 20.0),
    row(1, "poly", "2026-01-01 10:00:00", "u-d-f", POLY_XML, 10.0, 20.0),
    # same second as id 1 - id must break the tie
    row(2, "poly", "2026-01-01 10:00:00", "u-d-f", POLY_XML, 10.0, 20.0),
    row(4, "far",  "2026-01-01 10:00:03", "u-d-f", detail(far), 50.05, 50.05),
    row(5, "pt",   "2026-01-01 10:00:04", "u-d-p", POINT_XML, 10.0, 20.0),
    row(6, "empty","2026-01-01 10:00:05", "u-d-f", "<detail/>", None, None),
]
dels = [
    ("2026-01-01 10:05:00", "poly", "", 43),            # blank creator - today's server
    ("2026-01-01 10:06:00", "pt", "ANDROID-CloudTAK-x", 43),  # a future server that fills it in
    ("2026-01-01 10:07:00", "far", "", 43),            # excluded shape -> must not appear
    ("2026-01-01 10:08:00", "unknown-uid", "", 43),    # never seen at all -> must not appear
]
out, summ, _coll = shapes.build_rows(rows, H, dels, box(10.1, 9.9, 19.9, 20.1), "(not recorded)")

check("included: the polygon and the point", summ["included_uids"] == {"poly", "pt"})
check("excluded (never touched the box): the far polygon", summ["excluded_uids"] == {"far"})
check("no geometry: the empty row", summ["no_geometry_uids"] == {"empty"})
check("deletions written only for included shapes", summ["deletions"] == 2)

poly_versions = [r for r in out if r[1] == "poly" and r[0] == "version"]
check("every version of an included shape is written", len(poly_versions) == 3)
check("same-second versions ordered by id", [r[23] for r in poly_versions] == [1, 2, 3])
check("no rows at all for an excluded shape", not any(r[1] == "far" for r in out))
check("no rows for an unknown deletion uid", not any(r[1] == "unknown-uid" for r in out))

d_poly = next(r for r in out if r[1] == "poly" and r[0] == "deleted")
d_pt = next(r for r in out if r[1] == "pt" and r[0] == "deleted")
check("deletion row carries the last known kind/type", d_poly[2] == "polygon" and d_poly[3] == "u-d-f")
check("blank creatoruid on a deletion -> the not-recorded literal", d_poly[7] == "(not recorded)")
check("a populated creatoruid passes straight through (future TAK versions)",
      d_pt[7] == "ANDROID-CloudTAK-x")
check("deletion row carries mission_id", d_poly[22] == 43)

check("rows are chronological across versions and deletions",
      [r[4] for r in out] == sorted(r[4] for r in out))
check("row width matches CSV_HEADERS for every row",
      all(len(r) == len(shapes.CSV_HEADERS) for r in out))
v = poly_versions[0]
check("version row: vertices serialised as 'lat,lon' pairs, closed=yes",
      v[10].startswith("10.1,19.9 10.1,20.1") and v[11] == "yes")
check("version row: colours as AARRGGBB hex", v[17] == "FFD63939" and v[18] == "7FD63939")

check("argb_hex: negative int -> unsigned hex", shapes.argb_hex(-16711936) == "FF00FF00")
check("argb_hex: None -> empty", shapes.argb_hex(None) == "")

# Determinism: identical input twice -> identical rows (the package hash depends on it)
out2, _, _ = shapes.build_rows(list(reversed(rows)), H, dels, box(10.1, 9.9, 19.9, 20.1), "(not recorded)")
check("build_rows is order-independent and deterministic", out == out2)

# ---------------------------------------------------------------------------
# outlines() - the Export map overlay: latest version per object, viewport
# box rule, and NOTHING identifying in the output.
# ---------------------------------------------------------------------------
OH = ["uid", "cot_type", "latitude", "longitude", "raw_detail"]
orows = [
    ("poly", "u-d-f", 10.0, 20.0, POLY_XML),          # inside the box
    ("line", "u-d-f", 10.0, 20.0, LINE_XML),          # crosses it
    ("circ", "u-d-c-c", 10.0, 20.0, CIRCLE_XML),      # centre inside
    ("pt",   "u-d-p", 10.0, 20.0, POINT_XML),         # a point: left out
    ("far",  "u-d-f", 50.05, 50.05, detail(far)),     # elsewhere
]
ol = shapes.outlines(orows, OH, 10.1, 9.9, 19.9, 20.1)
kinds = sorted(o["kind"] for o in ol)
check("outlines: polygon, line and circle that touch the viewport are returned", kinds == ["circle", "line", "polygon"])
check("outlines: a dropped point is left out (it is a position, not a shape)", not any(o["kind"] == "point" for o in ol))
check("outlines: a shape elsewhere is left out", len(ol) == 3)
leak = [k for o in ol for k in o if k not in ("kind", "latlngs", "center", "radius_m")]
check("outlines: nothing identifying in the output (no uid/label/creator/colour)", not leak, leak)
circ = next(o for o in ol if o["kind"] == "circle")
check("outlines: a circle carries centre + radius, not a ring", circ["center"] == [10.0, 20.0] and circ["radius_m"] == 500.0)
check("outlines: the closed ring keeps its vertices as [lat, lon] lists",
      next(o for o in ol if o["kind"] == "polygon")["latlngs"][0] == [10.1, 19.9])

# ---------------------------------------------------------------------------
# Automated feeds: a shape carrying an AUTOMATED_FEED_MARKS element is left
# out of collect()/outlines() unless include_feed_shapes is True. The
# fixture is the skeleton read off the real server on 2026-09-19 (no
# <creator>, no styling, <__nodered> and mission destinations) with
# made-up values.
# ---------------------------------------------------------------------------
FEED_XML = ('<detail><contact callsign="Feature 1"/><remarks/><labels_on value="true"/>'
            + links(SQUARE) +
            '<marti><dest mission-guid="00000000-0000-0000-0000-000000000000"/></marti>'
            '<__nodered flow="layer-import"/>'
            '<_flow-tags_ TAK-Server-00000000000000000000000000000000="2026-09-08T00:00:00Z"/></detail>')
g = shapes.parse_geometry("u-d-f", FEED_XML, 10.0, 20.0)
check("feed: parse_geometry reports the mark", g["feed_mark"] == "__nodered" and g["kind"] == "polygon")
check("feed: a hand-drawn shape reports no mark",
      shapes.parse_geometry("u-d-f", POLY_XML, 10.0, 20.0)["feed_mark"] is None)
check("feed: a mark that is only text, not an element, does not count",
      shapes.parse_geometry("u-d-f", detail('<remarks>__nodered</remarks>' + links(SQUARE)), 10.0, 20.0)["feed_mark"] is None)

frows = rows + [
    row(7, "feed-a", "2026-01-01 10:00:06", "u-d-f", FEED_XML, 10.0, 20.0),
    row(8, "feed-a", "2026-01-01 10:00:07", "u-d-f", FEED_XML, 10.0, 20.0),   # a second version
    row(9, "feed-b", "2026-01-01 10:00:08", "u-d-f", FEED_XML, 10.0, 20.0),
]
fout, fsumm, _ = shapes.build_rows(frows, H, dels, box(10.1, 9.9, 19.9, 20.1), "(not recorded)")
check("feed: left out by default, per object, with the mark named",
      fsumm["feed_uids"] == {"feed-a": "__nodered", "feed-b": "__nodered"})
check("feed: the number of version rows left out is counted", fsumm["feed_versions"] == 3)
check("feed: the marks found are counted per object", fsumm["feed_marks"] == {"__nodered": 2})
check("feed: no rows for a feed shape", not any(r[1].startswith("feed-") for r in fout))
check("feed: hand-drawn shapes unaffected", fsumm["included_uids"] == {"poly", "pt"} and fsumm["excluded_uids"] == {"far"})
check("feed: a feed shape is not also reported as box-excluded or no-geometry",
      not (set(fsumm["feed_uids"]) & (fsumm["excluded_uids"] | fsumm["no_geometry_uids"])))

iout, isumm, _ = shapes.build_rows(frows, H, dels, box(10.1, 9.9, 19.9, 20.1), "(not recorded)",
                                include_feed_shapes=True)
check("feed: included on request - the objects go through the box rule like any other",
      isumm["feed_uids"] == {} and isumm["feed_versions"] == 0 and {"feed-a", "feed-b"} <= isumm["included_uids"])
check("feed: the marks found are still counted when included (the README says what was found)",
      isumm["feed_marks"] == {"__nodered": 2})
check("feed: included rows are ordinary version rows", sum(1 for r in iout if r[1] == "feed-a") == 2)

fol = shapes.outlines(orows + [("feed", "u-d-f", 10.0, 20.0, FEED_XML)], OH, 10.1, 9.9, 19.9, 20.1)
check("feed: the map overlay leaves feed shapes out by default", len(fol) == 3)
fol2 = shapes.outlines(orows + [("feed", "u-d-f", 10.0, 20.0, FEED_XML)], OH, 10.1, 9.9, 19.9, 20.1,
                       include_feed_shapes=True)
check("feed: the map overlay draws them when asked", len(fol2) == 4)

print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("ALL SHAPE TESTS PASSED")
