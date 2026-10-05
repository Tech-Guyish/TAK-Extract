"""Drawn map objects - fire lines, perimeters, circles, dropped points - as
real geometry, for shapes.csv.

Everything here reads the `detail` XML that cot_router already stores and
cot.csv already exports as raw_detail; nothing new is captured from the
server. What was missing was parsing it: a drawn shape's vertices live
inside that XML, while the only geometry the database indexes (event_pt)
is a single anchor point, so until now a fire line exported as one dot.

Formats below were read off real CloudTAK-drawn data (node-cot 14.52.1)
on 2026-09-13 - see NOTES.md - not assumed from the CoT spec:

  u-d-f        one <link point="lat,lon[,hae]"/> per vertex. Closed (a
               polygon) when the first vertex equals the last; otherwise an
               open line. That equality is the ENTIRE convention - there is
               no closed= attribute or separate type for an open line.
               CloudTAK draws rectangles as a 4-corner u-d-f polygon; ATAK's
               own u-d-r rectangle uses the same link-point form.
  u-d-c-c etc  <shape><ellipse major="m" minor="m" angle="deg"/></shape>,
               centred on the row's event_pt. major/minor are RADII in
               metres (semi-axes) - confirmed from node-cot's to_geojson,
               which hands major/1000 to @turf/ellipse as a semi-axis in
               km. A circle has major == minor.
  u-d-p, b-m-* a dropped point: no geometry beyond event_pt.

Colour is <strokeColor value=N/> / <fillColor value=N/> as a SIGNED 32-bit
ARGB integer (Android's Color int), or <color argb=N/> on a point. A
b-x-KmlStyle <link> also appears inside <shape> with a <color> child, but
node-cot writes and reads that as AARRGGBB, not KML's real AABBGGRR - so
it is ignored here and never trusted as a KML colour.

This module deliberately imports nothing from exports.py: exports.py
imports it, and the same module-level cycle that already forces kmz.py to
be imported lazily would otherwise repeat. Anything shared (the map-object
cot_type patterns, the "(not recorded)" literal) is passed in by the caller.
"""
import math
import xml.etree.ElementTree as ET

# The three CoT types node-cot treats as an ellipse (its ELLIPSE_TYPE_PREFIXES):
# drawn circle, range-and-bearing circle, drawn ellipse. Matched as prefixes.
ELLIPSE_TYPES = ("u-d-c-c", "u-r-b-c-c", "u-d-c-e")

# Elements an automated feed writes into a shape's <detail>. A shape that
# carries one was pushed to the server by software, not drawn by a person
# at a map, and the exports leave it out unless the operator asks for it.
#
# Read off a real server on 2026-09-19, from the element names alone (no
# values): about 10,000 u-d-f polygons and lines - neighbourhood and water
# boundaries from an imported GIS layer - every one carrying
# <__nodered flow="..."/>, the element Node-RED's TAK node adds to what it
# sends, none carrying <creator>, arriving in bursts of hundreds a minute
# with a stale time of days. Every hand-drawn shape on the same server
# carried <creator> and none carried __nodered. `how` did not separate
# them: the feed wrote h-e ("human entered") on every one. Add a mark here
# only with the same kind of evidence, and say so in this comment.
AUTOMATED_FEED_MARKS = ("__nodered",)

EARTH_RADIUS_M = 6371008.8

CSV_HEADERS = [
    "record", "uid", "shape_kind", "cot_type", "servertime", "event_time",
    "callsign", "creator_uid", "creator_callsign", "creator_time",
    "vertices", "closed", "center_lat", "center_lon",
    "radius_m", "minor_radius_m", "angle_deg",
    "stroke_argb", "fill_argb", "stroke_weight",
    "channels", "channel_numbers", "mission_id", "record_id",
]


# ---------------------------------------------------------------------------
# Parsing one version
# ---------------------------------------------------------------------------

def _attr_float(el, name):
    try:
        return float(el.get(name))
    except (TypeError, ValueError):
        return None


def _parse_detail(detail_xml):
    """ElementTree root for a detail blob, or None if it won't parse.
    cot_router stores detail as the server received it, which is normally
    well-formed - but a row is not trusted to be, so a parse failure is a
    per-row 'no geometry', never an exception that fails the export."""
    if not detail_xml:
        return None
    try:
        return ET.fromstring(detail_xml)
    except ET.ParseError:
        return None


def parse_geometry(cot_type, detail_xml, anchor_lat, anchor_lon):
    """Geometry and styling for one version of one shape, or None when the
    row carries nothing drawable (no vertices, no ellipse, no anchor).

    Returns a dict with:
      kind        'polygon' | 'line' | 'circle' | 'ellipse' | 'point'
      vertices    [(lat, lon), ...] for polygon/line, else []
      closed      True for a polygon (first vertex == last), else False
      center      (lat, lon) for circle/ellipse/point, else None
      radius_m    major semi-axis for circle/ellipse, else None
      minor_m     minor semi-axis, else None
      angle_deg   ellipse rotation as written, else None
      stroke_argb / fill_argb   signed ARGB ints or None
      stroke_weight             float or None
      callsign, creator_uid, creator_callsign, creator_time  strings or ''
      feed_mark   the AUTOMATED_FEED_MARKS element the detail carries, or
                  None for a shape with none (a hand-drawn one)
    """
    root = _parse_detail(detail_xml)
    anchor = None
    if anchor_lat is not None and anchor_lon is not None:
        try:
            anchor = (float(anchor_lat), float(anchor_lon))
        except (TypeError, ValueError):
            anchor = None

    out = {
        "kind": None, "vertices": [], "closed": False, "center": None,
        "radius_m": None, "minor_m": None, "angle_deg": None,
        "stroke_argb": None, "fill_argb": None, "stroke_weight": None,
        "callsign": "", "creator_uid": "", "creator_callsign": "", "creator_time": "",
        "feed_mark": None,
    }

    if root is not None:
        for tag in AUTOMATED_FEED_MARKS:
            if root.find(tag) is not None:
                out["feed_mark"] = tag
                break
        contact = root.find("contact")
        if contact is not None:
            out["callsign"] = contact.get("callsign") or ""
        creator = root.find("creator")
        if creator is not None:
            out["creator_uid"] = creator.get("uid") or ""
            out["creator_callsign"] = creator.get("callsign") or ""
            out["creator_time"] = creator.get("time") or ""

        # Vertices: only <link> elements that carry point= - the KmlStyle
        # <link> inside <shape> has uid=/type= instead and is not a vertex.
        for link in root.iter("link"):
            pt = link.get("point")
            if not pt:
                continue
            parts = pt.split(",")
            if len(parts) < 2:
                continue
            try:
                out["vertices"].append((float(parts[0]), float(parts[1])))
            except ValueError:
                continue

        ellipse = root.find("./shape/ellipse")
        if ellipse is not None:
            out["radius_m"] = _attr_float(ellipse, "major")
            out["minor_m"] = _attr_float(ellipse, "minor")
            out["angle_deg"] = _attr_float(ellipse, "angle")

        for tag, key in (("strokeColor", "stroke_argb"), ("fillColor", "fill_argb")):
            el = root.find(tag)
            if el is not None:
                try:
                    out[key] = int(el.get("value"))
                except (TypeError, ValueError):
                    pass
        sw = root.find("strokeWeight")
        if sw is not None:
            out["stroke_weight"] = _attr_float(sw, "value")
        # A dropped point carries its colour as <color argb=/> instead.
        if out["stroke_argb"] is None:
            col = root.find("color")
            if col is not None:
                try:
                    out["stroke_argb"] = int(col.get("argb") or col.get("value"))
                except (TypeError, ValueError):
                    pass

    verts = out["vertices"]
    if len(verts) >= 2:
        out["closed"] = verts[0] == verts[-1] and len(verts) >= 4
        out["kind"] = "polygon" if out["closed"] else "line"
        return out

    if out["radius_m"] is not None and anchor is not None:
        out["center"] = anchor
        is_circle = (cot_type or "").startswith(ELLIPSE_TYPES[0]) or (
            out["minor_m"] is None or abs(out["radius_m"] - out["minor_m"]) < 1e-6
        )
        out["kind"] = "circle" if is_circle else "ellipse"
        return out

    if anchor is not None:
        out["center"] = anchor
        out["kind"] = "point"
        return out

    return None


# ---------------------------------------------------------------------------
# Geometry vs the export's bounding box
# ---------------------------------------------------------------------------

def _in_box(lat, lon, north, south, west, east):
    return south <= lat <= north and west <= lon <= east


def _haversine_m(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(math.sqrt(a))


def _segments_intersect(a, b, c, d):
    """Do segments a-b and c-d intersect (including touching)? Points are
    (lat, lon); treated as planar, which is fine at the scale of a drawn
    search box - the same approximation ST_MakeEnvelope's && already makes
    server-side for the point rows."""
    def orient(p, q, r):
        v = (q[1] - p[1]) * (r[0] - q[0]) - (q[0] - p[0]) * (r[1] - q[1])
        return 0 if abs(v) < 1e-15 else (1 if v > 0 else 2)

    def on_seg(p, q, r):
        return (min(p[0], r[0]) <= q[0] <= max(p[0], r[0]) and
                min(p[1], r[1]) <= q[1] <= max(p[1], r[1]))

    o1, o2, o3, o4 = orient(a, b, c), orient(a, b, d), orient(c, d, a), orient(c, d, b)
    if o1 != o2 and o3 != o4:
        return True
    return ((o1 == 0 and on_seg(a, c, b)) or (o2 == 0 and on_seg(a, d, b)) or
            (o3 == 0 and on_seg(c, a, d)) or (o4 == 0 and on_seg(c, b, d)))


def _point_in_polygon(lat, lon, verts):
    """Ray-cast point-in-polygon; verts may or may not repeat the first."""
    # x = lon, y = lat. Cast a ray east from the point; each polygon edge
    # that straddles the point's latitude and crosses the ray to its east
    # flips the parity.
    inside = False
    n = len(verts)
    j = n - 1
    for i in range(n):
        yi, xi = verts[i]
        yj, xj = verts[j]
        if (yi > lat) != (yj > lat):
            x_cross = (xj - xi) * (lat - yi) / ((yj - yi) or 1e-300) + xi
            if lon < x_cross:
                inside = not inside
        j = i
    return inside


def intersects_box(geom, north, south, west, east):
    """Does any part of this geometry touch the box? This is the inclusion
    rule for shapes.csv, deliberately different from cot.csv's: cot.csv
    keeps a row when its single point is inside the box, which for a shape
    is only the anchor - so a fire line crossing the box whose anchor
    happened to fall outside it was dropped entirely. Disclosed in the
    manifest and README because the two rules coexist in one package."""
    kind = geom["kind"]
    if kind == "point":
        lat, lon = geom["center"]
        return _in_box(lat, lon, north, south, west, east)

    if kind in ("circle", "ellipse"):
        # Nearest point of the box to the centre, then a real distance to it.
        # An ellipse is tested as a circle of its major radius - a superset,
        # so it can only over-include, never silently drop one.
        clat, clon = geom["center"]
        nlat = min(max(clat, south), north)
        nlon = min(max(clon, west), east)
        return _haversine_m(clat, clon, nlat, nlon) <= (geom["radius_m"] or 0)

    verts = geom["vertices"]
    if any(_in_box(la, lo, north, south, west, east) for la, lo in verts):
        return True
    corners = [(north, west), (north, east), (south, east), (south, west)]
    box_edges = [(corners[i], corners[(i + 1) % 4]) for i in range(4)]
    for i in range(len(verts) - 1):
        for c, d in box_edges:
            if _segments_intersect(verts[i], verts[i + 1], c, d):
                return True
    if kind == "polygon":
        # The box entirely inside the shape: no vertex or edge crosses, but
        # every corner of the box is within the polygon.
        return any(_point_in_polygon(la, lo, verts) for la, lo in corners)
    return False


# ---------------------------------------------------------------------------
# shapes.csv rows
# ---------------------------------------------------------------------------

def argb_hex(v):
    """A signed 32-bit ARGB int as 'AARRGGBB', or '' when absent. Hex is
    unambiguous in a CSV in a way the raw signed int is not."""
    if v is None:
        return ""
    return f"{int(v) & 0xFFFFFFFF:08X}"


def _fmt_vertices(verts):
    return " ".join(f"{la!r},{lo!r}" for la, lo in verts)


def collect(version_rows, headers, deletion_rows, params, include_feed_shapes=False):
    """Parse every map object once and decide its fate under the feed rule
    and then the box rule.

    The single source both renderings draw from - shapes.csv (see
    rows_from_collection) and the KMZ's drawn-shapes folder (kmz.py) - so
    the two cannot disagree about which objects are in, what each version's
    geometry is, or when a deletion happened.

    version_rows/headers: straight off the cursor - must include id, uid,
        servertime, event_time, cot_type, callsign, latitude, longitude,
        channels, channel_numbers, raw_detail.
    deletion_rows: (ts, uid, creatoruid, mission_id) from mission_change
        where change_type = 3 (REMOVE_CONTENT).
    params: the export's north/south/west/east.

    An object whose versions carry an AUTOMATED_FEED_MARKS element is from
    an automated feed and is left out before the box is even looked at,
    unless include_feed_shapes is True (the operator's explicit choice).
    Otherwise an object is included when ANY version's geometry touches
    the box, and then EVERY version of it is kept, so replay of a shape
    that moved into or out of the area is coherent rather than truncated
    at the edge.

    Returns a dict:
      objects   {uid: {"versions": [ {row fields..., "geom": parsed} ...]
                       sorted by (servertime, id),
                       "deletion": (ts, creatoruid, mission_id) or None}}
                for INCLUDED objects only
      included_uids / excluded_uids / no_geometry_uids   sets
      feed_uids       {uid: mark} for objects the feed rule left out
      feed_versions   number of version rows the feed rule left out (0 when
                      include_feed_shapes is True - nothing was left out)
      feed_marks      {mark: number of objects carrying it}, counted whether
                      or not they were left out, so the README can say what
                      was found either way
    """
    idx = {h: i for i, h in enumerate(headers)}

    def col(row, name):
        i = idx.get(name)
        return row[i] if i is not None else None

    north, south = float(params["north"]), float(params["south"])
    west, east = float(params["west"]), float(params["east"])

    by_uid = {}
    for row in version_rows:
        by_uid.setdefault(col(row, "uid"), []).append(row)

    included, excluded, no_geom = set(), set(), set()
    feed = {}   # uid -> the mark(s) its versions carry
    feed_versions = 0
    feed_marks = {}
    objects = {}
    for uid, rows in by_uid.items():
        # Two versions can share a whole-second servertime; id is monotonic.
        rows.sort(key=lambda r: (str(col(r, "servertime")), col(r, "id") or 0))
        versions = []
        for r in rows:
            g = parse_geometry(col(r, "cot_type"), col(r, "raw_detail"),
                               col(r, "latitude"), col(r, "longitude"))
            if g is None:
                continue
            versions.append({
                "id": col(r, "id"), "servertime": col(r, "servertime"),
                "event_time": col(r, "event_time"), "cot_type": col(r, "cot_type"),
                "callsign": g["callsign"] or col(r, "callsign") or "",
                "channels": col(r, "channels"), "channel_numbers": col(r, "channel_numbers"),
                "geom": g,
            })
        if not versions:
            no_geom.add(uid)
            continue
        # The feed rule, on the object: one marked version marks the object
        # (a feed does not hand a shape over to a person part-way through).
        marks = {v["geom"]["feed_mark"] for v in versions if v["geom"]["feed_mark"]}
        if marks:
            for m in sorted(marks):
                feed_marks[m] = feed_marks.get(m, 0) + 1
            if not include_feed_shapes:
                feed[uid] = "+".join(sorted(marks))
                feed_versions += len(versions)
                continue
        if not any(intersects_box(v["geom"], north, south, west, east) for v in versions):
            excluded.add(uid)
            continue
        included.add(uid)
        objects[uid] = {"versions": versions, "deletion": None}

    for ts, uid, creatoruid, mission_id in deletion_rows:
        if uid in objects and objects[uid]["deletion"] is None:
            objects[uid]["deletion"] = (ts, creatoruid, mission_id)

    return {"objects": objects, "included_uids": included,
            "excluded_uids": excluded, "no_geometry_uids": no_geom,
            "feed_uids": feed, "feed_versions": feed_versions, "feed_marks": feed_marks}


def rows_from_collection(coll, not_recorded):
    """shapes.csv rows from collect()'s output.

    not_recorded: the literal written when a deletion's creatoruid is empty.
        TAK Server (as of 5.x) leaves it blank on REMOVE_CONTENT rows, so
        the record says when and what was deleted but not who; passed
        through rather than hard-coded so that if a later server version
        does fill it in, the name appears here with no code change.
    """
    out = []
    n_del = 0
    for uid, obj in coll["objects"].items():
        for v in obj["versions"]:
            g = v["geom"]
            c = g["center"] or (None, None)
            out.append([
                "version", uid, g["kind"], v["cot_type"], v["servertime"], v["event_time"],
                v["callsign"], g["creator_uid"], g["creator_callsign"], g["creator_time"],
                _fmt_vertices(g["vertices"]), "yes" if g["closed"] else "no",
                c[0], c[1], g["radius_m"], g["minor_m"], g["angle_deg"],
                argb_hex(g["stroke_argb"]), argb_hex(g["fill_argb"]), g["stroke_weight"],
                v["channels"], v["channel_numbers"], "", v["id"],
            ])
        if obj["deletion"]:
            ts, creatoruid, mission_id = obj["deletion"]
            last = obj["versions"][-1]
            out.append([
                "deleted", uid, last["geom"]["kind"], last["cot_type"], ts, "", "",
                (creatoruid or "").strip() or not_recorded, "", "",
                "", "", None, None, None, None, None, "", "", None,
                "", "", mission_id, "",
            ])
            n_del += 1

    # Chronological across versions and deletions alike, then by uid so a
    # same-second tie is still deterministic (the package hash depends on it).
    out.sort(key=lambda r: (str(r[4]), r[1], str(r[23])))
    return out, n_del


def build_rows(version_rows, headers, deletion_rows, params, not_recorded,
               include_feed_shapes=False):
    """collect() + rows_from_collection() in one call.

    Returns (rows, summary, collection). The summary carries the
    included/excluded/no_geometry/feed uid sets, the feed counts and the
    number of deletion rows written; the collection comes back too because
    an export needs all three - the rows become shapes.csv, the summary
    decides each manifest row's fate and the README's feed note, and the
    KMZ's drawn-shapes folder is rendered from the collection itself, so
    the two can never disagree about what was found.

    This is the one place the summary is assembled. It used to be built a
    second time, inline in exports.build_package, while this function was
    called only by the tests - so the tests were exercising a shortcut the
    export never took, and the seven keys existed twice.
    """
    coll = collect(version_rows, headers, deletion_rows, params, include_feed_shapes)
    out, n_del = rows_from_collection(coll, not_recorded)
    return out, {
        "included_uids": coll["included_uids"], "excluded_uids": coll["excluded_uids"],
        "no_geometry_uids": coll["no_geometry_uids"], "deletions": n_del,
        "feed_uids": coll["feed_uids"], "feed_versions": coll["feed_versions"],
        "feed_marks": coll["feed_marks"],
    }, coll


# ---------------------------------------------------------------------------
# Helpers for the KMZ rendering (kmz.py)
# ---------------------------------------------------------------------------

def kml_color(argb, default="ff000000"):
    """KML wants aabbggrr (alpha, BLUE, green, red) - the reverse byte
    order of the ARGB int TAK stores. node-cot's embedded KmlStyle skips
    this reordering, which is why that element is never trusted here."""
    if argb is None:
        return default
    v = int(argb) & 0xFFFFFFFF
    a, r, g, b = (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF
    return f"{a:02x}{b:02x}{g:02x}{r:02x}"


def ellipse_ring(center, major_m, minor_m, angle_deg, n=64):
    """A closed ring of (lat, lon) approximating an ellipse - KML has no
    circle primitive. `angle` follows node-cot's reading of the CoT value
    (turf receives 90 - angle), i.e. degrees clockwise from north for the
    major axis. A circle is the major == minor case. Deterministic for
    identical inputs, which the package hash depends on."""
    lat0, lon0 = center
    minor_m = minor_m if minor_m is not None else major_m
    # Metres per degree at this latitude; adequate at shape scale, and the
    # same flat-earth approximation the box test already makes.
    m_per_deg_lat = 2 * math.pi * EARTH_RADIUS_M / 360.0
    m_per_deg_lon = m_per_deg_lat * math.cos(math.radians(lat0)) or 1e-9
    rot = math.radians(90.0 - (angle_deg or 0.0))
    ring = []
    for i in range(n):
        t = 2 * math.pi * i / n
        x = major_m * math.cos(t)          # along the major axis
        y = minor_m * math.sin(t)
        east = x * math.cos(rot) - y * math.sin(rot)
        north = x * math.sin(rot) + y * math.cos(rot)
        ring.append((lat0 + north / m_per_deg_lat, lon0 + east / m_per_deg_lon))
    ring.append(ring[0])
    return ring


def planar_area(verts):
    """Shoelace area in square degrees - only ever compared to other shapes
    to decide draw order (larger beneath smaller), never reported."""
    if len(verts) < 3:
        return 0.0
    a = 0.0
    for i in range(len(verts) - 1):
        (y1, x1), (y2, x2) = verts[i], verts[i + 1]
        a += x1 * y2 - x2 * y1
    return abs(a) / 2.0


def footprint_area(geom):
    """Ordering key: a polygon's ring area, an ellipse's bounding area, zero
    for lines and points (drawn last, i.e. on top of everything)."""
    if geom["kind"] == "polygon":
        return planar_area(geom["vertices"])
    if geom["kind"] in ("circle", "ellipse"):
        return planar_area(ellipse_ring(geom["center"], geom["radius_m"], geom["minor_m"], geom["angle_deg"], n=16))
    return 0.0


# ---------------------------------------------------------------------------
# Export-page overlay: outlines only, de-identified
# ---------------------------------------------------------------------------

def outlines(rows, headers, north, south, west, east, include_feed_shapes=False):
    """The Export map's faint shape outlines - a drawing aid for placing the
    box, in the same spirit as its device-motion trails: geometry only,
    never identified. No uid, no label, no creator, no colour of the
    original (which could itself identify a unit's convention), so nothing
    in the response says whose shape it is or what it was called.

    Shapes from automated feeds (AUTOMATED_FEED_MARKS) are left out unless
    include_feed_shapes is True - the same rule collect() applies to the
    export, so the map shows what the package will hold.

    rows: one row per object, its LATEST version in the window (the caller
    uses DISTINCT ON (uid) ... ORDER BY servertime DESC) - the map is not
    time-stepped, so the most recent state is what an operator drawing a
    box around "where the fire line is" needs. Included when any part of
    that version touches the current viewport, the same rule shapes.csv
    applies to the export box.

    Returns a list of {"kind": "polygon"|"line", "latlngs": [[lat, lon]..]}
    or {"kind": "circle", "center": [lat, lon], "radius_m": r}. Dropped
    points are left out - they are single positions and the trails layer
    is not about positions.
    """
    idx = {h: i for i, h in enumerate(headers)}
    out = []
    for r in rows:
        g = parse_geometry(r[idx["cot_type"]], r[idx["raw_detail"]],
                           r[idx["latitude"]], r[idx["longitude"]])
        if g is None or g["kind"] == "point":
            continue
        if g["feed_mark"] and not include_feed_shapes:
            continue
        if not intersects_box(g, north, south, west, east):
            continue
        if g["kind"] in ("circle", "ellipse"):
            if g["kind"] == "circle":
                out.append({"kind": "circle", "center": list(g["center"]), "radius_m": g["radius_m"]})
            else:
                out.append({"kind": "polygon", "latlngs": [list(p) for p in
                            ellipse_ring(g["center"], g["radius_m"], g["minor_m"], g["angle_deg"])]})
        else:
            out.append({"kind": g["kind"], "latlngs": [list(p) for p in g["vertices"]]})
    return out
