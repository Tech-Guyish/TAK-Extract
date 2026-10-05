"""
KMZ generation for TAK-Extract.

Produces a Google Earth file from the same query that drives the CSV export,
so the map view and the spreadsheet describe identical records.

Design notes, all of which are documented for the reader inside the KMZ:

  - Tracks break where a device stopped reporting, rather than drawing a
    straight line through a gap it may not have travelled.
  - Points are uniform. Accuracy is in the popup, not the icon size, because
    scaling icons competes with the track shape for attention and Google
    Earth scales icons in screen space anyway, so a scaled icon would imply
    a precision it cannot actually represent.
  - Points whose accuracy is unknown, and positions a human placed by hand
    rather than a GPS fix, get a different colour. Those are differences in
    kind, not degree, and the map should not show them as ordinary fixes.
"""

import io
import zipfile
from xml.sax.saxutils import escape

import exports
import shapes

# A device that has not reported for longer than this is treated as a gap,
# and the track is broken rather than interpolated across it. Defined in
# exports.py (shared with app.py's /api/trails) - aliased here so every
# existing GAP_SECONDS reference in this file keeps working unchanged.
GAP_SECONDS = exports.GAP_SECONDS

# Sentinels meaning "not available". See the export README.
UNKNOWN_NUMERIC = 9999999


def _category(cot_type):
    """Which Google Earth folder a record belongs in. Personnel/Vehicles and
    equipment/Infrastructure/Map objects come from exports.cot_category() -
    the same patterns app.py's /api/count uses for the record-count preview,
    so this folder breakdown can't silently disagree with that preview.
    "Other entities" and "Other" are catch-alls for whatever's left, not
    patterns of their own, so there's nothing to keep in sync there."""
    label = exports.cot_category(cot_type)
    if label:
        return label
    if cot_type and cot_type.startswith("a-"):
        return "Other entities"
    return "Other"


def _accuracy_unknown(ce):
    return ce is None or float(ce) >= UNKNOWN_NUMERIC


def _manually_placed(how):
    return bool(how) and str(how).startswith("h-")


def _style_for(point):
    if _manually_placed(point["how"]):
        return "#manualPlaced"
    if _accuracy_unknown(point["ce_m"]):
        return "#accuracyUnknown"
    return "#normalFix"


def _fmt(value, suffix="", unknown="not reported"):
    if value is None or value == "":
        return unknown
    return f"{value}{suffix}"


def _speed_text(speed):
    """Speed needs its own handling: -1 means unavailable, 0.0 means the
    device measured itself as stationary. Those are opposite claims."""
    if speed is None or speed == "":
        return "not reported"
    try:
        v = float(speed)
    except (TypeError, ValueError):
        return escape(str(speed))
    if v < 0:
        return "unavailable (device had no speed solution)"
    if v == 0:
        return "0.0 m/s - stationary (measured)"
    return f"{v:.2f} m/s ({v * 2.23694:.1f} mph)"


def _course_text(course):
    if course is None or course == "":
        return "not reported"
    try:
        v = float(course)
    except (TypeError, ValueError):
        return escape(str(course))
    if v < 0 or v >= UNKNOWN_NUMERIC:
        return "unavailable (device had no heading solution)"
    return f"{v:.1f}&#176;"


def _accuracy_text(ce):
    if _accuracy_unknown(ce):
        return "UNKNOWN - the device did not report accuracy"
    return f"{float(ce):.1f} m horizontal"


def _popup(p, case_id):
    """The description balloon for a single position."""
    manual = ""
    if _manually_placed(p["how"]):
        manual = (
            "<p style='color:#b00'><b>This position was placed by hand, "
            "not measured by GPS.</b> It is someone's estimate of a "
            "location, not a device report.</p>"
        )

    return f"""<![CDATA[
<div style="font-family:sans-serif;font-size:12px">
<h3 style="margin:0 0 6px 0">{escape(p['callsign'] or p['uid'] or 'unknown')}</h3>
{manual}
<table cellpadding="3">
<tr><td><b>Time (server)</b></td><td>{escape(str(p['servertime']))}</td></tr>
<tr><td><b>Time (device)</b></td><td>{escape(str(p['event_time']))}</td></tr>
<tr><td><b>Position</b></td><td>{p['latitude']:.6f}, {p['longitude']:.6f}</td></tr>
<tr><td><b>Accuracy</b></td><td>{_accuracy_text(p['ce_m'])}</td></tr>
<tr><td><b>Speed</b></td><td>{_speed_text(p['speed_ms'])}</td></tr>
<tr><td><b>Heading</b></td><td>{_course_text(p['course_deg'])}</td></tr>
<tr><td><b>Fix source</b></td><td>{escape(_fmt(p['how']))}</td></tr>
<tr><td><b>Type code</b></td><td>{escape(_fmt(p['cot_type']))}</td></tr>
<tr><td><b>Channels</b></td><td>{escape(_fmt(p['channels']))}</td></tr>
<tr><td><b>Team reported</b></td><td>{escape(_fmt(p['reported_team']))}</td></tr>
<tr><td><b>Role</b></td><td>{escape(_fmt(p['reported_role']))}</td></tr>
<tr><td><b>Device</b></td><td>{escape(_fmt(p['device_model']))} /
    {escape(_fmt(p['tak_platform']))} {escape(_fmt(p['tak_version'], unknown=''))}</td></tr>
<tr><td><b>Battery</b></td><td>{escape(_fmt(p['battery_pct'], '%'))}</td></tr>
<tr><td><b>Record id</b></td><td>{p['id']}</td></tr>
</table>
<p style="color:#666;font-size:11px">
Case {escape(case_id)}. Verify this record with:<br>
<code>SELECT * FROM cot_router WHERE id = {p['id']};</code>
</p>
</div>
]]>"""


STYLES = """
  <Style id="normalFix">
    <IconStyle>
      <scale>0.7</scale>
      <color>ff00aaff</color>
      <Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon>
    </IconStyle>
    <LabelStyle><scale>0</scale></LabelStyle>
  </Style>
  <Style id="accuracyUnknown">
    <IconStyle>
      <scale>0.7</scale>
      <color>ff00ffff</color>
      <Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle_highlight.png</href></Icon>
    </IconStyle>
    <LabelStyle><scale>0</scale></LabelStyle>
  </Style>
  <Style id="manualPlaced">
    <IconStyle>
      <scale>0.9</scale>
      <color>ff0000ff</color>
      <Icon><href>http://maps.google.com/mapfiles/kml/shapes/square.png</href></Icon>
    </IconStyle>
    <LabelStyle><scale>0</scale></LabelStyle>
  </Style>
  <Style id="trackLine">
    <LineStyle><color>cc00aaff</color><width>3</width></LineStyle>
  </Style>
  <Style id="startPoint">
    <IconStyle>
      <scale>1.0</scale>
      <Icon><href>http://maps.google.com/mapfiles/kml/paddle/go.png</href></Icon>
    </IconStyle>
  </Style>
  <Style id="endPoint">
    <IconStyle>
      <scale>1.0</scale>
      <Icon><href>http://maps.google.com/mapfiles/kml/paddle/stop.png</href></Icon>
    </IconStyle>
  </Style>
"""


def _kml_time(dt):
    """KML wants ISO 8601. Postgres gives timezone-aware datetimes."""
    if dt is None:
        return ""
    return dt.isoformat()


def _device_folder(uid, points, case_id):
    """One folder per device: its track segments and every position point."""
    label = points[0]["callsign"] or uid
    first = points[0]["servertime"]
    last = points[-1]["servertime"]
    segments = exports.split_segments(points)

    gap_note = ""
    if len(segments) > 1:
        gap_note = (
            f"<p><b>{len(segments)} track segments.</b> The track is broken "
            f"where this device stopped reporting for more than "
            f"{GAP_SECONDS // 60} minutes. A break means no data, not a "
            f"straight-line path.</p>"
        )

    out = [f"""    <Folder>
      <name>{escape(label)}</name>
      <description><![CDATA[
        <div style="font-family:sans-serif;font-size:12px">
        <p><b>UID</b> {escape(uid)}<br>
        <b>Positions</b> {len(points)}<br>
        <b>First</b> {escape(str(first))}<br>
        <b>Last</b> {escape(str(last))}</p>
        {gap_note}
        </div>
      ]]></description>
      <open>0</open>"""]

    # Track lines, one per unbroken segment.
    for i, seg in enumerate(segments, 1):
        if len(seg) < 2:
            continue
        coords = " ".join(
            f"{p['longitude']:.6f},{p['latitude']:.6f},0" for p in seg
        )
        seg_name = (
            "Track" if len(segments) == 1
            else f"Track segment {i} of {len(segments)}"
        )
        out.append(f"""      <Placemark>
        <name>{escape(label)} - {seg_name}</name>
        <styleUrl>#trackLine</styleUrl>
        <TimeSpan>
          <begin>{_kml_time(seg[0]['servertime'])}</begin>
          <end>{_kml_time(seg[-1]['servertime'])}</end>
        </TimeSpan>
        <LineString>
          <tessellate>1</tessellate>
          <coordinates>{coords}</coordinates>
        </LineString>
      </Placemark>""")

    # Start and end markers, so a track reads directionally.
    out.append(f"""      <Placemark>
        <name>{escape(label)} - first position</name>
        <styleUrl>#startPoint</styleUrl>
        <TimeStamp><when>{_kml_time(points[0]['servertime'])}</when></TimeStamp>
        <Point><coordinates>{points[0]['longitude']:.6f},{points[0]['latitude']:.6f},0</coordinates></Point>
      </Placemark>
      <Placemark>
        <name>{escape(label)} - last position</name>
        <styleUrl>#endPoint</styleUrl>
        <TimeStamp><when>{_kml_time(points[-1]['servertime'])}</when></TimeStamp>
        <Point><coordinates>{points[-1]['longitude']:.6f},{points[-1]['latitude']:.6f},0</coordinates></Point>
      </Placemark>""")

    # Every individual position, in a subfolder so it can be switched off.
    out.append("""      <Folder>
        <name>Individual positions</name>
        <open>0</open>
        <visibility>0</visibility>""")

    for p in points:
        out.append(f"""        <Placemark>
          <name>{escape(str(p['servertime']))}</name>
          <visibility>0</visibility>
          <styleUrl>{_style_for(p)}</styleUrl>
          <TimeStamp><when>{_kml_time(p['servertime'])}</when></TimeStamp>
          <description>{_popup(p, case_id)}</description>
          <Point><coordinates>{p['longitude']:.6f},{p['latitude']:.6f},0</coordinates></Point>
        </Placemark>""")

    out.append("      </Folder>")
    out.append("    </Folder>")
    return "\n".join(out)


def _kml_time_any(v):
    """ISO 8601 for KML from either a psycopg2 datetime or an already
    formatted string (tests); '' for None."""
    if v is None:
        return ""
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return str(v).strip().replace(" ", "T", 1)


def _coords(ring):
    """KML coordinate text: lon,lat,alt triples, space separated."""
    return " ".join(f"{lo:.7f},{la:.7f},0" for la, lo in ring)


def _shape_geometry_xml(g):
    """The KML geometry element for one parsed shape version, or None for a
    kind this folder does not draw (a dropped point is already a position
    record in cot.csv and is rendered with the other positions)."""
    kind = g["kind"]
    if kind == "polygon":
        ring = g["vertices"]
    elif kind in ("circle", "ellipse"):
        ring = shapes.ellipse_ring(g["center"], g["radius_m"], g["minor_m"], g["angle_deg"])
    elif kind == "line":
        return (f"<LineString><tessellate>1</tessellate>"
                f"<coordinates>{_coords(g['vertices'])}</coordinates></LineString>")
    else:
        return None
    return (f"<Polygon><tessellate>1</tessellate><outerBoundaryIs><LinearRing>"
            f"<coordinates>{_coords(ring)}</coordinates></LinearRing></outerBoundaryIs></Polygon>")


def _shape_style_xml(g):
    width = g["stroke_weight"] if g["stroke_weight"] is not None else 3
    line = f"<LineStyle><color>{shapes.kml_color(g['stroke_argb'])}</color><width>{width:g}</width></LineStyle>"
    if g["kind"] == "line":
        return f"<Style>{line}</Style>"
    # A polygon with no fill recorded gets a faint one rather than opaque
    # black, which is what an absent PolyStyle color would render as.
    fill = shapes.kml_color(g["fill_argb"], default="40808080")
    return f"<Style>{line}<PolyStyle><color>{fill}</color></PolyStyle></Style>"


def _shape_placemark(uid, label, i, n, v, begin, end, deletion):
    g = v["geom"]
    geom_xml = _shape_geometry_xml(g)
    if geom_xml is None:
        return ""
    if g["kind"] in ("circle", "ellipse"):
        extent = f"radius {g['radius_m']:.0f} m" + (
            "" if g["kind"] == "circle" else f" / {g['minor_m']:.0f} m, angle {g['angle_deg']:g}")
    else:
        extent = f"{len(g['vertices'])} vertices"
    drawn_by = escape(g["creator_callsign"] or g["creator_uid"] or "not recorded")
    if i == n:
        if deletion:
            fate = f"Deleted (server record) at {escape(_kml_time_any(deletion[0]))}"
        else:
            fate = "Still present at the end of the export window"
    else:
        fate = f"Replaced by version {i + 1} at {escape(_kml_time_any(end))}"
    desc = f"""<![CDATA[
<div style="font-family:sans-serif;font-size:12px">
<h3 style="margin:0 0 6px 0">{escape(label)}</h3>
<table cellpadding="3">
<tr><td><b>Version</b></td><td>{i} of {n}</td></tr>
<tr><td><b>Kind</b></td><td>{escape(g['kind'])}, {escape(extent)}</td></tr>
<tr><td><b>From (server)</b></td><td>{escape(_kml_time_any(begin))}</td></tr>
<tr><td><b>Drawn / edited by</b></td><td>{drawn_by}</td></tr>
<tr><td><b>Then</b></td><td>{fate}</td></tr>
<tr><td><b>Record id</b></td><td>{v['id']}</td></tr>
</table>
<p style="color:#666;font-size:11px">Object uid {escape(uid)}. Shown on the time slider only
while this version was current. Full detail in shapes.csv.</p>
</div>
]]>"""
    end_xml = f"<end>{escape(_kml_time_any(end))}</end>" if end is not None else ""
    # Machine-readable facts alongside the human description, so the
    # Verify page (and anything else reading this file) identifies a shape
    # placemark and its version by contract rather than by inferring it
    # from folder names or the presence of a Polygon. Google Earth shows
    # these as a small table in the balloon, which is harmless. A circle
    # also carries its true centre/radius so a viewer with a real circle
    # primitive can draw one instead of the 64-segment ring KML needs.
    ext = [
        ("tak_shape_uid", uid), ("tak_shape_kind", g["kind"]),
        ("tak_shape_version", str(i)), ("tak_shape_versions", str(n)),
        ("tak_shape_label", label),
        ("tak_shape_by", g["creator_callsign"] or g["creator_uid"] or ""),
        ("tak_shape_deleted", _kml_time_any(deletion[0]) if deletion else ""),
    ]
    if g["kind"] in ("circle", "ellipse"):
        ext.append(("tak_shape_center", f"{g['center'][0]!r},{g['center'][1]!r}"))
        ext.append(("tak_shape_radius_m", f"{g['radius_m']!r}"))
    ext_xml = "<ExtendedData>" + "".join(
        f'<Data name="{k}"><value>{escape(str(v))}</value></Data>' for k, v in ext
    ) + "</ExtendedData>"
    return f"""      <Placemark>
        <name>{escape(label)} (v{i}/{n})</name>
        <TimeSpan><begin>{escape(_kml_time_any(begin))}</begin>{end_xml}</TimeSpan>
        {_shape_style_xml(g)}
        {ext_xml}
        <description>{desc}</description>
        {geom_xml}
      </Placemark>"""


def _shapes_folder(coll):
    """One <Folder> per drawn object, one <Placemark> per version, each
    bounded by a <TimeSpan> so the time slider shows exactly the version
    that was current - a redrawn line changes as the slider moves, and a
    deleted shape vanishes at the moment the server recorded its removal.

    Draw order: larger footprints first (beneath), smaller last (on top),
    so a shape drawn inside another stays visible and clickable. Lines
    have no footprint and go last of all. Within a size tie, uid order -
    deterministic, because the package hash depends on the bytes.
    """
    objs = coll["objects"]
    def area(uid):
        return max(shapes.footprint_area(v["geom"]) for v in objs[uid]["versions"])
    ordered = sorted(objs, key=lambda u: (-area(u), u))

    # Labels come from the shape's callsign, and drawing tools default that
    # to something generic - CloudTAK names every new shape "New Feature" -
    # so several objects in one export routinely share a label. Google
    # Earth doesn't mind, but a person reading the folder tree does: a
    # duplicated label gets the first 8 characters of its uid appended.
    def raw_label(uid):
        vs = [v for v in objs[uid]["versions"] if v["geom"]["kind"] != "point"]
        return (vs[-1]["callsign"] if vs else "") or uid
    seen = {}
    for uid in ordered:
        seen[raw_label(uid)] = seen.get(raw_label(uid), 0) + 1
    def label_for(uid):
        lab = raw_label(uid)
        return f"{lab} [{uid[:8]}]" if seen[lab] > 1 else lab

    out = [f"""  <Folder>
    <name>Drawn shapes ({len(ordered)})</name>
    <description><![CDATA[{len(ordered)} drawn objects, one entry per version. Each version is
visible on the time slider only for the period it was current.]]></description>
    <open>0</open>"""]
    for uid in ordered:
        obj = objs[uid]
        versions = [v for v in obj["versions"] if v["geom"]["kind"] != "point"]
        if not versions:
            continue
        label = label_for(uid)
        n = len(versions)
        deletion = obj["deletion"]
        out.append(f"""    <Folder>
      <name>{escape(label)} ({n} version{'s' if n != 1 else ''}{', deleted' if deletion else ''})</name>
      <open>0</open>""")
        for i, v in enumerate(versions, start=1):
            begin = v["servertime"]
            if i < n:
                end = versions[i]["servertime"]
            elif deletion:
                end = deletion[0]
            else:
                end = None
            out.append(_shape_placemark(uid, label, i, n, v, begin, end, deletion))
        out.append("    </Folder>")
    out.append("  </Folder>")
    return chr(10).join(out)


def _shapes_overview(shape_count):
    if not shape_count:
        return ""
    return f"""<h3>Drawn shapes</h3>
<p>{shape_count} drawn objects (fire lines, perimeters, circles) are under
"Drawn shapes", one entry per version. Each version is visible on the time
slider only for the period it was current, so a line that was redrawn changes
as the slider moves, and a shape the server recorded as deleted disappears at
that moment. Their anchor points also appear as single positions under Map
objects, because those are position records in their own right.</p>
<p>The area rule for shapes is wider than for positions: a shape is included
when any part of any version touched the requested area, not only when its
anchor point did. See shapes.csv and the package README.</p>
"""


def build_kmz(rows, columns, params, case_id, actor, app_version,
              requested_for=None, shape_collection=None):
    """Assemble the KMZ from position rows.

    rows/columns come straight from the positional query, so the KMZ and the
    CSV are generated from one result set and cannot disagree.
    """
    idx = {name: i for i, name in enumerate(columns)}

    def field(row, name):
        return row[idx[name]] if name in idx else None

    # Group rows by device, preserving query order (uid, then servertime).
    devices = {}
    for row in rows:
        uid = field(row, "uid")
        devices.setdefault(uid, []).append({
            "id": field(row, "id"),
            "uid": uid,
            "callsign": field(row, "callsign"),
            "servertime": field(row, "servertime"),
            "event_time": field(row, "event_time"),
            "latitude": float(field(row, "latitude")),
            "longitude": float(field(row, "longitude")),
            "ce_m": field(row, "ce_m"),
            "how": field(row, "how"),
            "cot_type": field(row, "cot_type"),
            "channels": field(row, "channels"),
            "reported_team": field(row, "reported_team"),
            "reported_role": field(row, "reported_role"),
            "course_deg": field(row, "course_deg"),
            "speed_ms": field(row, "speed_ms"),
            "battery_pct": field(row, "battery_pct"),
            "device_model": field(row, "device_model"),
            "tak_platform": field(row, "tak_platform"),
            "tak_version": field(row, "tak_version"),
        })

    # Sort devices into category folders.
    categories = {}
    for uid, points in devices.items():
        cat = _category(points[0]["cot_type"])
        categories.setdefault(cat, []).append((uid, points))

    order = ["Personnel", "Vehicles and equipment", "Infrastructure",
             "Other entities", "Map objects", "Other"]

    folders = []
    for cat in order:
        if cat not in categories:
            continue
        entries = sorted(categories[cat], key=lambda e: (e[1][0]["callsign"] or e[0]))
        device_count = len(entries)
        point_count = sum(len(p) for _u, p in entries)
        folders.append(f"""  <Folder>
    <name>{escape(cat)} ({device_count})</name>
    <description><![CDATA[{device_count} tracked, {point_count} positions]]></description>
    <open>0</open>""")
        for uid, points in entries:
            folders.append(_device_folder(uid, points, case_id))
        folders.append("  </Folder>")

    # Drawn shapes as real geometry - see _shapes_folder(). Only when the
    # caller ran the shapes pipeline (a full package with shapes.csv
    # selected); a standalone locations KMZ stays a rendering of cot.csv
    # rows alone, as its own overview says.
    shape_count = 0
    if shape_collection and shape_collection.get("objects"):
        shape_count = len(shape_collection["objects"])
        folders.append(_shapes_folder(shape_collection))

    total_points = sum(len(p) for p in devices.values())

    overview = f"""<![CDATA[
<div style="font-family:sans-serif;font-size:12px;max-width:520px">
<h2>Case {escape(case_id)}</h2>
<p>Position data extracted from a TAK Server, showing what the server
recorded within a specific time window and geographic area.</p>

<h3>What was asked for</h3>
<table cellpadding="3">
<tr><td><b>Time window</b></td><td>{escape(str(params['start']))}<br>to {escape(str(params['end']))}</td></tr>
<tr><td><b>North edge</b></td><td>{params['north']}</td></tr>
<tr><td><b>South edge</b></td><td>{params['south']}</td></tr>
<tr><td><b>West edge</b></td><td>{params['west']}</td></tr>
<tr><td><b>East edge</b></td><td>{params['east']}</td></tr>
<tr><td><b>Exported by</b></td><td>{escape(actor)}</td></tr>
<tr><td><b>Requested for</b></td><td>{escape(requested_for or exports.NOT_RECORDED)}</td></tr>
<tr><td><b>Tool</b></td><td>{escape(app_version)}</td></tr>
</table>

<h3>What is here</h3>
<p>{len(devices)} tracked items, {total_points} positions, grouped into
folders by what kind of thing they are.</p>

<h3>How to read it</h3>
<p>Use the time slider at the top of Google Earth to replay the period.
Click any position for its details. Individual position points are hidden
by default - switch on "Individual positions" under a device to see them.</p>

<p><b>Broken tracks are deliberate.</b> Where a device stopped reporting for
more than {GAP_SECONDS // 60} minutes the line stops and restarts. A gap
means there is no data for that period. It does not mean the device
travelled in a straight line across it.</p>

<h3>Point colours</h3>
<ul>
<li><b>Orange circle</b> - ordinary GPS position with reported accuracy.</li>
<li><b>Yellow circle</b> - position reported, but the device did not say how
accurate it was. Do not assume it was precise.</li>
<li><b>Red square</b> - a position a person placed by hand rather than a
device measuring it. This is someone's estimate, not a measurement.</li>
</ul>

{_shapes_overview(shape_count)}
<h3>Limits</h3>
<p>This shows what the SERVER received. A device that lost connectivity may
have recorded positions locally that never reached the server. Positions are
GPS measurements with a margin of error, shown per point, not exact points.</p>

<p>This file is a rendering of the same records contained in the CSV files of
the full evidence package. If the two ever disagree, the CSV governs.</p>
</div>
]]>"""

    kml = f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2">
<Document>
  <name>Case {escape(case_id)}</name>
  <description>{overview}</description>
{STYLES}
{chr(10).join(folders)}
</Document>
</kml>
"""

    # Deterministic entry timestamps (see exports.write_deterministic_zip_entry)
    # - this same function is called twice for identical content whenever a
    # full package bundles its own locations.kmz alongside a standalone one
    # (see exports.build_package()), and without this, the two would hash
    # differently despite having identical KML content, purely from when
    # each happened to run.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Google Earth opens doc.kml by convention.
        exports.write_deterministic_zip_entry(z, "doc.kml", kml)
        exports.write_deterministic_zip_entry(z, "parameters.txt", _parameters_text(
            case_id, actor, params, len(devices), total_points, app_version,
            requested_for))
    return buf.getvalue()


def _parameters_text(case_id, actor, params, device_count, point_count, app_version,
                     requested_for=None):
    """A plain-text copy of the query parameters, carried inside the KMZ so
    the file self-describes even if opened years later by someone who does
    not have the rest of the package."""
    return f"""CoT Location Package - Query Parameters
=======================================
Case / reference : {case_id}
Exported by      : {actor}
Requested for    : {requested_for or exports.NOT_RECORDED}
Export tool      : {app_version}

TIME WINDOW (start inclusive, end exclusive)
  Start : {params['start']}
  End   : {params['end']}

GEOGRAPHIC BOX (WGS84 / EPSG:4326, decimal degrees)
  North : {params['north']}
  South : {params['south']}
  West  : {params['west']}
  East  : {params['east']}

CONTENTS
  Tracked items : {device_count}
  Positions     : {point_count}

WHAT THIS FILE IS
  A rendering of position records held by a TAK Server, for viewing in
  Google Earth. It is not the authoritative record. The full evidence
  package contains the same positions as CSV, along with the device
  manifest, connection records and other supporting files.

  Tracks break where a device stopped reporting for more than
  {GAP_SECONDS // 60} minutes. A break means no data for that period, not a
  straight-line path.

  Point colours: orange is an ordinary GPS fix; yellow means the device did
  not report its accuracy; red square means a person placed that position by
  hand rather than a device measuring it.
"""
