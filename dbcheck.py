"""Does this TAK Server database still hold what the exporter expects?

The question this answers is the one a Postgres or TAK Server upgrade
raises: not "can we connect" - the System page's Test connection covers
that - but "do the statements that build an evidence package still resolve
against what is there now, and has anything shifted underneath us that
still runs?"

Two halves, deliberately separate:

  fingerprint(conn)   A handful of catalogue reads: per-table columns and
                      types in ordinal order, extensions, geometry columns,
                      server version, the channel mask width. Milliseconds,
                      no new connection. This is the half that detects
                      drift, and it is cheap enough to run inside an
                      export's own snapshot and on a page load.

  run(conn, ...)      The above, plus executing every statement the
                      exporter actually sends with LIMIT 0, plus the
                      handful of things LIMIT 0 cannot prove. The
                      deliberate one, run after an update.

The expectations are not written down anywhere here. They come from
exports.py - the real statements, executed - and from the baseline this
install recorded when connect-database.sh set it up. A hand-maintained
list of tables and columns would be a third copy that drifts from both,
and drift is the thing being looked for.

THE RULE THAT MATTERS: every statement is executed with the parameter
tuple its builder returned, including an empty one. Never None. psycopg2
only runs its own %-interpolation when vars is not None, and several of
these statements carry a deliberately doubled '%%' (see QUALITY_CHECKS in
exports.py, and the outage recorded above it). Pass None and that doubling
reaches Postgres literally. tests/test_dbcheck.py asserts it.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import exports

# A window and a box for the statements to be planned against. Under
# LIMIT 0 the values never matter, but they must be castable: the string
# form is the one the Export page's datetime-local inputs send, so the
# ::timestamptz casts are exercised against the server's own DateStyle.
PROBE_PARAMS = {
    "start": "2026-01-01T00:00",
    "end": "2026-01-01T00:01",
    "west": -98.6, "south": 39.7, "east": -98.3, "north": 39.9,
    "case_id": "schema-check",
}

# Geometry columns the exporter reads, and what it assumes about them.
# ST_MakeEnvelope(..., 4326) is hardcoded in seven places; a column in a
# different SRID does not raise, it returns nothing.
GEOMETRY_COLUMNS = (
    ("cot_router", "event_pt", 4326),
    ("cot_router_chat", "event_pt", 4326),
    ("resource", "location", 4326),
)

# Plain-English gloss for the SQLSTATEs a schema change actually produces,
# so a report reads as a diagnosis rather than a driver error.
SQLSTATE_GLOSS = {
    "42P01": "the table does not exist (renamed, dropped, or in another schema)",
    "42703": "the column does not exist (renamed or dropped)",
    "42883": "the function or operator does not exist - PostGIS is the usual cause",
    "42804": "a column's type changed to one this statement cannot use",
    "42501": "permission denied - the grants did not survive",
    "3F000": "the schema does not exist",
    "22P02": "a value could not be cast - the server's input formats changed",
}

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"
_RANK = {SKIP: 0, OK: 1, WARN: 2, FAIL: 3}


def _worst(statuses):
    return max(statuses, key=lambda s: _RANK.get(s, 0)) if statuses else OK


def _item(ident, label, status, detail=""):
    return {"id": ident, "label": label, "status": status, "detail": detail}


def _known_identities(recent):
    """The set of database identities recent exports recorded.

    app.recent_source_identities() returns DICTS - {identity, when,
    case_id} - not strings. Treating them as strings raised
    "TypeError: unhashable type: 'dict'" and took the whole check down,
    but only on an install that had actually recorded an export: a fresh
    audit log returns an empty list, so every test box missed it and the
    production one failed on the first run. Accepts either shape, because
    the caller injects this and should not have to know.
    """
    out = set()
    for entry in recent or []:
        value = entry.get("identity") if isinstance(entry, dict) else entry
        if value:
            out.add(str(value))
    return out


def _clean(text):
    """Text from the database, made safe to splice into a document.

    Control characters out (a quoted Postgres identifier may contain a
    newline, and both the package README's header block and the audit
    log's "; "-joined clauses are line- and separator-structured), runs of
    whitespace collapsed, and a length cap so one enormous identifier
    cannot push everything else off the page. `;` goes too, matching what
    app.detail_safe() strips, so a value can never open an audit clause."""
    s = " ".join(str(text if text is not None else "").split())
    s = "".join(c for c in s if ord(c) >= 32 and ord(c) != 127 and c != ";")
    return s[:300]


def _err(e):
    """A psycopg2 error as a sentence. e.diag carries the server's own
    SQLSTATE and primary message, which are far more use than str(e)."""
    code = getattr(getattr(e, "diag", None), "sqlstate", None)
    msg = getattr(getattr(e, "diag", None), "message_primary", None) or str(e).strip()
    msg = " ".join(msg.split())
    if code:
        gloss = SQLSTATE_GLOSS.get(code)
        return f"{code}: {msg}" + (f" - {gloss}" if gloss else "")
    return f"{type(e).__name__}: {msg}"


# ---------------------------------------------------------------------------
# The statements the exporter actually sends
# ---------------------------------------------------------------------------

def collect_statements(probe_bitpos=None, columns=None):
    """Every statement an export issues, as (label, sql, params).

    Two passes over the file queries: without a channel filter, then with
    one, because the channel clause is a bit-string predicate that only
    appears when an operator has chosen channels - and it is the single
    most upgrade-fragile construct in the app.

    `columns` is cot_router's real column list, so the raw-rows statement
    verified here is the one an export would send rather than the r.*
    fallback. None means the fallback, which is what a caller that could
    not read the catalogue has.
    """
    p = PROBE_PARAMS
    out = []

    passes = [(None, "")]
    if probe_bitpos is not None:
        passes.append(({probe_bitpos}, " [channel filter]"))

    for channels, suffix in passes:
        for name, sql, params in exports.build_queries(p, channels=channels):
            out.append((f"{name}{suffix}", sql, params))

        chan_and, chan_params = exports.channel_where_clause(
            "r.groups", channels, prefix="AND")
        raw_params = (p["start"], p["end"], p["west"], p["south"],
                      p["east"], p["north"], *chan_params)
        out.append((f"cot_router-raw.csv{suffix}",
                    exports.raw_rows_sql(chan_and, columns), raw_params))
        out.append((f"locations.csv{suffix}",
                    exports.single_csv_sql(chan_and),
                    exports.filter_args(p) + tuple(chan_params)))

        plain_chan_and, plain_chan_params = exports.channel_where_clause(
            "groups", channels, prefix="AND")
        out.append((f"data quality summary{suffix}",
                    exports.quality_sql(plain_chan_and),
                    exports.filter_args(p) + tuple(plain_chan_params)))
        out.append((f"record count preview{suffix}",
                    exports.count_sql(plain_chan_and),
                    exports.filter_args(p) + tuple(plain_chan_params)))

    out.append(("positions-plain.csv", exports.PLAIN_POSITIONS_SQL,
                exports.plain_positions_params(p)))
    out.append(("shape deletions", exports.SHAPE_DELETIONS_SQL,
                (p["start"], p["end"])))
    out.append(("available channels", exports.available_channels_sql(),
                exports.available_channels_params(p)))
    for table, _label in exports.CENSUS_TABLES:
        out.append((f"census: {table}", exports.census_count_sql(table), ()))
    return out


def _run_statements(conn, statements):
    """Each statement with LIMIT 0, inside its own savepoint so one failure
    does not abort the rest. LIMIT 0 rather than EXPLAIN because it catches
    the same parse and plan errors AND yields cur.description - which is
    the header row of that evidence file, and the single most useful thing
    to record for drift."""
    items, headers = [], {}
    for label, sql, params in statements:
        limited = exports.with_limit(sql, 0)
        try:
            with conn.cursor() as cur:
                cur.execute("SAVEPOINT takx_stmt;")
                try:
                    cur.execute(limited, params)
                    if cur.description:
                        headers[label] = [d[0] for d in cur.description]
                    cur.execute("RELEASE SAVEPOINT takx_stmt;")
                    items.append(_item(label, label, OK, "resolves"))
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT takx_stmt;")
                    cur.execute("RELEASE SAVEPOINT takx_stmt;")
                    items.append(_item(label, label, FAIL, _err(e)))
        except Exception as e:
            # The savepoint itself failed, so the transaction is gone.
            items.append(_item(label, label, FAIL, _err(e)))
            break
    return items, headers


# ---------------------------------------------------------------------------
# The cheap half: what the schema looks like right now
# ---------------------------------------------------------------------------

def fingerprint(conn):
    """A canonical picture of everything the exporter depends on.

    Catalogue reads only - no table is touched - so this is safe to call
    inside an export's snapshot and cheap enough for a page load.
    """
    fp = {"taken_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")}
    with conn.cursor() as cur:
        cur.execute("""SELECT current_setting('server_version'),
                              current_setting('server_version_num'),
                              current_setting('TimeZone'),
                              current_setting('DateStyle'),
                              current_user, current_database();""")
        (fp["server_version"], fp["server_version_num"], fp["timezone"],
         fp["datestyle"], fp["db_user"], fp["db_name"]) = [str(v) for v in cur.fetchone()]

        cur.execute("""SELECT extname, extversion FROM pg_extension
                        WHERE extname LIKE 'postgis%' OR extname = 'plpgsql'
                        ORDER BY extname;""")
        fp["extensions"] = {n: v for n, v in cur.fetchall()}

        # Column names and types, in ordinal order, for every granted table.
        # format_type() is what psql prints, so a widened varchar or a
        # changed numeric precision shows up rather than reading as "text".
        cur.execute("""SELECT c.relname, a.attnum, a.attname,
                              format_type(a.atttypid, a.atttypmod)
                         FROM pg_attribute a
                         JOIN pg_class c ON c.oid = a.attrelid
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                          AND c.relname = ANY(%s)
                          AND a.attnum > 0 AND NOT a.attisdropped
                        ORDER BY c.relname, a.attnum;""",
                    (list(exports.GRANTED_TABLES),))
        tables = {}
        for relname, _attnum, attname, fmt in cur.fetchall():
            tables.setdefault(relname, []).append(f"{attname} {fmt}")
        fp["tables"] = tables
        # Called out separately because raw_rows_sql builds a column list
        # from it, so its shape IS cot_router-raw.csv's shape.
        fp["cot_router_columns"] = tables.get("cot_router", [])

        # geometry_columns is itself a PostGIS view, so this is the second
        # read that a broken install can stop - and stopping here would
        # report "relation geometry_columns does not exist", which is the
        # symptom rather than the diagnosis. Its own savepoint, so the
        # PostGIS line above (read from pg_extension, which always exists)
        # is what the reader is told instead.
        try:
            cur.execute("SAVEPOINT takx_geomcols;")
            cur.execute("""SELECT f_table_name, f_geometry_column, srid, type
                             FROM geometry_columns
                            WHERE f_table_schema = 'public'
                            ORDER BY f_table_name, f_geometry_column;""")
            fp["geometry_columns"] = {
                f"{t}.{c}": f"{typ} srid={srid}" for t, c, srid, typ in cur.fetchall()
            }
            cur.execute("RELEASE SAVEPOINT takx_geomcols;")
        except Exception as e:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT takx_geomcols;")
                cur.execute("RELEASE SAVEPOINT takx_geomcols;")
            except Exception:
                pass
            fp["geometry_columns"] = {}
            fp["geometry_columns_error"] = _err(e)

        # The channel bitmask's width. The comment above channel_names()
        # records this as ~32768 on a live server; a change here silently
        # changes which bit every channel decodes from.
        #
        # This is the ONLY part of the fingerprint that reads a table
        # rather than the catalogue, so it is the only part that a revoked
        # grant can stop. It gets its own savepoint and its own failure
        # value: losing the mask width must not cost us the whole
        # fingerprint, because the privilege section is what explains why,
        # and it cannot explain anything if this took the report down with
        # it. (Found by revoking SELECT against a real server.)
        try:
            cur.execute("SAVEPOINT takx_mask;")
            cur.execute("""SELECT DISTINCT length(groups) FROM cot_router
                            WHERE groups IS NOT NULL LIMIT 4;""")
            fp["channel_mask_bits"] = sorted(r[0] for r in cur.fetchall())
            cur.execute("RELEASE SAVEPOINT takx_mask;")
        except Exception as e:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT takx_mask;")
                cur.execute("RELEASE SAVEPOINT takx_mask;")
            except Exception:
                pass
            fp["channel_mask_bits"] = []
            fp["channel_mask_error"] = _err(e)
    return fp


# Left out of the hash: when it was taken, and anything only SOME callers
# collect. output_headers comes from the statement pass, which the full
# check runs and an export does not - including it would mean a package
# recorded a fingerprint that could never equal the baseline's even on an
# unchanged schema, which makes the number in an evidence package
# worthless. Headers are still diffed; they are just not part of the
# identity of "what this schema is".
_UNHASHED = ("taken_utc", "output_headers", "channel_mask_error",
             "geometry_columns_error")


def fingerprint_sha256(fp):
    """A hash of the schema itself, so the value a package records is
    directly comparable to the baseline's."""
    stable = {k: v for k, v in (fp or {}).items() if k not in _UNHASHED}
    blob = json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def diff_fingerprint(baseline, current):
    """What changed, classified. A removal, a type change or a reorder is a
    failure: it changes what an evidence file contains. An addition is a
    warning - nothing breaks, but cot_router-raw.csv is now a different
    shape from the one an earlier package holds."""
    changes = []
    if not baseline:
        return changes

    def note(status, what):
        # Sanitised HERE, at the one point every change string is built, so
        # all three sinks are covered at once: the package README, the
        # chained audit detail, and the System page.
        #
        # These strings carry text the DATABASE supplies - table and column
        # names, format_type() output, server error messages. A quoted
        # Postgres identifier may contain newlines and semicolons, and the
        # README splices this into a fixed-width header block that states
        # the source database, the account and its write privileges. A
        # column named so as to close that line could forge further header
        # lines in a document that is then hashed and certified as genuine.
        # The audit path already had detail_safe() for the same reason
        # (clause forgery, twice); the README had nothing, and the fix
        # belongs where the value is made rather than at each sink.
        changes.append({"status": status, "detail": _clean(what)})

    for key, label in (("server_version", "PostgreSQL version"),
                       ("timezone", "server timezone"),
                       ("datestyle", "server DateStyle"),
                       ("db_user", "database user"),
                       ("db_name", "database name")):
        was, now = baseline.get(key), current.get(key)
        if was is not None and was != now:
            status = WARN if key in ("server_version", "timezone", "datestyle") else FAIL
            note(status, f"{label}: was {was}, now {now}")

    was_major = (baseline.get("server_version_num") or "")[:2]
    now_major = (current.get("server_version_num") or "")[:2]
    if was_major and now_major and was_major != now_major:
        note(WARN, "PostgreSQL major version changed - grants, pg_hba.conf and "
                   "PostGIS are the usual casualties of a major upgrade")

    for name in sorted(set(baseline.get("extensions", {})) | set(current.get("extensions", {}))):
        was = baseline.get("extensions", {}).get(name)
        now = current.get("extensions", {}).get(name)
        if was and not now:
            note(FAIL, f"extension {name} is gone (was {was})")
        elif now and not was:
            note(WARN, f"extension {name} {now} is new")
        elif was != now:
            note(WARN, f"extension {name}: was {was}, now {now}")

    for key in sorted(set(baseline.get("geometry_columns", {}))
                      | set(current.get("geometry_columns", {}))):
        was = baseline.get("geometry_columns", {}).get(key)
        now = current.get("geometry_columns", {}).get(key)
        if was != now:
            note(FAIL if was else WARN,
                 f"geometry column {key}: was {was or 'absent'}, now {now or 'absent'}")

    b_tables, c_tables = baseline.get("tables", {}), current.get("tables", {})
    for table in sorted(set(b_tables) | set(c_tables)):
        was, now = b_tables.get(table), c_tables.get(table)
        if was and now is None:
            note(FAIL, f"table {table} is gone")
            continue
        if now and was is None:
            note(WARN, f"table {table} is new")
            continue
        if was == now:
            continue
        was_names = [c.split(" ", 1)[0] for c in was]
        now_names = [c.split(" ", 1)[0] for c in now]
        for gone in [n for n in was_names if n not in now_names]:
            note(FAIL, f"{table}.{gone} was removed")
        for added in [n for n in now_names if n not in was_names]:
            note(WARN, f"{table}.{added} was added at column "
                       f"{now_names.index(added) + 1} of {len(now_names)}"
                       + (f" - {table}-raw.csv now has {len(now_names)} columns "
                          f"instead of {len(was_names)}" if table == "cot_router" else ""))
        for col in was:
            name = col.split(" ", 1)[0]
            match = next((c for c in now if c.split(" ", 1)[0] == name), None)
            if match and match != col:
                note(FAIL, f"{table}.{name}: type was {col.split(' ', 1)[1]}, "
                           f"now {match.split(' ', 1)[1]}")
        shared_was = [n for n in was_names if n in now_names]
        shared_now = [n for n in now_names if n in was_names]
        if shared_was != shared_now:
            note(FAIL, f"{table}: the column order changed")

    # What each statement produces. Classified the same way as the columns
    # themselves rather than as a blanket failure: a file that gained a
    # column is not comparable to an older package's copy, but nothing about
    # it is wrong - that is what an upgrade does. A file that LOST a column,
    # or reordered the ones it kept, is a different matter.
    b_heads = baseline.get("output_headers", {})
    c_heads = current.get("output_headers", {})
    for key in sorted(set(b_heads) & set(c_heads)):
        was, now = b_heads[key], c_heads[key]
        if was == now:
            continue
        lost = [h for h in was if h not in now]
        kept_was = [h for h in was if h in now]
        kept_now = [h for h in now if h in was]
        if lost:
            note(FAIL, f"{key} no longer produces: {', '.join(lost)}")
        elif kept_was != kept_now:
            note(FAIL, f"{key}: the order of its columns changed")
        else:
            gained = [h for h in now if h not in was]
            note(WARN, f"{key} now also produces: {', '.join(gained)}"
                       f" ({len(was)} columns before, {len(now)} now)")

    was_bits = baseline.get("channel_mask_bits")
    now_bits = current.get("channel_mask_bits")
    if was_bits and now_bits and was_bits != now_bits:
        note(WARN, f"channel mask width: was {was_bits}, now {now_bits}")
    return changes


# ---------------------------------------------------------------------------
# The things LIMIT 0 cannot prove
# ---------------------------------------------------------------------------

def _live_checks(conn):
    """Constructs that resolve happily and return the wrong answer. All
    bounded to the newest rows, so this stays cheap on a large table."""
    items = []

    for table, column, want_srid in GEOMETRY_COLUMNS:
        label = f"{table}.{column} is a geometry in SRID {want_srid}"
        try:
            with conn.cursor() as cur:
                cur.execute("SAVEPOINT takx_geom;")
                try:
                    cur.execute(f"""SELECT ST_SRID({column}), ST_X({column}), ST_Y({column})
                                      FROM {table} WHERE {column} IS NOT NULL
                                     LIMIT 1;""")
                    row = cur.fetchone()
                    cur.execute("RELEASE SAVEPOINT takx_geom;")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT takx_geom;")
                    cur.execute("RELEASE SAVEPOINT takx_geom;")
                    items.append(_item(f"srid:{table}.{column}", label, FAIL, _err(e)))
                    continue
        except Exception as e:
            items.append(_item(f"srid:{table}.{column}", label, FAIL, _err(e)))
            continue
        if row is None:
            items.append(_item(f"srid:{table}.{column}", label, SKIP,
                               "no rows with a position to check"))
        elif row[0] != want_srid:
            items.append(_item(f"srid:{table}.{column}", label, FAIL,
                               f"SRID is {row[0]}, not {want_srid} - the box filter "
                               f"compares against an envelope built in {want_srid}, so "
                               f"it returns NOTHING rather than raising"))
        elif not (-180 <= row[1] <= 180 and -90 <= row[2] <= 90):
            items.append(_item(f"srid:{table}.{column}", label, FAIL,
                               f"SRID says {want_srid} but the newest value is "
                               f"({row[1]}, {row[2]}), which is not degrees"))
        else:
            items.append(_item(f"srid:{table}.{column}", label, OK,
                               f"SRID {row[0]}, newest value in range"))

    # The channel bit decode, and the detail-XML extraction, over the same
    # recent slice. Both resolve fine when broken; both just stop finding
    # anything, which is what makes them worth executing.
    try:
        with conn.cursor() as cur:
            # How many channels are DEFINED, first. Without this the two
            # states below are indistinguishable: a mask that has stopped
            # decoding (broken) and a server with no channels configured
            # at all (perfectly normal) both yield zero names.
            cur.execute("SELECT count(*) FROM groups;")
            defined = cur.fetchone()[0]
            cur.execute(f"""SELECT count(*),
                                   count({exports.channel_names('r.groups')}),
                                   count(substring(r.detail from '<contact[^>]*callsign="([^"]*)"'))
                              FROM (SELECT * FROM cot_router
                                     WHERE groups IS NOT NULL
                                     ORDER BY servertime DESC LIMIT 200) r;""")
            seen, decoded, callsigns = cur.fetchone()
    except Exception as e:
        items.append(_item("decode", "channel bits and detail XML decode", FAIL, _err(e)))
        return items

    if not seen:
        items.append(_item("decode", "channel bits and detail XML decode", SKIP,
                           "no recent rows carrying a channel mask to decode"))
    elif not defined:
        items.append(_item(
            "decode:channels", "channel bitmask decodes to channel names", WARN,
            "no channels are defined on this server, so there is nothing for a "
            "mask to decode to - normal on a server that does not use them, and "
            "it means channel filtering has nothing to offer"))
    else:
        items.append(_item(
            "decode:channels", "channel bitmask decodes to channel names",
            OK if decoded else FAIL,
            f"{decoded} of {seen} recent rows named a channel" if decoded else
            f"{defined} channel(s) are defined but none of {seen} recent rows "
            f"decoded to one - channel filtering would silently match nothing"))
        items.append(_item(
            "decode:detail", "callsigns extract from the detail XML",
            OK if callsigns else WARN,
            f"{callsigns} of {seen} recent rows yielded a callsign" if callsigns else
            f"none of {seen} recent rows yielded a callsign - either the detail "
            f"format changed, or these rows genuinely carry no contact element"))
    return items


def _privileges(conn):
    """Every granted table: present, readable, and - the part that matters
    for an evidence tool - still not writable."""
    items = []
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT t,
                                  to_regclass('public.' || t) IS NOT NULL,
                                  has_table_privilege(to_regclass('public.' || t), 'SELECT'),
                                  has_table_privilege(to_regclass('public.' || t), 'INSERT')
                               OR has_table_privilege(to_regclass('public.' || t), 'UPDATE')
                               OR has_table_privilege(to_regclass('public.' || t), 'DELETE')
                               OR has_table_privilege(to_regclass('public.' || t), 'TRUNCATE')
                             FROM unnest(%s::text[]) AS t ORDER BY t;""",
                        (list(exports.GRANTED_TABLES),))
            rows = cur.fetchall()
    except Exception as e:
        return [_item("privileges", "table grants", FAIL, _err(e))]

    missing = [t for t, present, _s, _w in rows if not present]
    unreadable = [t for t, present, sel, _w in rows if present and not sel]
    writable = [t for t, present, _s, wr in rows if present and wr]

    items.append(_item("tables:present", f"all {len(rows)} granted tables exist",
                       FAIL if missing else OK,
                       "missing: " + ", ".join(missing) if missing else "none missing"))
    items.append(_item("tables:select", "every table that exists is readable",
                       FAIL if unreadable else OK,
                       "cannot SELECT: " + ", ".join(unreadable) if unreadable
                       else "SELECT granted throughout"))
    items.append(_item("tables:readonly", "the account still cannot write",
                       FAIL if writable else OK,
                       "HAS WRITE ACCESS TO: " + ", ".join(writable) if writable
                       else "no INSERT, UPDATE, DELETE or TRUNCATE anywhere"))

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT has_function_privilege(current_user, "
                        "'pg_control_system()', 'EXECUTE');")
            granted = cur.fetchone()[0]
        items.append(_item("grant:pg_control_system",
                           "cluster identifier readable (optional grant)",
                           OK if granted else WARN,
                           "granted - exports record the cluster's own identifier" if granted
                           else "not granted - exports fall back to the weaker catalog "
                                "fingerprint and say so; connect-database.sh offers it"))
    except Exception as e:
        items.append(_item("grant:pg_control_system",
                           "cluster identifier readable (optional grant)", WARN, _err(e)))
    return items


def _liveness(conn, previous_max=None):
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT min(servertime), max(servertime), now() FROM cot_router;")
            oldest, newest, now = cur.fetchone()
    except Exception as e:
        return [_item("liveness", "the server is still writing", FAIL, _err(e))], None
    if newest is None:
        return [_item("liveness", "the server is still writing", WARN,
                      "cot_router holds no rows at all")], None
    age = now - newest
    detail = f"oldest {oldest}, newest {newest} ({age} ago)"
    if previous_max:
        moved = str(newest) != str(previous_max)
        detail += ("; new rows since the last check" if moved
                   else f"; NOTHING new since the last check, which saw {previous_max}")
        return [_item("liveness", "the server is still writing",
                      OK if moved else WARN, detail)], str(newest)
    return [_item("liveness", "the server is still writing", OK, detail)], str(newest)


# ---------------------------------------------------------------------------
# The whole check
# ---------------------------------------------------------------------------

def run(conn, baseline=None, previous_max=None, recent_identities=None, quick=False):
    """Everything, against an open connection. Returns a report dict.

    Connection-injected like exports.build_package, so the CLI, a Flask
    route and a test harness all drive it the same way and this module
    never imports the web app.
    """
    report = {
        "checked_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "tool_version": None, "sections": [], "changes": [], "verdict": OK,
    }
    context = {}
    exports.begin_snapshot(conn, context)
    if context.get("snapshot_error"):
        report["sections"].append({
            "name": "Connection", "items": [
                _item("snapshot", "read-only snapshot opened", FAIL,
                      context["snapshot_error"])]})
        report["verdict"] = FAIL
        return report

    # --- identity -----------------------------------------------------
    exports.read_source_identity(conn, context)
    ident = []
    ident.append(_item("snapshot", "read-only snapshot opened", OK,
                       f"as {context.get('db_user')}, "
                       f"writes: {context.get('write_privs', 'unknown')}"))
    # exports.source_identity(), NOT the raw id: that is the exact function
    # whose output an export writes into the audit log's "source database:"
    # clause, and the log's values are what `known` holds. Comparing the
    # bare id against a logged "cluster <n>" could never match, so this item
    # would have WARNed on every run of a correctly-configured install,
    # printing two values that read the same and calling them different -
    # and writing a non-OK verdict into the chained log each time. The
    # comparison had never actually executed before (it raised on the dict
    # shape first), so the mismatch shipped unnoticed.
    #
    # The kind stays part of the compared string on purpose: a cluster id
    # and a catalog id are not worth the same, so "catalog 7690" must not
    # match "cluster 7690".
    current_identity = exports.source_identity(context)
    known = _known_identities(recent_identities)
    if known:
        matches = current_identity in known
        ident.append(_item(
            "identity", "the database recent exports came from", OK if matches else WARN,
            f"{current_identity}" + ("" if matches else
            f" - recent exports recorded {', '.join(sorted(known))}. A rebuilt, "
            f"upgraded or restored cluster reports a new identifier while holding "
            f"the same data, so a difference is not in itself a sign anything is wrong")))
    else:
        ident.append(_item("identity", "source database identity", OK,
                           current_identity or "not recorded"))
    report["sections"].append({"name": "Connection and identity", "items": ident})

    # --- privileges FIRST ---------------------------------------------
    # Before the fingerprint, because a revoked grant is one of the things
    # that stops a fingerprint being taken - and a report that says only
    # "could not fingerprint" while knowing perfectly well that SELECT was
    # revoked is a report that withheld the answer.
    report["sections"].append({"name": "Tables and privileges", "items": _privileges(conn)})

    # --- fingerprint --------------------------------------------------
    fp = {}
    try:
        fp = fingerprint(conn)
        fp_items = [_item("fingerprint", "schema fingerprint taken", OK,
                          f"PostgreSQL {fp['server_version']}, "
                          f"{len(fp['tables'])} tables, "
                          f"{len(fp['cot_router_columns'])} columns in cot_router")]
        postgis = [n for n in fp["extensions"] if n.startswith("postgis")]
        fp_items.append(_item("postgis", "PostGIS is installed",
                              OK if postgis else FAIL,
                              ", ".join(f"{n} {fp['extensions'][n]}" for n in postgis)
                              if postgis else "no postgis extension - every map-based "
                                              "query depends on it"))
        if fp.get("channel_mask_error"):
            fp_items.append(_item("mask", "channel mask width readable", WARN,
                                  fp["channel_mask_error"]))
        if fp.get("geometry_columns_error"):
            fp_items.append(_item(
                "geomcols", "geometry columns readable",
                WARN if postgis else FAIL,
                fp["geometry_columns_error"] + ("" if postgis else
                " - which is what PostGIS being absent looks like")))
    except Exception as e:
        # Not a return: the sections below still have things to say, and
        # the drift comparison simply has nothing to compare.
        fp_items = [_item("fingerprint", "schema fingerprint taken", FAIL, _err(e))]
        try:
            conn.rollback()
            exports.begin_snapshot(conn, context)
        except Exception:
            pass
    report["sections"].append({"name": "Schema fingerprint", "items": fp_items})

    report["sections"].append({"name": "Values, not just types", "items": _live_checks(conn)})

    # --- the real statements -----------------------------------------
    if not quick:
        columns, _col_err = exports.cot_router_columns(conn)
        probe = None
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT min(bitpos) FROM groups;")
                row = cur.fetchone()
                probe = row[0] if row else None
        except Exception:
            conn.rollback()
            exports.begin_snapshot(conn, context)
        stmt_items, headers = _run_statements(
            conn, collect_statements(probe_bitpos=probe, columns=columns))
        fp["output_headers"] = headers
        report["sections"].append({
            "name": "The statements an export sends", "items": stmt_items})
        if probe is None:
            report["sections"][-1]["items"].append(_item(
                "channels:probe", "channel-filtered pass", SKIP,
                "no channels defined, so the bit-string predicate was not exercised"))

    live_items, newest = _liveness(conn, previous_max)
    report["sections"].append({"name": "Liveness", "items": live_items})
    report["newest_servertime"] = newest

    # --- drift --------------------------------------------------------
    report["fingerprint"] = fp or None
    report["fingerprint_sha256"] = fingerprint_sha256(fp) if fp else None
    report["baseline_sha256"] = fingerprint_sha256(baseline) if baseline else None
    report["changes"] = diff_fingerprint(baseline, fp) if fp else []
    # Only a fingerprint we actually took can become a baseline. Seeding
    # from a failed read would record an empty schema as the truth.
    report["baseline_seeded"] = baseline is None and bool(fp)

    statuses = [i["status"] for s in report["sections"] for i in s["items"]]
    statuses += [c["status"] for c in report["changes"]]
    report["verdict"] = _worst(statuses)
    try:
        conn.rollback()
    except Exception:
        pass
    return report


# ---------------------------------------------------------------------------
# Where the baseline lives
# ---------------------------------------------------------------------------
# audit.sqlite, because it is already on the bind-mounted volume, already
# included in the System page's backup, already writable by the app, and
# already per-install - which a baseline must be, since it encodes THIS
# server's schema. A JSON file beside it would be a second artifact to
# protect for no gain.

def init_tables(sqlite_path):
    """Same idempotent-migration convention as app.init_audit()."""
    con = sqlite3.connect(sqlite_path)
    con.execute("""
        CREATE TABLE IF NOT EXISTS schema_baseline (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            created_utc       TEXT NOT NULL,
            created_by        TEXT,
            approved          INTEGER NOT NULL DEFAULT 0,
            fingerprint_json  TEXT NOT NULL,
            fingerprint_sha256 TEXT NOT NULL,
            note              TEXT
        );
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS schema_checks (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc            TEXT NOT NULL,
            actor             TEXT,
            where_run         TEXT,
            tool_version      TEXT,
            verdict           TEXT,
            fingerprint_sha256 TEXT,
            baseline_sha256   TEXT,
            max_servertime    TEXT,
            report_json       TEXT
        );
    """)
    con.commit()
    con.close()


def load_baseline(sqlite_path):
    """The newest approved baseline, or None. Returns (fingerprint, row)."""
    try:
        init_tables(sqlite_path)
        con = sqlite3.connect(sqlite_path)
        row = con.execute("""SELECT id, created_utc, created_by, fingerprint_json, note
                               FROM schema_baseline WHERE approved = 1
                              ORDER BY id DESC LIMIT 1;""").fetchone()
        con.close()
    except Exception:
        return None, None
    if not row:
        return None, None
    try:
        return json.loads(row[3]), {"id": row[0], "created_utc": row[1],
                                    "created_by": row[2], "note": row[4]}
    except Exception:
        return None, None


def save_baseline(sqlite_path, fp, created_by, note=""):
    init_tables(sqlite_path)
    con = sqlite3.connect(sqlite_path)
    con.execute("""INSERT INTO schema_baseline
                     (created_utc, created_by, approved, fingerprint_json,
                      fingerprint_sha256, note)
                   VALUES (?, ?, 1, ?, ?, ?);""",
                (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
                 created_by, json.dumps(fp, sort_keys=True), fingerprint_sha256(fp), note))
    con.commit()
    con.close()


def last_newest_servertime(sqlite_path):
    """What the previous check saw as the newest row, so liveness can say
    "the server has written since" rather than guess at an age threshold."""
    try:
        con = sqlite3.connect(sqlite_path)
        row = con.execute("""SELECT max_servertime FROM schema_checks
                              WHERE max_servertime IS NOT NULL
                              ORDER BY id DESC LIMIT 1;""").fetchone()
        con.close()
        return row[0] if row else None
    except Exception:
        return None


def record_check(sqlite_path, report, actor=None, where_run=None, tool_version=None):
    try:
        init_tables(sqlite_path)
        con = sqlite3.connect(sqlite_path)
        con.execute("""INSERT INTO schema_checks
                         (ts_utc, actor, where_run, tool_version, verdict,
                          fingerprint_sha256, baseline_sha256, max_servertime, report_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                    (report.get("checked_utc"), actor, where_run, tool_version,
                     report.get("verdict"), report.get("fingerprint_sha256"),
                     report.get("baseline_sha256"), report.get("newest_servertime"),
                     json.dumps(report, sort_keys=True, default=str)))
        con.commit()
        con.close()
    except Exception as e:
        print(f"could not record this check: {type(e).__name__}: {e}", flush=True)


def audit_detail(report):
    """One "; "-joined clause line for the chained audit log, in the same
    shape the export and re-check entries use."""
    counts = {}
    for section in report.get("sections", []):
        for item in section["items"]:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
    parts = [f"verdict {report.get('verdict')}"]
    parts.append("checks " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())))
    if report.get("fingerprint_sha256"):
        parts.append(f"schema fingerprint sha256 {report['fingerprint_sha256']}")
    if report.get("baseline_sha256"):
        parts.append(f"baseline sha256 {report['baseline_sha256']}")
    if report.get("baseline_seeded"):
        parts.append("baseline seeded by this run")
    changes = report.get("changes") or []
    if changes:
        parts.append(f"drift {len(changes)} change(s)")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_MARK = {OK: "[ok]  ", WARN: "[WARN]", FAIL: "[FAIL]", SKIP: "[--]  "}


def render_text(report):
    out = [""]
    out.append("=" * 72)
    out.append(f"TAK-Extract database check - {report['checked_utc']}")
    out.append("=" * 72)
    for section in report["sections"]:
        out.append("")
        out.append(f"==> {section['name']}")
        for item in section["items"]:
            out.append(f"  {_MARK.get(item['status'], '[?]   ')} {item['label']}")
            if item["detail"]:
                for line in _wrap(item["detail"], 64):
                    out.append(f"         {line}")

    out.append("")
    out.append("==> Drift since the recorded baseline")
    fp_hash = report.get("fingerprint_sha256")
    changes = report.get("changes") or []
    if not fp_hash:
        out.append("  [--]   the schema could not be read, so there was nothing to")
        out.append("         compare. See the sections above for why.")
    elif report.get("baseline_seeded"):
        out.append("  [--]   no baseline recorded before this run - seeding from it.")
        out.append("         Nothing here is verified against anything earlier; this")
        out.append("         baseline is what the NEXT update will be measured against.")
    elif not changes:
        out.append("  [ok]   nothing changed")
        out.append(f"         fingerprint {fp_hash[:16]}...")
    else:
        for change in changes:
            out.append(f"  {_MARK.get(change['status'], '[?]   ')} {change['detail']}")

    out.append("")
    out.append("-" * 72)
    verdict = report["verdict"]
    if verdict == FAIL:
        out.append("VERDICT: something is wrong. Lines marked [FAIL] above say what.")
    elif verdict == WARN:
        out.append("VERDICT: usable, with things worth reading. See [WARN] above.")
    else:
        out.append("VERDICT: everything the exporter needs is present and behaving.")
    out.append("-" * 72)

    todo = [i for s in report["sections"] for i in s["items"] if i["status"] == FAIL]
    if todo:
        out.append("")
        out.append("What to do")
        for item in todo:
            out.append(f"  - {item['label']}: {item['detail']}")
        out.append("")
        out.append("  Grants, pg_hba.conf and the re-check folder are what")
        out.append("  connect-database.sh sets up - re-running it is safe and")
        out.append("  idempotent, and it checks each step before changing anything.")
    out.append("")
    return "\n".join(out)


def _wrap(text, width):
    words, line, lines = str(text).split(), "", []
    for word in words:
        if line and len(line) + 1 + len(word) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
# app is imported HERE rather than at module scope, so a Flask route can
# `import dbcheck` without a cycle and this module stays testable with no
# web app at all.

def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        prog="dbcheck",
        description="Check that the TAK Server database still holds what an "
                    "export needs. Read-only: every statement is a SELECT, "
                    "and it runs in a READ ONLY transaction.")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON instead of text")
    parser.add_argument("--quick", action="store_true",
                        help="skip the statement pass; fingerprint and live checks only")
    parser.add_argument("--approve-baseline", action="store_true",
                        help="record the current schema as the baseline future "
                             "runs are measured against")
    parser.add_argument("--approved-by", default=None,
                        help="who approved the new baseline (required with "
                             "--approve-baseline)")
    parser.add_argument("--no-audit", action="store_true",
                        help="do not write an entry to the chained audit log")
    args = parser.parse_args(argv)

    if args.approve_baseline and not args.approved_by:
        parser.error("--approve-baseline needs --approved-by NAME, so the log "
                     "records who accepted the change")

    # This is not a server starting, so suppress app's "log in at" banner.
    import os
    os.environ.setdefault("TAKX_NO_BANNER", "1")
    import app  # noqa: E402  - deliberately late, see above

    sqlite_path = app.AUDIT_DB
    baseline, baseline_row = load_baseline(sqlite_path)

    try:
        conn = app.get_connection()
    except Exception as e:
        print(f"\nCould not connect to the TAK Server database: {_err(e)}")
        text = str(e).lower()
        if "no pg_hba.conf entry" in text:
            print("\n  Postgres is reachable and refused the connection: nothing in")
            print("  its pg_hba.conf matches where this tool is connecting from.")
            print("  A major-version upgrade writes a fresh pg_hba.conf, which is")
            print("  the usual way this line goes missing. connect-database.sh")
            print("  re-adds it and reloads - it checks before changing anything.")
        elif "password authentication failed" in text or "role" in text:
            print("\n  Postgres is reachable and rejected the credentials. A new")
            print("  cluster carries roles across only if the upgrade used")
            print("  pg_upgrade; connect-database.sh re-creates the role and grants.")
        elif "could not translate host name" in text:
            print("\n  The host name could not be resolved. Check the host on the")
            print("  System page - a value saved there wins over .env.")
        elif "could not connect" in text or "connection refused" in text:
            print("\n  Nothing answered on that address and port. A major-version")
            print("  upgrade leaves the old cluster in place and the new one may")
            print("  not be on the port this install is configured for, and a new")
            print("  cluster defaults listen_addresses back to localhost, which a")
            print("  container on the Docker bridge cannot reach. Check both:")
            print("    sudo pg_lsclusters")
            print("    sudo ss -ltnp | grep -i postgres")
        return 3

    try:
        recent = None
        try:
            recent = [i for i in app.recent_source_identities() if i]
        except Exception:
            pass
        report = run(conn, baseline=baseline,
                     previous_max=last_newest_servertime(sqlite_path),
                     recent_identities=recent, quick=args.quick)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    report["tool_version"] = getattr(app, "APP_VERSION", None)
    if baseline_row:
        report["baseline_recorded"] = baseline_row

    if report.get("baseline_seeded") and report.get("fingerprint"):
        save_baseline(sqlite_path, report["fingerprint"], "install",
                      "seeded on the first run - not verified against anything earlier")
    elif args.approve_baseline and report.get("fingerprint"):
        save_baseline(sqlite_path, report["fingerprint"], args.approved_by,
                      "approved after review")
        report["baseline_approved_by"] = args.approved_by

    record_check(sqlite_path, report, actor=args.approved_by or "cli",
                 where_run="command line", tool_version=report["tool_version"])

    if not args.no_audit:
        try:
            # An empty dict, not None: audit() reads case_id and the window
            # off it with .get(), so None makes the row fail to write - and
            # it fails inside audit()'s own handler, which prints and
            # carries on, so the check looked like it had logged when it
            # had not. A schema check has no case or window; the columns
            # are simply left NULL.
            app.audit(args.approved_by or "cli", None, {}, "schema-check",
                      0, report["verdict"], detail=audit_detail(report))
        except Exception as e:
            print(f"could not write the audit entry: {type(e).__name__}: {e}")

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        print(render_text(report))
        if report.get("baseline_approved_by"):
            print(f"Baseline updated, approved by {report['baseline_approved_by']}.\n")

    return {OK: 0, SKIP: 0, WARN: 1, FAIL: 2}.get(report["verdict"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
