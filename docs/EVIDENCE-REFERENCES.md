# Evidence references

Sources consulted while designing TAK-Extract's evidence features, with what
each one says and how it shaped the tool. Kept so the reasoning can be
re-read later, and so counsel has the citations to hand. Not legal advice.

Last updated 2026-09-18.

---

## 1. What the profession actually does (the sanity check)

The pattern across forensic tools and standards bodies is **two hashes, one
acquisition**: an *acquisition hash* computed as data is read from the source,
and a *verification hash* of the resulting evidence file, compared to show the
copy is what was captured. Nobody re-acquires from a live source a second time
to prove the first acquisition; a live system is understood to be
non-repeatable. What makes a record defensible is the hash at capture, the
documented process, the tool version, and the custody trail.

- SWGDE, *Best Practices for Digital Evidence Collection* (18-F-002, v2.0,
  2025) — hash at acquisition, verify the container afterwards, custody
  documentation from collection onward.
  https://www.swgde.org/documents/published-complete-listing/18-f-002-best-practices-for-digital-evidence-collection/
- SWGDE, *Best Practices for Computer Forensic Acquisitions* (17-F-002) —
  acquisition hash vs verification hash; NIST-approved algorithms.
  https://www.swgde.org/documents/published-complete-listing/17-f-002-best-practices-for-computer-forensic-acquisitions/
- SWGDE, *Best Practices for Digital Evidence Acquisition, Preservation, and
  Analysis from Cloud Service Providers* (23-F-004) — "if a provider has
  provided hash values, verify them": compare against the source's own hashes
  where they exist. (Closest analogue to comparing the package against the
  administrator's own re-run.)
  https://www.swgde.org/documents/published-complete-listing/23-f-004-best-practices-for-digital-evidence-acquisition-preservation-and-analysis-from-cloud-service-providers/
- NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident
  Response* — acquire with procedures that preserve integrity; hash; document.
  https://csrc.nist.gov/pubs/sp/800/86/final
- ACPO (UK) *Good Practice Guide for Digital Evidence*, Principle 3: "An audit
  trail or other record of all processes applied to digital evidence should be
  created and preserved. An independent third party should be able to examine
  those processes and achieve the same result." Reproducing the *process from
  the record* is the test - which is what `queries.sql` (every statement as
  sent, with its values) is for.
  https://forensiccontrol.com/guides/acpo-guidelines-principles-explained/
  https://cryptome.org/acpo-guide.htm
- How commercial tools present hashes: Magnet AXIOM writes hash verification
  into its case files; Cellebrite reports carry MD5/SHA-256 so a defence copy
  can be checked against the prosecution's and against the acquisition hash.
  https://www.forensicfocus.com/news/a-deeper-look-at-magnet-axioms-improved-hashing/
  https://elitedf.com/reading-cellebrite-reports/
- A hash match supports admissibility but never guarantees it; a court may
  ask whether the hash was computed and stored correctly.
  https://www.custodytrack.io/blog/cryptographic-hashing-tamper-evident-evidence

**Decision this drove (2026-09-18):** the administrator's re-run is over and
above the standard. One byte-identical file (`cot_router-raw.csv`, written
the way psql writes CSV) is enough; making every package CSV match by hash
was engineering for a challenge the profession does not normally face, at
the cost of complexity that creates its own failure mode (a false mismatch).
Not built. Revisit only if a real challenge turns on chat or mission content
matching by hash.

**Decision this drove (2026-09-26):** the certification is **produced on
demand from the audit log, not shipped blank in the package**. Its sections
3 and 4 - the zip's own hash, the re-check's hashes, the folder, the date
recorded - do not exist when the package is being built, and every one of
them is in the log by the time a custodian fills the form in. Shipping a
blank form meant hand-transcribing 64-character values the tool already
held, which is an error source in the one document a person signs. The
package instead carries `VERIFY.txt`: how to check it, for whoever has the
package and no access to the tool.

**Decision this drove (2026-09-26):** **one verdict, not a reading
exercise.** Verifying a package used to mean assembling an answer from
three tabs, five documents and eight actions - one of which, checking the
files inside a package against the package's own hash list, nothing ever
performed. Verify & Replay now states four things plainly and performs
that check in the browser. The wording distinguishes what the per-file
check shows (the members agree with the list that shipped beside them)
from what ties that list to the tool (the zip's own hash matching the
log), and says so explicitly when the second is absent.

**Decision this drove (2026-09-26):** **an export records which database it
was read from.** A package can then be told apart from one produced against
a different server, and the System page can notice the connection being
repointed. Recorded as the cluster's own `system_identifier` where the
read-only role has been granted it, otherwise a weaker catalog
fingerprint - and the package says which it used. Stated everywhere it
appears: a difference is not in itself a sign that anything is wrong (a
rebuilt, upgraded or restored cluster reports a new identifier while
holding the same data), and a match does not prove which machine was read
(a replica reports the same value as the cluster it copies).

## 2. Rules of evidence (US federal; most states track them)

- **FRE 901(a), 901(b)(1), 901(b)(9)** — authentication: a witness with
  knowledge, or evidence describing a process or system and showing it
  produces an accurate result. The package README (statements as sent,
  snapshot, account and privileges, clocks, version and commit), the public
  source, and the administrator's re-run are the "process or system" evidence.
- **FRE 902(13), 902(14)** — self-authenticating certified records generated
  by an electronic process, and data copied from a device or file
  "authenticated by a process of digital identification"; the 2017 advisory
  committee note names hash values explicitly. The certification produced
  from Verify & Replay exists for this route.
- **FRE 803(6)** — records of a regularly conducted activity (business
  records); needs a custodian or a 902(11) certification. TAK Server's
  records are the agency's own operational records.
- **FRE 1001(d)** — a printout or output that accurately reflects electronic
  data is an original.
- Machine-generated data (GPS coordinates, timestamps) is generally treated
  as not hearsay; human-entered content (chat, remarks, callsigns, drawn
  shapes, the "For" note) needs an exception.
- *Lorraine v. Markel American Insurance Co.*, 241 F.R.D. 534 (D. Md. 2007)
  — the standard opinion laying out the 901/902/803 framework for
  electronically stored information.
- Business-records foundation for digital records, explained:
  https://behindthecrimescene.com/foundation-for-business-records-in-digital-forensics-what-makes-evidence-admissible-in-court
- Database evidence in discovery (compare against backups, export to CSV):
  https://www.howelawfirm.com/e-discovery-and-forensics/database-evidence/

## 3. TAK Server facts, from its published source

Repository: https://github.com/TAK-Product-Center/Server

- `src/takserver-core/takserver-war/src/main/java/com/bbn/marti/MissionKMLServlet.java`
  and `.../util/KmlUtils.java` — the server's own KML/KMZ export
  ("Situational Awareness -> Export Mission", `/Marti/ExportMission.jsp`,
  POST `ExportMissionKML`). Query: `servertime BETWEEN start AND end`
  (inclusive both ends), no bounding box, excludes `b-t-f`, `b-f-t-r`,
  `b-f-t-a`; `<when>` is `servertime`; `optimizeExport` (page label "Remove
  Identical Position Reports") defaults to true and drops consecutive reports
  at an identical position; timestamps parse as `yyyy-MM-dd'T'HH:mm:ss.S'Z'`.
  **Not used for verification** (2026-09-17): it covers the whole server for
  a window, so it pulls far more location data than an area-limited package.
- `src/takserver-plugins/src/main/java/tak/server/Constants.java` —
  `COT_DATE_FORMAT`.
- `MissionChangeType` (persisted by ordinal): 0 CREATE_MISSION,
  1 DELETE_MISSION, 2 ADD_CONTENT, 3 REMOVE_CONTENT, 4 CREATE_DATA_FEED,
  5 DELETE_DATA_FEED.

## 4. PostgreSQL facts relied on

- psql CSV output (`\pset format csv`, psql 12+): `src/fe_utils/print.c`,
  `csv_print_field()` — a field is quoted only if it contains the separator,
  a double quote, CR or LF, or is exactly `\.`; quotes inside are doubled;
  NULL prints as the `\pset null` value (set to empty); header row plain;
  `\n` line ends; no footer in csv format. This is the rule
  `cot_router-raw.csv` is written to, so the administrator's
  `recheck-cot_router-raw.csv` has the same hash.
  https://github.com/postgres/postgres/blob/REL_15_STABLE/src/fe_utils/print.c
- `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY` must be the
  first statement of its transaction; psycopg2 opens a transaction on the
  first statement of a connection, so any open transaction is ended first.
- `txid_current_snapshot()` for the snapshot id (present in every supported
  version); `has_table_privilege()` for the account's write privileges;
  `now()` inside REPEATABLE READ is the transaction's start time.
- psql `\set ON_ERROR_ROLLBACK on` uses savepoints so one failed statement
  does not abort the rest of a transaction.
