# Security policy

TAK-Extract reads the recorded movements of real people and produces
packages that get put in front of courts, review boards and records
requesters. A defect that lets someone alter what it records, or read data
they should not, matters more here than the size of the codebase suggests.
Reports are welcome, including ones that turn out to be nothing.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private reporting: the **Security** tab of this repository →
**Report a vulnerability**. It goes to the maintainer and nobody else, and
it gives us somewhere to talk before anything is public.

If that is unavailable to you, open an ordinary issue saying only that you
have a security report and how to reach you — **no details** — and you will
be contacted privately.

Useful in a report, roughly in order:

- what an attacker can do that they should not be able to;
- who they have to be (an unauthenticated stranger, a signed-in viewer, an
  administrator, someone holding a re-check token, someone with a shell on
  the TAK Server) — this changes the severity more than anything else;
- the steps, ideally against a throwaway install rather than a live one;
- the version (`System` page, or `APP_VERSION` in `app.py`).

### What to expect

This is maintained by one person alongside other work, so:

- **Acknowledgement within a week.** If you hear nothing in two, assume it
  went astray and chase it.
- **An assessment after that** — whether it is reproducible, what the real
  severity looks like, and a rough timeline.
- **Credit in the release notes** if you want it, and none if you do not.

There is no bug bounty. Nothing is paid for a report.

Please give a reasonable window to fix something before publishing. What is
reasonable depends on what it is, and is worth agreeing rather than
assuming — say what you have in mind and it will almost certainly be fine.

## What is in scope

Anything in this repository, and particularly:

- **The audit log's integrity.** Entries are hash-chained, and the pages
  that read them parse recorded text back into labelled clauses. A way to
  make the log display a verdict nobody recorded — or to make a re-check
  appear to have compared something it did not — is a real finding, even
  though the log is "only" a display. Two such issues have been fixed this
  way already.
- **The token-authenticated re-check routes** (`/recheck/<token>/…`).
  These deliberately sit outside the login gate: the TAK Server has no
  session here. Anything a token holder can do beyond fetching that one
  script and posting a hash list is worth reporting.
- **Authentication and authorisation** — the `local` login and the
  `authentik` header trust mode, role separation between `admin` and
  `viewer`, session handling, CSRF.
- **Anything that reaches the database.** The export account is read-only
  by design; a path to a write, or to a table outside the documented grant
  list, is in scope.
- **The installers** (`setup.sh`, `connect-database.sh`), which run with
  `sudo` on a TAK Server host.
- **Cross-site scripting** on any page, including through a file dropped on
  Verify & Replay — filenames inside an uploaded zip are attacker-supplied.

## What is not a vulnerability here

Stated plainly so nobody spends time on them:

- **The audit log is tamper-evident, not tamper-proof.** It is a SQLite
  file beside the application; the chain makes an edit detectable, but
  someone with write access to that file can regenerate the chain. That is
  a known and documented property, not a defect. The answer to it is
  operational — keep a copy of the log somewhere the host's accounts cannot
  reach. Reports that assume filesystem or root access on the host are
  generally out of scope for the same reason.
- **The re-check confirms two files, not nineteen.** That is deliberate and
  explained in the package README under *WHAT THE RE-CHECK COMPARES*. A
  report that the other files "are not verified" is describing the design.
- **Denial of service.** Not a focus. This is a small internal tool behind
  a login, usually on a private network.
- **Missing hardening with no exploit path** — a header that could be
  stricter, a cookie flag on a non-session cookie. Welcome as an ordinary
  issue, just not through the private channel.
- **Anything about a deployment rather than the code** — an operator's
  reverse proxy, their TLS, their network exposure, their choice of
  database account. Those are the deploying agency's to get right.

## Supported versions

The newest release only. There are no long-term support branches; fixes go
into the next release rather than being backported.

## How this project already looks for these

Context, not a claim of sufficiency — every release goes through a security
review of the pending diff and `pip-audit` on both requirement files before
it is pushed, and the repository runs `pip-audit` weekly on a schedule.
Several real issues have come out of that process, and they are written up
in `CHANGELOG.md` with what was wrong rather than a vague "security fix".
It has still missed things, which is why this file exists.
