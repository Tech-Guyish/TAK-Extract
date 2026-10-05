# Third-Party Notices

TAK-Extract itself is licensed under [AGPL-3.0](LICENSE). It uses the
following third-party software, none of which requires anything different
from what's already true of this repository, with one exception noted below.

Checked directly against each project's own license file, not assumed from
memory, since getting this wrong is exactly the kind of thing worth getting
right before a public release.

## Python (installed via `pip install -r requirements.txt`, or `pip install gunicorn` for production)

| Package | License | Source |
|---|---|---|
| Flask | BSD-3-Clause | https://github.com/pallets/flask |
| psycopg2-binary | LGPL-3.0-or-later (+ OpenSSL linking exception) | https://github.com/psycopg/psycopg2 |
| python-dotenv | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| tzdata | Apache-2.0 | https://github.com/python/tzdata |
| gunicorn (Docker/production only - not in requirements.txt, see Dockerfile) | MIT | https://github.com/benoitc/gunicorn |

**psycopg2-binary is the one exception**: it's LGPL, not permissive like the
rest of this list. LGPL and AGPL are explicitly compatible (no conflict),
but LGPL does require a few things when the combined work is distributed:
this notice, a copy of its license terms, and confirmation it's used
unmodified with its source freely available (all satisfied above - it's an
ordinary, unmodified pip dependency). Anyone can still swap it for a
different version themselves; nothing here prevents that.

## JavaScript (loaded from unpkg.com at runtime, pinned by version + SRI hash - see the `integrity=` attributes in each template)

| Library | License used | Source |
|---|---|---|
| Leaflet | BSD-2-Clause | https://github.com/Leaflet/Leaflet |
| Leaflet.draw | MIT | https://github.com/Leaflet/Leaflet.draw |
| leaflet-control-geocoder | BSD-2-Clause | https://github.com/perliedman/leaflet-control-geocoder |
| JSZip | MIT (JSZip dual-licenses MIT/GPL-3.0; this project uses it under the MIT option) | https://github.com/Stuk/jszip |
| PapaParse | MIT | https://github.com/mholt/PapaParse |

Every one of the above is permissive (MIT/BSD) and imposes no restrictions
on how this project itself is licensed or distributed.
