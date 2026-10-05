Screenshots embedded in the User Guide (/guide), served by app.py's
/guide/img/<name> route behind the same login as the guide.

Every image was generated from SYNTHETIC data - invented callsigns
(UNIT-1, UNIT-2), invented shape names, case ids CASE-0001/0002, made-up
requesters - placed at the app's default map view: rural Kansas, the
geographic centre of the US, a location unrelated to any real deployment.
The OpenStreetMap tiles visible there identify nothing. Nothing here comes
from a real export. Regenerate with tests/make_guide_screenshots.py against a
throwaway dev server if the pages change appearance.
