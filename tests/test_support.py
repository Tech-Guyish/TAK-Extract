"""Helpers imported by the subprocess snippets in test_auth.py (run()
prepends `from test_support import login` to every snippet, so tests
never spell the import out themselves)."""


def login(client, data, **kwargs):
    """POST /login the way a browser does: GET the form first so the
    session holds a CSRF token, then submit it with the form. The login
    form carries a token (login CSRF: without one, a hostile page could
    log a victim's browser into an account the attacker controls, so the
    victim's later exports are audited under the attacker's name).
    Extra keyword arguments (follow_redirects=...) pass straight through
    to the test client."""
    import re
    page = client.get("/login").data.decode()
    m = re.search(r'name="csrf_token" value="([^"]+)"', page)
    payload = dict(data)
    if m:
        payload["csrf_token"] = m.group(1)
    return client.post("/login", data=payload, **kwargs)


def logout(client):
    """POST /logout with the session's CSRF token, the way the header's
    Log out form does (a GET is a 405 now)."""
    with client.session_transaction() as sess:
        token = sess.get("csrf_token") or ""
    return client.post("/logout", data={"csrf_token": token})
