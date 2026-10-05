"""Self-signed TLS support for TAK-Extract's optional SERVE_TLS mode (see
README.md and .env.example) - shared by gunicorn.conf.py (Docker and
bare-metal production) and app.py's own dev-server block (`python app.py`),
so every path uses byte-identical logic instead of duplicated copies that
could drift.

Off by default: without SERVE_TLS, this app is loopback-only everywhere
(a reverse proxy is expected to provide any real network exposure and its
own TLS - see docker-compose.yml/tak-extract.service). This module only
matters to someone who explicitly wants this app to terminate its own
HTTPS with no proxy in front of it.
"""
import ipaddress
import os
import socket
import subprocess


def running_in_container():
    """True inside a Docker container - Docker creates this file in every
    container it starts, a standard, reliable check."""
    return os.path.exists("/.dockerenv")


def detect_local_ip():
    """Best-effort real network-interface IP - never used for binding
    itself, only as a certificate SAN and for the printed login-URL
    message. A UDP "connect" to a public address sends no bytes; it just
    asks the OS routing table which interface it'd use, so this works
    offline. Falls back to 127.0.0.1 if even that fails. Deliberately not
    called at all from inside a container for anything address-sensitive
    (see app.py's bootstrap message) - it would report the container's
    own internal bridge IP, not the host's."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _restrict_key(key_path):
    """The private key, owner-only.

    `openssl req -keyout` writes it with the process umask - 0644 under
    both systemd's default and the container's - and it sits in the same
    data/ directory as the audit database, which was found world-readable
    on a real install. A readable private key lets anyone on the host
    impersonate this server's HTTPS to anyone who accepted its certificate.

    Applied to an EXISTING key as well as a freshly generated one, so an
    install created before this gets corrected on its next start rather
    than only on a re-run of the installer. Best-effort: a filesystem
    without POSIX modes must not stop TLS coming up.
    """
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass


def ensure_self_signed_cert(cert_path, key_path, common_name):
    """Generate a self-signed cert/key pair at these paths if neither
    already exists. Does nothing if a cert is already there, even an
    expired one - regenerating it silently would invalidate every
    browser's already-accepted security exception, forcing everyone to
    click through the warning again for no benefit. Replacing an expired
    cert is a deliberate operator action (delete the two files, restart),
    not something to do automatically out from under whoever already
    accepted the old one.

    RSA 4096 / SHA-256 / 10-year validity, matching infra-TAK's own
    self-signed cert generation exactly (checked directly against its
    source, not assumed) - this ecosystem's own established practice for
    exactly this kind of internal-tool cert. subjectAltName always covers
    127.0.0.1 and localhost (valid regardless of network setup) plus
    common_name itself - modern browsers require a SAN entry, not just
    the legacy CN field, to avoid an ADDITIONAL warning on top of the
    expected "self-signed" one. common_name is usually a bare IP (from
    detect_local_ip()), but openssl's -addext rejects anything under
    "IP:" that doesn't actually parse as one ("bad ip address") - checked
    with ipaddress.ip_address() so a future hostname/domain common_name
    is labeled "DNS:" instead rather than failing outright, and skipped
    entirely from the extra entry if it's already 127.0.0.1/localhost,
    avoiding a duplicate SAN value.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        _restrict_key(key_path)
        return
    parent = os.path.dirname(cert_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    sans = ["DNS:localhost", "IP:127.0.0.1"]
    if common_name not in ("127.0.0.1", "localhost"):
        try:
            ipaddress.ip_address(common_name)
            sans.append(f"IP:{common_name}")
        except ValueError:
            sans.append(f"DNS:{common_name}")
    subject_alt_names = "subjectAltName=" + ",".join(sans)
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256",
                "-days", "3650", "-nodes",
                "-keyout", key_path, "-out", cert_path,
                "-subj", f"/CN={common_name}",
                "-addext", subject_alt_names,
            ],
            check=True, capture_output=True, text=True,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "SERVE_TLS is on but 'openssl' isn't installed/on PATH - it's "
            "needed to generate the self-signed certificate. See the "
            "Dockerfile/README for how each install path provides it."
        )
    except subprocess.CalledProcessError as e:
        # CalledProcessError's own default message doesn't include the
        # captured stderr - without re-raising it explicitly, a real
        # openssl failure here (a bad common_name, a permissions issue on
        # the target directory) would surface as a bare "returned non-
        # zero exit status 1" with no hint of the actual reason.
        raise RuntimeError(
            f"self-signed certificate generation failed (exit {e.returncode}): "
            f"{e.stderr.strip()}"
        )
    _restrict_key(key_path)
