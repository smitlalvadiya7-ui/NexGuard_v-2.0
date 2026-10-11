"""Make `backend/` importable so tests can `import aggregator` directly,
matching how the app itself runs (uvicorn main:app from backend/)."""

import os
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# auth.py refuses to import without JWT_SECRET unless debug is on (A02: the old
# random per-process fallback broke multi-worker deploys silently). The suite
# must not depend on a developer's .env, so it declares itself a debug run.
# test_auth_hardening.py checks the production behaviour in a subprocess.
os.environ.setdefault("NEXGUARD_DEBUG", "1")

# The community blocklist pulls ~74 MB of live feeds and main.py warms it at
# import time. Tests must stay hermetic and offline, so the suite runs with the
# kill switch on; test_phish_feeds.py clears it per-test and stubs requests.get.
os.environ.setdefault("NEXGUARD_DISABLE_FEEDS", "1")

# The quota limiter paces real API calls against their published rate limits
# (apis/quota.py). Left on, it paced the SUITE too: run time went from 70
# seconds to 17 minutes 45, which destroys the feedback loop that makes
# test-first work at all. Tests must never wait on a rate limiter they are not
# testing — test_quota.py sets its own limits explicitly and is unaffected.
os.environ.setdefault("NEXGUARD_QUOTA_VIRUSTOTAL_WAIT", "0")
os.environ.setdefault("NEXGUARD_QUOTA_WEB_RISK_WAIT", "0")
os.environ.setdefault("NEXGUARD_QUOTA_SAFE_BROWSING_WAIT", "0")
os.environ.setdefault("NEXGUARD_QUOTA_URLSCAN_WAIT", "0")
os.environ.setdefault("NEXGUARD_QUOTA_URLHAUS_WAIT", "0")


@pytest.fixture(scope="session")
def tls_server(tmp_path_factory):
    """
    A real TLS listener on localhost with a self-signed certificate.

    Exists so certificate-reading code can be tested against an actual
    handshake instead of a mock — the bug it was written for (getpeercert()
    returning {} under CERT_NONE) is invisible to any mock of getpeercert.
    """
    import http.server
    import socket
    import ssl
    import threading
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NexGuard Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    d = tmp_path_factory.mktemp("tls")
    cert_file, key_file = d / "cert.pem", d / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)

    class Quiet(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html>ok</html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Quiet)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "localhost", srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
