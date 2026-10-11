"""
SSL/TLS certificate enrichment for the URL scanner.

Reads the certificate the server presents on the live TLS connection (a single
short handshake to :443) and extracts forensic signals:

  * issuer organisation (the CA)               e.g. "Let's Encrypt"
  * whether the issuer is a FREE / automated CA (Let's Encrypt, ZeroSSL,
    Google Trust Services, Buypass, Actalis free, …) — by itself benign (most
    of the web uses them) but a strong corroborator when paired with a brand-new
    domain that impersonates a brand (classic phishing kit footprint),
  * certificate AGE — days since `notBefore`. A cert minted hours ago on a
    brand-impersonating domain is a phishing tell,
  * validity window + subject CN / SAN count.

Public surface
--------------
  async check_ssl_cert(domain) -> {
      "has_cert":        bool,
      "issuer":          str | None,   # CA organisation / common name
      "is_free_ca":      bool,
      "issued":          str | None,   # ISO date (notBefore)
      "expires":         str | None,   # ISO date (notAfter)
      "cert_age_days":   int | None,
      "days_to_expiry":  int | None,
      "san_count":       int | None,
      "subject_cn":      str | None,
      "detail":          str,          # human-readable summary
  }

Everything fails NEUTRAL: no HTTPS, handshake error, timeout, or an unverifiable
cert all return the null fallback with has_cert=False. The work runs in a worker
thread (asyncio.to_thread) under the per-source circuit breaker.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from apis.url_cache import cache_get, cache_put
from apis.circuit_breaker import guarded, SourceUnavailable

# Parse the DER cert directly with cryptography — getpeercert() returns {} under
# CERT_NONE, and we want to read whatever the server presents (incl. self-signed
# / expired, which are themselves signals). Import-guarded: fall back to the
# stdlib parsed dict (verified connections only) if cryptography is absent.
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

_KEY = "tls:"
_TIMEOUT = 4.0

_FALLBACK = {
    "has_cert": False,
    "issuer": None,
    "is_free_ca": False,
    "issued": None,
    "expires": None,
    "cert_age_days": None,
    "days_to_expiry": None,
    "san_count": None,
    "subject_cn": None,
    "detail": "unavailable",
}

# Free / fully-automated certificate authorities. Matched as a substring against
# the issuer organisation or common name (case-insensitive).
_FREE_CA_MARKERS = (
    "let's encrypt", "lets encrypt", "zerossl", "google trust services",
    "buypass go", "actalis free", "sslforfree", "cpanel, inc", "gts ca",
    "encryption everywhere",
)

# RFC 5280 cert time format, e.g. "Jun  1 12:00:00 2026 GMT"
_CERT_TIME_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_cert_time(value: str):
    try:
        dt = datetime.strptime(value, _CERT_TIME_FMT)
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _name_field(name_tuples, key: str):
    """Pull a field (e.g. 'organizationName', 'commonName') from a getpeercert() name."""
    try:
        for rdn in name_tuples:
            for k, v in rdn:
                if k == key:
                    return v
    except Exception:
        pass
    return None


def _parse_der(der: bytes):
    """Parse a DER cert with cryptography. Returns (issuer, cn, notBefore,
    notAfter, san_count) or None. Works for any cert (verified or not)."""
    try:
        cert = x509.load_der_x509_certificate(der)

        def _attr(name, oid):
            try:
                vals = name.get_attributes_for_oid(oid)
                return vals[0].value if vals else None
            except Exception:
                return None

        issuer = (_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
                  or _attr(cert.issuer, NameOID.COMMON_NAME))
        subject_cn = _attr(cert.subject, NameOID.COMMON_NAME)

        # Prefer the timezone-aware accessors (cryptography >= 42); fall back.
        try:
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
        except AttributeError:  # pragma: no cover
            nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
            na = cert.not_valid_after.replace(tzinfo=timezone.utc)

        san_count = None
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_count = len(ext.value.get_values_for_type(x509.DNSName))
        except Exception:
            san_count = None

        return issuer, subject_cn, nb, na, (san_count or None)
    except Exception:
        return None


def _parse_stdlib(cert):
    """Fallback parser using the stdlib getpeercert() dict (verified conns only)."""
    if not cert:
        return None
    issuer = (_name_field(cert.get("issuer", ()), "organizationName")
              or _name_field(cert.get("issuer", ()), "commonName"))
    subject_cn = _name_field(cert.get("subject", ()), "commonName")
    nb = _parse_cert_time(cert.get("notBefore", ""))
    na = _parse_cert_time(cert.get("notAfter", ""))
    san_count = len([x for x in cert.get("subjectAltName", ()) if x and x[0] == "DNS"])
    return issuer, subject_cn, nb, na, (san_count or None)


def _ssl_sync(domain: str, port: int = 443) -> dict:
    """
    Certificate facts for a host. `port` defaults to 443 but is a real
    parameter: phishing kits are regularly served from non-standard https
    ports (:8443, :2053), and the corpus collector needs to read those certs
    too. The cache key carries the port so two ports on one host cannot
    collide.
    """
    if not domain:
        return _FALLBACK.copy()

    _cache_key = _KEY + domain + (f":{port}" if port != 443 else "")
    cached = cache_get(_cache_key)
    if cached is not None:
        return cached

    def _call() -> dict:
        ctx = ssl.create_default_context()
        # We want to READ whatever cert the server presents, even if it would
        # fail strict verification (self-signed / expired are themselves signals).
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, port), timeout=_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    parsed = ssock.getpeercert()  # populated only if verified
        except (socket.timeout, TimeoutError) as exc:
            raise SourceUnavailable(f"TLS timeout: {exc}")
        except (socket.gaierror, ConnectionRefusedError, OSError):
            # Host has no reachable :443 — definitive "no cert", not a breaker fault.
            return _FALLBACK.copy()

        info = _parse_der(der) if (der and _HAVE_CRYPTO) else _parse_stdlib(parsed)
        if info is None:
            result = dict(_FALLBACK, has_cert=True, detail="cert present (unparseable)")
            cache_put(_cache_key, result)
            return result

        issuer, subject_cn, nb, na, san_count = info
        issuer_blob = (issuer or "").lower()
        is_free_ca = any(m in issuer_blob for m in _FREE_CA_MARKERS)

        now = datetime.now(timezone.utc)
        cert_age_days = (now - nb).days if nb else None
        days_to_expiry = (na - now).days if na else None

        bits = []
        if issuer:
            bits.append(f"issued by {issuer}")
        if cert_age_days is not None:
            bits.append(f"cert age {cert_age_days}d")
        if is_free_ca:
            bits.append("free/automated CA")
        detail = ", ".join(bits) or "cert present"

        result = {
            "has_cert": True,
            "issuer": issuer,
            "is_free_ca": is_free_ca,
            "issued": nb.date().isoformat() if nb else None,
            "expires": na.date().isoformat() if na else None,
            "cert_age_days": cert_age_days,
            "days_to_expiry": days_to_expiry,
            "san_count": san_count or None,
            "subject_cn": subject_cn,
            "detail": detail,
        }
        cache_put(_cache_key, result)
        return result

    return guarded("tls_cert", _call, fallback=_FALLBACK.copy())


async def check_ssl_cert(domain: str, port: int = 443) -> dict:
    """Non-blocking entry point — TLS certificate inspection for a domain."""
    return await asyncio.to_thread(_ssl_sync, domain, port)


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.ssl_cert <domain>)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    print(json.dumps(asyncio.run(check_ssl_cert(target)), indent=2))
