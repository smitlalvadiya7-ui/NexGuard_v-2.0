"""
SSRF guard for outbound fetches (OWASP A10).

Public surface
--------------
  validate_url(url) -> url        # raises BlockedURLError if unsafe to fetch
  safe_get(url, **kw) -> Response # requests.get, every redirect hop re-checked

The scanner's core feature is "fetch a URL the user handed us", so every
outbound GET is an SSRF primitive unless the destination is checked first.
This module refuses a URL when:

  * the scheme is not http/https, or the port is not 80/443, or
  * ANY address the hostname resolves to is inside our trust boundary —
    loopback (127/8, ::1), RFC-1918 private, link-local (169.254.0.0/16, which
    is where the AWS/GCP/Azure metadata endpoint lives), reserved, multicast,
    or unspecified.

Checking once is not enough: a perfectly public hostname can answer with a 302
to http://169.254.169.254/, and DNS can be re-pointed between the check and the
connect. So safe_get() turns automatic redirect following OFF and walks the
chain itself, re-validating each hop.

This is a deny-on-error guard, not a fail-open one: a hostname that will not
resolve is refused rather than attempted. Callers (apis/page_content.py) already
wrap fetches in try/except and fall back to their null result, so a blocked URL
degrades a scan to "no page content" instead of raising into the scan path.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWED_PORTS = {80, 443}
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Redirect statuses we follow manually (307/308 preserve method; we only GET).
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5


class BlockedURLError(Exception):
    """The URL is not safe for the server to fetch."""


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------

def _resolve_ips(host: str) -> list[str]:
    """Every address `host` resolves to (A + AAAA). Raises if it cannot resolve."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise BlockedURLError(f"Hostname '{host}' could not be resolved") from exc
    return [info[4][0] for info in infos]


def _is_internal(ip_text: str) -> bool:
    """True if the address belongs to a range the server must never be aimed at."""
    try:
        # getaddrinfo can hand back a scoped v6 literal ('fe80::1%eth0').
        ip = ipaddress.ip_address(ip_text.split("%", 1)[0])
    except ValueError:
        return True  # unparseable -> treat as hostile, never as public

    # ::ffff:127.0.0.1 is loopback wearing a v6 costume; unwrap before judging.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped

    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _addresses_for(host: str) -> list[str]:
    """Addresses to judge: an IP literal is itself; a name goes through DNS."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        return _resolve_ips(host)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def validate_url(url: str) -> str:
    """Return `url` unchanged if it is safe to fetch, else raise BlockedURLError."""
    parsed = urlparse(url or "")

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise BlockedURLError(f"Scheme '{scheme or "(none)"}' is not fetchable")

    host = parsed.hostname  # already lowercased, IPv6 brackets stripped
    if not host:
        raise BlockedURLError("URL has no hostname")

    try:
        port = parsed.port or _DEFAULT_PORTS[scheme]
    except ValueError as exc:  # malformed port, e.g. http://h:notaport/
        raise BlockedURLError("URL has an invalid port") from exc
    if port not in _ALLOWED_PORTS:
        raise BlockedURLError(f"Port {port} is not allowed (only 80/443)")

    for ip_text in _addresses_for(host):
        if _is_internal(ip_text):
            raise BlockedURLError(
                f"Host '{host}' resolves to internal address {ip_text}"
            )

    return url


def safe_get(url: str, **kwargs) -> requests.Response:
    """
    requests.get() with the SSRF check applied to the initial URL and to every
    redirect hop. Automatic redirects are disabled so no hop escapes the check.
    Keyword arguments (headers, timeout, stream, ...) pass straight through.
    """
    kwargs["allow_redirects"] = False
    current = url

    for _ in range(_MAX_REDIRECTS + 1):
        validate_url(current)
        resp = requests.get(current, **kwargs)

        location = resp.headers.get("Location")
        if resp.status_code in _REDIRECT_CODES and location:
            resp.close()
            current = urljoin(current, location)
            continue
        return resp

    raise BlockedURLError(f"More than {_MAX_REDIRECTS} redirects from '{url}'")
