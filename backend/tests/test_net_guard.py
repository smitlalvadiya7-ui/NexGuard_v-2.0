"""
A10 (SSRF) — outbound-fetch guard.

The scanner's whole job is "fetch a URL the user gave us", which is textbook
SSRF unless the destination is checked. apis/net_guard resolves the hostname
BEFORE connecting and refuses anything that lands inside our own trust
boundary: loopback, RFC-1918 private, link-local (169.254.169.254 — the cloud
metadata endpoint), reserved, and multicast. Scheme is restricted to
http/https and the port to 80/443.

Redirects are the other half: a public hostname can 302 straight to
169.254.169.254, so safe_get() disables automatic redirects and re-validates
every hop itself.

DNS is patched in these tests so they stay offline and deterministic — the
only thing under test is the decision, not the network.
"""

import pytest

from apis import net_guard
from apis.net_guard import BlockedURLError, safe_get, validate_url


def patch_dns(monkeypatch, mapping):
    """Point _resolve_ips at a fixed hostname -> [ip] map (no real DNS)."""
    def fake(host):
        if host not in mapping:
            raise BlockedURLError(f"DNS failure for {host}")
        return mapping[host]
    monkeypatch.setattr(net_guard, "_resolve_ips", fake)


# ---------------------------------------------------------------------------
# Internal address ranges are refused
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:80/admin",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.5/",
        "http://[::1]/",
        "http://224.0.0.1/",          # multicast
        "http://0.0.0.0/",            # reserved / unspecified
    ],
)
def test_internal_ip_literals_are_blocked(url):
    with pytest.raises(BlockedURLError):
        validate_url(url)


def test_localhost_hostname_is_blocked(monkeypatch):
    patch_dns(monkeypatch, {"localhost": ["127.0.0.1"]})
    with pytest.raises(BlockedURLError):
        validate_url("http://localhost:80/")


def test_public_hostname_resolving_to_private_ip_is_blocked(monkeypatch):
    """DNS-rebinding style: innocuous name, internal answer."""
    patch_dns(monkeypatch, {"evil.example": ["10.1.2.3"]})
    with pytest.raises(BlockedURLError):
        validate_url("http://evil.example/")


def test_mixed_answer_with_one_internal_ip_is_blocked(monkeypatch):
    """If ANY resolved address is internal, refuse — not just the first."""
    patch_dns(monkeypatch, {"sneaky.example": ["93.184.216.34", "127.0.0.1"]})
    with pytest.raises(BlockedURLError):
        validate_url("http://sneaky.example/")


# ---------------------------------------------------------------------------
# Scheme / port restrictions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "ftp://example.com/x", "gopher://example.com/",
     "dict://example.com:11211/"],
)
def test_non_http_schemes_are_blocked(url):
    with pytest.raises(BlockedURLError):
        validate_url(url)


def test_non_standard_port_is_blocked(monkeypatch):
    patch_dns(monkeypatch, {"example.com": ["93.184.216.34"]})
    with pytest.raises(BlockedURLError):
        validate_url("http://example.com:8000/")


# ---------------------------------------------------------------------------
# A normal public URL still passes
# ---------------------------------------------------------------------------

def test_public_url_is_allowed(monkeypatch):
    patch_dns(monkeypatch, {"example.com": ["93.184.216.34"]})
    assert validate_url("http://example.com/login") == "http://example.com/login"


def test_public_https_default_port_is_allowed(monkeypatch):
    patch_dns(monkeypatch, {"example.com": ["93.184.216.34"]})
    assert validate_url("https://example.com/") == "https://example.com/"


def test_explicit_port_443_is_allowed(monkeypatch):
    patch_dns(monkeypatch, {"example.com": ["93.184.216.34"]})
    assert validate_url("https://example.com:443/x") == "https://example.com:443/x"


# ---------------------------------------------------------------------------
# safe_get() re-validates every redirect hop
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code=200, location=None):
        self.status_code = status_code
        self.headers = {"Location": location} if location else {}
        self.closed = False

    def close(self):
        self.closed = True


def test_safe_get_follows_and_revalidates_a_public_redirect(monkeypatch):
    patch_dns(monkeypatch, {"a.example": ["93.184.216.34"],
                            "b.example": ["93.184.216.35"]})
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        assert kw.get("allow_redirects") is False  # we follow them ourselves
        if url == "http://a.example/":
            return FakeResponse(302, "http://b.example/next")
        return FakeResponse(200)

    monkeypatch.setattr(net_guard.requests, "get", fake_get)
    resp = safe_get("http://a.example/")

    assert resp.status_code == 200
    assert seen == ["http://a.example/", "http://b.example/next"]


def test_safe_get_blocks_a_redirect_into_the_metadata_endpoint(monkeypatch):
    """The attack the one-shot check misses: public host 302s to 169.254.169.254."""
    patch_dns(monkeypatch, {"a.example": ["93.184.216.34"]})
    hops = []

    def fake_get(url, **kw):
        hops.append(url)
        return FakeResponse(302, "http://169.254.169.254/latest/meta-data/")

    monkeypatch.setattr(net_guard.requests, "get", fake_get)

    with pytest.raises(BlockedURLError):
        safe_get("http://a.example/")

    # The first hop was fetched; the metadata hop was never requested.
    assert hops == ["http://a.example/"]


def test_safe_get_stops_after_the_redirect_cap(monkeypatch):
    patch_dns(monkeypatch, {"loop.example": ["93.184.216.34"]})

    def fake_get(url, **kw):
        return FakeResponse(302, "http://loop.example/again")

    monkeypatch.setattr(net_guard.requests, "get", fake_get)

    with pytest.raises(BlockedURLError):
        safe_get("http://loop.example/")


# ---------------------------------------------------------------------------
# The guard is actually wired into the page fetcher (apis/page_content.py)
# ---------------------------------------------------------------------------

def record_requests(monkeypatch):
    """Replace requests.get everywhere with a recorder; return the call log.

    Deliberately does NOT raise on call: analyze_page_content swallows every
    exception into its null fallback, so a raising fake would make the test
    pass for the wrong reason.
    """
    calls = []

    def fake_get(url, **kw):
        calls.append(url)
        return FakeResponse(200)

    monkeypatch.setattr(net_guard.requests, "get", fake_get)
    return calls


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:80/",
        "http://10.0.0.1/",
    ],
)
def test_page_fetch_never_reaches_an_internal_url(monkeypatch, url):
    from apis import page_content

    calls = record_requests(monkeypatch)
    out = page_content.analyze_page_content(url)

    assert calls == [], f"outbound fetch was attempted for {url}"
    assert out["fetched"] is False
    assert out["content_risk"] == 0


def test_page_fetch_never_reaches_localhost(monkeypatch):
    from apis import page_content

    patch_dns(monkeypatch, {"localhost": ["127.0.0.1"]})
    calls = record_requests(monkeypatch)
    out = page_content.analyze_page_content("http://localhost/admin")

    assert calls == []
    assert out["fetched"] is False


def test_page_fetch_still_works_for_a_public_url(monkeypatch):
    """The guard must not break normal scanning."""
    from apis import page_content

    patch_dns(monkeypatch, {"shop.example": ["93.184.216.34"]})

    class HtmlResponse(FakeResponse):
        def __init__(self):
            super().__init__(200)
            self.headers = {"Content-Type": "text/html; charset=utf-8"}
            self.encoding = "utf-8"
            self.raw = self

        def read(self, *a, **kw):
            return b"<html><title>Shop</title><body><h1>Hi</h1></body></html>"

    monkeypatch.setattr(net_guard.requests, "get", lambda url, **kw: HtmlResponse())
    out = page_content.analyze_page_content("http://shop.example/")

    assert out["fetched"] is True


def test_favicon_fetch_is_guarded(monkeypatch):
    """The favicon URL comes from page HTML — an attacker controls it too."""
    from bs4 import BeautifulSoup

    from apis import page_content

    calls = record_requests(monkeypatch)
    soup = BeautifulSoup(
        '<link rel="icon" href="http://169.254.169.254/latest/meta-data/">',
        "html.parser",
    )
    assert page_content._favicon_hash("http://shop.example/", soup) is None
    assert calls == []
