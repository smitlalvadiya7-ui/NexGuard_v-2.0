"""
Safe Browsing must reuse one HTTPS session, not build a new one per lookup.

Measured 2026-10-09 on the 200-URL test pack, laptop on battery: 0 SAFE,
136 UNKNOWN. Every lookup went through requests.post(), which opens a fresh
Session, so every lookup built a new SSL context and loaded the certifi CA
bundle — 0.24 s of CPU on its own (OpenSSL 3.0), about 6 s with 20 in
parallel because the loads contend on OpenSSL's locks. A batch runs 8 scans
at once, so Safe Browsing missed full_scan's 2.2 s budget, counted as
"unavailable", and every SAFE became UNKNOWN. A single scan was unaffected.

With one shared Session the same 48 URLs read 48 SAFE in 26 s; without it,
14 SAFE / 34 UNKNOWN in 69 s.
"""

import asyncio

import pytest
import requests

from apis import circuit_breaker as cb
from apis import quota


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    quota.reset()
    cb.reset_all()
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
    from deployment_profile import profile
    profile.cache_clear()
    yield
    quota.reset()
    cb.reset_all()
    profile.cache_clear()


class _Resp:
    status_code = 200

    def json(self):
        return {}

    def raise_for_status(self):
        pass


def test_lookups_share_one_session(monkeypatch):
    from apis import safe_browsing

    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "a-real-looking-key")
    monkeypatch.setattr(safe_browsing, "cache_get", lambda k: None)
    monkeypatch.setattr(safe_browsing, "cache_put", lambda k, v, ttl=None: None)

    sessions = []

    def fake_request(self, method, url, **kw):
        # Keep the object itself, not id(self): a freed Session's address can
        # be handed to the next one, which would make three sessions look
        # like one.
        sessions.append(self)
        return _Resp()

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)

    for i in range(3):
        res = asyncio.run(safe_browsing.check_safe_browsing(f"https://site{i}.example/"))
        assert res == {"status": "clean", "detail": "not listed"}

    assert len(sessions) == 3
    assert len({id(s) for s in sessions}) == 1, "each lookup opened its own HTTPS session"
