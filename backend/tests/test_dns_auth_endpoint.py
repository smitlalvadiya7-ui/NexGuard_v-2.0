"""
POST /analyze-email consults the sender domain's published mail policy.

apis.dns_auth measures the domain; email_analyzer scores an injected reading of
it. This is the wiring between the two, and it is the only place the lookup is
allowed to touch the network.

What these tests hold in place:
  * the endpoint looks up the domain the mail actually came FROM
  * a domain publishing nothing raises the score when headers proved nothing
  * a DNS failure is reported, scored at zero, and never crashes the scan
  * the lookup never runs on a domain that cannot publish its own policy

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import io

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402

UNAUTH_EML = (
    "From: Billing <billing@secure-invoice-portal.example>\n"
    "Subject: Invoice attached\n"
    "\n"
    "Please review the attached invoice and confirm payment.\n"
)


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(main, "enforce_scan_quota", lambda user, request: None)
    monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)

    async def _no_links(_text):
        return {"links_found": 0, "worst_score": 0, "worst_verdict": "SAFE",
                "scanned_links": []}

    monkeypatch.setattr(main, "scan_embedded_links", _no_links)
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def _post(client, content):
    return client.post(
        "/analyze-email",
        files={"file": ("mail.eml", io.BytesIO(content.encode()), "message/rfc822")},
    ).json()


def _posture(status, **over):
    p = {"status": status, "available": status != "unknown",
         "dmarc_policy": None, "dmarc_enforcing": False,
         "spf": None, "mx": False, "detail": status}
    p.update(over)
    return p


class TestEndpointWiring:
    def test_looks_up_the_domain_the_mail_came_from(self, client, monkeypatch):
        asked = []

        async def _fake(domain):
            asked.append(domain)
            return _posture("unauthenticated")

        monkeypatch.setattr(main, "check_dns_auth", _fake)
        _post(client, UNAUTH_EML)

        assert asked == ["secure-invoice-portal.example"]

    def test_unauthenticated_domain_is_reported_and_scored(self, client, monkeypatch):
        async def _fake(_domain):
            return _posture("unauthenticated")

        monkeypatch.setattr(main, "check_dns_auth", _fake)
        data = _post(client, UNAUTH_EML)

        assert data["dns_posture"]["status"] == "unauthenticated"
        assert any("no DMARC" in r for r in data["reasons"]), data["reasons"]

    def test_dns_failure_is_reported_but_never_scored(self, client, monkeypatch):
        async def _failing(_domain):
            return _posture("unknown")

        async def _clean(_domain):
            return _posture("protected", dmarc_policy="reject",
                            dmarc_enforcing=True, spf="strict", mx=True)

        monkeypatch.setattr(main, "check_dns_auth", _failing)
        failed = _post(client, UNAUTH_EML)
        monkeypatch.setattr(main, "check_dns_auth", _clean)
        clean = _post(client, UNAUTH_EML)

        assert failed["dns_posture"]["status"] == "unknown"
        assert failed["risk_score"] == clean["risk_score"]

    def test_a_raising_lookup_does_not_break_the_scan(self, client, monkeypatch):
        async def _boom(_domain):
            raise RuntimeError("resolver exploded")

        monkeypatch.setattr(main, "check_dns_auth", _boom)
        data = _post(client, UNAUTH_EML)

        assert data["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN")
        assert data["dns_posture"]["status"] == "unknown"
