"""
E8 — webmail inline sender badge. verify_sender_simple() gives a header-free
verdict for a bare "Name <address>" sender (webmail DOMs expose no SPF/DKIM,
so it never claims "verified" — only that the domain genuinely belongs to the
claimed brand, or that it does not). POST /verify-sender exposes it to the
extension.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import pytest

email_analyzer = pytest.importorskip("email_analyzer")
main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402

from email_analyzer import verify_sender_simple  # noqa: E402


# ---------------------------------------------------------------------------
# verify_sender_simple
# ---------------------------------------------------------------------------

def test_brand_claim_with_official_domain_matches():
    r = verify_sender_simple("PayPal <service@paypal.com>")
    assert r["status"] == "brand_match"
    assert r["brand"] == "paypal"
    assert r["sender_domain"] == "paypal.com"
    assert "paypal" in r["detail"].lower()


def test_official_subdomain_matches_too():
    # live-verified pattern: banks send from subdomains of their official domains
    r = verify_sender_simple("ICICI Bank <alerts@custcomm.icici.bank.in>")
    assert r["status"] == "brand_match"
    assert r["brand"] == "icici"


def test_brand_claim_from_wrong_domain_is_impersonation():
    r = verify_sender_simple("PayPal Support <security@paypal-alerts.ru>")
    assert r["status"] == "impersonation"
    assert r["brand"] == "paypal"
    assert "paypal.com" in r["detail"]          # official domains named


def test_free_mail_claiming_a_bank_is_impersonation():
    r = verify_sender_simple("HDFC Bank <hdfc.care@gmail.com>")
    assert r["status"] == "impersonation"
    assert r["brand"] == "hdfc"


def test_no_brand_claim_means_no_badge():
    r = verify_sender_simple("Aunt Meena <meena@gmail.com>")
    assert r["status"] == "none"


def test_never_claims_verified_without_auth_headers():
    # the webmail badge has no SPF/DKIM/DMARC access — "verified" is reserved
    # for the full email analyzer
    r = verify_sender_simple("PayPal <service@paypal.com>")
    assert r["status"] != "verified"
    assert "verified" not in r["detail"].lower()


def test_junk_input_is_safe():
    assert verify_sender_simple("")["status"] == "none"
    assert verify_sender_simple(None)["status"] == "none"
    assert verify_sender_simple("no angle brackets or at sign")["status"] == "none"


# ---------------------------------------------------------------------------
# POST /verify-sender
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    with TestClient(main.app) as c:
        yield c


def test_endpoint_impersonation(client):
    data = client.post("/verify-sender",
                       json={"sender": "Amazon <deals@amazon-offers.top>"}).json()
    assert data["status"] == "impersonation"
    assert data["brand"] == "amazon"


def test_endpoint_brand_match(client):
    data = client.post("/verify-sender",
                       json={"sender": "GitHub <noreply@github.com>"}).json()
    assert data["status"] == "brand_match"


def test_endpoint_no_claim(client):
    data = client.post("/verify-sender", json={"sender": "Bob <bob@example.com>"}).json()
    assert data["status"] == "none"
