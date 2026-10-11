"""
Sender-domain DNS posture: does the domain publish mail authentication at all?

email_analyzer already reads SPF/DKIM/DMARC, but only from the
Authentication-Results header a receiving server wrote. Its own comment records
the hole (email_analyzer.py:148): a webmail DOM exposes "Name <address>" and
nothing else, so a screenshot or OCR scan arrives with no authentication
evidence whatsoever.

Asking DNS needs no header, only the sender's domain. Measured on
eval/_corpus_m4.json (2026-09-08): 7.8% of attacker-registered phishing domains
publish DMARC against 70.1% of legitimate ones — a 62-point gap.

The contract these tests pin down:

  * a published, ENFORCING policy is evidence FOR the sender
  * nothing published is evidence AGAINST it
  * a FAILED lookup is neither, and must never be scored as "nothing
    published" — that is the reject-option principle the whole project rests
    on, and it is the one thing a network blip would otherwise silently break
"""

import pytest

from apis import dns_auth


@pytest.fixture(autouse=True)
def _no_cache(monkeypatch):
    """Every test drives the resolver directly, never a previous test's cache."""
    monkeypatch.setattr(dns_auth, "cache_get", lambda k: None)
    monkeypatch.setattr(dns_auth, "cache_put", lambda k, v, ttl=None: None)


def _resolver(answers):
    """Fake DNS-over-HTTPS. `answers` maps (name, type) -> list of strings,
    or to the string 'FAIL' to simulate the resolver being unreachable."""

    class _Resp:
        def __init__(self, payload, status=200):
            self._payload = payload
            self.status_code = status

        def json(self):
            return self._payload

    def _get(url, params=None, **kw):
        key = (params["name"], params["type"])
        val = answers.get(key, [])
        if val == "FAIL":
            return _Resp({}, status=503)
        return _Resp({"Status": 0,
                      "Answer": [{"data": '"%s"' % v} for v in val]})

    return _get


# ---------------------------------------------------------------------------
# What the resolver says, turned into a posture
# ---------------------------------------------------------------------------

class TestPosture:
    def test_enforcing_dmarc_is_protected(self, monkeypatch):
        monkeypatch.setattr(dns_auth.requests, "get", _resolver({
            ("_dmarc.hsbc.co.uk", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@b.c"],
            ("hsbc.co.uk", "TXT"): ["v=spf1 include:_spf.example.com -all"],
            ("hsbc.co.uk", "MX"): ["10 mx.hsbc.co.uk."],
        }))
        r = dns_auth.dns_posture_sync("hsbc.co.uk")

        assert r["available"] is True
        assert r["dmarc_policy"] == "reject"
        assert r["dmarc_enforcing"] is True
        assert r["spf"] == "strict"
        assert r["mx"] is True
        assert r["status"] == "protected"

    def test_nothing_published_is_unauthenticated(self, monkeypatch):
        monkeypatch.setattr(dns_auth.requests, "get", _resolver({}))
        r = dns_auth.dns_posture_sync("secure-login-verify.tk")

        assert r["available"] is True
        assert r["dmarc_policy"] is None
        assert r["spf"] is None
        assert r["mx"] is False
        assert r["status"] == "unauthenticated"

    def test_dmarc_p_none_is_published_but_not_enforcing(self, monkeypatch):
        monkeypatch.setattr(dns_auth.requests, "get", _resolver({
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
            ("example.com", "TXT"): ["v=spf1 ~all"],
            ("example.com", "MX"): ["10 mail.example.com."],
        }))
        r = dns_auth.dns_posture_sync("example.com")

        assert r["dmarc_policy"] == "none"
        assert r["dmarc_enforcing"] is False
        assert r["spf"] == "soft"
        assert r["status"] == "partial"

    def test_spf_only_is_partial_not_protected(self, monkeypatch):
        monkeypatch.setattr(dns_auth.requests, "get", _resolver({
            ("small-shop.co", "TXT"): ["v=spf1 include:zoho.com -all"],
            ("small-shop.co", "MX"): ["10 mx.zoho.com."],
        }))
        r = dns_auth.dns_posture_sync("small-shop.co")

        assert r["dmarc_policy"] is None
        assert r["spf"] == "strict"
        assert r["status"] == "partial"


# ---------------------------------------------------------------------------
# The reject option: absent evidence is not evidence of absence
# ---------------------------------------------------------------------------

class TestFailedLookupIsNotAVerdict:
    def test_resolver_failure_is_unknown_never_unauthenticated(self, monkeypatch):
        monkeypatch.setattr(dns_auth.requests, "get", _resolver({
            ("_dmarc.hsbc.co.uk", "TXT"): "FAIL",
            ("hsbc.co.uk", "TXT"): "FAIL",
            ("hsbc.co.uk", "MX"): "FAIL",
        }))
        r = dns_auth.dns_posture_sync("hsbc.co.uk")

        assert r["available"] is False
        assert r["status"] == "unknown"
        assert r["status"] != "unauthenticated"

    def test_partial_failure_does_not_claim_nothing_published(self, monkeypatch):
        # DMARC answered "none published", but the SPF and MX lookups broke.
        # We cannot say the domain publishes nothing when we only asked once.
        monkeypatch.setattr(dns_auth.requests, "get", _resolver({
            ("_dmarc.x.com", "TXT"): [],
            ("x.com", "TXT"): "FAIL",
            ("x.com", "MX"): "FAIL",
        }))
        r = dns_auth.dns_posture_sync("x.com")

        assert r["available"] is False
        assert r["status"] == "unknown"

    def test_unknown_posture_contributes_no_risk(self):
        assert dns_auth.posture_risk({"status": "unknown", "available": False}) == 0

    def test_unauthenticated_posture_contributes_risk(self):
        assert dns_auth.posture_risk({"status": "unauthenticated", "available": True}) > 0

    def test_protected_posture_contributes_no_risk(self):
        assert dns_auth.posture_risk({"status": "protected", "available": True}) == 0


# ---------------------------------------------------------------------------
# Hosts that cannot publish their own policy
# ---------------------------------------------------------------------------

class TestSharedHosting:
    def test_tenant_is_not_judged_on_its_platforms_records(self, monkeypatch):
        # alice.blogspot.com cannot publish DMARC; only blogspot.com can.
        # Scoring the tenant as "unauthenticated" would invent a signal.
        monkeypatch.setattr(dns_auth.requests, "get", _resolver({}))
        r = dns_auth.dns_posture_sync("alice.blogspot.com")

        assert r["status"] == "not_applicable"
        assert dns_auth.posture_risk(r) == 0

    def test_empty_domain_is_not_applicable(self):
        r = dns_auth.dns_posture_sync("")
        assert r["status"] == "not_applicable"


# ---------------------------------------------------------------------------
# Integration: analyze_email consumes an injected posture
# ---------------------------------------------------------------------------

from email_analyzer import analyze_email  # noqa: E402

SILENT_HEADERS = {"spf": "none", "dkim": "none", "dmarc": "none"}
PASSING_HEADERS = {"spf": "pass", "dkim": "pass", "dmarc": "pass"}

UNAUTHENTICATED = {"status": "unauthenticated", "available": True,
                   "dmarc_policy": None, "dmarc_enforcing": False,
                   "spf": None, "mx": False, "detail": "publishes nothing"}
UNKNOWN_POSTURE = {"status": "unknown", "available": False,
                   "dmarc_policy": None, "dmarc_enforcing": False,
                   "spf": None, "mx": False, "detail": "DNS did not answer"}
PROTECTED = {"status": "protected", "available": True,
             "dmarc_policy": "reject", "dmarc_enforcing": True,
             "spf": "strict", "mx": True, "detail": "p=reject"}

EMAIL = ("From: Billing <billing@secure-invoice-portal.tk>\n"
         "Subject: Invoice attached\n\nPlease see the attached invoice.\n")


class TestAnalyzeEmailUsesPosture:
    def test_posture_is_reported_in_the_result(self):
        r = analyze_email(EMAIL, auth_results=SILENT_HEADERS,
                          dns_posture=UNAUTHENTICATED)
        assert r["dns_posture"]["status"] == "unauthenticated"

    def test_unauthenticated_domain_raises_score_when_headers_are_silent(self):
        base = analyze_email(EMAIL, auth_results=SILENT_HEADERS)
        with_dns = analyze_email(EMAIL, auth_results=SILENT_HEADERS,
                                 dns_posture=UNAUTHENTICATED)
        assert with_dns["score"] > base["score"]
        assert any("DMARC" in x or "SPF" in x for x in with_dns["reasons"])

    def test_the_safe_override_does_not_swallow_measured_dns_evidence(self):
        """The SAFE override caps a headerless email at 15 because 'missing
        auth is NEUTRAL — never risk'. That was right while nothing could be
        checked. Once DNS has been asked and answered 'this domain publishes
        no DMARC, no SPF and no MX', the absence is measured, not unknown, and
        capping it away discards the only evidence there is.

        Without this test the feature scores 18 and is silently clamped back
        to 15 before it reaches the verdict.
        """
        pressure = (
            "From: Billing <billing@secure-invoice-portal.example>\n"
            "Subject: Urgent: invoice payment overdue\n\n"
            "Your account will be suspended. Confirm your payment details "
            "immediately.\n"
        )
        base = analyze_email(pressure, auth_results=SILENT_HEADERS)
        with_dns = analyze_email(pressure, auth_results=SILENT_HEADERS,
                                 dns_posture=UNAUTHENTICATED)

        assert base["score"] == 15, "precondition: the override caps this at 15"
        assert with_dns["score"] > 15
        assert not any("Legitimate email" in r for r in with_dns["reasons"])

    def test_the_override_still_protects_a_domain_that_does_publish(self):
        # partial is not a red flag. Plenty of small legitimate senders have
        # SPF and MX but never got round to DMARC.
        partial = {"status": "partial", "available": True,
                   "dmarc_policy": None, "dmarc_enforcing": False,
                   "spf": "soft", "mx": True, "detail": "SPF and MX only"}
        pressure = (
            "From: Billing <billing@small-shop.example>\n"
            "Subject: Urgent: invoice payment overdue\n\n"
            "Your account will be suspended. Confirm your payment details "
            "immediately.\n"
        )
        r = analyze_email(pressure, auth_results=SILENT_HEADERS,
                          dns_posture=partial)
        assert r["score"] == 15
        assert any("Legitimate email" in x for x in r["reasons"])

    def test_unknown_posture_leaves_the_score_alone(self):
        base = analyze_email(EMAIL, auth_results=SILENT_HEADERS)
        with_dns = analyze_email(EMAIL, auth_results=SILENT_HEADERS,
                                 dns_posture=UNKNOWN_POSTURE)
        assert with_dns["score"] == base["score"]

    def test_headers_win_when_they_already_proved_authentication(self):
        # SPF, DKIM and DMARC all passed. Whatever DNS says about the policy,
        # this specific message authenticated, so the posture must not be
        # charged against it a second time.
        passing = analyze_email(EMAIL, auth_results=PASSING_HEADERS)
        both = analyze_email(EMAIL, auth_results=PASSING_HEADERS,
                             dns_posture=UNAUTHENTICATED)
        assert both["score"] == passing["score"]

    def test_protected_domain_adds_no_risk(self):
        base = analyze_email(EMAIL, auth_results=SILENT_HEADERS)
        with_dns = analyze_email(EMAIL, auth_results=SILENT_HEADERS,
                                 dns_posture=PROTECTED)
        assert with_dns["score"] == base["score"]

    def test_omitting_the_posture_keeps_the_old_behaviour(self):
        # Every existing caller passes two arguments. They must be unaffected.
        r = analyze_email(EMAIL, auth_results=SILENT_HEADERS)
        assert r["dns_posture"]["status"] == "unknown"
