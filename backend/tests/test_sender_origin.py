"""
Sender origin verification (WORK_PLAN Task 9): "is this email really from
the platform it claims to be from?"

Contract:
  * verified      — display name claims a known brand AND the sender domain
                    is one of that brand's official domains AND the
                    authentication is aligned (DMARC pass, or SPF+DKIM pass)
  * mismatch      — claims a known brand but the sender domain does NOT
                    belong to that brand (the classic phish)
  * spoof_suspected — official domain in From, but authentication FAILS
  * authenticated — no brand claim; auth aligned for whatever domain it is
  * unknown       — nothing provable either way

Product rules the user asked for:
  * verified bank mail is NOT penalized for banking/OTP vocabulary
  * a brand claim from the wrong domain raises the score hard
  * every email result carries a genuine-vs-fake ratio
"""

from email_analyzer import analyze_email, verify_sender_origin

AUTH_PASS = {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
AUTH_FAIL = {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
AUTH_NONE = {"spf": "none", "dkim": "none", "dmarc": "none"}


# ---------------------------------------------------------------------------
# verify_sender_origin unit contract
# ---------------------------------------------------------------------------

class TestVerifySenderOrigin:
    def test_verified_official_domain_and_auth(self):
        res = verify_sender_origin(
            display_name="ICICI Bank",
            subject="Your account statement",
            sender_domain="alerts.icicibank.com",
            auth_results=AUTH_PASS,
        )
        assert res["status"] == "verified"
        assert res["claimed_brand"] == "icici"
        assert "icicibank.com" in res["detail"]

    def test_verified_regulated_bank_in_domain(self):
        # Live FP 2026-07-16: a genuine ICICI mail from custcomm.icici.bank.in
        # (RBI's regulated .bank.in namespace — only real banks can register
        # there) was flagged as impersonation because the map only knew
        # icicibank.com.
        res = verify_sender_origin(
            display_name="ICICI Bank",
            subject="Your portfolio called. It needs this!",
            sender_domain="custcomm.icici.bank.in",
            auth_results=AUTH_PASS,
        )
        assert res["status"] == "verified"

    def test_mismatch_wrong_domain(self):
        res = verify_sender_origin(
            display_name="ICICI Bank",
            subject="Security alert",
            sender_domain="icici-verify.top",
            auth_results=AUTH_NONE,
        )
        assert res["status"] == "mismatch"
        assert res["claimed_brand"] == "icici"
        assert "icici-verify.top" in res["detail"]

    def test_spoof_suspected_right_domain_failing_auth(self):
        res = verify_sender_origin(
            display_name="PayPal",
            subject="Receipt",
            sender_domain="paypal.com",
            auth_results=AUTH_FAIL,
        )
        assert res["status"] == "spoof_suspected"

    def test_authenticated_without_brand_claim(self):
        res = verify_sender_origin(
            display_name="Weekly Digest",
            subject="Your weekend reading",
            sender_domain="newsletter.example",
            auth_results=AUTH_PASS,
        )
        assert res["status"] == "authenticated"
        assert res["claimed_brand"] is None

    def test_unknown_without_anything(self):
        res = verify_sender_origin(
            display_name="Weekly Digest",
            subject="Hello",
            sender_domain="newsletter.example",
            auth_results=AUTH_NONE,
        )
        assert res["status"] == "unknown"

    def test_subject_brand_mention_alone_is_not_a_claim(self):
        # "Top deals on Amazon this week" from a deals newsletter is NOT an
        # impersonation claim — subject mentions only upgrade to verified
        # when the domain actually matches, never to mismatch.
        res = verify_sender_origin(
            display_name="Deals Digest",
            subject="Top deals on Amazon this week",
            sender_domain="dealsdigest.example",
            auth_results=AUTH_PASS,
        )
        assert res["status"] == "authenticated"

    def test_subject_brand_with_matching_domain_verifies(self):
        res = verify_sender_origin(
            display_name="Customer Care",
            subject="Your Amazon order has shipped",
            sender_domain="amazon.in",
            auth_results=AUTH_PASS,
        )
        assert res["status"] == "verified"
        assert res["claimed_brand"] == "amazon"

    def test_short_brand_names_need_word_boundaries(self):
        # 'sbi' must not fire inside unrelated words.
        res = verify_sender_origin(
            display_name="Absolutely Fabulous Yarns",
            subject="New wool colors",
            sender_domain="fabyarns.example",
            auth_results=AUTH_PASS,
        )
        assert res["claimed_brand"] is None


# ---------------------------------------------------------------------------
# analyze_email integration — the user's exact complaint
# ---------------------------------------------------------------------------

GENUINE_BANK_MAIL = (
    "Subject: Important: safety tips for your credit card\n"
    "From: ICICI Bank <alerts@icicibank.com>\n"
    "Body: Dear customer, never share your OTP or CVV with anyone. "
    "Your credit card statement is ready. Log in to internet banking to "
    "view your account. Beware of phishing calls asking you to verify your account."
)

FAKE_BANK_MAIL = (
    "Subject: Important: verify your account\n"
    "From: ICICI Bank <security@icici-verify.top>\n"
    "Body: Dear customer, your account has been suspended. Verify now with "
    "your OTP and card number within 24 hours to avoid suspension."
)


class TestAnalyzeEmailOrigin:
    def test_verified_bank_mail_with_banking_words_is_safe(self):
        res = analyze_email(GENUINE_BANK_MAIL, auth_results=AUTH_PASS)
        assert res["sender_origin"]["status"] == "verified"
        assert res["verdict"] == "SAFE", res["reasons"]
        assert res["risk_score"] <= 20
        assert res["genuine_ratio"] >= 80

    def test_brand_claim_from_wrong_domain_scores_hard(self):
        res = analyze_email(FAKE_BANK_MAIL, auth_results=AUTH_NONE)
        assert res["sender_origin"]["status"] == "mismatch"
        assert res["verdict"] in ("SUSPICIOUS", "MALICIOUS"), res["reasons"]
        assert res["risk_score"] >= 60
        assert any("does not belong" in r or "not an official" in r for r in res["reasons"])

    def test_same_words_wrong_origin_vs_right_origin(self):
        # The user's core ask: identical banking vocabulary must score
        # completely differently depending on where the mail really came from.
        genuine = analyze_email(GENUINE_BANK_MAIL, auth_results=AUTH_PASS)
        fake = analyze_email(FAKE_BANK_MAIL, auth_results=AUTH_NONE)
        assert genuine["risk_score"] + 40 <= fake["risk_score"]

    def test_genuine_ratio_present_on_every_result(self):
        for content, auth in ((GENUINE_BANK_MAIL, AUTH_PASS), (FAKE_BANK_MAIL, AUTH_NONE)):
            res = analyze_email(content, auth_results=auth)
            assert res["genuine_ratio"] == 100 - res["risk_score"]

    def test_spoofed_official_domain_fails_auth(self):
        content = (
            "Subject: Your PayPal receipt\n"
            "From: PayPal <service@paypal.com>\n"
            "Body: You sent a payment. If this wasn't you, verify your account now."
        )
        res = analyze_email(content, auth_results=AUTH_FAIL)
        assert res["sender_origin"]["status"] == "spoof_suspected"
        assert res["verdict"] in ("SUSPICIOUS", "MALICIOUS")
