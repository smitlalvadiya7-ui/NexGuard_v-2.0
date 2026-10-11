import re
from email.utils import parseaddr
from ai_engine import analyze_ai, verdict_from_score

# One source of truth for what a posture is worth. Imported rather than
# duplicated so the weight cannot drift away from the tests that pin it.
from apis.dns_auth import posture_risk as _posture_risk

# What a caller that supplied no posture gets. "unknown" scores zero — the
# lookup did not happen, and a lookup that did not happen is not evidence.
_POSTURE_UNKNOWN = {
    "status": "unknown", "available": False,
    "dmarc_policy": None, "dmarc_enforcing": False,
    "spf": None, "mx": False,
    "detail": "Sender-domain DNS policy was not checked.",
}

SPOOFED_DISPLAY_BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "bank", "hsbc", "barclays", "lloyds"]
FREE_SENDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"}

# ---------------------------------------------------------------------------
# Sender origin verification (WORK_PLAN Task 9)
# ---------------------------------------------------------------------------
# brand -> that brand's OFFICIAL sending registrable domains. Maintained list:
# add brands (and their transactional-mail domains, e.g. facebookmail.com)
# as they surface. Matching is word-boundary on the display name, so short
# names ('sbi') never fire inside unrelated words.
BRAND_DOMAINS = {
    "google":    {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com",
                  "microsoftonline.com", "azure.com", "hotmail.com"},
    "apple":     {"apple.com", "icloud.com"},
    "amazon":    {"amazon.com", "amazon.in", "amazon.co.uk", "amazonses.com",
                  "primevideo.com"},
    "paypal":    {"paypal.com", "paypal.co.uk", "paypal.in"},
    "netflix":   {"netflix.com"},
    "facebook":  {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com"},
    "whatsapp":  {"whatsapp.com", "facebookmail.com"},
    "linkedin":  {"linkedin.com"},
    "github":    {"github.com"},
    "flipkart":  {"flipkart.com"},
    "paytm":     {"paytm.com"},
    "phonepe":   {"phonepe.com"},
    # Indian banks also send from RBI's regulated <brand>.bank.in namespace
    # (IDRBT registry, banks only — live-verified: custcomm.icici.bank.in).
    "icici":     {"icicibank.com", "icici.bank.in"},
    "hdfc":      {"hdfcbank.com", "hdfcbank.net", "hdfc.bank.in"},
    "sbi":       {"sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbi.bank.in"},
    "axis":      {"axisbank.com", "axis.bank.in"},
    "kotak":     {"kotak.com", "kotak.bank.in"},
    "hsbc":      {"hsbc.com", "hsbc.co.in", "hsbc.co.uk"},
    "barclays":  {"barclays.com", "barclays.co.uk"},
    "lloyds":    {"lloydsbank.com", "lloydsbank.co.uk"},
    "revolut":   {"revolut.com"},
    "stripe":    {"stripe.com"},
}


def _claimed_brand(text: str):
    """Word-boundary brand detection ('sbi' never fires inside 'absolutely')."""
    lower = (text or "").lower()
    for brand in BRAND_DOMAINS:
        if re.search(rf"\b{re.escape(brand)}\b", lower):
            return brand
    return None


def _domain_matches(sender_domain: str, official: set) -> bool:
    d = (sender_domain or "").lower().strip().rstrip(".")
    return any(d == o or d.endswith("." + o) for o in official)


def verify_sender_origin(display_name: str, subject: str, sender_domain: str,
                         auth_results: dict | None) -> dict:
    """
    Decide whether an email genuinely comes from the platform it claims:
      verified / mismatch / spoof_suspected / authenticated / unknown.

    The display name is a CLAIM ("ICICI Bank <x@evil.ru>" claims ICICI); a
    brand word in the subject alone is not — newsletters legitimately write
    about brands — it only upgrades to verified when the domain matches too.
    """
    auth = auth_results or {}
    auth_aligned = auth.get("dmarc") == "pass" or (
        auth.get("spf") == "pass" and auth.get("dkim") == "pass"
    )
    auth_failing = (
        auth.get("spf") in ("fail", "softfail")
        or auth.get("dkim") == "fail"
        or auth.get("dmarc") == "fail"
    )

    claimed = _claimed_brand(display_name)
    subject_brand = _claimed_brand(subject)

    result = {
        "claimed_brand": claimed,
        "sender_domain": sender_domain or "",
        "expected_domains": sorted(BRAND_DOMAINS[claimed]) if claimed else [],
        "status": "unknown",
        "detail": "",
    }

    if claimed:
        official = BRAND_DOMAINS[claimed]
        if _domain_matches(sender_domain, official):
            if auth_failing:
                result["status"] = "spoof_suspected"
                result["detail"] = (
                    f"Sender domain '{sender_domain}' belongs to {claimed}, but "
                    "SPF/DKIM/DMARC authentication FAILED — the From address may be forged."
                )
            elif auth_aligned:
                result["status"] = "verified"
                result["detail"] = (
                    f"Verified sender — genuinely from '{sender_domain}', an official "
                    f"{claimed} domain, with passing authentication."
                )
            else:
                # right domain, but nothing provable (no auth headers at all)
                result["status"] = "unknown"
                result["detail"] = (
                    f"Sender domain '{sender_domain}' matches {claimed}, but no "
                    "authentication headers were available to confirm it."
                )
        else:
            result["status"] = "mismatch"
            result["detail"] = (
                f"Claims to be '{claimed}' but was sent from '{sender_domain}', "
                f"which does not belong to {claimed} (official: "
                f"{', '.join(sorted(official))})."
            )
        return result

    # No display-name claim. A subject brand mention only VERIFIES when the
    # domain genuinely matches; it never convicts.
    if subject_brand and _domain_matches(sender_domain, BRAND_DOMAINS[subject_brand]) and auth_aligned:
        result["claimed_brand"] = subject_brand
        result["expected_domains"] = sorted(BRAND_DOMAINS[subject_brand])
        result["status"] = "verified"
        result["detail"] = (
            f"Verified sender — genuinely from '{sender_domain}', an official "
            f"{subject_brand} domain, with passing authentication."
        )
        return result

    if auth_aligned and sender_domain:
        result["status"] = "authenticated"
        result["detail"] = (
            f"Sender domain '{sender_domain}' passed SPF/DKIM/DMARC authentication."
        )
    else:
        result["detail"] = "Sender could not be verified from the available headers."
    return result

def verify_sender_simple(sender: str, subject: str = "") -> dict:
    """
    Header-free sender check for the webmail badge (NEXT_PHASE_PLAN E8).

    Webmail DOMs expose only "Name <address>" — no SPF/DKIM/DMARC — so this
    NEVER says "verified"; it only reports whether the display name claims a
    known brand and whether the sending domain genuinely belongs to it:

      brand_match   — claims a brand AND the domain is official ("✓" badge)
      impersonation — claims a brand from a non-official domain ("⚠" badge)
      none          — no brand claim (or unparsable input): no badge, low noise
    """
    result = {"status": "none", "brand": None, "sender_domain": "", "detail": ""}
    if not sender or not isinstance(sender, str):
        return result

    display_name, address = parseaddr(sender)
    if "@" not in address:
        return result
    domain = address.rsplit("@", 1)[1].lower().strip().rstrip(".")
    result["sender_domain"] = domain

    claimed = _claimed_brand(display_name)
    if not claimed:
        # A brand word in the SUBJECT alone is not a claim (newsletters write
        # about brands) — it may only CONFIRM a matching domain, never convict.
        # Same rule as verify_sender_origin.
        subject_brand = _claimed_brand(subject or "")
        if subject_brand and _domain_matches(domain, BRAND_DOMAINS[subject_brand]):
            result["brand"] = subject_brand
            result["status"] = "brand_match"
            result["detail"] = (
                f"Sender domain '{domain}' is an official {subject_brand} domain."
            )
        return result

    official = BRAND_DOMAINS[claimed]
    result["brand"] = claimed
    if _domain_matches(domain, official):
        result["status"] = "brand_match"
        result["detail"] = (
            f"Sender domain '{domain}' is an official {claimed} domain. "
            "(Authentication headers are not visible here — the full email "
            "analyzer can confirm SPF/DKIM/DMARC.)"
        )
    else:
        result["status"] = "impersonation"
        result["detail"] = (
            f"Claims to be '{claimed}' but was sent from '{domain}', which is "
            f"not a {claimed} domain (official: {', '.join(sorted(official))})."
        )
    return result


# Reputable senders: with aligned/neutral auth + only reputable links, an email
# from one of these (registrable match) comes out SAFE (FIX 4).
REPUTABLE_SENDER_DOMAINS = {
    "github.com", "google.com", "gmail.com", "microsoft.com", "office.com",
    "outlook.com", "live.com", "apple.com", "icloud.com", "amazon.com",
    "paypal.com", "linkedin.com", "facebook.com", "instagram.com",
    "stripe.com", "atlassian.com", "slack.com", "dropbox.com",
}


# ---------------------------------------------------------------------------
# Scam-intent scoring of the email body
# ---------------------------------------------------------------------------
# Weighted social-engineering phrases grouped by manipulation category. Each
# phrase contributes its weight to the intent_score; categories also feed the
# simple count-based signals below.
SCAM_INTENT_CUES = {
    # account threat / fear
    "account suspended": ("threat", 18),
    "account has been suspended": ("threat", 20),
    "account will be closed": ("threat", 20),
    "account has been locked": ("threat", 18),
    "account locked": ("threat", 16),
    "suspend your account": ("threat", 16),
    "avoid suspension": ("threat", 16),
    "unusual activity": ("threat", 14),
    "suspicious activity": ("threat", 14),
    "unauthorized access": ("threat", 16),
    "unauthorized login": ("threat", 16),
    "your account will be terminated": ("threat", 20),
    "permanently closed": ("threat", 16),
    # urgency
    "act now": ("urgency", 14),
    "immediately": ("urgency", 8),
    "urgent": ("urgency", 12),
    "within 24 hours": ("urgency", 14),
    "within 48 hours": ("urgency", 14),
    "final warning": ("urgency", 18),
    "last chance": ("urgency", 12),
    "respond immediately": ("urgency", 14),
    "as soon as possible": ("urgency", 8),
    "expires today": ("urgency", 14),
    # credential / identity harvesting
    "verify now": ("credential", 16),
    "verify your account": ("credential", 16),
    "verify your identity": ("credential", 14),
    "confirm your account": ("credential", 14),
    "confirm your identity": ("credential", 14),
    "update your password": ("credential", 14),
    "reset your password": ("credential", 12),
    "your password will expire": ("credential", 18),
    "password expiry": ("credential", 16),
    "password is about to expire": ("credential", 16),
    "one time password": ("credential", 18),
    "otp": ("credential", 16),
    "login credentials": ("credential", 14),
    "social security number": ("credential", 18),
    "ssn": ("credential", 14),
    "card number": ("credential", 14),
    "cvv": ("credential", 18),
    "pin number": ("credential", 14),
    # money / payment lures
    "wire transfer": ("money", 18),
    "gift card": ("money", 20),
    "google play card": ("money", 20),
    "itunes card": ("money", 20),
    "bitcoin": ("money", 16),
    "cryptocurrency": ("money", 14),
    "payment failed": ("money", 12),
    "billing problem": ("money", 12),
    "update your billing": ("money", 12),
    "outstanding invoice": ("money", 12),
    "you have won": ("money", 16),
    "claim your prize": ("money", 16),
    "claim your reward": ("money", 14),
    "inheritance": ("money", 16),
    "tax refund": ("money", 14),
    # 2026-07-19 — big Indian scam families the table missed (found when the
    # expanded testdata screenshots scored a false SAFE 0):
    # lottery / prize bait
    "you won": ("money", 14),
    "lucky draw": ("money", 18),
    "lottery": ("money", 14),
    "prize money": ("money", 16),
    "processing fee": ("money", 18),
    # job-offer fee scams
    "work from home": ("lure", 12),
    "registration fee": ("money", 18),
    "no experience": ("lure", 10),
    "offer letter": ("lure", 10),
    # investment / doubling scams
    "guaranteed return": ("money", 14),
    "double your money": ("money", 16),
    "minimum invest": ("money", 12),
    "crypto trading": ("money", 12),
    # delivery / customs scams
    "at customs": ("threat", 14),
    "customs duty": ("money", 16),
    "import duty": ("money", 16),
    # digital-arrest scams
    "digital arrest": ("threat", 20),
    "money laundering case": ("threat", 18),
    "arrest warrant": ("threat", 18),
    "safe account": ("money", 14),
}

# Direct requests for money or credentials (simple regex signals).
_MONEY_REQUEST_RE = re.compile(
    r"\b(wire|transfer|send|pay)\b.{0,30}\b(\$|usd|eur|gbp|money|funds|bitcoin|gift\s*card)\b",
    re.IGNORECASE,
)
_CREDENTIAL_REQUEST_RE = re.compile(
    r"\b(enter|provide|confirm|reply\s+with|send|share|update)\b.{0,40}"
    r"\b(password|otp|pin|cvv|card\s*number|ssn|social\s*security|credentials|login)\b",
    re.IGNORECASE,
)


def score_scam_intent(text: str) -> dict:
    """
    Score the social-engineering / scam intent of an email body.

    Returns {"intent_score": int 0-100, "matched_cues": list[str],
             "urgency_count": int, "money_request": bool, "credential_request": bool}.
    """
    # Collapse ALL whitespace: email bodies and OCR text wrap lines mid-phrase
    # ("double your\nmoney"), and a phrase cue must still match across a wrap.
    lower = re.sub(r"\s+", " ", (text or "").lower())
    score = 0
    matched = []
    by_category: dict[str, int] = {}

    for phrase, (category, weight) in SCAM_INTENT_CUES.items():
        if phrase in lower:
            score += weight
            matched.append(phrase)
            by_category[category] = by_category.get(category, 0) + 1

    urgency_count = by_category.get("urgency", 0) + by_category.get("threat", 0)
    money_request = bool(_MONEY_REQUEST_RE.search(lower)) or by_category.get("money", 0) > 0
    credential_request = bool(_CREDENTIAL_REQUEST_RE.search(lower)) or by_category.get("credential", 0) > 0

    # Simple compounding signals: stacked urgency + an actual ask is a classic
    # phishing structure, so reward the combination.
    if urgency_count >= 3:
        score += 10
    if money_request and credential_request:
        score += 12
    elif money_request or credential_request:
        score += 6

    return {
        "intent_score": max(0, min(100, int(score))),
        "matched_cues": matched,
        "urgency_count": urgency_count,
        "money_request": money_request,
        "credential_request": credential_request,
    }


def _extract_sender(content: str) -> str:
    match = re.search(r"^From:\s*(.+)$", content or "", re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else "Unknown"


def _extract_header(content: str, name: str) -> str:
    match = re.search(rf"^{name}:\s*(.+)$", content or "", re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else ""


def _sender_domain(sender: str) -> str:
    _, addr = parseaddr(sender or "")
    if "@" not in addr:
        return ""
    return addr.split("@")[-1].lower()


def _root_domain(domain: str) -> str:
    parts = (domain or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "")


def analyze_email(content, auth_results=None, attachments=None, dns_posture=None):
    """
    `dns_posture` is apis.dns_auth's reading of the SENDER DOMAIN's published
    mail policy, injected rather than fetched so this function stays pure and
    synchronous — the same treatment `auth_results` already gets.

    It only speaks when the headers do not. Authentication-Results is evidence
    about THIS message; a DNS policy is evidence about the domain. When the
    headers already returned a verdict, charging the domain again would count
    one fact twice.
    """
    content = content or ""
    posture = dns_posture or dict(_POSTURE_UNKNOWN)

    # Empty / unreadable email — return a complete, neutral object with a clear
    # message rather than a silently "safe" verdict on no content.
    if not content.strip():
        return {
            "sender": "Unknown", "sender_domain": "Unknown",
            "score": 0, "risk_score": 0, "verdict": "UNKNOWN",
            "reasons": ["The email had no readable content to analyze"],
            "urls": [], "auth_results": {"spf": "none", "dkim": "none", "dmarc": "none"},
            "intent_score": 0, "matched_cues": [], "attachment_results": [],
            "sender_origin": {
                "status": "unknown", "claimed_brand": None, "sender_domain": "",
                "expected_domains": [],
                "detail": "No readable content to verify the sender from.",
            },
            "dns_posture": dict(_POSTURE_UNKNOWN),
            "genuine_ratio": 0,
            "ai_explanation": (
                "No readable email content was found. Upload a valid .eml file or "
                "paste the email text."
            ),
        }

    lower = content.lower()

    sender = _extract_sender(content)

    sender_domain = _sender_domain(sender)

    reply_to = _extract_header(content, "Reply-To")
    reply_to_domain = _sender_domain(reply_to)

    score = 0

    safe_score = 0

    reasons = []

    # Hard phishing signals — the ONLY things that should raise an email's risk
    # (FIX 4). Tracked as booleans so a clean email is never inflated by neutral
    # signals or a noisy keyword bag.
    display_brand_mismatch = False
    credential_reply = False
    attachment_risky = False

    # REAL AUTHENTICATION SIGNALS (parsed from email headers by email_parser)
    _auth = auth_results or {}
    _spf   = _auth.get("spf",   "none")
    _dkim  = _auth.get("dkim",  "none")
    _dmarc = _auth.get("dmarc", "none")

    if _spf == "pass":
        safe_score += 20
    elif _spf in ("fail", "softfail"):
        score += 20
        reasons.append("SPF check failed — sender not authorized to send from this domain")

    if _dkim == "pass":
        safe_score += 20
    elif _dkim == "fail":
        score += 25
        reasons.append("DKIM authentication failed — message may be forged or tampered")

    if _dmarc == "pass":
        safe_score += 20
    elif _dmarc == "fail":
        score += 30
        reasons.append("DMARC authentication failed — domain policy rejected this sender")

    # All three pass = strong trust signal (bonus matches old safe_score total of 75)
    if _spf == "pass" and _dkim == "pass" and _dmarc == "pass":
        safe_score += 15

    # THE SENDER DOMAIN'S OWN POLICY, when the headers settled nothing.
    # A webmail DOM or a screenshot carries no Authentication-Results at all,
    # which used to leave this path with no authentication evidence whatever.
    # Measured on eval/_corpus_m4.json: 59 of 64 attacker-registered phishing
    # domains publish no DMARC, no SPF and no MX, against 30% of legitimate
    # ones — corroborating, never convicting, hence the modest weight.
    _headers_silent = not any(
        v == "pass" or v in ("fail", "softfail") for v in (_spf, _dkim, _dmarc)
    )
    if _headers_silent:
        _dns_risk = _posture_risk(posture)
        if _dns_risk:
            score += _dns_risk
            reasons.append(
                "Sender domain publishes no DMARC, no SPF and no MX record — "
                "it sends mail but claims no mail identity"
            )

    # Legitimate sender domain signals (unchanged)
    if "google.com" in lower:
        safe_score += 15

    if "microsoft.com" in lower:
        safe_score += 15

    if "amazon.com" in lower:
        safe_score += 15

    # SENDER CHECKS

    if sender == "Unknown" or "@" not in sender:

        score += 10

        reasons.append(
            "Sender address is missing or unusual"
        )

    display_name, addr = parseaddr(sender)

    display_lower = (
        display_name or sender
    ).lower()

    # SENDER ORIGIN VERIFICATION (Task 9) — is this really from the platform
    # it claims? Decides how the rest of the email is judged.
    subject_line = _extract_header(content, "Subject")
    sender_origin = verify_sender_origin(
        display_name or sender, subject_line, sender_domain, auth_results
    )
    origin_verified = sender_origin["status"] == "verified"

    if sender_origin["status"] == "mismatch":
        score += 45
        display_brand_mismatch = True
        reasons.append(sender_origin["detail"])
    elif sender_origin["status"] == "spoof_suspected":
        score += 25
        display_brand_mismatch = True
        reasons.append(sender_origin["detail"])
    elif origin_verified:
        reasons.append(sender_origin["detail"])

    # Crude display-brand fallback — only for brands the origin map doesn't
    # know (generic 'bank', etc.); a mapped brand was already judged above.
    if sender_origin["claimed_brand"] is None:
        for brand in SPOOFED_DISPLAY_BRANDS:

            if (
                brand in display_lower
                and
                brand not in sender_domain
            ):

                score += 25

                display_brand_mismatch = True

                reasons.append(
                    f"Display name mentions {brand}, but sender domain does not match"
                )

                break

    # FREE EMAIL + FINANCIAL BAIT

    if (
        sender_domain in FREE_SENDERS
        and
        any(
            b in lower
            for b in [
                "bank",
                "paypal",
                "payment",
                "invoice",
                "security alert",
                "account"
            ]
        )
    ):

        score += 14

        reasons.append(
            "Financial/security email appears to come from a free email provider"
        )

    # CREDENTIAL THEFT

    if re.search(
        r"reply\s+(with|to).*(otp|password|pin|cvv|security code)",
        lower
    ):

        score += 35

        credential_reply = True

        reasons.append(
            "Email asks user to reply with sensitive credentials"
        )

    # PROMOTIONAL PRESSURE — a VERIFIED sender's own vocabulary is exempt:
    # genuine bank/platform mail legitimately says "verify", "account", "urgent".
    if (
        not origin_verified
        and
        "unsubscribe" not in lower
        and
        any(
            x in lower
            for x in [
                "limited time",
                "gift",
                "winner",
                "claim now",
                "urgent",
                "verify now",
                "account suspended"
            ]
        )
    ):

        score += 12

        reasons.append(
            "Urgency or phishing-style pressure wording detected"
        )

    # SCAM-INTENT SCORING (urgency / social-engineering cues in the body).
    # Verified-origin mail is NOT penalized for banking/OTP vocabulary (Task 9,
    # the user's core complaint) — a real bank talking about OTP safety is
    # normal. Hard signals (reply-with-OTP, bad attachments, flagged links)
    # still apply to verified senders below.
    intent = score_scam_intent(content)
    intent_reasons = []
    if intent["intent_score"] > 0 and not origin_verified:
        # Audit finding 2 (2026-07-27): the flat 45 cap sat below the MALICIOUS
        # threshold of 70, so a link-less, attachment-less mail with neutral
        # auth could NEVER convict however blatant it was. Three unrelated
        # maximum-intent scams — KBC lottery, advance-fee, digital arrest — all
        # scored EXACTLY 57, the signature of a saturated cap. That is the whole
        # family of scams which deliberately carry no link, because the payload
        # is "reply to us" / "call this number" / "send to this UPI".
        #
        # The higher cap is licensed by a STRUCTURAL ask — the mail explicitly
        # wants money or credentials — never by urgency vocabulary alone, so
        # ordinary pushy marketing ("act now, sale expires today") still tops
        # out at 45 and stays out of the MALICIOUS band.
        hard_ask = bool(intent["money_request"] or intent["credential_request"])
        intent_cap = 70 if (hard_ask and intent["intent_score"] >= 70) else 45
        score += min(intent["intent_score"], intent_cap)
        if intent["matched_cues"]:
            shown = ", ".join(intent["matched_cues"][:6])
            intent_reasons.append(f"Scam-intent cues detected: {shown}")
        if intent["credential_request"]:
            intent_reasons.append("Email directly requests credentials/OTP")
        if intent["money_request"]:
            intent_reasons.append("Email requests money / gift card / transfer")

    # ATTACHMENT REPUTATION (SHA-256 checked against VirusTotal)

    attachment_results = []
    for att in (attachments or []):
        status = att.get("status", "clean")
        entry = {
            "filename":      att.get("filename", "unnamed"),
            "sha256":        att.get("sha256", ""),
            "size":          att.get("size", 0),
            "content_type":  att.get("content_type", ""),
            "status":        status,
            "detail":        att.get("detail", ""),
            "raw_positives": att.get("raw_positives", 0),
        }
        attachment_results.append(entry)
        if status == "flag":
            score += 60
            attachment_risky = True
            reasons.append(
                f"Malicious attachment '{entry['filename']}' — VirusTotal: {entry['detail']}"
            )
        elif status == "warn":
            score += 25
            attachment_risky = True
            reasons.append(
                f"Suspicious attachment '{entry['filename']}' — VirusTotal: {entry['detail']}"
            )

    # REPLY-TO / FROM DOMAIN MISMATCH (hard signal)

    reply_mismatch = bool(
        reply_to_domain
        and sender_domain
        and reply_to_domain != sender_domain
        and _root_domain(reply_to_domain) != _root_domain(sender_domain)
    )
    if reply_mismatch:
        score += 22
        reasons.append(
            f"Reply-To domain '{reply_to_domain}' differs from sender domain '{sender_domain}'"
        )

    # AI ENGINE

    ai = analyze_ai(content)

    # Only the URL-derived link risk feeds the score — the raw body keyword bag
    # is dropped so a legitimate email that merely mentions 'account'/'secure'
    # is not inflated (FIX 4). Real scam wording is already captured by the
    # structured scam-intent scorer above.
    url_score = int(ai.get("url_score", 0))

    final_score = (
        score
        + url_score
        - safe_score
    )

    final_score = max(
        0,
        min(100, int(final_score))
    )

    # ------------------------------------------------------------------
    # SAFE override (FIX 4): a reputable / authenticated sender with NO hard
    # risk signal and only reputable links must come out SAFE. Missing auth
    # (e.g. a .eml with no headers) is NEUTRAL — never risk.
    # ------------------------------------------------------------------
    auth_failing = _spf in ("fail", "softfail") or _dkim == "fail" or _dmarc == "fail"
    auth_aligned = _dmarc == "pass" or (_spf == "pass" and _dkim == "pass")
    sender_reputable = (
        sender_domain in REPUTABLE_SENDER_DOMAINS
        or _root_domain(sender_domain) in REPUTABLE_SENDER_DOMAINS
    )
    links_risky = url_score >= 40
    strong_intent = intent["intent_score"] >= 30 and not origin_verified

    no_hard_risk = not (
        auth_failing or reply_mismatch or display_brand_mismatch
        or credential_reply or attachment_risky or links_risky or strong_intent
    )
    # "Missing auth is NEUTRAL" held while nothing could be checked. Once DNS
    # has been ASKED and answered that the domain publishes no DMARC, no SPF
    # and no MX, the absence is measured rather than unknown, and the weakest
    # branch of this override would throw away the only evidence there is.
    # A reputable domain, a verified origin or aligned headers still win —
    # only the "nothing is known either way" fallback is withdrawn.
    dns_unauthenticated = posture.get("status") == "unauthenticated"

    if no_hard_risk and (auth_aligned or sender_reputable or origin_verified
                         or (not auth_failing and url_score == 0
                             and not dns_unauthenticated)):
        final_score = min(final_score, 15)
        reasons.append(
            "Legitimate email — reputable/authenticated sender, aligned or neutral "
            "SPF/DKIM/DMARC, and only reputable links"
        )

    combined = (
        reasons
        + intent_reasons
        + ai.get("reasons", [])
    )

    seen = set()

    final_reasons = []

    for r in combined:

        if r and r not in seen:

            final_reasons.append(r)

            seen.add(r)

    if (
        final_score < 15
        and
        safe_score >= 50
    ):

        final_reasons.append(
            "Strong SPF/DKIM/DMARC authentication detected"
        )

    verdict = verdict_from_score(final_score)

    return {
        "sender":        sender,
        "sender_domain": sender_domain or "Unknown",
        "score":         final_score,
        "risk_score":    final_score,
        "verdict":       verdict,
        "reasons":       final_reasons,
        "urls":          ai.get("urls", []),
        "auth_results":  {
            "spf":   _spf,
            "dkim":  _dkim,
            "dmarc": _dmarc,
        },
        "intent_score":       intent["intent_score"],
        "matched_cues":       intent["matched_cues"],
        "attachment_results": attachment_results,
        "sender_origin":      sender_origin,
        "dns_posture":        posture,
        "genuine_ratio":      100 - final_score,
        "ai_explanation": (
            "; ".join(final_reasons)
            if final_reasons
            else "No strong phishing email indicators detected."
        ),
    }