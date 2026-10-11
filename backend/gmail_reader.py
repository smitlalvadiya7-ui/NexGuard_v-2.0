from pathlib import Path
import base64
import re

from email_parser import parse_email
from email_analyzer import analyze_email

# Same regex used by email_parser — kept local so modules stay decoupled
_AUTH_RE = re.compile(r'\b(spf|dkim|dmarc)=(\w+)', re.IGNORECASE)

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Module-level so tests (and deployments) can point elsewhere.
CREDENTIALS_PATH = Path(__file__).resolve().parent / "credentials.json"
TOKEN_PATH = Path(__file__).resolve().parent / "token.json"


def _gmail_auth_from_headers(headers: list) -> dict:
    """
    Extract SPF/DKIM/DMARC verdicts from the Gmail API payload.headers list
    (format: [{"name": "...", "value": "..."}, ...]).
    """
    verdicts = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for h in (headers or []):
        name = h.get("name", "").lower()
        val  = h.get("value", "")
        if name == "authentication-results":
            for key, v in _AUTH_RE.findall(val):
                verdicts[key.lower()] = v.lower()
        elif name == "received-spf" and verdicts["spf"] == "none":
            m = re.match(r"\s*(\w+)", val)
            if m:
                verdicts["spf"] = m.group(1).lower()
    return verdicts


def read_sample_emails() -> list:
    """
    Analyze the bundled sample .eml files exactly like real mail, labeled
    source="sample". Served ONLY behind the explicit demo mode of
    /gmail-emails?demo=1 — never as a stand-in for a live inbox.
    """
    base = Path(__file__).resolve().parent
    candidates = (
        list(base.glob("temp_*.eml"))
        + list(base.parent.glob("temp_*.eml"))
        + list((base.parent / "samples").glob("temp_*.eml"))
    )
    results = []

    for p in candidates[:10]:
        try:
            parsed = parse_email(str(p))
            body = parsed.get("body", "")
            combined = (
                f"Subject: {parsed.get('subject', '')}\n"
                f"From: {parsed.get('from', '')}\n"
                f"Body: {body}"
            )
            verdict = analyze_email(combined, auth_results=parsed.get("auth_results"))
            results.append({
                "subject":       parsed.get("subject", p.name),
                "from":          parsed.get("from", "Unknown"),
                "verdict":       verdict.get("verdict", "SAFE"),
                "score":         verdict.get("score", 0),
                "risk_score":    verdict.get("risk_score", verdict.get("score", 0)),
                "reasons":       verdict.get("reasons", []),
                "auth_results":  verdict.get("auth_results", {"spf": "none", "dkim": "none", "dmarc": "none"}),
                "sender_origin": verdict.get("sender_origin"),
                "genuine_ratio": verdict.get("genuine_ratio"),
                "body":          body,
                "source":        "sample",
            })
        except Exception:
            # A sample that fails to parse is silently skipped — demo mode
            # must never fabricate result rows.
            continue

    return results


def _decode_body(payload):
    snippet = ""
    def walk(part):
        nonlocal snippet
        if not isinstance(part, dict):
            return
        body = part.get("body", {})
        data = body.get("data")
        if data and part.get("mimeType") in ("text/plain", "text/html"):
            try:
                decoded = base64.urlsafe_b64decode(data + "===")
                text = decoded.decode("utf-8", errors="ignore")
                if text and not snippet:
                    snippet = text[:4000]
            except Exception:
                pass
        for child in part.get("parts", []) or []:
            walk(child)
    walk(payload)
    return snippet


def _fetch_live_emails() -> list:
    """
    Fetch + score recent Gmail messages via the Gmail API. Raises on any
    failure — read_gmail() turns that into an honest {"status": "error"}.
    """
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = None
    if TOKEN_PATH.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                str(CREDENTIALS_PATH),
                SCOPES
            )
            # Desktop local OAuth. Browser will open on first run.
            creds = flow.run_local_server(port=0)

        TOKEN_PATH.write_text(creds.to_json(), encoding="utf-8")

    service = build("gmail", "v1", credentials=creds, cache_discovery=False)

    results = service.users().messages().list(
        userId="me",
        maxResults=10,
        q="newer_than:30d"
    ).execute()

    messages = results.get("messages", [])
    email_list = []

    for msg in messages:
        message = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()

        payload = message.get("payload", {})
        headers = payload.get("headers", [])

        subject = next((h.get("value", "") for h in headers if h.get("name", "").lower() == "subject"), "No Subject")
        sender  = next((h.get("value", "") for h in headers if h.get("name", "").lower() == "from"), "Unknown")

        body     = _decode_body(payload) or message.get("snippet", "")
        combined = f"Subject: {subject}\nFrom: {sender}\nBody: {body}"

        auth_results = _gmail_auth_from_headers(headers)
        result = analyze_email(combined, auth_results=auth_results)

        email_list.append({
            "subject":       subject,
            "from":          sender,
            "verdict":       result.get("verdict", "SAFE"),
            "score":         result.get("score", 0),
            "risk_score":    result.get("risk_score", result.get("score", 0)),
            "reasons":       result.get("reasons", []),
            "auth_results":  result.get("auth_results", auth_results),
            "sender_origin": result.get("sender_origin"),
            "genuine_ratio": result.get("genuine_ratio"),
            "body":          body,
            "source":        "gmail",
        })

    return email_list


def read_gmail() -> dict:
    """
    Honest Gmail read — returns a status object, NEVER a fabricated inbox:
      {"status": "not_connected", "detail": ..., "emails": []}  credentials.json missing
      {"status": "connected",     "emails": [...]}              live scan (may be empty)
      {"status": "error",         "detail": ..., "emails": []}  auth/network failure
    """
    if not CREDENTIALS_PATH.exists():
        return {
            "status": "not_connected",
            "detail": (
                "backend/credentials.json not found. Add your Google OAuth "
                "client file to enable live inbox scanning."
            ),
            "emails": [],
        }

    try:
        return {"status": "connected", "emails": _fetch_live_emails()}
    except Exception as e:
        return {
            "status": "error",
            "detail": f"Gmail scan failed: {str(e)[:180]}",
            "emails": [],
        }
