from email import policy
from email.parser import BytesParser
import hashlib
import re

_AUTH_TOKEN_RE = re.compile(r'\b(spf|dkim|dmarc)=(\w+)', re.IGNORECASE)


def _parse_auth_results(msg) -> dict:
    """
    Extract real SPF/DKIM/DMARC verdicts from structured email headers.

    Reads (in order):
      - All 'Authentication-Results' headers  (spf= dkim= dmarc= tokens)
      - 'Received-SPF' header                 (fallback for SPF when A-R is absent)

    Returns {"spf": str, "dkim": str, "dmarc": str} with lowercase verdict words
    (pass / fail / softfail / neutral / none / unknown).
    """
    verdicts = {"spf": "none", "dkim": "none", "dmarc": "none"}

    for header_val in (msg.get_all("Authentication-Results") or []):
        for key, val in _AUTH_TOKEN_RE.findall(header_val):
            verdicts[key.lower()] = val.lower()

    # Received-SPF supplements when Authentication-Results is absent
    received_spf = msg.get("Received-SPF") or ""
    if received_spf and verdicts["spf"] == "none":
        m = re.match(r"\s*(\w+)", received_spf)
        if m:
            verdicts["spf"] = m.group(1).lower()

    return verdicts


def _extract_attachments(msg) -> list:
    """
    Collect each attachment's filename, size and SHA-256 hash.

    Returns [{"filename": str, "content_type": str, "size": int, "sha256": str}].
    Inline images and body parts are skipped — only real attachments are hashed.
    """
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disposition != "attachment" and not filename:
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if not payload:
            continue
        attachments.append({
            "filename": filename or "unnamed",
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    return attachments


def parse_email(path):

    result = {
        "subject": "",
        "from": "",
        "body": "",
        "auth_results": {"spf": "none", "dkim": "none", "dmarc": "none"},
        "attachments": [],
    }

    try:

        with open(path, "rb") as f:

            msg = BytesParser(
                policy=policy.default
            ).parse(f)

        result["subject"] = str(msg.get("subject", ""))
        result["from"]    = str(msg.get("from", ""))
        result["auth_results"] = _parse_auth_results(msg)
        result["attachments"] = _extract_attachments(msg)

        if msg.is_multipart():

            parts = []

            for part in msg.walk():

                ctype = part.get_content_type()

                if ctype == "text/plain":

                    try:

                        parts.append(
                            part.get_content()
                        )

                    except Exception:
                        pass    # undecodable part — skip it, keep the rest

            result["body"] = "\n".join(parts)

        else:

            try:

                result["body"] = msg.get_content()

            except Exception:

                result["body"] = ""

    except Exception as e:

        result["body"] = f"Email parse failed: {str(e)}"

    return result