"""
Email notifications for support tickets (WORK_PLAN Task 12).

The TOOL's own mail account sends new-ticket notifications to the site
owner's inbox — the owner's address is a server-side env var and is NEVER
exposed on the website. If SMTP isn't configured, send_ticket_notification()
is a safe no-op that reports "not configured" (tickets still land in the
admin Support inbox regardless).

Configure in backend/.env:
    NEXGUARD_SMTP_HOST=smtp.gmail.com
    NEXGUARD_SMTP_PORT=587
    NEXGUARD_SMTP_USER=nexguard.support@gmail.com
    NEXGUARD_SMTP_PASSWORD=<app password>
    NEXGUARD_SUPPORT_TO=owner@example.com      # where tickets are emailed
    NEXGUARD_SMTP_FROM=nexguard.support@gmail.com   # optional; defaults to USER
"""
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

logger = logging.getLogger("nexguard.notify")


def smtp_configured() -> bool:
    return bool(
        os.getenv("NEXGUARD_SMTP_HOST")
        and os.getenv("NEXGUARD_SMTP_USER")
        and os.getenv("NEXGUARD_SMTP_PASSWORD")
        and os.getenv("NEXGUARD_SUPPORT_TO")
    )


def _build_message(ticket: dict) -> EmailMessage:
    sender = os.getenv("NEXGUARD_SMTP_FROM") or os.getenv("NEXGUARD_SMTP_USER")
    msg = EmailMessage()
    msg["Subject"] = f"[NexGuard support #{ticket['id']}] {ticket.get('subject') or ticket.get('category', 'ticket')}"
    msg["From"] = sender
    msg["To"] = os.getenv("NEXGUARD_SUPPORT_TO")
    # Let the owner reply straight to the reporter.
    if ticket.get("email"):
        msg["Reply-To"] = ticket["email"]
    msg.set_content(
        f"New support ticket #{ticket['id']}\n"
        f"From: {ticket.get('email', 'unknown')}"
        + (f" (user #{ticket['user_id']})" if ticket.get("user_id") else " (not signed in)")
        + f"\nCategory: {ticket.get('category', 'question')}\n"
        f"Subject: {ticket.get('subject') or '(none)'}\n"
        f"When: {ticket.get('created_at', '')}\n\n"
        f"{ticket.get('message', '')}\n\n"
        f"— Reply from the NexGuard admin Support inbox, or just reply to this email."
    )
    return msg


def send_ticket_notification(ticket: dict) -> dict:
    """
    Email a new ticket to the owner. Returns {sent: bool, detail: str}.
    Never raises — a mail failure must not break ticket creation.
    """
    if not smtp_configured():
        logger.info("SMTP not configured; ticket #%s stored, no email sent.", ticket.get("id"))
        return {"sent": False, "detail": "email notifications not configured"}

    host = os.getenv("NEXGUARD_SMTP_HOST")
    port = int(os.getenv("NEXGUARD_SMTP_PORT", "587"))
    user = os.getenv("NEXGUARD_SMTP_USER")
    password = os.getenv("NEXGUARD_SMTP_PASSWORD")

    try:
        msg = _build_message(ticket)
        context = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
                server.login(user, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.starttls(context=context)
                server.login(user, password)
                server.send_message(msg)
        logger.info("Support ticket #%s emailed to owner.", ticket.get("id"))
        return {"sent": True, "detail": "email sent"}
    except Exception as e:
        logger.warning("Support ticket email failed: %s", e)
        return {"sent": False, "detail": f"email failed: {str(e)[:120]}"}
