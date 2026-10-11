"""
NexGuard AI — Telegram bot (T1): every scan tool over Telegram.

Send the bot:
  * a link or a question  -> /support/ask (a URL runs the REAL full scan; a
                             scam-looking pasted message runs the email
                             analyzer; anything else gets the FAQ answer —
                             the same trustable chat replies as the web
                             Support bot)
  * a photo               -> ALL THREE checks, one combined reply: /scan-qr
                             (QR decoded + its link scanned), /analyze-screenshot
                             (OCR scam check), /analyze-image-origin (AI or real?)
  * a voice note / audio  -> /analyze-voice (ffmpeg converts Telegram's .oga)
  * an .eml file          -> /analyze-email
  * /start or /help       -> capability card with tap-to-scan buttons

UX: inline buttons guide each flow (ForceReply prompts), every scan shows an
instant "Scanning…" message that is edited into the final rich HTML reply
(bold verdict, risk bar, why-bullets, safety tip). Replies are English only
(user decision 2026-07-19); users can write in any language.

Design: long-polling (getUpdates), so it runs on the same machine as the
local backend — no public hosting, no webhook. The bot is a pure API CLIENT
of the running backend (exactly like the browser extension): quotas, scan
history and the live threat feed behave the same as the web app. Replies only
relay what the engine actually found — the bot never invents a verdict.

Setup (backend/.env or environment):
  NEXGUARD_TELEGRAM_TOKEN   required — create a bot with @BotFather on
                            Telegram (/newbot) and paste the token here;
                            several bots: comma-separated, all run at once
  NEXGUARD_BOT_EMAIL       optional — sign the bot's scans into an account
  NEXGUARD_BOT_PASSWORD     optional   for the higher daily scan limit
  NEXGUARD_BACKEND_URL      optional — default http://127.0.0.1:8000

Run (two terminals):
  1) cd backend && py -m uvicorn main:app --host 127.0.0.1 --port 8000
  2) cd backend && py telegram_bot.py
"""

import html
import logging
import os
import subprocess
import sys
import time

import requests

try:                                    # load backend/.env like main.py does
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except Exception:
    pass

BACKEND_URL = (os.getenv("NEXGUARD_BACKEND_URL") or "http://127.0.0.1:8000").rstrip("/")
TOKENS = [t.strip() for t in (os.getenv("NEXGUARD_TELEGRAM_TOKEN") or "").split(",")
          if t.strip()]
TOKEN = TOKENS[0] if TOKENS else ""     # this process's bot; extras -> main()
BOT_EMAIL = (os.getenv("NEXGUARD_BOT_EMAIL") or "").strip()
BOT_PASSWORD = os.getenv("NEXGUARD_BOT_PASSWORD") or ""

POLL_TIMEOUT_S = 50                     # Telegram long-poll window
SCAN_TIMEOUT_S = 120                    # voice transcription can be slow

log = logging.getLogger("nexguard.telegram")


class BackendDown(Exception):
    """The NexGuard backend could not be reached — the honest reply says so."""


# ---------------------------------------------------------------------------
# Message classification — what did the user send?
# ---------------------------------------------------------------------------

_IMAGE_EXT = (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif")
_AUDIO_EXT = (".wav", ".mp3", ".m4a", ".ogg", ".oga", ".opus", ".aac",
              ".flac", ".mp4", ".amr")
_EMAIL_EXT = (".eml", ".msg", ".txt")


def classify_message(msg):
    """Return (kind, data): kind in text|photo|voice|email|unsupported."""
    if not isinstance(msg, dict):
        return "unsupported", {}
    text = msg.get("text")
    if isinstance(text, str) and text.strip():
        return "text", {"text": text}

    photos = msg.get("photo")
    if isinstance(photos, list) and photos:
        best = max(photos, key=lambda p: p.get("width", 0) or 0)
        if best.get("file_id"):
            return "photo", {"file_id": best["file_id"]}

    for key in ("voice", "audio", "video_note"):
        media = msg.get(key)
        if isinstance(media, dict) and media.get("file_id"):
            data = {"file_id": media["file_id"]}
            if media.get("file_name"):          # real name only — the download
                data["name"] = media["file_name"]   # provides one otherwise
            return "voice", data

    doc = msg.get("document")
    if isinstance(doc, dict) and doc.get("file_id"):
        name = (doc.get("file_name") or "").lower()
        data = {"file_id": doc["file_id"], "name": doc.get("file_name") or "file"}
        if name.endswith(_EMAIL_EXT):
            return "email", data
        if name.endswith(_IMAGE_EXT):
            return "photo", data
        if name.endswith(_AUDIO_EXT):
            return "voice", data

    return "unsupported", {}


# ---------------------------------------------------------------------------
# Trustable reply composition — relay the engine's result, never invent
# ---------------------------------------------------------------------------

def verdict_emoji(verdict):
    v = (verdict or "").upper()
    if v == "SAFE":
        return "\U0001F7E2"        # green circle
    if v == "SUSPICIOUS":
        return "\U0001F7E1"        # yellow circle
    if v == "MALICIOUS":
        return "\U0001F534"        # red circle
    return "⚪"


def _esc(text):
    """Escape engine/user text before it goes into a parse_mode:HTML message."""
    return html.escape(str(text), quote=False)


def risk_bar(risk):
    """10-block bar: risk 88 -> ▓▓▓▓▓▓▓▓▓░ (nearest block, junk-safe)."""
    try:
        filled = min(10, max(0, (int(risk) + 5) // 10))
    except (TypeError, ValueError):
        filled = 0
    return "▓" * filled + "░" * (10 - filled)


# Static per-kind safety tips shown under risky verdicts — no LLM involved.
_TIPS = {
    "voice message": ("💡 Tip: Banks never ask for OTPs or PINs on a call. "
                      "Hang up and dial the official number yourself."),
    "email": ("💡 Tip: Check the real sender address — scammers copy a bank's "
              "name but can't copy its domain."),
    "screenshot": ("💡 Tip: Never share OTPs in chat — no genuine company "
                   "asks for them."),
}
_TIP_DEFAULT = ("💡 Tip: Never enter passwords or OTPs on a page you reached "
                "from a random message.")


def suggestion_tip(kind_label, verdict):
    """A static tip for risky verdicts; None when there is nothing to warn about."""
    if (verdict or "").upper() not in ("MALICIOUS", "SUSPICIOUS"):
        return None
    return _TIPS.get(kind_label, _TIP_DEFAULT)


def compose_result_reply(kind_label, result):
    """Rich HTML Telegram reply: bold verdict, risk bar, why-bullets, tip.
    English only (user decision 2026-07-19) — findings relayed verbatim,
    HTML-escaped so engine text can never break or fake the formatting."""
    result = result or {}
    verdict = (result.get("verdict") or "UNKNOWN").upper()
    risk = result.get("risk_score", result.get("score", 0)) or 0
    lines = [f"{verdict_emoji(verdict)} <b>{verdict}</b> — {_esc(kind_label)}",
             f"Risk: {risk_bar(risk)} {risk}/100"]

    conf = result.get("confidence")
    if conf not in (None, ""):
        conf_text = f"{conf}%" if isinstance(conf, (int, float)) else _esc(conf)
        lines.append(f"Confidence: {conf_text}")

    summary = (result.get("plain_summary") or result.get("analysis")
               or result.get("ai_explanation") or result.get("summary") or "")
    if summary:
        lines.append("")
        lines.append(_esc(summary))

    reasons = (result.get("reasons") or result.get("indicators")
               or result.get("flags") or [])
    top = [_esc(r) for r in reasons[:3] if r]
    if top:
        lines.append("")
        lines.append("<b>Why:</b>")
        lines.extend(f"• {r}" for r in top)

    tail = (suggestion_tip(kind_label, verdict) if verdict != "SAFE"
            else "Stay alert anyway — no scanner can promise 100%.")
    if tail:
        lines.append("")
        lines.append(tail)
    return "\n".join(lines)


class Reply(str):
    """A reply string that optionally carries a Telegram reply_markup dict,
    so composers stay pure and the send layer decides how to deliver it."""

    def __new__(cls, text, markup=None):
        s = str.__new__(cls, text)
        s.markup = markup
        return s


MAIN_MENU = {"inline_keyboard": [
    [{"text": "🔗 Scan a link", "callback_data": "scan_link"},
     {"text": "🖼 Check a photo", "callback_data": "scan_photo"}],
    [{"text": "🎤 Check a voice", "callback_data": "scan_voice"},
     {"text": "📧 Check an email", "callback_data": "scan_email"}],
    [{"text": "❓ Help", "callback_data": "help"}],
]}


def result_buttons():
    return {"inline_keyboard": [
        [{"text": "🔁 Scan another", "callback_data": "menu"}],
        [{"text": "📄 Full report", "callback_data": "full_report"},
         {"text": "⚠️ Report wrong verdict", "callback_data": "report_wrong"}],
    ]}


def help_text():
    return (
        "🛡 <b>NexGuard AI</b> — your personal scam scanner.\n"
        "I use the real NexGuard engine and only report what it actually "
        "found — when I can't judge something I say UNKNOWN instead of "
        "guessing.\n\n"
        "<b>What I can check:</b>\n"
        "🔗 A link — full phishing scan, with the reasons\n"
        "🖼 A photo — QR codes decoded and their link scanned; chat "
        "screenshots checked for scam wording\n"
        "🎤 A voice note or audio file — scam-call detection, any language\n"
        "📧 An email — send an .eml file or paste the message text\n"
        "❓ Or just ask me a question about the tools\n\n"
        "Tap a button below, or simply send me something to check.\n"
        "You can write to me in any language — I reply in English."
    )


_UNSUPPORTED = ("I can't check that kind of message yet. Send me a link, a photo "
                "(QR or screenshot), a voice note, an .eml email file, or plain text.")

_BACKEND_DOWN = ("⚠ I could not reach the NexGuard backend, so this was NOT scanned. "
                 "Start the backend (py -m uvicorn main:app) and try again.")


# ---------------------------------------------------------------------------
# HTTP — Telegram API + backend API (thin wrappers, monkeypatched in tests)
# ---------------------------------------------------------------------------

_session = requests.Session()
_auth_token = None


def _auth_headers():
    return {"Authorization": f"Bearer {_auth_token}"} if _auth_token else {}


def sign_in():
    """Optional account sign-in (higher daily limit). Never raises."""
    global _auth_token
    if not (BOT_EMAIL and BOT_PASSWORD):
        return
    try:
        r = _session.post(f"{BACKEND_URL}/auth/login",
                          json={"email": BOT_EMAIL, "password": BOT_PASSWORD},
                          timeout=15)
        _auth_token = (r.json() or {}).get("token") if r.ok else None
        log.info("Bot account sign-in %s", "OK" if _auth_token else "failed")
    except Exception as e:
        log.warning("Bot account sign-in failed: %s", e)
        _auth_token = None


def backend_json(path, payload):
    """POST JSON to the backend; BackendDown when unreachable."""
    try:
        r = _session.post(f"{BACKEND_URL}{path}", json=payload,
                          headers=_auth_headers(), timeout=SCAN_TIMEOUT_S)
    except requests.RequestException as e:
        raise BackendDown(str(e))
    if r.status_code == 429:
        return {"answer": ("Today's scan limit is used up. I can still answer "
                           "questions about the tools.")}
    try:
        return r.json()
    except ValueError:
        raise BackendDown(f"non-JSON reply (HTTP {r.status_code})")


def backend_upload(path, filename, blob):
    """POST a file to a backend analyzer; BackendDown when unreachable."""
    try:
        r = _session.post(f"{BACKEND_URL}{path}",
                          files={"file": (filename, blob)},
                          headers=_auth_headers(), timeout=SCAN_TIMEOUT_S)
    except requests.RequestException as e:
        raise BackendDown(str(e))
    if r.status_code == 429:
        return {"verdict": "UNKNOWN", "risk_score": 0,
                "analysis": "Today's scan limit is used up — this file was NOT scanned."}
    try:
        return r.json()
    except ValueError:
        raise BackendDown(f"non-JSON reply (HTTP {r.status_code})")


def tg(method, payload):
    """Call the Telegram Bot API. Returns the 'result' field (or None)."""
    r = _session.post(f"https://api.telegram.org/bot{TOKEN}/{method}",
                      json=payload, timeout=POLL_TIMEOUT_S + 10)
    data = r.json() if r.ok else {}
    return data.get("result")


def tg_download(file_id):
    """Download a Telegram file. Returns (bytes, filename)."""
    info = tg("getFile", {"file_id": file_id}) or {}
    file_path = info.get("file_path") or ""
    if not file_path:
        raise RuntimeError("Telegram getFile returned no path")
    r = _session.get(
        f"https://api.telegram.org/file/bot{TOKEN}/{file_path}", timeout=60)
    r.raise_for_status()
    return r.content, os.path.basename(file_path) or "file"


# ---------------------------------------------------------------------------
# C3 — per-chat conversation memory (text turns only; in-memory, resets on
# restart). Lets "scan it again" re-run the scan on the URL from earlier.
# ---------------------------------------------------------------------------

_MEMORY_TURNS = 6
_chat_memory = {}                       # chat_id -> [{role, text}]


def remember_turn(chat_id, role, text):
    if chat_id is None or not text:
        return
    turns = _chat_memory.setdefault(chat_id, [])
    turns.append({"role": role, "text": str(text)[:2000]})
    del turns[:-_MEMORY_TURNS]


def chat_history(chat_id):
    return list(_chat_memory.get(chat_id, []))


# ---------------------------------------------------------------------------
# Routing — one message in, one honest reply out
# ---------------------------------------------------------------------------

_last_result = {}                       # chat_id -> {"label", "result"} for the
                                        # Full-report / wrong-verdict buttons

def _try_upload(path, filename, blob):
    """One photo sub-check; None instead of an exception so the other
    sections of the combined reply still reach the user."""
    try:
        return backend_upload(path, filename, blob)
    except BackendDown:
        return None
    except Exception as e:
        log.warning("photo sub-scan %s failed: %s", path, e)
        return None


def _scan_media(kind, data):
    """Run the right analyzer(s) for a media message. Returns (label, result);
    for photos the result is a combo dict — user decision 2026-07-19: every
    photo gets ALL THREE checks (QR + scam screenshot + AI origin)."""
    blob, name = tg_download(data["file_id"])
    filename = data.get("name") or name
    if kind == "photo":
        qr = _try_upload("/scan-qr", filename, blob)
        no_qr = qr is not None and (
            (qr.get("verdict") or "").upper() == "UNKNOWN"
            and "QR not detected" in str(qr.get("analysis", "")))
        combo = {
            "qr": None if no_qr else qr,
            "qr_checked": qr is not None,
            "screenshot": _try_upload("/analyze-screenshot", filename, blob),
            "origin": _try_upload("/analyze-image-origin", filename, blob),
        }
        if not combo["qr_checked"] and combo["screenshot"] is None \
                and combo["origin"] is None:
            raise BackendDown("all photo checks unreachable")
        return "photo", combo
    if kind == "voice":
        return "voice message", backend_upload("/analyze-voice", filename, blob)
    return "email", backend_upload("/analyze-email", filename, blob)


_ORIGIN_TITLES = {
    "AI_GENERATED": "AI-generated (confirmed)",
    "LIKELY_AI": "Likely AI-generated",
    "LIKELY_REAL": "Likely a real photo",
    "UNCERTAIN": "Uncertain",
}


def _origin_section(origin, cap=2):
    """The 🤖 lines for the AI-origin part of a photo reply."""
    if not origin:
        return "🤖 AI image check unavailable for this photo."
    verdict = (origin.get("verdict") or "UNCERTAIN").upper()
    line = f"🤖 <b>AI image check:</b> {_ORIGIN_TITLES.get(verdict, 'Uncertain')}"
    conf = origin.get("confidence")
    if verdict in ("LIKELY_AI", "LIKELY_REAL") and conf:
        line += f" ({conf}%)"
    lines = [line]
    gen = origin.get("generator")
    if gen:
        link = origin.get("generator_link")
        lines.append(f"Made with {_esc(gen)}"
                     + (f" — {_esc(link)}" if link else ""))
    reasons = origin.get("reasons") or []
    lines.extend(f"• {_esc(r)}" for r in (reasons[:cap] if cap else reasons) if r)
    return "\n".join(lines)


def compose_photo_reply(combo):
    """One combined HTML reply: QR verdict + scam-text verdict + AI origin."""
    combo = combo or {}
    parts = []
    if combo.get("qr"):
        parts.append(compose_result_reply("QR code", combo["qr"]))
    elif combo.get("qr_checked"):
        parts.append("No QR code found in the photo.")
    else:
        parts.append("QR check unavailable for this photo.")
    shot = combo.get("screenshot")
    parts.append(compose_result_reply("screenshot", shot) if shot
                 else "Screenshot scam check unavailable for this photo.")
    parts.append(_origin_section(combo.get("origin")))
    return "\n\n".join(parts)


def _record_result(chat_id, label, result):
    if chat_id is not None:
        _last_result[chat_id] = {"label": label, "result": result or {}}


_chat_pending = {}                      # chat_id -> guided flow ("link"|"photo"|
                                        # "voice"|"email"), cleared by next message

_GUIDED = {
    "scan_link": ("link", "Paste the link you want me to check 👇", "https://…"),
    "scan_photo": ("photo", "Send the photo now — I'll decode any QR code in it "
                            "and check it for scam signs.", "attach a photo"),
    "scan_voice": ("voice", "Send the voice note or audio file you want me to "
                            "check 👇", "attach a voice note"),
    "scan_email": ("email", "Send the email as an .eml file, or paste the full "
                            "message text 👇", "paste the email text"),
}

_NO_RECENT_SCAN = ("I don't have a recent scan in this chat — send me "
                   "something to scan first.")


def compose_full_report(entry):
    """Everything the engine returned for the chat's last scan — no 3-reason cap."""
    label, result = entry["label"], entry["result"] or {}
    if label == "photo":
        parts = ["📄 <b>Full report</b> — photo (QR + scam text + AI origin)"]
        for section_label, key in (("QR code", "qr"), ("screenshot", "screenshot")):
            sub = result.get(key)
            if sub:
                parts.append(_full_detail(section_label, sub))
        parts.append(_origin_section(result.get("origin"), cap=0))
        return Reply("\n\n".join(parts),
                     {"inline_keyboard": [[{"text": "🔁 Scan another",
                                            "callback_data": "menu"}]]})
    return Reply(f"📄 <b>Full report</b> — {_esc(label)}\n\n"
                 + _full_detail(label, result),
                 {"inline_keyboard": [[{"text": "🔁 Scan another",
                                        "callback_data": "menu"}]]})


def _full_detail(label, result):
    """Uncapped detail block for one engine result (used by Full report)."""
    result = result or {}
    verdict = (result.get("verdict") or "UNKNOWN").upper()
    risk = result.get("risk_score", result.get("score", 0)) or 0
    lines = [f"{verdict_emoji(verdict)} <b>{verdict}</b> — {_esc(label)}",
             f"Risk: {risk_bar(risk)} {risk}/100"]
    target = result.get("target") or result.get("url")
    if target:
        lines.append(f"Target: <code>{_esc(target)}</code>")
    conf = result.get("confidence")
    if conf not in (None, ""):
        lines.append(f"Confidence: {conf}%" if isinstance(conf, (int, float))
                     else f"Confidence: {_esc(conf)}")
    summary = (result.get("plain_summary") or result.get("analysis")
               or result.get("ai_explanation") or result.get("summary") or "")
    if summary:
        lines.append("")
        lines.append(_esc(summary))
    reasons = (result.get("reasons") or result.get("indicators")
               or result.get("flags") or [])
    every = [_esc(r) for r in reasons if r]
    if every:
        lines.append("")
        lines.append(f"<b>All findings ({len(every)}):</b>")
        lines.extend(f"• {r}" for r in every)
    return "\n".join(lines)


def _file_wrong_verdict_ticket(chat_id):
    """Open a wrong_info support ticket about the chat's last scan."""
    entry = _last_result.get(chat_id)
    if not entry:
        return _NO_RECENT_SCAN
    result = entry["result"] or {}
    reasons = "; ".join(str(r) for r in (result.get("reasons") or [])[:5]) or "-"
    message = ("Telegram user reports a wrong verdict.\n"
               f"Kind: {entry['label']}\n"
               f"Verdict: {(result.get('verdict') or 'UNKNOWN').upper()}\n"
               f"Risk: {result.get('risk_score', result.get('score', 0)) or 0}\n"
               f"Target: {result.get('target') or result.get('url') or '-'}\n"
               f"Reasons: {reasons}")
    resp = backend_json("/support/tickets", {
        "email": BOT_EMAIL or "telegram-user@nexguard.local",
        "subject": "Telegram: wrong verdict report",
        "message": message,
        "category": "wrong_info",
    }) or {}
    if resp.get("ok"):
        return ("✅ Thanks — your report was filed and the NexGuard team will "
                "review this verdict.")
    return ("I could not file the report right now — please try again later.")


def handle_callback(cb):
    """React to a button press; always returns the Reply to send."""
    cb = cb or {}
    chat_id = (((cb.get("message") or {}).get("chat")) or {}).get("id")
    data = cb.get("data") or ""
    try:
        if data in _GUIDED:
            kind, prompt, placeholder = _GUIDED[data]
            if chat_id is not None:
                _chat_pending[chat_id] = kind
            return Reply(prompt, {"force_reply": True,
                                  "input_field_placeholder": placeholder})
        if data == "full_report":
            entry = _last_result.get(chat_id)
            return compose_full_report(entry) if entry else _NO_RECENT_SCAN
        if data == "report_wrong":
            return _file_wrong_verdict_ticket(chat_id)
        # "help", "menu", or anything unknown -> the capability card is the
        # safest, most useful answer.
        return Reply(help_text(), MAIN_MENU)
    except BackendDown as e:
        log.warning("Backend unreachable: %s", e)
        return _BACKEND_DOWN
    except Exception as e:                      # a bad button must not kill the bot
        log.exception("Callback failed: %s", e)
        return "Something went wrong with that button — please try again."


def handle_message(msg):
    """Route one Telegram message; always returns a Reply/plain string."""
    kind, data = classify_message(msg)
    chat_id = ((msg or {}).get("chat") or {}).get("id")
    try:
        # Guided flows are one-shot: whatever arrives next consumes the state.
        pending = _chat_pending.pop(chat_id, None) if chat_id is not None else None
        if kind == "text":
            text = data["text"].strip()
            if text.startswith(("/start", "/help")):
                return Reply(help_text(), MAIN_MENU)
            if pending == "email":
                # The user chose "Check an email" and pasted the text — run the
                # real email analyzer instead of guessing intent.
                result = backend_upload("/analyze-email", "pasted.txt",
                                        text.encode("utf-8"))
                _record_result(chat_id, "email", result)
                return Reply(compose_result_reply("email", result),
                             result_buttons())
            answer = backend_json("/support/ask", {
                "question": text,
                "history": chat_history(chat_id),        # C3 follow-ups
            }) or {}
            raw = answer.get("answer") or _UNSUPPORTED
            remember_turn(chat_id, "user", text)
            remember_turn(chat_id, "bot", raw)
            # A real scan ran — add the rich headline + action buttons on top
            # of the engine's own English explanation.
            scan = answer.get("scan")
            if isinstance(scan, dict) and scan.get("verdict"):
                verdict = str(scan["verdict"]).upper()
                risk = scan.get("risk_score", 0) or 0
                head = (f"{verdict_emoji(verdict)} <b>{verdict}</b> — link\n"
                        f"Risk: {risk_bar(risk)} {risk}/100")
                _record_result(chat_id, "link", scan)
                return Reply(head + "\n\n" + _esc(raw), result_buttons())
            return _esc(raw)
        if kind in ("photo", "voice", "email"):
            label, result = _scan_media(kind, data)
            _record_result(chat_id, label, result)
            text_out = (compose_photo_reply(result) if kind == "photo"
                        else compose_result_reply(label, result))
            return Reply(text_out, result_buttons())
        return _UNSUPPORTED
    except BackendDown as e:
        log.warning("Backend unreachable: %s", e)
        return _BACKEND_DOWN
    except Exception as e:                      # one bad update must not kill the bot
        log.exception("Handling failed: %s", e)
        return ("Something went wrong while checking that — it was NOT "
                "scanned. Please try again.")


# ---------------------------------------------------------------------------
# Send layer + long-poll loop — progress "animation": every scan gets an
# instant "Scanning…" message that is edited into the final rich reply, so
# the bot never looks dead during a 30–60 s voice/photo analysis.
# ---------------------------------------------------------------------------

ALLOWED_UPDATES = ["message", "callback_query"]


def progress_text(kind):
    return {
        "photo": ("🔍 Scanning your photo… QR + scam-text + AI-origin checks "
                  "(can take up to a minute)."),
        "voice": "🎧 Listening to the audio… transcription can take up to a minute.",
        "email": "📧 Analyzing the email…",
    }.get(kind, "🔍 Checking…")


def send_reply(chat_id, reply, edit_message_id=None, reply_to=None):
    """Deliver a Reply: edit the progress message when there is one, fall back
    to a fresh send, and drop parse_mode as a last resort so a formatting
    problem can never swallow a verdict."""
    payload = {"chat_id": chat_id, "text": str(reply)[:4000],
               "parse_mode": "HTML", "disable_web_page_preview": True}
    markup = getattr(reply, "markup", None)
    if markup:
        payload["reply_markup"] = markup
    if edit_message_id is not None:
        if tg("editMessageText", {**payload, "message_id": edit_message_id}):
            return
    elif reply_to is not None:
        payload["reply_to_message_id"] = reply_to
    if not tg("sendMessage", payload):
        plain = {k: v for k, v in payload.items() if k != "parse_mode"}
        tg("sendMessage", plain)


def process_update(upd):
    """Handle one getUpdates entry — a message or a button press."""
    upd = upd or {}
    cb = upd.get("callback_query")
    if cb:
        tg("answerCallbackQuery", {"callback_query_id": cb.get("id")})
        chat_id = (((cb.get("message") or {}).get("chat")) or {}).get("id")
        if chat_id is not None:
            send_reply(chat_id, handle_callback(cb))
        return
    msg = upd.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    if chat_id is None:
        return
    kind, _ = classify_message(msg)
    text = (msg.get("text") or "").strip()
    instant = kind == "text" and text.startswith(("/start", "/help"))
    tg("sendChatAction", {"chat_id": chat_id,
                          "action": "upload_photo" if kind == "photo" else "typing"})
    progress_id = None
    if not instant:
        sent = tg("sendMessage", {
            "chat_id": chat_id, "text": progress_text(kind),
            "reply_to_message_id": msg.get("message_id"),
        }) or {}
        progress_id = sent.get("message_id")
    send_reply(chat_id, handle_message(msg), edit_message_id=progress_id,
               reply_to=msg.get("message_id"))


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if not TOKEN:
        print("NEXGUARD_TELEGRAM_TOKEN is not set.\n"
              "1) In Telegram, talk to @BotFather -> /newbot -> copy the token\n"
              "2) Add NEXGUARD_TELEGRAM_TOKEN=<token> to backend/.env\n"
              "3) Run this again: py telegram_bot.py")
        return

    # Every extra comma-separated token (e.g. an old and a new bot) runs as its
    # own copy of this script with just that token — fully isolated chat
    # memory and poll offset. load_dotenv never overrides the env we pass.
    children = [subprocess.Popen([sys.executable, os.path.abspath(__file__)],
                                 env={**os.environ, "NEXGUARD_TELEGRAM_TOKEN": tok})
                for tok in TOKENS[1:]]
    try:
        poll_forever()
        for child in children:                  # own token rejected — keep
            child.wait()                        # the other bots running
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        for child in children:
            child.terminate()


def poll_forever():
    """Long-poll this process's bot; returns only if Telegram rejects TOKEN."""
    me = tg("getMe", {}) or {}
    if not me.get("username"):
        print(f"Telegram rejected the token ending ...{TOKEN[-4:]} (getMe "
              "failed). Check NEXGUARD_TELEGRAM_TOKEN in backend/.env.")
        return
    sign_in()
    print(f"NexGuard Telegram bot running as @{me['username']} "
          f"(backend {BACKEND_URL}). Press Ctrl+C to stop.")

    offset = 0
    while True:
        try:
            updates = tg("getUpdates", {
                "offset": offset, "timeout": POLL_TIMEOUT_S,
                "allowed_updates": ALLOWED_UPDATES,
            }) or []
            for upd in updates:
                offset = max(offset, upd.get("update_id", 0) + 1)
                process_update(upd)
        except Exception as e:                  # network blip — keep polling
            log.warning("Poll error: %s", e)
            time.sleep(3)


if __name__ == "__main__":
    main()
