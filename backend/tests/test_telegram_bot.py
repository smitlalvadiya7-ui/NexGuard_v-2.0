"""
T1 — Telegram bot: every scan tool over Telegram, as a pure API client of the
running backend (same engine, same quotas, same honest wording as the web
Support bot). These tests pin the offline logic — update classification,
trustable reply composition, and the routing/fallback rules — with the
Telegram and backend HTTP calls monkeypatched out.
"""

import telegram_bot as bot


# ---------------------------------------------------------------------------
# classify_message — what did the user send?
# ---------------------------------------------------------------------------

def test_plain_text_is_text():
    kind, data = bot.classify_message({"text": "is this safe http://x.top ?"})
    assert kind == "text"
    assert data["text"] == "is this safe http://x.top ?"

def test_photo_picks_the_largest_size():
    msg = {"photo": [
        {"file_id": "small", "width": 90},
        {"file_id": "big", "width": 1280},
        {"file_id": "mid", "width": 320},
    ]}
    kind, data = bot.classify_message(msg)
    assert kind == "photo"
    assert data["file_id"] == "big"

def test_voice_note_and_audio_are_voice():
    kind, data = bot.classify_message({"voice": {"file_id": "v1"}})
    assert (kind, data["file_id"]) == ("voice", "v1")
    kind, data = bot.classify_message({"audio": {"file_id": "a1", "file_name": "call.mp3"}})
    assert (kind, data["file_id"]) == ("voice", "a1")

def test_documents_route_by_extension():
    def doc(name):
        return {"document": {"file_id": "d1", "file_name": name}}
    assert bot.classify_message(doc("mail.eml"))[0] == "email"
    assert bot.classify_message(doc("shot.PNG"))[0] == "photo"
    assert bot.classify_message(doc("call.m4a"))[0] == "voice"
    assert bot.classify_message(doc("virus.exe"))[0] == "unsupported"

def test_junk_messages_never_throw():
    assert bot.classify_message({})[0] == "unsupported"
    assert bot.classify_message({"sticker": {}})[0] == "unsupported"
    assert bot.classify_message({"photo": []})[0] == "unsupported"


# ---------------------------------------------------------------------------
# compose_result_reply — a trustable answer: verdict + risk + why, no invention
# ---------------------------------------------------------------------------

RESULT = {
    "verdict": "MALICIOUS",
    "risk_score": 88,
    "confidence": 80,
    "plain_summary": "This link imitates a bank login page.",
    "reasons": ["Typosquat of icicibank.com", "Credential form on page",
                "Domain registered 3 days ago", "A fourth reason"],
}

def test_reply_has_verdict_risk_and_why():
    text = bot.compose_result_reply("link", RESULT)
    assert "MALICIOUS" in text
    assert "88" in text
    assert "This link imitates a bank login page." in text
    assert "Typosquat of icicibank.com" in text

def test_reply_caps_reasons_at_three():
    text = bot.compose_result_reply("link", RESULT)
    assert "A fourth reason" not in text

def test_reply_verdict_emojis():
    assert bot.verdict_emoji("SAFE") == "\U0001F7E2"
    assert bot.verdict_emoji("SUSPICIOUS") == "\U0001F7E1"
    assert bot.verdict_emoji("MALICIOUS") == "\U0001F534"
    assert bot.verdict_emoji("UNKNOWN") == "⚪"
    assert bot.verdict_emoji(None) == "⚪"

def test_unknown_is_honest_not_safe():
    text = bot.compose_result_reply("voice message", {
        "verdict": "UNKNOWN", "risk_score": 0,
        "analysis": "No transcript could be produced — this is NOT a safe verdict.",
    })
    assert "UNKNOWN" in text
    assert "NOT a safe verdict" in text

def test_reply_survives_missing_fields():
    text = bot.compose_result_reply("link", {})
    assert "UNKNOWN" in text


# ---------------------------------------------------------------------------
# UX upgrade — rich HTML replies: risk bar, escaping, static tips
# ---------------------------------------------------------------------------

def test_risk_bar_boundaries():
    assert bot.risk_bar(0) == "░" * 10
    assert bot.risk_bar(100) == "▓" * 10
    assert bot.risk_bar(88) == "▓" * 9 + "░"
    assert bot.risk_bar(55) == "▓" * 6 + "░" * 4
    assert bot.risk_bar(None) == "░" * 10          # junk never throws

def test_reply_is_html_with_bold_verdict_and_risk_bar():
    text = bot.compose_result_reply("link", RESULT)
    assert "<b>MALICIOUS</b>" in text
    assert "Risk: ▓▓▓▓▓▓▓▓▓░ 88/100" in text

def test_engine_text_is_html_escaped():
    text = bot.compose_result_reply("link", {
        "verdict": "SUSPICIOUS", "risk_score": 50,
        "plain_summary": "Page title is <script>alert(1)</script>",
        "reasons": ["Uses <iframe> & fake login"],
    })
    assert "&lt;script&gt;" in text
    assert "&lt;iframe&gt; &amp; fake login" in text
    assert "<script>" not in text

def test_malicious_link_reply_carries_a_tip():
    text = bot.compose_result_reply("link", RESULT)
    assert "💡 Tip:" in text

def _callback_datas(markup):
    return [b.get("callback_data")
            for row in (markup or {}).get("inline_keyboard", []) for b in row]

def test_reply_carrier_is_a_string_with_markup():
    r = bot.Reply("hello", markup={"inline_keyboard": []})
    assert isinstance(r, str) and r == "hello"
    assert r.markup == {"inline_keyboard": []}
    assert bot.Reply("plain").markup is None

def test_main_menu_buttons_cover_every_scanner():
    assert set(_callback_datas(bot.MAIN_MENU)) == {
        "scan_link", "scan_photo", "scan_voice", "scan_email", "help"}

def test_start_reply_carries_the_main_menu(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no backend call expected")
    monkeypatch.setattr(bot, "backend_json", boom)
    reply = bot.handle_message({"text": "/start"})
    assert reply.markup is bot.MAIN_MENU

def test_scan_reply_carries_action_buttons_and_last_result(monkeypatch):
    bot._last_result.clear()
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"img", "photo.jpg"))
    monkeypatch.setattr(bot, "backend_upload", lambda p, f, b: {
        "verdict": "MALICIOUS", "risk_score": 80,
        "analysis": "QR leads to a phishing page"})
    reply = bot.handle_message({"chat": {"id": 42},
                                "photo": [{"file_id": "p1", "width": 100}]})
    assert {"menu", "full_report", "report_wrong"} <= set(_callback_datas(reply.markup))
    assert bot._last_result[42]["result"]["qr"]["verdict"] == "MALICIOUS"

def test_text_scan_gets_rich_headline_buttons_and_last_result(monkeypatch):
    bot._chat_memory.clear()
    bot._last_result.clear()
    monkeypatch.setattr(bot, "backend_json", lambda p, payload: {
        "answer": "I ran a full scan on http://x.top.\nVerdict: MALICIOUS — risk score 88/100.",
        "action": "scanned_url",
        "scan": {"target": "http://x.top", "verdict": "MALICIOUS", "risk_score": 88},
    })
    reply = bot.handle_message({"chat": {"id": 7}, "text": "check http://x.top"})
    assert "<b>MALICIOUS</b>" in reply
    assert "▓" in reply
    assert "I ran a full scan" in reply
    assert "full_report" in _callback_datas(reply.markup)
    assert bot._last_result[7]["result"]["verdict"] == "MALICIOUS"

def test_faq_answer_has_no_buttons(monkeypatch):
    bot._chat_memory.clear()
    monkeypatch.setattr(bot, "backend_json", lambda p, payload: {
        "answer": "NexGuard scans links, emails, QR codes and voice notes."})
    reply = bot.handle_message({"chat": {"id": 8}, "text": "what can you do?"})
    assert getattr(reply, "markup", None) is None


def test_voice_tip_mentions_otp_and_safe_keeps_note_without_tip():
    voice = bot.compose_result_reply("voice message", {
        "verdict": "MALICIOUS", "risk_score": 97, "analysis": "Bank-OTP scam"})
    assert "💡 Tip:" in voice and "OTP" in voice
    safe = bot.compose_result_reply("link", {"verdict": "SAFE", "risk_score": 3})
    assert "no scanner can promise 100%" in safe
    assert "💡 Tip:" not in safe
    unknown = bot.compose_result_reply("link", {"verdict": "UNKNOWN"})
    assert "💡 Tip:" not in unknown


# ---------------------------------------------------------------------------
# handle_message — routing with the network stubbed out
# ---------------------------------------------------------------------------

def test_text_goes_to_support_ask(monkeypatch):
    seen = {}
    def fake_backend_json(path, payload):
        seen["path"], seen["payload"] = path, payload
        return {"answer": "I ran a full scan on http://x.top — MALICIOUS."}
    monkeypatch.setattr(bot, "backend_json", fake_backend_json)
    bot._chat_memory.clear()
    reply = bot.handle_message({"text": "check http://x.top"})
    assert seen["path"] == "/support/ask"
    assert seen["payload"] == {"question": "check http://x.top", "history": []}
    assert "MALICIOUS" in reply

def test_start_and_help_answer_without_backend(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no backend call expected")
    monkeypatch.setattr(bot, "backend_json", boom)
    for cmd in ("/start", "/help"):
        reply = bot.handle_message({"text": cmd})
        for word in ("link", "photo", "voice", ".eml"):
            assert word in reply.lower()

ORIGIN_AI = {
    "verdict": "LIKELY_AI", "confidence": 91, "generator": None,
    "generator_link": None, "ai_probability": 91,
    "reasons": ["The local detector model rates this 91% likely AI-generated."],
    "actions": [], "analysis": "Likely AI-generated (confidence 91%).",
}

def test_photo_without_qr_runs_all_three_checks(monkeypatch):
    calls = []
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"img-bytes", "photo.jpg"))
    def fake_upload(path, filename, blob):
        calls.append(path)
        if path == "/scan-qr":
            return {"verdict": "UNKNOWN", "risk_score": 0, "analysis": "QR not detected"}
        if path == "/analyze-image-origin":
            return dict(ORIGIN_AI)
        return {"verdict": "SUSPICIOUS", "risk_score": 55,
                "analysis": "OTP-sharing scam wording detected"}
    monkeypatch.setattr(bot, "backend_upload", fake_upload)
    reply = bot.handle_message({"photo": [{"file_id": "p1", "width": 100}]})
    assert calls == ["/scan-qr", "/analyze-screenshot", "/analyze-image-origin"]
    assert "SUSPICIOUS" in reply
    assert "No QR code" in reply
    assert "Likely AI-generated" in reply

def test_photo_with_qr_still_runs_all_checks(monkeypatch):
    calls = []
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"img", "photo.jpg"))
    def fake_upload(path, filename, blob):
        calls.append(path)
        if path == "/scan-qr":
            return {"verdict": "MALICIOUS", "risk_score": 80,
                    "analysis": "QR leads to a phishing page"}
        if path == "/analyze-image-origin":
            return dict(ORIGIN_AI)
        return {"verdict": "SAFE", "risk_score": 2, "analysis": "No scam wording"}
    monkeypatch.setattr(bot, "backend_upload", fake_upload)
    reply = bot.handle_message({"photo": [{"file_id": "p1", "width": 100}]})
    assert calls == ["/scan-qr", "/analyze-screenshot", "/analyze-image-origin"]
    assert "MALICIOUS" in reply                    # QR section kept
    assert "AI image check" in reply

def test_photo_origin_failure_keeps_the_other_sections(monkeypatch):
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"img", "photo.jpg"))
    def fake_upload(path, filename, blob):
        if path == "/analyze-image-origin":
            raise bot.BackendDown("origin route down")
        if path == "/scan-qr":
            return {"verdict": "UNKNOWN", "risk_score": 0, "analysis": "QR not detected"}
        return {"verdict": "SUSPICIOUS", "risk_score": 55,
                "analysis": "OTP-sharing scam wording detected"}
    monkeypatch.setattr(bot, "backend_upload", fake_upload)
    reply = bot.handle_message({"photo": [{"file_id": "p1", "width": 100}]})
    assert "SUSPICIOUS" in reply
    assert "AI image check unavailable" in reply

def test_photo_full_report_shows_every_section(monkeypatch):
    bot._last_result.clear()
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"img", "photo.jpg"))
    def fake_upload(path, filename, blob):
        if path == "/scan-qr":
            return {"verdict": "MALICIOUS", "risk_score": 80,
                    "analysis": "QR leads to a phishing page",
                    "reasons": ["r1", "r2", "r3", "A fourth reason"]}
        if path == "/analyze-image-origin":
            return dict(ORIGIN_AI)
        return {"verdict": "SAFE", "risk_score": 2, "analysis": "No scam wording"}
    monkeypatch.setattr(bot, "backend_upload", fake_upload)
    bot.handle_message({"chat": {"id": 42}, "photo": [{"file_id": "p1", "width": 100}]})
    report = bot.handle_callback(_cb("full_report"))
    assert "A fourth reason" in report              # uncapped findings
    assert "AI image check" in report
    assert "91%" in report

def test_voice_routes_to_analyze_voice(monkeypatch):
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"opus", "note.oga"))
    seen = {}
    def fake_upload(path, filename, blob):
        seen["path"], seen["filename"] = path, filename
        return {"verdict": "MALICIOUS", "risk_score": 97,
                "analysis": "Bank-OTP scam script"}
    monkeypatch.setattr(bot, "backend_upload", fake_upload)
    reply = bot.handle_message({"voice": {"file_id": "v9"}})
    assert seen["path"] == "/analyze-voice"
    assert seen["filename"] == "note.oga"
    assert "MALICIOUS" in reply

def test_eml_document_routes_to_analyze_email(monkeypatch):
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"raw-eml", "mail.eml"))
    seen = {}
    def fake_upload(path, filename, blob):
        seen["path"] = path
        return {"verdict": "SAFE", "risk_score": 5, "analysis": "Verified sender"}
    monkeypatch.setattr(bot, "backend_upload", fake_upload)
    reply = bot.handle_message({"document": {"file_id": "d2", "file_name": "mail.eml"}})
    assert seen["path"] == "/analyze-email"
    assert "SAFE" in reply

def test_unsupported_message_gets_helpful_reply(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no backend call expected")
    monkeypatch.setattr(bot, "backend_json", boom)
    monkeypatch.setattr(bot, "backend_upload", boom)
    reply = bot.handle_message({"sticker": {}})
    assert "link" in reply.lower()

def test_backend_down_gives_honest_error(monkeypatch):
    def down(*a, **k):
        raise bot.BackendDown("connection refused")
    monkeypatch.setattr(bot, "backend_json", down)
    reply = bot.handle_message({"text": "check http://x.top"})
    assert "backend" in reply.lower()
    assert "not scanned" in reply.lower() or "could not" in reply.lower()


# ---------------------------------------------------------------------------
# UX upgrade — callbacks, guided flows, report actions
# ---------------------------------------------------------------------------

def _cb(data, chat_id=42):
    return {"id": "cb1", "data": data, "message": {"chat": {"id": chat_id}}}

def test_scan_button_sets_pending_and_asks_with_force_reply():
    bot._chat_pending.clear()
    reply = bot.handle_callback(_cb("scan_link"))
    assert "link" in reply.lower()
    assert reply.markup.get("force_reply") is True
    assert bot._chat_pending[42] == "link"

def test_help_and_menu_callbacks_return_the_card():
    for data in ("help", "menu", "totally_bogus"):
        reply = bot.handle_callback(_cb(data))
        assert reply.markup is bot.MAIN_MENU

def test_pending_email_routes_pasted_text_to_email_analyzer(monkeypatch):
    bot._chat_pending.clear()
    bot._chat_memory.clear()
    seen = {}
    def fake_upload(path, filename, blob):
        seen["path"], seen["filename"], seen["blob"] = path, filename, blob
        return {"verdict": "SUSPICIOUS", "risk_score": 60,
                "analysis": "Urgent-payment scam wording"}
    monkeypatch.setattr(bot, "backend_upload", fake_upload)
    bot.handle_callback(_cb("scan_email"))
    reply = bot.handle_message({"chat": {"id": 42},
                                "text": "URGENT: your account is blocked, pay now"})
    assert seen["path"] == "/analyze-email"
    assert seen["filename"] == "pasted.txt"
    assert b"account is blocked" in seen["blob"]
    assert "SUSPICIOUS" in reply
    assert 42 not in bot._chat_pending            # one-shot

def test_pending_link_uses_normal_support_ask(monkeypatch):
    bot._chat_pending.clear()
    bot._chat_memory.clear()
    seen = {}
    def fake_backend_json(path, payload):
        seen["path"] = path
        return {"answer": "Verdict: SAFE — risk score 2/100."}
    monkeypatch.setattr(bot, "backend_json", fake_backend_json)
    bot.handle_callback(_cb("scan_link"))
    bot.handle_message({"chat": {"id": 42}, "text": "https://example.com"})
    assert seen["path"] == "/support/ask"
    assert 42 not in bot._chat_pending

def test_full_report_shows_every_reason_or_is_honest():
    bot._last_result.clear()
    assert "scan" in bot.handle_callback(_cb("full_report")).lower()  # nothing yet
    bot._last_result[42] = {"label": "link", "result": RESULT}
    reply = bot.handle_callback(_cb("full_report"))
    assert "A fourth reason" in reply              # short reply caps at 3
    assert "<b>MALICIOUS</b>" in reply

def test_report_wrong_files_a_ticket(monkeypatch):
    bot._last_result[42] = {"label": "link", "result": RESULT}
    seen = {}
    def fake_backend_json(path, payload):
        seen["path"], seen["payload"] = path, payload
        return {"ok": True, "ticket": {"id": 1}}
    monkeypatch.setattr(bot, "backend_json", fake_backend_json)
    reply = bot.handle_callback(_cb("report_wrong"))
    assert seen["path"] == "/support/tickets"
    assert seen["payload"]["category"] == "wrong_info"
    assert "MALICIOUS" in seen["payload"]["message"]
    assert "✅" in reply

def test_report_wrong_without_scan_or_backend_is_honest(monkeypatch):
    bot._last_result.clear()
    reply = bot.handle_callback(_cb("report_wrong"))
    assert "scan" in reply.lower()                 # nothing to report yet
    bot._last_result[42] = {"label": "link", "result": RESULT}
    def down(*a, **k):
        raise bot.BackendDown("refused")
    monkeypatch.setattr(bot, "backend_json", down)
    reply = bot.handle_callback(_cb("report_wrong"))
    assert "could not" in reply.lower() or "not" in reply.lower()


# ---------------------------------------------------------------------------
# UX upgrade — progress animation + send layer + loop wiring
# ---------------------------------------------------------------------------

def _record_tg(monkeypatch, edit_ok=True, send_ok=True):
    calls = []
    def fake_tg(method, payload):
        calls.append((method, payload))
        if method == "sendMessage":
            return {"message_id": 777} if send_ok else None
        if method == "editMessageText":
            return {"message_id": 777} if edit_ok else None
        return {}
    monkeypatch.setattr(bot, "tg", fake_tg)
    return calls

def test_loop_listens_for_button_presses():
    assert bot.ALLOWED_UPDATES == ["message", "callback_query"]

def test_process_update_shows_progress_then_edits_in_the_result(monkeypatch):
    calls = _record_tg(monkeypatch)
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"img", "photo.jpg"))
    monkeypatch.setattr(bot, "backend_upload", lambda p, f, b: {
        "verdict": "MALICIOUS", "risk_score": 80, "analysis": "QR phishing"})
    bot.process_update({"update_id": 5, "message": {
        "message_id": 9, "chat": {"id": 42},
        "photo": [{"file_id": "p1", "width": 100}]}})
    assert [m for m, _ in calls] == ["sendChatAction", "sendMessage",
                                     "editMessageText"]
    assert calls[0][1]["action"] == "upload_photo"
    assert "Scanning" in calls[1][1]["text"]
    final = calls[2][1]
    assert final["message_id"] == 777
    assert final["parse_mode"] == "HTML"
    assert "<b>MALICIOUS</b>" in final["text"]
    assert "full_report" in str(final.get("reply_markup"))

def test_start_replies_instantly_without_progress(monkeypatch):
    calls = _record_tg(monkeypatch)
    bot.process_update({"message": {"message_id": 1, "chat": {"id": 42},
                                    "text": "/start"}})
    assert "editMessageText" not in [m for m, _ in calls]
    sends = [p for m, p in calls if m == "sendMessage"]
    assert len(sends) == 1
    assert sends[0]["reply_markup"] is bot.MAIN_MENU

def test_callback_update_is_answered_and_prompts(monkeypatch):
    bot._chat_pending.clear()
    calls = _record_tg(monkeypatch)
    bot.process_update({"callback_query": _cb("scan_link")})
    assert calls[0][0] == "answerCallbackQuery"
    send = [p for m, p in calls if m == "sendMessage"][0]
    assert send["reply_markup"]["force_reply"] is True

def test_edit_failure_falls_back_to_a_fresh_send(monkeypatch):
    calls = _record_tg(monkeypatch, edit_ok=False)
    monkeypatch.setattr(bot, "tg_download", lambda fid: (b"img", "photo.jpg"))
    monkeypatch.setattr(bot, "backend_upload", lambda p, f, b: {
        "verdict": "SAFE", "risk_score": 2, "analysis": "Clean QR"})
    bot.process_update({"message": {"message_id": 9, "chat": {"id": 42},
                                    "photo": [{"file_id": "p1", "width": 100}]}})
    assert [m for m, _ in calls][-2:] == ["editMessageText", "sendMessage"]
    assert "<b>SAFE</b>" in calls[-1][1]["text"]

def test_html_failure_falls_back_to_plain_send(monkeypatch):
    calls = _record_tg(monkeypatch, send_ok=False)
    bot.process_update({"message": {"message_id": 1, "chat": {"id": 42},
                                    "text": "/start"}})
    sends = [p for m, p in calls if m == "sendMessage"]
    assert len(sends) == 2
    assert sends[0].get("parse_mode") == "HTML"
    assert "parse_mode" not in sends[1]


# ---------------------------------------------------------------------------
# C3 — per-chat conversation memory
# ---------------------------------------------------------------------------

def test_chat_memory_flows_into_support_ask(monkeypatch):
    bot._chat_memory.clear()
    payloads = []
    def fake_backend_json(path, payload):
        payloads.append(payload)
        return {"answer": "Verdict: MALICIOUS — risk score 88/100."}
    monkeypatch.setattr(bot, "backend_json", fake_backend_json)

    chat = {"chat": {"id": 111}}
    bot.handle_message({**chat, "text": "is https://evil.tk bad?"})
    bot.handle_message({**chat, "text": "scan it again"})

    assert payloads[0]["history"] == []
    hist = payloads[1]["history"]
    assert {"role": "user", "text": "is https://evil.tk bad?"} in hist
    assert any(t["role"] == "bot" for t in hist)

def test_chat_memory_is_per_chat_and_capped(monkeypatch):
    bot._chat_memory.clear()
    monkeypatch.setattr(bot, "backend_json", lambda p, payload: {"answer": "ok"})
    for i in range(10):
        bot.handle_message({"chat": {"id": 1}, "text": f"q{i}"})
    bot.handle_message({"chat": {"id": 2}, "text": "other chat"})

    assert len(bot.chat_history(1)) == bot._MEMORY_TURNS
    assert all("other chat" != t["text"] for t in bot.chat_history(1))
    assert len(bot.chat_history(2)) == 2      # its own user + bot turn only
