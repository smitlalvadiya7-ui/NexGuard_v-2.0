"""
Ollama local-LLM tier for the support bot (spec 2026-07-19). requests is
monkeypatched — no server, no network. Tests delenv/setenv the gate key so
the developer's real backend/.env (loaded by `import main` elsewhere in the
suite) can never leak in.
"""

import pytest

support_llm = pytest.importorskip("support_llm")


class _FakeResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def test_ollama_happy_path(monkeypatch):
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.delenv("NEXGUARD_OLLAMA_URL", raising=False)
    calls = {}

    def fake_post(url, json=None, timeout=None):
        calls["url"] = url
        calls["json"] = json
        calls["timeout"] = timeout
        return _FakeResp(200, {"message": {"content": "NexGuard scans links with several engines."}})

    monkeypatch.setattr(support_llm.requests, "post", fake_post)

    out = support_llm._ollama_answer("how do you check links?", [
        {"role": "user", "text": "hi"},
        {"role": "bot", "text": "hello!"},
    ])
    assert out["matched"] is True
    assert out["action"] == "ai"
    assert "several engines" in out["answer"]

    assert calls["url"] == "http://127.0.0.1:11434/api/chat"
    assert calls["timeout"] == support_llm.OLLAMA_TIMEOUT_S == 120
    body = calls["json"]
    assert body["model"] == "qwen2.5:7b"
    assert body["stream"] is False
    # system prompt (FAQ corpus) leads, question is the last user turn
    assert body["messages"][0]["role"] == "system"
    assert "NexGuard" in body["messages"][0]["content"]
    assert body["messages"][1] == {"role": "user", "content": "hi"}
    assert body["messages"][2] == {"role": "assistant", "content": "hello!"}
    assert body["messages"][-1] == {"role": "user", "content": "how do you check links?"}


def test_ollama_disabled_without_env(monkeypatch):
    monkeypatch.delenv("NEXGUARD_OLLAMA_MODEL", raising=False)

    def explode(*a, **k):
        raise AssertionError("Ollama must not be called when unconfigured")

    monkeypatch.setattr(support_llm.requests, "post", explode)
    assert support_llm._ollama_answer("q", []) is None


def test_ollama_connection_error_returns_none(monkeypatch):
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")

    def refuse(*a, **k):
        raise support_llm.requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(support_llm.requests, "post", refuse)
    assert support_llm._ollama_answer("q", []) is None


def test_ollama_timeout_returns_none(monkeypatch):
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")

    def slow(*a, **k):
        raise support_llm.requests.exceptions.Timeout("120s")

    monkeypatch.setattr(support_llm.requests, "post", slow)
    assert support_llm._ollama_answer("q", []) is None


def test_ollama_http_error_returns_none(monkeypatch):
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setattr(support_llm.requests, "post",
                        lambda *a, **k: _FakeResp(500, {}))
    assert support_llm._ollama_answer("q", []) is None


def test_ollama_empty_answer_returns_none(monkeypatch):
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setattr(support_llm.requests, "post",
                        lambda *a, **k: _FakeResp(200, {"message": {"content": "   "}}))
    assert support_llm._ollama_answer("q", []) is None


def test_ollama_custom_url(monkeypatch):
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setenv("NEXGUARD_OLLAMA_URL", "http://192.168.1.50:11434/")
    seen = {}

    def fake_post(url, json=None, timeout=None):
        seen["url"] = url
        return _FakeResp(200, {"message": {"content": "ok"}})

    monkeypatch.setattr(support_llm.requests, "post", fake_post)
    assert support_llm._ollama_answer("q", [])["answer"] == "ok"
    assert seen["url"] == "http://192.168.1.50:11434/api/chat"


def _enable_ollama_reply(monkeypatch, text="local answer"):
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")
    monkeypatch.setattr(support_llm.requests, "post",
                        lambda *a, **k: _FakeResp(200, {"message": {"content": text}}))


def test_no_claude_key_uses_ollama(monkeypatch):
    monkeypatch.setattr(support_llm, "API_KEY", "")
    _enable_ollama_reply(monkeypatch)
    out = support_llm.ai_answer("how do link scans work?", [])
    assert out["action"] == "ai"
    assert out["answer"] == "local answer"


def test_claude_error_falls_through_to_ollama(monkeypatch):
    monkeypatch.setattr(support_llm, "API_KEY", "sk-test")

    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(support_llm, "_get_client", boom)
    _enable_ollama_reply(monkeypatch)
    out = support_llm.ai_answer("q", [])
    assert out["answer"] == "local answer"


def test_claude_refusal_never_reaches_ollama(monkeypatch):
    monkeypatch.setattr(support_llm, "API_KEY", "sk-test")
    monkeypatch.setattr(support_llm, "_claude_answer",
                        lambda q, h: support_llm._REFUSED)
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")

    def explode(*a, **k):
        raise AssertionError("refused questions must not go to the local model")

    monkeypatch.setattr(support_llm.requests, "post", explode)
    assert support_llm.ai_answer("q", []) is None


def test_claude_success_skips_ollama(monkeypatch):
    monkeypatch.setattr(support_llm, "API_KEY", "sk-test")
    monkeypatch.setattr(support_llm, "_claude_answer",
                        lambda q, h: {"matched": True, "confidence": 1.0,
                                      "question": None, "answer": "claude answer",
                                      "related": [], "action": "ai"})
    monkeypatch.setenv("NEXGUARD_OLLAMA_MODEL", "qwen2.5:7b")

    def explode(*a, **k):
        raise AssertionError("Claude answered — Ollama must not be called")

    monkeypatch.setattr(support_llm.requests, "post", explode)
    assert support_llm.ai_answer("q", [])["answer"] == "claude answer"
