"""
C2 — optional real Claude AI for the support bot. Env-gated: without an
ANTHROPIC_API_KEY the free FAQ bot answers exactly as before (zero cost);
with a key, questions the FAQ can't match get a natural-language answer
grounded in the FAQ corpus. The API client is monkeypatched — no network,
no key needed to test.
"""

import pytest

support_llm = pytest.importorskip("support_llm")


class _FakeBlock:
    def __init__(self, type_, text=""):
        self.type = type_
        self.text = text


class _FakeMessage:
    def __init__(self, blocks, stop_reason="end_turn"):
        self.content = blocks
        self.stop_reason = stop_reason


class _FakeMessages:
    def __init__(self, reply_text):
        self._reply = reply_text
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return _FakeMessage([
            _FakeBlock("thinking"),
            _FakeBlock("text", self._reply),
        ])


class _FakeClient:
    def __init__(self, reply_text):
        self.messages = _FakeMessages(reply_text)


def test_disabled_without_key(monkeypatch):
    monkeypatch.delenv("NEXGUARD_OLLAMA_MODEL", raising=False)
    monkeypatch.setattr(support_llm, "API_KEY", "")
    assert support_llm.ai_available() is False
    assert support_llm.ai_answer("why is the sky blue?", []) is None


def test_answers_with_key_and_grounds_in_faq(monkeypatch):
    fake = _FakeClient("NexGuard checks links with several engines…")
    monkeypatch.setattr(support_llm, "API_KEY", "sk-test")
    monkeypatch.setattr(support_llm, "_get_client", lambda: fake)

    out = support_llm.ai_answer("can u explain how u check my links?", [])
    assert out["matched"] is True
    assert out["action"] == "ai"
    assert "NexGuard checks links" in out["answer"]

    kwargs = fake.messages.last_kwargs
    assert kwargs["model"] == support_llm.MODEL
    # the FAQ corpus rides in the system prompt so answers stay grounded
    system_text = kwargs["system"][0]["text"]
    assert "NexGuard" in system_text
    # conversation question arrives as the last user message
    assert kwargs["messages"][-1] == {
        "role": "user", "content": "can u explain how u check my links?"}


def test_history_becomes_conversation_turns(monkeypatch):
    fake = _FakeClient("ok")
    monkeypatch.setattr(support_llm, "API_KEY", "sk-test")
    monkeypatch.setattr(support_llm, "_get_client", lambda: fake)

    support_llm.ai_answer("and what about QR codes?", [
        {"role": "user", "text": "how does the URL scan work?"},
        {"role": "bot", "text": "It runs the full pipeline…"},
    ])
    msgs = fake.messages.last_kwargs["messages"]
    assert msgs[0] == {"role": "user", "content": "how does the URL scan work?"}
    assert msgs[1] == {"role": "assistant", "content": "It runs the full pipeline…"}
    assert msgs[-1]["content"] == "and what about QR codes?"


def test_refusal_and_errors_fall_back_to_none(monkeypatch):
    monkeypatch.delenv("NEXGUARD_OLLAMA_MODEL", raising=False)
    monkeypatch.setattr(support_llm, "API_KEY", "sk-test")

    class _Refusing(_FakeClient):
        def __init__(self):
            super().__init__("")
            self.messages.create = lambda **k: _FakeMessage([], stop_reason="refusal")

    monkeypatch.setattr(support_llm, "_get_client", lambda: _Refusing())
    assert support_llm.ai_answer("q", []) is None

    def boom():
        raise RuntimeError("network down")
    monkeypatch.setattr(support_llm, "_get_client", boom)
    assert support_llm.ai_answer("q", []) is None
