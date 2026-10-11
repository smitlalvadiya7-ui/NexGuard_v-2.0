"""
Optional real Claude AI for the support bot (NEXT_PHASE_PLAN C2).

Env-gated: without an ANTHROPIC_API_KEY in backend/.env this module does
nothing and the FREE built-in FAQ bot answers exactly as before — zero cost.
With a key, questions the FAQ can't match get a natural, multi-turn answer
from Claude, grounded in the same FAQ corpus so it stays trustable:
the model is told to answer only about NexGuard, to say plainly when it
doesn't know, and NEVER to invent scan results (real scans keep going
through the scan tools, not the LLM).

Any failure — missing package, network, refusal — falls back silently to
the FAQ bot's normal reply; the endpoint never breaks because of the LLM.

Setup (backend/.env):
  ANTHROPIC_API_KEY=sk-ant-...          enables Claude answers
  NEXGUARD_CLAUDE_MODEL=claude-opus-4-8  optional override
"""

import logging
import os

import requests

from support_faq import FAQ

log = logging.getLogger("nexguard.support_llm")

API_KEY = (os.getenv("ANTHROPIC_API_KEY") or "").strip()
MODEL = (os.getenv("NEXGUARD_CLAUDE_MODEL") or "claude-opus-4-8").strip()

_client = None


def ai_available() -> bool:
    return bool(API_KEY)


def _get_client():
    """Lazy singleton; ImportError surfaces to the caller's fail-safe."""
    global _client
    if _client is None:
        import anthropic
        _client = anthropic.Anthropic(api_key=API_KEY)
    return _client


def _system_prompt() -> str:
    corpus = "\n\n".join(
        f"Q: {entry['question']}\nA: {entry['answer']}" for entry in FAQ
    )
    return (
        "You are the support assistant for NexGuard AI, a phishing- and "
        "scam-detection tool (URL/QR/email/voice/screenshot scanners, a "
        "browser extension and a Telegram bot). Answer in simple, friendly "
        "English.\n\n"
        "Rules you must follow:\n"
        "- Only answer questions about NexGuard and online safety. For "
        "anything else, politely say you can only help with NexGuard.\n"
        "- Ground your answers in the product knowledge below. If the "
        "answer is not there and you are not sure, say so and point the "
        "user to the contact form — never guess about product behavior.\n"
        "- NEVER invent a scan verdict or claim you scanned something. "
        "Scans run through the real scanner, not through you; tell users "
        "to paste the link/message in this chat to have it scanned.\n\n"
        "Product knowledge:\n\n" + corpus
    )


_REFUSED = object()   # sentinel: deliberate safety refusal — never retried locally


def _history_messages(question, history):
    """Chat history in provider message format, the new question last."""
    messages = []
    for turn in history or []:
        role = "assistant" if turn.get("role") == "bot" else "user"
        messages.append({"role": role, "content": turn.get("text", "")})
    messages.append({"role": "user", "content": question})
    return messages


def _claude_answer(question, history):
    """
    Claude reply dict, None on error (caller may try another provider),
    or _REFUSED on a safety refusal (caller must NOT try another provider).
    """
    try:
        client = _get_client()
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            thinking={"type": "adaptive"},
            system=[{
                "type": "text",
                "text": _system_prompt(),
                # stable corpus → prompt-cached across support questions
                "cache_control": {"type": "ephemeral"},
            }],
            messages=_history_messages(question, history),
        )
        if response.stop_reason == "refusal":
            return _REFUSED
        text = "".join(
            block.text for block in response.content if block.type == "text"
        ).strip()
        if not text:
            return None
        return {
            "matched": True,
            "confidence": 1.0,
            "question": None,
            "answer": text,
            "related": [],
            "action": "ai",
        }
    except Exception as e:                      # LLM must never break support
        log.warning("Claude support answer failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# Ollama tier (spec 2026-07-19): free, fully-offline answers from a local
# model. Enabled by NEXGUARD_OLLAMA_MODEL in backend/.env; any failure
# returns None so the FAQ bot always stands behind it.
# ---------------------------------------------------------------------------
OLLAMA_TIMEOUT_S = 120     # qwen2.5:7b on CPU takes 20-40 s per answer


def _ollama_config():
    """(url, model) from env at call time — hot-reloadable and test-friendly."""
    model = (os.getenv("NEXGUARD_OLLAMA_MODEL") or "").strip()
    url = (os.getenv("NEXGUARD_OLLAMA_URL") or "http://127.0.0.1:11434").strip().rstrip("/")
    return url, model


def _ollama_answer(question, history):
    """Local-model reply dict, or None (unconfigured, down, timeout, empty)."""
    url, model = _ollama_config()
    if not model:
        return None
    try:
        messages = [{"role": "system", "content": _system_prompt()}]
        messages += _history_messages(question, history)
        resp = requests.post(
            url + "/api/chat",
            json={"model": model, "messages": messages, "stream": False},
            timeout=OLLAMA_TIMEOUT_S,
        )
        if resp.status_code != 200:
            log.warning("Ollama support answer failed: HTTP %s", resp.status_code)
            return None
        text = (((resp.json() or {}).get("message") or {}).get("content") or "").strip()
        if not text:
            return None
        return {
            "matched": True,
            "confidence": 1.0,
            "question": None,
            "answer": text,
            "related": [],
            "action": "ai",
        }
    except Exception as e:                      # LLM must never break support
        log.warning("Ollama support answer failed, using FAQ fallback: %s", e)
        return None


def ai_answer(question, history):
    """
    AI answer for a question the FAQ couldn't match, or None to fall back
    to the FAQ bot. Priority: Claude (paid key deliberately configured) →
    local Ollama → None. A Claude safety refusal is final — it is never
    retried on the local model.
    """
    if ai_available():
        result = _claude_answer(question, history)
        if result is _REFUSED:
            return None
        if result is not None:
            return result
        # Claude errored — the free local tier still gets its chance.
    return _ollama_answer(question, history)
