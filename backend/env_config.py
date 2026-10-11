"""
Load backend/.env exactly once, for EVERY entry point.

Why this module exists
----------------------
`load_dotenv()` used to be called only in `main.py` and `telegram_bot.py` — the
two entry points somebody remembered. Every other way into the same code got no
API keys at all: `eval/realworld_eval.py` (the benchmark every accuracy figure
comes from), the audit scripts, the corpus collector, any CLI tool, any test.

That failed silently, because a source with no key returns
`{"status": ..., "detail": "unavailable"}` and contributes nothing to the score.
The scan simply proceeded without VirusTotal and Safe Browsing.

Measured cost, 2026-07-28, on the top 20 entries of a 190,542-domain
known-malicious corpus (romainmarcoux/malicious-domains):

    without keys    26.7% flagged   73.3% SAFE
    with keys      100.0% flagged    0.0% SAFE

Same code, same corpus, same hosts. VirusTotal alone flagged 20/20 — one of them
at 23/92 engines — while the pipeline was calling those domains SAFE.

Imported by `apis/__init__.py`, so touching ANY source module is enough, and by
`aggregator.py`, so any scan path is covered however it was reached.

Real environment variables always win
-------------------------------------
`override=False` is the whole contract. In cloud there is no .env file and the
platform injects real environment variables; a loader that overrode them would
replace production secrets with whatever a stray file on disk happened to
contain. The file only ever FILLS GAPS.
"""

from __future__ import annotations

import os
from pathlib import Path

_ENV_PATH = Path(__file__).resolve().parent / ".env"
_loaded = False


def load_env(path: Path | None = None) -> bool:
    """
    Fill missing environment variables from backend/.env. Idempotent.

    Returns True when a file was read. Never raises: a missing file, an
    unreadable file, or python-dotenv not being installed must not stop the app
    from starting — in cloud the real environment already carries the values.
    """
    global _loaded
    if _loaded and path is None:
        return True
    target = Path(path) if path is not None else _ENV_PATH
    try:
        if not target.exists():
            _loaded = True
            return False
        try:
            from dotenv import load_dotenv
        except Exception:
            _fallback_parse(target)
        else:
            load_dotenv(target, override=False)
        _loaded = True
        return True
    except Exception:
        _loaded = True
        return False


def _fallback_parse(target: Path) -> None:
    """
    Minimal KEY=VALUE reader for when python-dotenv is absent.

    Deliberately dumb — it exists so a missing optional dependency cannot
    silently disable the threat-intelligence sources, which is the exact
    failure mode this module was written to end.
    """
    for raw in target.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


# Loading on import is the point: no caller has to remember to do it.
load_env()
