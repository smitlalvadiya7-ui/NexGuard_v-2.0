"""
Deployment readiness check — which keys are set, which are still missing.

    cd backend
    py check_env.py

Prints STATUS ONLY. It never prints a secret's value, so the output is safe to
paste into a chat or an issue.

Exit code 0 when everything REQUIRED for this build is present, 1 otherwise —
so it can gate a deploy script.

See ../SETUP_KEYS.md for where each key comes from.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import os  # noqa: E402

import env_config  # noqa: E402,F401  — loads backend/.env
from deployment_profile import blocked_sources, describe, profile  # noqa: E402

PLACEHOLDERS = {"your_key_here", "changeme", "xxx", "todo", "replace_me"}

# (key, requirement, what it is)
CHECKS = [
    ("THREAT INTELLIGENCE", [
        # Required only in the COMMERCIAL build. There it replaces VirusTotal
        # and Safe Browsing, which are blocked by licence, so without it the
        # build has no reputation source at all. The non-commercial build has
        # those two, so Web Risk is a bonus there rather than the foundation.
        ("GOOGLE_WEB_RISK_API_KEY",
         "required" if profile() == "commercial" else "recommended",
         "Google Web Risk — THE reputation source for a commercial build"),
        ("URLHAUS_AUTH_KEY", "recommended", "URLhaus community feed"),
        ("URLSCAN_API_KEY", "optional", "page screenshot + sandbox intel"),
    ]),
    ("SECURITY", [
        ("JWT_SECRET", "required", "session signing — rotate before deploy"),
        ("ADMIN_PASSWORD", "required", "admin login — rotate before deploy"),
        ("SUPERADMIN_PASSWORD", "required", "superadmin — rotate before deploy"),
    ]),
    ("DEPLOYMENT", [
        ("NEXGUARD_ALLOWED_ORIGINS", "required", "CORS — your real domain(s)"),
        ("REDIS_URL", "recommended", "shared cache; REQUIRED with >1 worker"),
        ("DATABASE_URL", "recommended", "Postgres; SQLite will not survive scale"),
    ]),
    ("BILLING (only if you are selling)", [
        ("STRIPE_SECRET_KEY", "optional", "Premium checkout"),
        ("STRIPE_PUBLISHABLE_KEY", "optional", "Premium checkout"),
        ("STRIPE_WEBHOOK_SECRET", "optional", "subscription events"),
    ]),
    ("OPTIONAL FEATURES", [
        ("NEXGUARD_TELEGRAM_TOKEN", "optional", "Telegram bot"),
        ("NEXGUARD_SMTP_PASSWORD", "optional", "support ticket emails"),
        ("ANTHROPIC_API_KEY", "optional", "support chat (Ollama is the fallback)"),
    ]),
]

# Colour only when a terminal is going to render it. Piped into a file, a log,
# or a chat message, escape codes are noise — and this output is meant to be
# pasteable. NO_COLOR is honoured as the de-facto standard.
if sys.stdout.isatty() and not os.getenv("NO_COLOR"):
    GREEN, YELLOW, RED, RESET = "\033[92m", "\033[93m", "\033[91m", "\033[0m"
else:
    GREEN = YELLOW = RED = RESET = ""


def state(key: str) -> tuple[str, bool]:
    raw = (os.getenv(key) or "").strip()
    if not raw:
        return "MISSING", False
    if raw.lower() in PLACEHOLDERS:
        return "PLACEHOLDER", False
    return f"set ({len(raw)} chars)", True


def main() -> int:
    print("=" * 72)
    print("NexGuard — deployment readiness")
    print("=" * 72)
    print(describe())
    blocked = blocked_sources()
    if blocked:
        print(f"\nBlocked by licence in this build: {', '.join(blocked)}")
        print("Their keys may stay in .env; this build never calls them.")

    missing_required = []
    for section, items in CHECKS:
        print(f"\n{section}")
        print("-" * 72)
        for key, need, what in items:
            status, ok = state(key)
            if ok:
                colour, mark = GREEN, "OK "
            elif need == "required":
                colour, mark = RED, "!! "
                missing_required.append((key, what))
            else:
                colour, mark = YELLOW, ".. "
            print(f"  {mark}{key:30s} {colour}{status:16s}{RESET} {what}")

    print("\n" + "=" * 72)
    if missing_required:
        print(f"{RED}NOT READY{RESET} — {len(missing_required)} required value(s) missing:")
        for key, what in missing_required:
            print(f"    {key}  ({what})")
        print("\nSee SETUP_KEYS.md for where each one comes from.")
        if profile() == "commercial" and not (os.getenv("GOOGLE_WEB_RISK_API_KEY") or "").strip():
            print(f"\n{RED}Start with GOOGLE_WEB_RISK_API_KEY.{RESET} Without it this build "
                  "has\nno reputation source at all — measured 26.7% on a known-malicious "
                  "corpus\nversus 96.7% with a full stack.")
        return 1

    print(f"{GREEN}READY{RESET} — every required value is present.")
    print("\nNext: py -m pytest (from the repo root), then")
    print("      cd backend && py -m eval.realworld_eval")
    return 0


if __name__ == "__main__":
    sys.exit(main())
