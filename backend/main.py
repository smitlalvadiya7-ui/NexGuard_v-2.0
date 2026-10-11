import hashlib
import json
import os
import secrets
import shutil
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Load environment variables from backend/.env BEFORE importing modules
# that read API keys at import time (e.g. ai_engine, auth).
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except Exception:
    pass

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Header, Response
from fastapi import Request as FastAPIRequest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import asyncio
import requests

from sqlalchemy import func, inspect, text

from db_config import engine, SessionLocal
from models import ScanHistory, Base, User, Request, AuditLog, Watchlist, ApiKey, VerdictFeedback, SupportTicket
from support_faq import FAQ, answer_question
from support_tools import (
    bot_message_reply,
    bot_quota_reply,
    bot_rescan_reply,
    bot_scan_reply,
    extract_url,
    history_url,
    is_followup_scan,
    looks_like_message,
    normalize_history,
)
from notify import send_ticket_notification
from support_llm import ai_answer

from auth import (
    RegisterRequest, LoginRequest,
    do_register, do_login,
    get_optional_user, get_optional_active_user, get_current_user,
    require_admin, require_superadmin,
    create_user, get_user_by_email,
    hash_password, verify_password,
    create_access_token, _decode_token,
)

from aggregator import full_scan, scan_embedded_links, _domain_from_url
from apis import rate_limit
from apis.url_cache import cache_backend, cache_size, cache_healthy
from apis.circuit_breaker import snapshot_all as breaker_snapshot
from db_config import db_backend
from email_analyzer import analyze_email, verify_sender_simple
from email_analyzer import _sender_domain as _email_sender_domain
from apis.dns_auth import check_dns_auth
from email_parser import parse_email
from apis.virustotal import check_file_hash
from gmail_reader import read_gmail, read_sample_emails
from scan_facets import country_centroid, derive_scan_facets
from voice_analyzer import analyze_voice
from ocr_analyzer import analyze_screenshot
from image_origin import analyze_image_origin
from qr_scanner import decode_qr_image
from report_generator import generate_report, generate_batch_report
import billing

app = FastAPI(title="NexGuard AI")

# ---------------------------------------------------------------------------
# ML model sanity check (FIX 2): load the SoftVotingEnsemble on startup, log a
# clear WARNING if it failed to load (never run silently on heuristics only),
# and print sample calibration probabilities (github.com low, phishing high).
# ---------------------------------------------------------------------------
import logging as _logging

# Structured logging (human lines by default; NEXGUARD_LOG_JSON=1 for JSON).
from logging_config import configure_logging
configure_logging()
log = _logging.getLogger("nexguard.api")
try:
    from ml.predict import startup_check as _ml_startup_check
    _ml_startup_check()
except Exception as _ml_e:
    _logging.getLogger("nexguard.ml").warning(
        "ML startup sanity check could not run: %s", _ml_e
    )

# Refuse to start quietly with nothing to check against. On 2026-07-30 a user
# scanned 190,542 known-malicious domains and got SAFE for every one: the
# commercial profile had blocked VirusTotal and Safe Browsing by licence, and
# the Web Risk key that replaces them did not exist yet. The app started
# normally and said nothing. See intel_health.
try:
    from intel_health import log_startup_warning as _intel_warn
    _intel_warn()
except Exception as _intel_e:
    _logging.getLogger("nexguard.intel").warning(
        "could not check reputation-source availability: %s", _intel_e
    )

# Community blocklist (OpenPhish + Phishing.Database): pull the first snapshot
# on a daemon thread so the multi-MB cold fetch never lands on a scan request.
try:
    from apis.phish_feeds import warm_in_background as _warm_feeds
    _warm_feeds()
except Exception as _feed_e:
    _logging.getLogger("nexguard.api").warning(
        "Community blocklist warm-up could not start: %s", _feed_e
    )

# ---------------------------------------------------------------------------
# DB bootstrap: create tables then apply incremental migrations
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=engine)


def _utcnow() -> datetime:
    """Naive UTC now. Replaces datetime.utcnow(), which is deprecated since
    Python 3.12. Returns a naive value, exactly as utcnow() did, because the
    stored rows and the WHOIS dates it is compared against are naive."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _run_migrations():
    """Add new columns to existing tables without losing data (SQLite safe)."""
    insp = inspect(engine)
    tables = insp.get_table_names()

    if "scan_history" in tables:
        existing = {c["name"] for c in insp.get_columns("scan_history")}
        if "user_id" not in existing:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE scan_history ADD COLUMN user_id INTEGER"))
                conn.commit()
            print("[NexGuard] Migration: added user_id to scan_history")
        # Task 4 facets — structured threat type / brand / origin per scan
        facet_cols = {
            "threat_types": "VARCHAR DEFAULT ''",
            "brand":        "VARCHAR DEFAULT ''",
            "geo_country":  "VARCHAR DEFAULT ''",
        }
        added = [c for c in facet_cols if c not in existing]
        if added:
            with engine.connect() as conn:
                for col in added:
                    conn.execute(text(f"ALTER TABLE scan_history ADD COLUMN {col} {facet_cols[col]}"))
                conn.commit()
            print(f"[NexGuard] Migration: added scan_history columns -> {', '.join(added)}")

    if "users" in tables:
        existing = {c["name"] for c in insp.get_columns("users")}
        # column name -> ADD COLUMN DDL (constant defaults so existing rows backfill)
        new_cols = {
            "role":             "VARCHAR DEFAULT 'user'",
            "tier":             "VARCHAR DEFAULT 'free'",
            "status":           "VARCHAR DEFAULT 'active'",
            "daily_scan_count": "INTEGER DEFAULT 0",
            "last_scan_date":   "DATE",
            "stripe_customer_id":     "VARCHAR",
            "stripe_subscription_id": "VARCHAR",
        }
        added = []
        with engine.connect() as conn:
            for col, ddl in new_cols.items():
                if col not in existing:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {ddl}"))
                    added.append(col)
            conn.commit()
        if added:
            print(f"[NexGuard] Migration: added users columns -> {', '.join(added)}")


def _reconcile_password(db, email: str, env_pw: Optional[str]) -> bool:
    """
    Keep a seeded account's password in sync with its .env value.

    If the account already exists and *env_pw* is set but no longer matches the
    stored hash, reset the hash to env_pw and return True. This makes the .env
    credential authoritative on every startup, so a password that was seeded
    randomly (before the env var was set) is corrected rather than left stale.
    """
    if not env_pw:
        return False
    user = get_user_by_email(db, email)
    if not user or verify_password(env_pw, user.password_hash):
        return False
    user.password_hash = hash_password(env_pw)
    db.commit()
    return True


def _seed_admin():
    """Create admin@nexguard.local on first startup if no admin exists, and on
    every startup reconcile its password to ADMIN_PASSWORD so .env stays
    authoritative."""
    db = SessionLocal()
    try:
        env_pw = os.getenv("ADMIN_PASSWORD")
        if _reconcile_password(db, "admin@nexguard.local", env_pw):
            print("\nNexGuard AI -- admin@nexguard.local password reconciled to ADMIN_PASSWORD from .env.\n")

        if db.query(User).filter(User.role == "admin").first():
            return
        pw = env_pw or secrets.token_urlsafe(14)
        create_user(db, "admin@nexguard.local", pw, role="admin")
        print(
            "\n"
            "=======================================================\n"
            "  NexGuard AI -- Admin account created\n"
            "  Email:    admin@nexguard.local\n"
            f"  Password: {pw}\n"
            "  Set ADMIN_PASSWORD in backend/.env to keep this.\n"
            "=======================================================\n"
        )
    finally:
        db.close()


def _seed_superadmin():
    """Create the single superadmin on first startup if none exists, and on
    every startup reconcile its password to SUPERADMIN_PASSWORD so .env stays
    authoritative."""
    db = SessionLocal()
    try:
        env_pw = os.getenv("SUPERADMIN_PASSWORD")
        if _reconcile_password(db, "superadmin@nexguard.local", env_pw):
            print("\nNexGuard AI -- superadmin@nexguard.local password reconciled to SUPERADMIN_PASSWORD from .env.\n")

        if db.query(User).filter(User.role == "superadmin").first():
            return
        pw = env_pw or secrets.token_urlsafe(16)
        create_user(db, "superadmin@nexguard.local", pw, role="superadmin")
        print(
            "\n"
            "=======================================================\n"
            "  NexGuard AI -- SUPERADMIN account created\n"
            "  Email:    superadmin@nexguard.local\n"
            f"  Password: {pw}\n"
            "  Set SUPERADMIN_PASSWORD in backend/.env to keep this.\n"
            "=======================================================\n"
        )
    finally:
        db.close()


_run_migrations()
_seed_admin()
_seed_superadmin()


# ---------------------------------------------------------------------------
# WebSocket connection manager — one asyncio.Queue per connected client, each
# tagged with the user it belongs to.
#
# Alerts carry the scan target (a URL, an email sender, a filename), so they
# are per-user data, not a public feed: delivery is scoped to the owner. An
# alert with no owner (anonymous scan) reaches nobody — fanning it out to every
# listener is exactly the cross-tenant leak this scoping exists to stop.
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self) -> None:
        self._clients: list[tuple[int, asyncio.Queue]] = []

    async def connect(self, ws: WebSocket, user_id: int) -> asyncio.Queue:
        await ws.accept()
        q: asyncio.Queue = asyncio.Queue()
        self._clients.append((user_id, q))
        return q

    def disconnect(self, q: asyncio.Queue) -> None:
        self._clients = [(uid, qq) for uid, qq in self._clients if qq is not q]

    async def broadcast(self, payload: dict, user_id: Optional[int] = None) -> None:
        """Deliver `payload` to every socket owned by `user_id`."""
        if user_id is None:
            return
        for uid, q in list(self._clients):
            if uid == user_id:
                await q.put(payload)


manager = ConnectionManager()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# Rolling window of URL scan times (ms) — capped at last 500 scans
_scan_times_ms: list[float] = []
_SCAN_TIMES_CAP = 500

# SECURITY: do not use "*" with allow_credentials=True. Restrict to known origins.
# Override in production via NEXGUARD_ALLOWED_ORIGINS="https://yourdomain.com,..."
_default_origins = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
_env_origins = os.getenv("NEXGUARD_ALLOWED_ORIGINS", "").strip()
ALLOWED_ORIGINS = [o.strip() for o in _env_origins.split(",") if o.strip()] or _default_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    # Narrowed to what the API actually exposes and what clients actually send
    # (the app declares only GET/POST/DELETE routes). Authorization for the JWT,
    # X-API-Key for the developer API, Content-Type for JSON + uploads.
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)


class URLRequest(BaseModel):
    url: str


def _merge_verdict(score: int) -> str:
    """Standard 70/40 verdict thresholds shared across all scan modules."""
    return "MALICIOUS" if score >= 70 else "SUSPICIOUS" if score >= 40 else "SAFE"


def _apply_link_scan(result: dict, link_scan: dict) -> None:
    """
    Fold an embedded-link scan into an email result (Task 9 merge rule):
    a VERIFIED sender's links only escalate the email when a link carries a
    CONFIRMED blocklist flag — lexical/ML/VT-noise link scores never override
    a verified origin (BUG 1's second layer: genuine tracking links read as
    phishy). Unverified senders keep the plain worst-score merge.
    """
    result["links_found"] = link_scan["links_found"]
    result["scanned_links"] = link_scan["scanned_links"]
    if link_scan["links_found"] == 0:
        return

    verified = (result.get("sender_origin") or {}).get("status") == "verified"
    if verified:
        confirmed = any(
            any(s.get("status") == "flag" for s in (link.get("sources") or []))
            for link in link_scan.get("scanned_links", [])
        )
        if not confirmed:
            if link_scan.get("worst_score", 0) >= 40:
                result.setdefault("reasons", []).append(
                    "Embedded links scored risky on lexical/engine-noise signals "
                    "only — not held against this verified sender."
                )
            result["genuine_ratio"] = 100 - result.get("risk_score", 0)
            return

    new_score = max(result.get("risk_score", 0), link_scan["worst_score"])
    result["risk_score"] = new_score
    result["score"] = new_score
    result["verdict"] = _merge_verdict(new_score)
    result["genuine_ratio"] = 100 - new_score


# ---------------------------------------------------------------------------
# Single source of truth for scan history (SQLAlchemy -> nexguard.db)
# ---------------------------------------------------------------------------
def save_scan(module: str, result: dict, target: str = "", user_id: Optional[int] = None):
    """Persist a scan to the history table. Only called when user is authenticated."""
    try:
        facets = derive_scan_facets(module, result)
        db = SessionLocal()
        entry = ScanHistory(
            module=module,
            verdict=result.get("verdict", "UNKNOWN"),
            score=int(result.get("risk_score", result.get("score", 0)) or 0),
            target=target or result.get("url", ""),
            summary=result.get("ai_explanation", result.get("summary", "")),
            user_id=user_id,
            threat_types=",".join(facets["threat_types"]),
            brand=facets["brand"],
            geo_country=facets["country"],
        )
        db.add(entry)
        # Maintain the per-user daily scan counter (resets each calendar day)
        if user_id:
            u = db.query(User).filter(User.id == user_id).first()
            if u:
                today = _utcnow().date()
                if u.last_scan_date != today:
                    u.daily_scan_count = 0
                    u.last_scan_date = today
                u.daily_scan_count = (u.daily_scan_count or 0) + 1
        db.commit()
        db.close()
    except Exception:
        # Still swallowed — a storage failure must never fail the scan the user
        # asked for — but no longer invisible: a silent failure here loses scan
        # history AND skips the quota increment.
        log.exception("save_scan failed for module=%s target=%s", module, target)


def _cleanup_temp(path: str) -> None:
    """
    Delete a scan tempfile. Never raises (it runs in `finally`), but never fails
    silently either — undeleted uploads accumulate on disk unnoticed.
    """
    try:
        os.remove(path)
    except FileNotFoundError:
        pass  # already cleaned up — not a problem
    except Exception:
        log.warning("Could not delete temporary scan file %s", path, exc_info=True)


# ---------------------------------------------------------------------------
# Free / Premium quota + response gating
# ---------------------------------------------------------------------------
FREE_DAILY_LIMIT = 10      # logged-in free tier: scans per calendar day
ANON_DAILY_LIMIT = 5       # anonymous (by IP) best-effort daily limit

# Premium-only intel stripped from the response for free/anonymous viewers.
_PREMIUM_FIELDS = [
    "resolved_ip", "ip_location", "ip_country", "asn", "hosting", "whois",
    "ssl", "ssl_cert", "threat_intel", "redirects", "screenshot_url",
    "page_title", "content_analysis", "explainability",
]

def _is_premium_viewer(user: Optional[User]) -> bool:
    """Premium tier and admins/superadmins always get the full object."""
    return user is not None and (user.tier == "premium" or user.role in ("admin", "superadmin"))


def require_premium(user: User = Depends(get_current_user)) -> User:
    """Gate premium-only features (e.g. the Watchlist). Admins/superadmins pass."""
    if not _is_premium_viewer(user):
        raise HTTPException(
            status_code=403,
            detail="This is a Premium feature. Upgrade to Premium to use it.",
        )
    return user


def _free_limit_response() -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "error": "free_limit",
            "message": "Daily free scan limit reached. Upgrade to Premium for unlimited scans.",
        },
    )


def enforce_scan_quota(user: Optional[User], request: FastAPIRequest) -> Optional[JSONResponse]:
    """
    Returns a 429 JSONResponse if the caller is over their daily quota, else None.
    Call BEFORE scanning. Premium + admin/superadmin are unlimited.
    Logged-in free users are counted in the DB (incremented by save_scan);
    anonymous users are counted in-memory by IP.
    """
    today = _utcnow().date()

    if user is not None:
        if _is_premium_viewer(user):
            return None
        # Free tier: counter resets each calendar day (see save_scan)
        count = (user.daily_scan_count or 0) if user.last_scan_date == today else 0
        if count >= FREE_DAILY_LIMIT:
            return _free_limit_response()
        return None

    # Anonymous: small per-IP daily limit. Uses the shared Redis counter when
    # configured (holds across workers/instances at scale), else a process-local
    # counter — identical behaviour for a single process.
    ip = request.client.host if request and request.client else "unknown"
    if not rate_limit.allow(f"anon:{ip}", limit=ANON_DAILY_LIMIT, window_s=86400):
        return _free_limit_response()
    return None


def _reduce_sources(sources):
    """Drop the human-readable 'detail' so only name + status remain."""
    if not isinstance(sources, list):
        return sources
    out = []
    for s in sources:
        out.append({"name": s.get("name"), "status": s.get("status")} if isinstance(s, dict) else s)
    return out


def _strip_link_previews(d: dict) -> bool:
    """Strip premium previews from any embedded scanned_links. Returns True if it found any."""
    links = d.get("scanned_links")
    if not isinstance(links, list) or not links:
        return False
    for l in links:
        if isinstance(l, dict):
            l["screenshot_url"] = None
            l["page_title"] = None
            l["sources"] = _reduce_sources(l.get("sources"))
    return True


def strip_premium(result: dict, user: Optional[User]) -> dict:
    """
    For free / anonymous viewers, remove premium-only intel and list what was
    hidden under `tier_locked`. Premium + admin/superadmin get the full object.
    """
    if not isinstance(result, dict) or _is_premium_viewer(user):
        return result

    locked = []
    for f in _PREMIUM_FIELDS:
        if f in result:
            result[f] = None
            locked.append(f)
    if "sources" in result:
        result["sources"] = _reduce_sources(result["sources"])
        locked.append("sources_detail")
    if _strip_link_previews(result):
        locked.append("embedded_link_previews")

    result["tier_locked"] = locked
    return result


def _save_upload(file: UploadFile) -> str:
    suffix = Path(file.filename or "upload").suffix
    fd, path = tempfile.mkstemp(prefix="nexguard_", suffix=suffix)
    os.close(fd)
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return path


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
# NOTE: GET / is no longer an API route — the built React SPA is mounted at /
# (see the _SpaStaticFiles mount at the very bottom of this file).


def _source_config_status() -> dict:
    """Whether each external intel source is configured (has a key) or keyless."""
    def on(var: str) -> str:
        v = os.getenv(var, "").strip()
        return "enabled" if v and v != "your_key_here" else "disabled"
    return {
        "virustotal":    on("VIRUSTOTAL_API_KEY"),
        "safe_browsing": on("GOOGLE_SAFEBROWSING_API_KEY"),
        "urlhaus":       on("URLHAUS_AUTH_KEY"),
        "urlscan":       on("URLSCAN_API_KEY"),
        # OpenPhish + Phishing.Database feeds — no key, so "keyless" unless the
        # eval kill switch turned them off. (Replaced the PhishTank row, whose
        # integration was a stub that never called anything.)
        "community_blocklist": (
            "disabled"
            if os.getenv("NEXGUARD_DISABLE_FEEDS", "").strip().lower() in ("1", "true", "yes")
            else "keyless"
        ),
        "rdap_whois":    "keyless",           # always available, no key needed
        "ip_geo":        "keyless",
        "tls_cert":      "keyless",
    }


@app.get("/health")
def health(user: Optional[User] = Depends(get_optional_user)):
    """
    Health view, detailed for admins and minimal for everyone else.

    The full view names which API keys are configured, the DB/cache backends
    and raw circuit-breaker `last_error` strings — precise reconnaissance for
    an attacker, so anonymous and non-admin callers get only liveness, which is
    all a container healthcheck or status page needs.
    """
    try:
        from intel_health import reputation_status
        _intel = reputation_status()
    except Exception:
        _intel = None

    if not (user and user.role in ("admin", "superadmin")):
        # Deliberately does NOT disclose that the scanner is blind.
        #
        # A first attempt did, on the reasoning that users deserve to know the
        # tool is not checking anything. test_hardening_config caught it, and
        # the tests were right: "our reputation checks are down" on an
        # unauthenticated endpoint tells an attacker exactly when to send
        # phishing links. That is the reconnaissance the OWASP pass closed.
        #
        # Users still find out, in the place that concerns them — every /scan
        # response carries `intel_complete` / `intel_unavailable` and a flag
        # naming the sources that could not be checked, so a degraded VERDICT
        # is disclosed without broadcasting the defence's state to everyone.
        # Operators get the startup banner, the admin view below, and
        # `python check_env.py`.
        return {
            "status": "ok",
            "modules": ["url", "qr", "email", "gmail-safe", "voice", "screenshot"],
        }

    breakers = {b["name"]: b for b in breaker_snapshot()}
    config = _source_config_status()

    sources = {}
    for name, cfg in config.items():
        b = breakers.get(name)
        if b is None:
            state = "ready" if cfg != "disabled" else cfg
            healthy = True
        else:
            # Breaker OPEN -> this source is currently short-circuited (degraded).
            healthy = b["state"] == "closed"
            state = b["state"] if cfg != "disabled" else "disabled"
        sources[name] = {
            "config": cfg,
            "breaker": (b or {}).get("state", "closed"),
            "healthy": healthy,
            "failures": (b or {}).get("total_failures", 0),
            "last_error": (b or {}).get("last_error"),
        }

    degraded = [n for n, s in sources.items()
                if s["config"] != "disabled" and not s["healthy"]]

    return {
        # "degraded" when nothing can be checked. A container healthcheck that
        # only looks for "ok" should fail a blind scanner — it is not serving
        # its purpose, however well the process is running.
        "status": "degraded" if (_intel and _intel["blind"]) else "ok",
        "degraded_sources": degraded,
        # Licence + key coverage, which the breaker view above cannot show: a
        # source blocked by the deployment profile has no breaker state because
        # it is never called, and a valid key for it is not coverage.
        "reputation_intel": _intel,
        "modules": ["url", "qr", "email", "gmail-safe", "voice", "screenshot"],
        "database": db_backend(),
        "cache": {
            "backend": cache_backend(),
            "healthy": cache_healthy(),
            "entries": cache_size(),
        },
        "rate_limit_backend": rate_limit.backend(),
        "sources": sources,
        # Back-compat: keep the original flat virustotal field.
        "virustotal": config["virustotal"],
    }


# ---------------------------------------------------------------------------
# Model performance — the saved ML evaluation metrics (public, read-only)
# ---------------------------------------------------------------------------
_METRICS_PATH = Path(__file__).resolve().parent / "ml" / "metrics.json"


@app.get("/model-metrics")
def model_metrics():
    """
    Return the saved ML evaluation metrics for the Model Performance page:
    accuracy / precision / recall / F1 / ROC-AUC, confusion matrix, ROC-curve
    points, feature importances, dataset size and the chosen model.
    """
    try:
        import json as _json
        with open(_METRICS_PATH, encoding="utf-8") as f:
            metrics = _json.load(f)
    except Exception:
        return JSONResponse(
            status_code=404,
            content={"available": False,
                     "message": "No metrics.json found. Train the model (ml/train.py) first."},
        )

    chosen = metrics.get("chosen_model")
    headline = (metrics.get("models", {}) or {}).get(chosen, {})
    return {
        "available": True,
        "model": chosen,
        "generated_at": metrics.get("generated_at"),
        "selection_metric": metrics.get("selection_metric"),
        "headline": headline,                       # accuracy/precision/recall/f1/roc_auc
        "models": metrics.get("models", {}),        # every candidate's scores
        "dataset": metrics.get("dataset", {}),
        "confusion_matrix": metrics.get("confusion_matrix", {}),
        "roc_curve": metrics.get("roc_curve", {}),
        "feature_importances": metrics.get("feature_importances", []),
    }


# ---------------------------------------------------------------------------
# Real-world evaluation metrics (live pipeline vs. Tranco + OpenPhish/PhishTank)
# Produced by `python -m eval.realworld_eval`; read-only here.
# ---------------------------------------------------------------------------
_REALWORLD_METRICS_PATH = Path(__file__).resolve().parent / "metrics_realworld.json"


@app.get("/model-metrics-realworld")
def model_metrics_realworld():
    """Return the saved real-world evaluation metrics for the Model Performance page."""
    try:
        import json as _json
        with open(_REALWORLD_METRICS_PATH, encoding="utf-8") as f:
            data = _json.load(f)
    except Exception:
        return JSONResponse(
            status_code=404,
            content={"available": False,
                     "message": "No metrics_realworld.json found. "
                                "Run `python -m eval.realworld_eval` first."},
        )
    data["available"] = True
    return data


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.post("/auth/register")
def auth_register(data: RegisterRequest):
    db = SessionLocal()
    try:
        return do_register(db, data.email, data.password)
    finally:
        db.close()


@app.post("/auth/login")
def auth_login(data: LoginRequest, request: FastAPIRequest):
    # The IP is half the lockout key (email+IP), so one attacker cannot lock
    # every other user out of their own account.
    ip = request.client.host if request and request.client else "unknown"
    db = SessionLocal()
    try:
        return do_login(db, data.email, data.password, ip=ip)
    finally:
        db.close()


@app.get("/auth/me")
def auth_me(user: User = Depends(get_current_user)):
    return user.as_dict()


# ---------------------------------------------------------------------------
# Billing — Stripe Premium subscriptions (TEST mode)
# ---------------------------------------------------------------------------
class CheckoutBody(BaseModel):
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None


def _frontend_base(request: FastAPIRequest) -> str:
    """Best-effort origin to redirect back to after Checkout."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin:
        return origin.rstrip("/").split("?")[0]
    return os.getenv("NEXGUARD_FRONTEND_URL", "http://localhost:5500")


@app.get("/billing/config")
def billing_config():
    """Tells the frontend whether Stripe is enabled + the publishable key."""
    return billing.config()


@app.post("/billing/create-checkout-session")
def billing_create_checkout_session(
    request: FastAPIRequest,
    body: Optional[CheckoutBody] = None,
    user: User = Depends(get_current_user),
):
    """Create a Stripe subscription Checkout session and return its URL."""
    if not billing.is_enabled():
        raise HTTPException(status_code=503,
                            detail="Stripe is not configured on the server.")
    if _is_premium_viewer(user):
        raise HTTPException(status_code=400, detail="You already have Premium.")

    base = _frontend_base(request)
    success_url = (body.success_url if body and body.success_url else
                   f"{base}/?billing=success")
    cancel_url = (body.cancel_url if body and body.cancel_url else
                  f"{base}/?billing=cancel")
    try:
        url = billing.create_checkout_session(user, success_url, cancel_url)
        return {"url": url}
    except Exception:
        log.exception("Stripe checkout session failed for user %s", user.id)
        raise HTTPException(
            status_code=502,
            detail="Could not start checkout. Please try again later.",
        )


def _find_billing_user(db, customer_id=None, subscription_id=None, user_id=None):
    """Locate the user a Stripe object belongs to (by id / customer / subscription)."""
    if user_id:
        u = db.query(User).filter(User.id == int(user_id)).first()
        if u:
            return u
    if subscription_id:
        u = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
        if u:
            return u
    if customer_id:
        return db.query(User).filter(User.stripe_customer_id == customer_id).first()
    return None


@app.post("/billing/webhook")
async def billing_webhook(request: FastAPIRequest):
    """
    Stripe webhook. Verifies the signature, then on subscription lifecycle
    events flips the user's tier between premium and free.
    """
    if not billing.is_enabled():
        raise HTTPException(status_code=503, detail="Stripe is not configured.")
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = billing.construct_event(payload, sig)
    except Exception:
        log.warning("Stripe webhook signature verification failed", exc_info=True)
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    etype = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}
    db = SessionLocal()
    try:
        if etype == "checkout.session.completed":
            user = _find_billing_user(
                db,
                customer_id=obj.get("customer"),
                subscription_id=obj.get("subscription"),
                user_id=obj.get("client_reference_id"),
            )
            if user:
                user.tier = "premium"
                if obj.get("customer"):
                    user.stripe_customer_id = obj.get("customer")
                if obj.get("subscription"):
                    user.stripe_subscription_id = obj.get("subscription")
                _audit(db, None, "stripe_subscribe", user.id, "checkout.session.completed")
                db.commit()

        elif etype in ("customer.subscription.updated", "customer.subscription.created"):
            user = _find_billing_user(
                db,
                customer_id=obj.get("customer"),
                subscription_id=obj.get("id"),
                user_id=(obj.get("metadata") or {}).get("user_id"),
            )
            if user:
                active = obj.get("status") in billing.ACTIVE_STATUSES
                user.tier = "premium" if active else "free"
                user.stripe_subscription_id = obj.get("id")
                if obj.get("customer"):
                    user.stripe_customer_id = obj.get("customer")
                _audit(db, None, "stripe_subscription_update", user.id,
                       f"status={obj.get('status')} -> tier={user.tier}")
                db.commit()

        elif etype == "customer.subscription.deleted":
            user = _find_billing_user(
                db,
                customer_id=obj.get("customer"),
                subscription_id=obj.get("id"),
                user_id=(obj.get("metadata") or {}).get("user_id"),
            )
            if user:
                user.tier = "free"
                user.stripe_subscription_id = None
                _audit(db, None, "stripe_cancel", user.id, "subscription.deleted")
                db.commit()
    finally:
        db.close()

    return {"received": True}


# ---------------------------------------------------------------------------
# Approval / administration
# ---------------------------------------------------------------------------
class TierUpdate(BaseModel):
    tier: str

class RoleUpdate(BaseModel):
    role: str

class DecisionBody(BaseModel):
    note: Optional[str] = None

class FeedbackRequest(BaseModel):
    scan_url: str
    module: Optional[str] = "URL Scanner"
    predicted_verdict: Optional[str] = ""
    predicted_score: Optional[int] = 0
    user_label: str                       # "safe" | "malicious"

class FeedbackReview(BaseModel):
    decision: str                         # "accepted" | "rejected"
    note: Optional[str] = None

class SupportAsk(BaseModel):
    question: str
    # C3 — last few conversation turns [{role: user|bot, text}], client-sent
    # and untrusted: normalize_history() validates and caps server-side.
    history: Optional[List[Dict[str, str]]] = None

class TicketCreate(BaseModel):
    email: str
    message: str
    subject: Optional[str] = ""
    category: Optional[str] = "question"  # question | problem | wrong_info | other

class TicketReply(BaseModel):
    reply: str
    status: str                           # "answered" | "resolved" | "open"


def _audit(db, actor_user_id: Optional[int], action: str,
           target_user_id: Optional[int] = None, detail: str = "") -> None:
    """Append an AuditLog row (caller commits)."""
    db.add(AuditLog(
        action=action,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        detail=detail or "",
    ))


@app.post("/requests/upgrade")
def create_upgrade_request(
    body: Optional[DecisionBody] = None,
    user: User = Depends(get_current_user),
):
    """Logged-in user asks to be upgraded to the premium tier."""
    db = SessionLocal()
    try:
        if user.tier == "premium":
            raise HTTPException(status_code=400, detail="You already have premium tier")
        existing = (
            db.query(Request)
            .filter(
                Request.requester_user_id == user.id,
                Request.type == "upgrade",
                Request.status == "pending",
            )
            .first()
        )
        if existing:
            raise HTTPException(status_code=409, detail="You already have a pending upgrade request")
        req = Request(
            type="upgrade",
            requester_user_id=user.id,
            note=(body.note if body and body.note else "") or "",
        )
        db.add(req)
        db.commit()
        db.refresh(req)
        return req.as_dict()
    finally:
        db.close()


@app.get("/admin/requests")
def list_requests(status: str = "pending", admin: User = Depends(require_admin)):
    """List approval requests (default: pending). admin/superadmin only."""
    db = SessionLocal()
    try:
        q = db.query(Request)
        if status and status != "all":
            q = q.filter(Request.status == status)
        rows = q.order_by(Request.id.desc()).all()
        out = []
        for r in rows:
            d = r.as_dict()
            ru = db.query(User).filter(User.id == r.requester_user_id).first()
            d["requester_email"] = ru.email if ru else None
            out.append(d)
        return out
    finally:
        db.close()


def _decide_request(req_id: int, decision: str, actor: User, note: Optional[str]) -> dict:
    db = SessionLocal()
    try:
        req = db.query(Request).filter(Request.id == req_id).first()
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")
        if req.status != "pending":
            raise HTTPException(status_code=409, detail=f"Request already {req.status}")
        # new_admin promotions require a superadmin; upgrades allow admin or superadmin
        if req.type == "new_admin" and actor.role != "superadmin":
            raise HTTPException(status_code=403, detail="Only a superadmin can decide new-admin requests")

        req.status = decision
        req.decided_by = actor.id
        req.decided_at = _utcnow()
        if note:
            req.note = note

        target = db.query(User).filter(User.id == req.requester_user_id).first()
        if decision == "approved" and target:
            if req.type == "upgrade":
                target.tier = "premium"
            elif req.type == "new_admin":
                target.role = "admin"

        _audit(db, actor.id, f"request_{decision}", req.requester_user_id,
               f"type={req.type} request_id={req.id}" + (f" note={note}" if note else ""))
        db.commit()
        db.refresh(req)
        return req.as_dict()
    finally:
        db.close()


@app.post("/requests/{req_id}/approve")
def approve_request(req_id: int, body: Optional[DecisionBody] = None,
                    actor: User = Depends(require_admin)):
    return _decide_request(req_id, "approved", actor, body.note if body else None)


@app.post("/requests/{req_id}/reject")
def reject_request(req_id: int, body: Optional[DecisionBody] = None,
                   actor: User = Depends(require_admin)):
    return _decide_request(req_id, "rejected", actor, body.note if body else None)


# ---------------------------------------------------------------------------
# Verdict feedback loop ("Report incorrect verdict") + admin review
# ---------------------------------------------------------------------------
@app.post("/feedback")
def submit_feedback(body: FeedbackRequest,
                    user: Optional[User] = Depends(get_optional_active_user)):
    """
    Record a user's "this verdict is wrong" report. Anonymous or logged-in.
    Stores the URL-lexical features at report time for the active-learning loop.
    Always returns a complete object.
    """
    label = (body.user_label or "").strip().lower()
    if label not in ("safe", "malicious"):
        raise HTTPException(status_code=400, detail="user_label must be 'safe' or 'malicious'")
    url = (body.scan_url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="scan_url is required")

    # Extract the same offline lexical features used at training/inference time.
    try:
        import json as _json
        from ml.features import extract_features
        feats_json = _json.dumps(extract_features(url))
    except Exception:
        feats_json = ""

    db = SessionLocal()
    try:
        row = VerdictFeedback(
            url=url,
            module=body.module or "URL Scanner",
            predicted_verdict=(body.predicted_verdict or "")[:32],
            predicted_score=int(body.predicted_score or 0),
            user_label=label,
            extracted_features=feats_json,
            user_id=user.id if user else None,
            status="pending",
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return {"ok": True, "feedback": row.as_dict()}
    finally:
        db.close()


@app.get("/admin/feedback")
def list_feedback(status: str = "pending", admin: User = Depends(require_admin)):
    """List reported verdicts (default: pending). admin/superadmin only."""
    db = SessionLocal()
    try:
        q = db.query(VerdictFeedback)
        if status and status != "all":
            q = q.filter(VerdictFeedback.status == status)
        rows = q.order_by(VerdictFeedback.id.desc()).all()
        out = []
        for r in rows:
            d = r.as_dict()
            ru = db.query(User).filter(User.id == r.user_id).first() if r.user_id else None
            d["reporter_email"] = ru.email if ru else "anonymous"
            out.append(d)
        return out
    finally:
        db.close()


@app.post("/admin/feedback/{fb_id}/review")
def review_feedback(fb_id: int, body: FeedbackReview, admin: User = Depends(require_admin)):
    """Accept or reject a reported verdict. Accepted items feed the retrain set."""
    decision = (body.decision or "").strip().lower()
    if decision not in ("accepted", "rejected"):
        raise HTTPException(status_code=400, detail="decision must be 'accepted' or 'rejected'")
    db = SessionLocal()
    try:
        row = db.query(VerdictFeedback).filter(VerdictFeedback.id == fb_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Feedback not found")
        if row.status != "pending":
            raise HTTPException(status_code=409, detail=f"Feedback already {row.status}")
        row.status = decision
        row.reviewed_by = admin.id
        row.reviewed_at = _utcnow()
        if body.note:
            row.admin_note = body.note[:500]
        _audit(db, admin.id, f"feedback_{decision}", row.user_id,
               f"feedback_id={row.id} label={row.user_label} url={row.url[:120]}")
        db.commit()
        db.refresh(row)
        return row.as_dict()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Support center — FAQ assistant + contact tickets (WORK_PLAN Task 12)
# ---------------------------------------------------------------------------
@app.get("/support/faq")
def support_faq():
    """Public FAQ list for the Support page."""
    return [{"question": e["question"], "answer": e["answer"]} for e in FAQ]


@app.post("/support/ask")
async def support_ask(
    body: SupportAsk,
    request: FastAPIRequest,
    user: Optional[User] = Depends(get_optional_active_user),
):
    """
    Assistant with scan tools (C1). A pasted link runs the REAL URL scanner;
    a pasted scam-looking message runs the message analyzer; anything else
    gets the built-in FAQ answer. Scans respect the normal daily quota, but
    the bot answers politely instead of surfacing a raw 429.
    """
    q = body.question or ""

    url = extract_url(q)
    # C3: "scan it again" carries no URL — pull the newest one the user
    # mentioned in the recent turns and re-run the real scan on it.
    rescan = False
    if not url and is_followup_scan(q):
        url = history_url(normalize_history(body.history))
        rescan = url is not None
    if url:
        limited = enforce_scan_quota(user, request)
        if limited:
            return bot_quota_reply()
        result = await full_scan(url)
        if user:
            save_scan("URL Scanner", result, url, user_id=user.id)
        verdict = (result.get("verdict") or "").upper()
        if verdict in ("SUSPICIOUS", "MALICIOUS"):
            await manager.broadcast({
                "verdict": verdict,
                "target": url,
                "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
                "time": _now_iso(),
            }, user_id=user.id if user else None)
        return bot_rescan_reply(url, result) if rescan else bot_scan_reply(url, result)

    reply = answer_question(q)
    if reply["matched"]:
        return reply

    if looks_like_message(q):
        limited = enforce_scan_quota(user, request)
        if limited:
            return bot_quota_reply()
        result = analyze_email(q)
        if user:
            save_scan("Email Analyzer", result, "Support bot message", user_id=user.id)
        return bot_message_reply(result)

    # C2: the FAQ couldn't match — real Claude answers naturally when an
    # ANTHROPIC_API_KEY is configured; otherwise the FAQ fallback stands.
    ai = ai_answer(q, normalize_history(body.history))
    if ai:
        return ai

    return reply


@app.post("/support/tickets")
def create_ticket(body: TicketCreate,
                  user: Optional[User] = Depends(get_optional_active_user)):
    """
    Open a support ticket. Anyone — including anonymous visitors — may submit.
    The ticket lands in the admin Support inbox AND is emailed to the site
    owner (if SMTP is configured). Email failure never blocks creation.
    """
    email = (body.email or "").strip()
    message = (body.message or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid contact email is required")
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    category = (body.category or "question").strip().lower()
    if category not in ("question", "problem", "wrong_info", "other"):
        category = "question"

    db = SessionLocal()
    try:
        row = SupportTicket(
            email=email[:200],
            subject=(body.subject or "")[:200],
            message=message[:5000],
            category=category,
            status="open",
            user_id=user.id if user else None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        ticket = row.as_dict()
    finally:
        db.close()

    # Notify the owner by email — best-effort, never breaks the request.
    try:
        notified = send_ticket_notification(ticket)
    except Exception:
        notified = {"sent": False, "detail": "email failed"}

    return {"ok": True, "ticket": ticket, "email_notification": notified}


@app.get("/support/tickets")
def my_tickets(user: User = Depends(get_current_user)):
    """The signed-in user's own tickets, so they see admin follow-ups."""
    db = SessionLocal()
    try:
        rows = (db.query(SupportTicket)
                .filter(SupportTicket.user_id == user.id)
                .order_by(SupportTicket.id.desc()).all())
        return [r.as_dict() for r in rows]
    finally:
        db.close()


@app.get("/admin/support/tickets")
def admin_list_tickets(status: str = "open", admin: User = Depends(require_admin)):
    """Support inbox (admin/superadmin). Filter by status or 'all'."""
    db = SessionLocal()
    try:
        q = db.query(SupportTicket)
        if status and status != "all":
            q = q.filter(SupportTicket.status == status)
        rows = q.order_by(SupportTicket.id.desc()).all()
        out = []
        for r in rows:
            d = r.as_dict()
            ru = db.query(User).filter(User.id == r.user_id).first() if r.user_id else None
            d["reporter_account"] = ru.email if ru else "not signed in"
            out.append(d)
        return out
    finally:
        db.close()


@app.post("/admin/support/tickets/{ticket_id}/reply")
def admin_reply_ticket(ticket_id: int, body: TicketReply, admin: User = Depends(require_admin)):
    """Reply to a ticket and set its status (open/answered/resolved)."""
    new_status = (body.status or "").strip().lower()
    if new_status not in ("open", "answered", "resolved"):
        raise HTTPException(status_code=400, detail="status must be open, answered or resolved")
    db = SessionLocal()
    try:
        row = db.query(SupportTicket).filter(SupportTicket.id == ticket_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Ticket not found")
        if body.reply and body.reply.strip():
            row.admin_reply = body.reply.strip()[:5000]
            row.replied_by = admin.id
            row.replied_at = _utcnow()
        row.status = new_status
        _audit(db, admin.id, "support_reply", row.user_id,
               f"ticket_id={row.id} status={new_status}")
        db.commit()
        db.refresh(row)
        return row.as_dict()
    finally:
        db.close()


@app.post("/admin/users/{user_id}/role")
def set_user_role(user_id: int, body: RoleUpdate, sa: User = Depends(require_superadmin)):
    """Promote/demote between user and admin. Superadmin only."""
    if body.role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="role must be 'user' or 'admin'")
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if u.role == "superadmin":
            raise HTTPException(status_code=403, detail="Cannot change a superadmin's role")
        u.role = body.role
        _audit(db, sa.id, "set_role", user_id, f"role={body.role}")
        db.commit()
        db.refresh(u)
        return u.as_dict()
    finally:
        db.close()


@app.post("/admin/users/{user_id}/tier")
def set_user_tier(user_id: int, body: TierUpdate, admin: User = Depends(require_admin)):
    if body.tier not in ("free", "premium"):
        raise HTTPException(status_code=400, detail="tier must be 'free' or 'premium'")
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        u.tier = body.tier
        _audit(db, admin.id, "set_tier", user_id, f"tier={body.tier}")
        db.commit()
        db.refresh(u)
        return u.as_dict()
    finally:
        db.close()


@app.post("/admin/users/{user_id}/suspend")
def suspend_user(user_id: int, admin: User = Depends(require_admin)):
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if u.role == "superadmin":
            raise HTTPException(status_code=403, detail="Cannot suspend a superadmin")
        u.status = "suspended"
        _audit(db, admin.id, "suspend", user_id, "")
        db.commit()
        db.refresh(u)
        return u.as_dict()
    finally:
        db.close()


@app.post("/admin/users/{user_id}/activate")
def activate_user(user_id: int, admin: User = Depends(require_admin)):
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        u.status = "active"
        _audit(db, admin.id, "activate", user_id, "")
        db.commit()
        db.refresh(u)
        return u.as_dict()
    finally:
        db.close()


@app.get("/admin/users")
def list_users(admin: User = Depends(require_admin)):
    """All users with role, tier, status and scan counts. admin/superadmin only."""
    db = SessionLocal()
    try:
        rows = db.query(User).order_by(User.id.asc()).all()
        out = []
        for u in rows:
            d = u.as_dict()
            d["total_scans"] = (
                db.query(func.count(ScanHistory.id))
                .filter(ScanHistory.user_id == u.id).scalar() or 0
            )
            out.append(d)
        return out
    finally:
        db.close()


@app.get("/admin/stats")
def admin_stats(admin: User = Depends(require_admin)):
    """Platform-wide totals. admin/superadmin only."""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        by_role, by_tier, by_status = {}, {}, {}
        for u in users:
            by_role[u.role]     = by_role.get(u.role, 0) + 1
            by_tier[u.tier]     = by_tier.get(u.tier, 0) + 1
            by_status[u.status] = by_status.get(u.status, 0) + 1
        total_scans = db.query(func.count(ScanHistory.id)).scalar() or 0
        threats = (
            db.query(func.count(ScanHistory.id))
            .filter(ScanHistory.verdict.in_(["SUSPICIOUS", "MALICIOUS"])).scalar() or 0
        )
        pending = (
            db.query(func.count(Request.id))
            .filter(Request.status == "pending").scalar() or 0
        )
        return {
            "total_users":      len(users),
            "users_by_role":    by_role,
            "users_by_tier":    by_tier,
            "users_by_status":  by_status,
            "total_scans":      total_scans,
            "threats_detected": threats,
            "pending_requests": pending,
        }
    finally:
        db.close()


@app.get("/superadmin/audit")
def get_audit_log(limit: int = 200, sa: User = Depends(require_superadmin)):
    """Full audit trail of privileged actions. superadmin only."""
    db = SessionLocal()
    try:
        rows = (
            db.query(AuditLog).order_by(AuditLog.id.desc())
            .limit(max(1, min(1000, limit))).all()
        )
        out = []
        for r in rows:
            d = r.as_dict()
            a = db.query(User).filter(User.id == r.actor_user_id).first()
            d["actor_email"] = a.email if a else None
            out.append(d)
        return out
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------
@app.post("/scan")
async def scan_url(
    data: URLRequest,
    request: FastAPIRequest,
    user: Optional[User] = Depends(get_optional_active_user),
):
    limited = enforce_scan_quota(user, request)
    if limited:
        return limited
    result = await full_scan(data.url)
    if result.get("scan_time_ms") is not None:
        _scan_times_ms.append(float(result["scan_time_ms"]))
        if len(_scan_times_ms) > _SCAN_TIMES_CAP:
            _scan_times_ms.pop(0)
    if user:
        save_scan("URL Scanner", result, data.url, user_id=user.id)
    verdict = result.get("verdict", "").upper()
    if verdict in ("SUSPICIOUS", "MALICIOUS"):
        await manager.broadcast({
            "verdict": verdict,
            "target": data.url,
            "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
            "time": _now_iso(),
        }, user_id=user.id if user else None)
    return strip_premium(result, user)


class VerifySenderRequest(BaseModel):
    sender: str
    subject: Optional[str] = ""


@app.post("/verify-sender")
def verify_sender(body: VerifySenderRequest):
    """
    Header-free sender-origin check for the extension's webmail badge (E8).
    Local computation only (brand list + domain match) — no network calls,
    no quota, nothing stored.
    """
    return verify_sender_simple(body.sender or "", body.subject or "")


@app.post("/scan-qr")
async def scan_qr(
    request: FastAPIRequest,
    file: UploadFile = File(...),
    user: Optional[User] = Depends(get_optional_active_user),
):
    limited = enforce_scan_quota(user, request)
    if limited:
        return limited
    path = _save_upload(file)
    try:
        qr_data = decode_qr_image(path)
        if not qr_data:
            return {
                "verdict": "UNKNOWN",
                "risk_score": 0,
                "confidence": "Low",
                "analysis": "QR not detected",
                "indicators": [],
            }
        # Full pipeline: sources, screenshot_url, whois, ip_location, plain_summary…
        result = await full_scan(qr_data)
        result["analysis"] = result.get("ai_explanation", "QR URL analyzed with the main URL scanner.")
        result["indicators"] = result.get("reasons", [])
        if user:
            save_scan("QR Scanner", result, result.get("url", qr_data), user_id=user.id)
        verdict = result.get("verdict", "").upper()
        if verdict in ("SUSPICIOUS", "MALICIOUS"):
            await manager.broadcast({
                "verdict": verdict,
                "target": qr_data,
                "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
                "time": _now_iso(),
            }, user_id=user.id if user else None)
        return strip_premium(result, user)
    finally:
        _cleanup_temp(path)


@app.post("/analyze-email")
async def analyze_email_file(
    request: FastAPIRequest,
    file: UploadFile = File(...),
    user: Optional[User] = Depends(get_optional_active_user),
):
    limited = enforce_scan_quota(user, request)
    if limited:
        return limited
    path = _save_upload(file)
    try:
        parsed = parse_email(path)
        combined = (
            f"Subject: {parsed.get('subject','')}\n"
            f"From: {parsed.get('from','')}\n"
            f"Body: {parsed.get('body','')}"
        )

        # Check each attachment's SHA-256 against VirusTotal (concurrent, fail-safe).
        attachments = parsed.get("attachments", []) or []
        if attachments:
            vt_lookups = await asyncio.gather(
                *[asyncio.to_thread(check_file_hash, a["sha256"]) for a in attachments],
                return_exceptions=True,
            )
            for att, vt in zip(attachments, vt_lookups):
                if not isinstance(vt, BaseException):
                    att.update({
                        "status":        vt.get("status", "clean"),
                        "detail":        vt.get("detail", ""),
                        "raw_positives": vt.get("raw_positives", 0),
                    })

        # The sender domain's OWN published policy, for the case the headers
        # settled nothing. A webmail DOM or a forwarded screenshot carries no
        # Authentication-Results at all, which used to leave this scan with no
        # authentication evidence whatever. Failure here is not a verdict: the
        # posture falls back to "unknown", which scores zero.
        _posture = None
        _from_domain = _email_sender_domain(parsed.get("from") or "")
        if _from_domain:
            try:
                _posture = await check_dns_auth(_from_domain)
            except Exception:
                log.warning("dns_auth lookup failed for %s", _from_domain,
                            exc_info=True)
                _posture = None

        result = analyze_email(
            combined,
            auth_results=parsed.get("auth_results"),
            attachments=attachments,
            dns_posture=_posture,
        )
        result["subject"] = parsed.get("subject", "No Subject")
        result["sender"] = parsed.get("from", "Unknown")

        link_scan = await scan_embedded_links(combined)
        _apply_link_scan(result, link_scan)

        if user:
            save_scan("Email Analyzer", result, parsed.get("from", "Unknown"), user_id=user.id)
        verdict = result.get("verdict", "").upper()
        if verdict in ("SUSPICIOUS", "MALICIOUS"):
            await manager.broadcast({
                "verdict": verdict,
                "target": parsed.get("from", "Email"),
                "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
                "time": _now_iso(),
            }, user_id=user.id if user else None)
        return strip_premium(result, user)
    except Exception:
        # The exception text names internal modules and paths — log it, don't
        # hand it to the caller.
        log.exception("Email analyzer failed")
        return {
            "verdict": "ERROR",
            "score": 0,
            "risk_score": 0,
            "reasons": ["The email could not be analyzed."],
            "ai_explanation": "Email analyzer failed. Please try again or contact support.",
        }
    finally:
        _cleanup_temp(path)


@app.get("/gmail-emails")
async def gmail_emails(
    request: FastAPIRequest,
    demo: bool = False,
    user: Optional[User] = Depends(get_optional_active_user),
):
    """
    Honest inbox scan (WORK_PLAN Task 2). Returns a status object:
      {"status": "connected"|"not_connected"|"error"|"demo", "emails": [...], "detail"?}
    Bundled sample emails are served ONLY when the caller explicitly asks
    with ?demo=1 — a missing/broken Gmail connection never fakes an inbox.
    """
    limited = enforce_scan_quota(user, request)
    if limited:
        return limited

    if demo:
        status = "demo"
        emails = await asyncio.to_thread(read_sample_emails)
    else:
        # read_gmail does blocking network I/O — run it off the event loop
        live = await asyncio.to_thread(read_gmail)
        if live.get("status") != "connected":
            return live
        status = "connected"
        emails = live.get("emails", [])

    # Run embedded-link scans on each email body concurrently (max 5 URLs each)
    link_scans = await asyncio.gather(
        *[scan_embedded_links(e.get("body", "")) for e in emails],
        return_exceptions=True,
    )
    for email, lres in zip(emails, link_scans):
        if isinstance(lres, BaseException):
            email["links_found"]   = 0
            email["scanned_links"] = []
        else:
            _apply_link_scan(email, lres)   # verified-sender merge rule (Task 9)
        email.pop("body", None)   # body was only needed for link scanning

    # Only a real connected scan lands in history — demo runs are not scans.
    if user and status == "connected":
        save_scan(
            "Gmail Monitor",
            {"verdict": "SCANNED", "risk_score": 0, "ai_explanation": f"{len(emails)} emails scanned"},
            "Gmail Inbox",
            user_id=user.id,
        )

    # Free / anonymous viewers don't get premium link previews
    if not _is_premium_viewer(user):
        for email in emails:
            if _strip_link_previews(email):
                email["tier_locked"] = ["embedded_link_previews"]
    return {"status": status, "emails": emails}


@app.post("/analyze-voice")
async def analyze_voice_file(
    request: FastAPIRequest,
    file: UploadFile = File(...),
    user: Optional[User] = Depends(get_optional_active_user),
):
    limited = enforce_scan_quota(user, request)
    if limited:
        return limited
    path = _save_upload(file)
    try:
        result = analyze_voice(path)

        link_scan = await scan_embedded_links(result.get("text", ""))
        result["links_found"] = link_scan["links_found"]
        result["scanned_links"] = link_scan["scanned_links"]
        if link_scan["links_found"] > 0:
            new_score = max(result.get("risk_score", 0), link_scan["worst_score"])
            result["risk_score"] = new_score
            result["score"] = new_score
            result["verdict"] = _merge_verdict(new_score)

        if user:
            save_scan("Voice Analyzer", result, file.filename or "audio", user_id=user.id)
        verdict = result.get("verdict", "").upper()
        if verdict in ("SUSPICIOUS", "MALICIOUS"):
            await manager.broadcast({
                "verdict": verdict,
                "target": file.filename or "audio",
                "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
                "time": _now_iso(),
            }, user_id=user.id if user else None)
        return strip_premium(result, user)
    finally:
        _cleanup_temp(path)


@app.post("/analyze-screenshot")
async def analyze_screenshot_file(
    request: FastAPIRequest,
    file: UploadFile = File(...),
    user: Optional[User] = Depends(get_optional_active_user),
):
    limited = enforce_scan_quota(user, request)
    if limited:
        return limited
    path = _save_upload(file)
    try:
        result = analyze_screenshot(path)

        link_scan = await scan_embedded_links(result.get("text", ""))
        result["links_found"] = link_scan["links_found"]
        result["scanned_links"] = link_scan["scanned_links"]
        if link_scan["links_found"] > 0:
            new_score = max(result.get("risk_score", 0), link_scan["worst_score"])
            result["risk_score"] = new_score
            result["score"] = new_score
            result["verdict"] = _merge_verdict(new_score)

        if user:
            save_scan("Screenshot OCR", result, file.filename or "screenshot", user_id=user.id)
        verdict = result.get("verdict", "").upper()
        if verdict in ("SUSPICIOUS", "MALICIOUS"):
            await manager.broadcast({
                "verdict": verdict,
                "target": file.filename or "screenshot",
                "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
                "time": _now_iso(),
            }, user_id=user.id if user else None)
        return strip_premium(result, user)
    finally:
        _cleanup_temp(path)


@app.post("/analyze-image-origin")
async def analyze_image_origin_file(
    request: FastAPIRequest,
    file: UploadFile = File(...),
    user: Optional[User] = Depends(get_optional_active_user),
):
    """AI-generated vs real photo — 3-layer local analysis (image_origin.py).
    Same quota/history/premium contracts as /analyze-screenshot; no
    live-threat broadcast because origin is not a threat verdict."""
    limited = enforce_scan_quota(user, request)
    if limited:
        return limited
    path = _save_upload(file)
    try:
        result = analyze_image_origin(path)
        if user:
            save_scan("AI Image Check", result, file.filename or "image",
                      user_id=user.id)
        return strip_premium(result, user)
    finally:
        _cleanup_temp(path)


# ---------------------------------------------------------------------------
# Reports & history (all from the single DB)
# ---------------------------------------------------------------------------


# /export-report renders a caller-supplied dict into a PDF with ReportLab, and
# anonymous callers may use it — so the input needs a hard ceiling or it is a
# free memory/CPU amplifier. A real report is a few KB.
EXPORT_MAX_BYTES = 256_000
EXPORT_MAX_KEYS = 60


def _validate_export_payload(data: dict) -> None:
    """Reject anything that isn't a plausibly-sized report object."""
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Report data must be an object")
    if len(data) > EXPORT_MAX_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Report data has too many fields (max {EXPORT_MAX_KEYS})",
        )
    try:
        size = len(json.dumps(data, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Report data is not serialisable")
    if size > EXPORT_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Report data is too large (max {EXPORT_MAX_BYTES // 1000} KB)",
        )


@app.post("/export-report")
async def export_report(
    data: dict,
    user: Optional[User] = Depends(get_optional_user),
):
    _validate_export_payload(data)
    safe_name = "NexGuard_Report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".pdf"
    file_path = str(Path(tempfile.gettempdir()) / safe_name)
    generate_report(data, file_path)
    if user:
        save_scan(data.get("module", "Report"), data, data.get("target", ""), user_id=user.id)
    return FileResponse(file_path, media_type="application/pdf", filename=safe_name)


@app.get("/history/lookup")
def history_lookup(target: str, user: Optional[User] = Depends(get_optional_user)):
    """
    Prior-scan history for a target (WORK_PLAN Task 6). Matches earlier scans
    of the SAME registrable domain (or the exact target) so a repeat target is
    obvious on the result. Scope: anonymous -> empty; user -> own; admin -> all.
    """
    domain = _domain_from_url(target or "") or ""
    empty = {"target": target, "domain": domain, "count": 0,
             "verdicts": {"SAFE": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}, "recent": []}
    if user is None or not target:
        return empty

    db = SessionLocal()
    try:
        query = db.query(ScanHistory)
        if user.role not in ("admin", "superadmin"):
            query = query.filter(ScanHistory.user_id == user.id)
        if domain:
            query = query.filter(ScanHistory.target.ilike(f"%{domain}%"))
        else:
            query = query.filter(ScanHistory.target == target)
        rows = query.order_by(ScanHistory.id.desc()).limit(200).all()
    finally:
        db.close()

    verdicts = {"SAFE": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
    recent = []
    for r in rows:
        v = (r.verdict or "").upper()
        if v in verdicts:
            verdicts[v] += 1
        if len(recent) < 8:
            recent.append({
                "module":  r.module,
                "verdict": v or "UNKNOWN",
                "score":   r.score or 0,
                "target":  r.target or "",
                "time":    (r.created_at or _utcnow()).isoformat(timespec="seconds"),
            })

    return {"target": target, "domain": domain, "count": len(rows),
            "verdicts": verdicts, "recent": recent}


@app.get("/history")
def scan_history(
    response: Response,
    limit: int = 100,
    offset: int = 0,
    q: Optional[str] = None,
    module: Optional[str] = None,
    verdict: Optional[str] = None,
    date: Optional[str] = None,
    user: Optional[User] = Depends(get_optional_user),
):
    """
    Returns scan history (always a JSON array, for backward compatibility).

    Search / filter / pagination (all optional):
      q        — substring match on target URL or verdict
      module   — exact module name (e.g. "URL Scanner")
      verdict  — SAFE / SUSPICIOUS / MALICIOUS
      date     — YYYY-MM-DD (single calendar day, UTC)
      limit    — page size (1..500, default 100)
      offset   — rows to skip (pagination)

    Total matching rows are returned in the `X-Total-Count` response header.

    Scope: anonymous -> empty; user -> own scans; admin/superadmin -> all scans.
    """
    response.headers["X-Total-Count"] = "0"
    if user is None:
        return []
    try:
        db = SessionLocal()
        try:
            query = db.query(ScanHistory)
            if user.role not in ("admin", "superadmin"):
                query = query.filter(ScanHistory.user_id == user.id)
            if module:
                query = query.filter(ScanHistory.module == module)
            if verdict:
                query = query.filter(func.upper(ScanHistory.verdict) == verdict.upper())
            if q:
                like = f"%{q}%"
                query = query.filter(
                    (ScanHistory.target.ilike(like)) | (ScanHistory.verdict.ilike(like))
                )
            if date:
                try:
                    day = datetime.strptime(date, "%Y-%m-%d").date()
                    start = datetime(day.year, day.month, day.day)
                    query = query.filter(
                        ScanHistory.created_at >= start,
                        ScanHistory.created_at < start + timedelta(days=1),
                    )
                except ValueError:
                    pass

            total = query.with_entities(func.count(ScanHistory.id)).scalar() or 0
            rows = (
                query.order_by(ScanHistory.id.desc())
                .offset(max(0, offset))
                .limit(max(1, min(500, limit)))
                .all()
            )
            response.headers["X-Total-Count"] = str(total)
            return [r.as_dict() for r in rows]
        finally:
            db.close()
    except Exception:
        return []


def _history_row_for(db, hist_id: int, user: User) -> ScanHistory:
    """Fetch a history row, enforcing ownership (admins/superadmins see all)."""
    row = db.query(ScanHistory).filter(ScanHistory.id == hist_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="History entry not found")
    if user.role not in ("admin", "superadmin") and row.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not your scan")
    return row


@app.post("/history/{hist_id}/rescan")
async def history_rescan(
    hist_id: int,
    request: FastAPIRequest,
    user: User = Depends(get_current_user),
):
    """Re-run a URL/QR scan for a stored history entry's target. Counts toward quota."""
    limited = enforce_scan_quota(user, request)
    if limited:
        return limited
    db = SessionLocal()
    try:
        row = _history_row_for(db, hist_id, user)
        target = row.target or ""
        module = row.module or "URL Scanner"
    finally:
        db.close()

    if not target or not target.lower().startswith(("http://", "https://")) and "." not in target:
        raise HTTPException(status_code=400, detail="This entry has no re-scannable URL target")

    result = await full_scan(target)
    save_scan(module, result, target, user_id=user.id)
    verdict = result.get("verdict", "").upper()
    if verdict in ("SUSPICIOUS", "MALICIOUS"):
        await manager.broadcast({
            "verdict": verdict, "target": target,
            "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
            "time": _now_iso(),
        }, user_id=user.id)
    return strip_premium(result, user)


@app.get("/history/{hist_id}/report.pdf")
def history_report_pdf(hist_id: int, user: User = Depends(get_current_user)):
    """Generate a PDF forensic report for a stored history entry (reportlab)."""
    db = SessionLocal()
    try:
        row = _history_row_for(db, hist_id, user)
        data = {
            "module":         row.module,
            "verdict":        row.verdict,
            "risk_score":     row.score,
            "score":          row.score,
            "target":         row.target,
            "url":            row.target,
            "summary":        row.summary or "",
            "ai_explanation": row.summary or "",
        }
    finally:
        db.close()

    safe_name = f"NexGuard_Report_{hist_id}_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".pdf"
    file_path = str(Path(tempfile.gettempdir()) / safe_name)
    generate_report(data, file_path)
    return FileResponse(file_path, media_type="application/pdf", filename=safe_name)


# ---------------------------------------------------------------------------
# Watchlist (Premium) — monitor domains/URLs for newly-detected threats
# ---------------------------------------------------------------------------
class WatchlistAdd(BaseModel):
    target: str


def _is_threat(verdict: str) -> bool:
    return (verdict or "").upper() in ("SUSPICIOUS", "MALICIOUS")


@app.get("/watchlist")
def watchlist_list(user: User = Depends(require_premium)):
    """List the current user's watched targets with their latest status."""
    db = SessionLocal()
    try:
        rows = (
            db.query(Watchlist)
            .filter(Watchlist.user_id == user.id)
            .order_by(Watchlist.id.desc())
            .all()
        )
        return [r.as_dict() for r in rows]
    finally:
        db.close()


@app.post("/watchlist")
def watchlist_add(body: WatchlistAdd, user: User = Depends(require_premium)):
    """Add a domain / URL to the watchlist."""
    target = (body.target or "").strip()
    if not target or "." not in target:
        raise HTTPException(status_code=400, detail="Enter a valid domain or URL")
    db = SessionLocal()
    try:
        existing = (
            db.query(Watchlist)
            .filter(Watchlist.user_id == user.id, Watchlist.target == target)
            .first()
        )
        if existing:
            raise HTTPException(status_code=409, detail="Already on your watchlist")
        entry = Watchlist(user_id=user.id, target=target)
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry.as_dict()
    finally:
        db.close()


@app.delete("/watchlist/{item_id}")
def watchlist_remove(item_id: int, user: User = Depends(require_premium)):
    """Remove a target from the watchlist."""
    db = SessionLocal()
    try:
        entry = (
            db.query(Watchlist)
            .filter(Watchlist.id == item_id, Watchlist.user_id == user.id)
            .first()
        )
        if not entry:
            raise HTTPException(status_code=404, detail="Watchlist item not found")
        db.delete(entry)
        db.commit()
        return {"deleted": item_id}
    finally:
        db.close()


@app.post("/watchlist/rescan")
async def watchlist_rescan(user: User = Depends(require_premium)):
    """
    Re-scan every watched target on demand. Compares each new verdict to the
    previously stored one; targets that flip from safe/unknown to a threat are
    reported as `new_threats` and pushed to the live-alert feed.
    """
    db = SessionLocal()
    try:
        rows = db.query(Watchlist).filter(Watchlist.user_id == user.id).all()
        items = [(r.id, r.target, r.last_verdict) for r in rows]
    finally:
        db.close()

    if not items:
        return {"checked": 0, "new_threats": [], "results": []}

    targets = [t for (_id, t, _v) in items]
    scans = await asyncio.gather(*[full_scan(t) for t in targets], return_exceptions=True)

    new_threats, results = [], []
    now = _utcnow()
    db = SessionLocal()
    try:
        for (item_id, target, prev_verdict), res in zip(items, scans):
            if isinstance(res, BaseException):
                results.append({"id": item_id, "target": target, "verdict": "ERROR", "score": 0})
                continue
            verdict = (res.get("verdict") or "UNKNOWN").upper()
            score = int(res.get("risk_score", 0) or 0)
            newly = _is_threat(verdict) and not _is_threat(prev_verdict or "")

            entry = db.query(Watchlist).filter(Watchlist.id == item_id).first()
            if entry:
                entry.last_checked = now
                entry.last_verdict = verdict
                entry.last_score = score
            results.append({"id": item_id, "target": target, "verdict": verdict,
                            "score": score, "newly_detected": newly})
            if newly:
                new_threats.append({"id": item_id, "target": target, "verdict": verdict, "score": score})
        db.commit()
    finally:
        db.close()

    # Push newly-detected threats to the live-alert system
    for t in new_threats:
        await manager.broadcast({
            "verdict": t["verdict"],
            "target": f"[Watchlist] {t['target']}",
            "severity": "CRITICAL" if t["verdict"] == "MALICIOUS" else "HIGH",
            "time": _now_iso(),
        }, user_id=user.id)

    return {"checked": len(items), "new_threats": new_threats, "results": results}


# ---------------------------------------------------------------------------
# Public developer API — API keys + X-API-Key authenticated scan endpoint
# ---------------------------------------------------------------------------
class ApiKeyCreate(BaseModel):
    label: Optional[str] = ""


# Per-key in-memory rate limiting / quotas.  key_id -> usage window state.
_API_USAGE: dict[int, dict] = {}
_API_QUOTAS = {
    "free":    {"per_day": 100,   "per_minute": 10},
    "premium": {"per_day": 10000, "per_minute": 60},
}


class _KeyViewer:
    """Lightweight stand-in for strip_premium(): gates by the API key's tier."""
    def __init__(self, tier: str):
        self.tier = tier
        self.role = "user"


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _api_rate_check(key_id: int, tier: str) -> Optional[JSONResponse]:
    """Fixed-window per-minute + per-day quota per key. 429 JSONResponse if over."""
    quota = _API_QUOTAS.get(tier, _API_QUOTAS["free"])
    today = _utcnow().date()
    minute = int(time.time() // 60)
    st = _API_USAGE.get(key_id)
    if not st or st["day"] != today:
        st = {"day": today, "day_count": 0, "minute": minute, "min_count": 0}
    if st["minute"] != minute:
        st["minute"] = minute
        st["min_count"] = 0

    if st["day_count"] >= quota["per_day"]:
        _API_USAGE[key_id] = st
        return JSONResponse(status_code=429, content={
            "error": "quota_exceeded",
            "message": f"Daily quota of {quota['per_day']} requests reached for this {tier} key.",
        })
    if st["min_count"] >= quota["per_minute"]:
        _API_USAGE[key_id] = st
        return JSONResponse(status_code=429, content={
            "error": "rate_limited",
            "message": f"Rate limit of {quota['per_minute']} requests/minute reached. Slow down.",
        })

    st["day_count"] += 1
    st["min_count"] += 1
    _API_USAGE[key_id] = st
    return None


@app.post("/api-keys")
def create_api_key(body: ApiKeyCreate, user: User = Depends(get_current_user)):
    """
    Create a developer API key for the logged-in user. The RAW key is returned
    ONCE here and never again — only its SHA-256 hash is stored. The key inherits
    the user's current tier (free/premium) for response detail + quotas.
    """
    raw = "ngk_" + secrets.token_urlsafe(32)
    tier = "premium" if _is_premium_viewer(user) else "free"
    db = SessionLocal()
    try:
        key = ApiKey(
            user_id=user.id,
            key_hash=_hash_key(raw),
            prefix=raw[:12],
            label=(body.label or "").strip()[:80],
            tier=tier,
        )
        db.add(key)
        db.commit()
        db.refresh(key)
        out = key.as_dict()
        out["key"] = raw   # shown only once
        return out
    finally:
        db.close()


@app.get("/api-keys")
def list_api_keys(user: User = Depends(get_current_user)):
    """List the user's API keys (never returns raw keys)."""
    db = SessionLocal()
    try:
        rows = (
            db.query(ApiKey)
            .filter(ApiKey.user_id == user.id)
            .order_by(ApiKey.id.desc())
            .all()
        )
        return [k.as_dict() for k in rows]
    finally:
        db.close()


@app.post("/api-keys/{key_id}/revoke")
def revoke_api_key(key_id: int, user: User = Depends(get_current_user)):
    """Revoke (deactivate) one of the user's API keys."""
    db = SessionLocal()
    try:
        key = (
            db.query(ApiKey)
            .filter(ApiKey.id == key_id, ApiKey.user_id == user.id)
            .first()
        )
        if not key:
            raise HTTPException(status_code=404, detail="API key not found")
        key.active = 0
        db.commit()
        db.refresh(key)
        return key.as_dict()
    finally:
        db.close()


@app.post("/api/v1/scan")
async def public_api_scan(
    data: URLRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """
    Public URL scan authenticated by the `X-API-Key` header.

    - Enforces per-key rate limits + daily quota (free vs premium key tiers).
    - Returns the same JSON as /scan via the shared aggregator.
    - Premium keys get full forensic detail; free keys get tier-limited fields
      (same gating as the free web tier), with a `tier_locked` list.
    """
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    db = SessionLocal()
    try:
        key = (
            db.query(ApiKey)
            .filter(ApiKey.key_hash == _hash_key(x_api_key), ApiKey.active == 1)
            .first()
        )
        if not key:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")

        limited = _api_rate_check(key.id, key.tier)
        if limited:
            return limited

        key.last_used = _utcnow()
        key.request_count = (key.request_count or 0) + 1
        owner_id, tier = key.user_id, key.tier
        db.commit()
    finally:
        db.close()

    result = await full_scan(data.url)
    save_scan("Developer API", result, data.url, user_id=owner_id)

    verdict = result.get("verdict", "").upper()
    if verdict in ("SUSPICIOUS", "MALICIOUS"):
        await manager.broadcast({
            "verdict": verdict, "target": f"[API] {data.url}",
            "severity": "CRITICAL" if verdict == "MALICIOUS" else "HIGH",
            "time": _now_iso(),
        }, user_id=owner_id)

    return strip_premium(result, _KeyViewer(tier))


# ---------------------------------------------------------------------------
# Batch scanning (Premium) — upload a CSV / list of URLs, scan concurrently with
# live progress, then export the results table as CSV or PDF.
# ---------------------------------------------------------------------------
import csv as _csv
import io as _io
import re
import uuid as _uuid

from ai_engine import is_valid_scan_url

# In-memory job store: job_id -> job dict. (For multi-instance deployments back
# this with Redis; single instance keeps it simple and dependency-free.)
_BATCH_JOBS: dict[str, dict] = {}
_BATCH_MAX = 200            # max URLs accepted per batch (reuses the premium scale)
_BATCH_CONCURRENCY = 8      # parallel scans per job — bounded to protect upstreams
_BATCH_JOBS_CAP = 50        # keep only the most recent N jobs in memory
# UNKNOWN rows are scanned once more after the main pass, a few at a time. On
# 2026-10-09 a busy batch left 130 of 200 rows UNKNOWN although no source had
# failed — the lookups were late, not down — and the same URLs scanned again
# later came back SAFE 133 / UNKNOWN 0 (tests/test_batch_unknown_recheck.py).
_BATCH_RECHECK_CONCURRENCY = 2
# Re-checks that come back UNKNOWN this many times in a row mean the sources
# really are unreachable (no key, outage); the rest keep their UNKNOWN.
_BATCH_RECHECK_GIVE_UP = 4
# Safe Browsing's limiter (apis.quota) allows a burst of 120 lookups and then
# 2 a second. A fast main pass (about 35 s for 200 URLs) uses the burst up, so
# the re-check waits twice this long before it starts and pauses this long
# between its own scans. That keeps it under the refill rate. Started at once
# on 2026-10-09, it found the budget empty and left 4 rows UNKNOWN.
_BATCH_RECHECK_PAUSE_S = 1.0


_BATCH_HEADER_WORDS = {"url", "urls", "link", "links", "domain", "domains", "website", "site"}
# Every verdict a scan can return. UNKNOWN ("not checked") was missing, so on
# 2026-09-29 89 of 200 rows were in no counter and the summary read "Errors 0".
_BATCH_VERDICTS = ("MALICIOUS", "SUSPICIOUS", "SAFE", "UNKNOWN", "ERROR")
# '#' after whitespace starts a comment ("https://x.com   # note"). A '#'
# glued to a URL is a real fragment (https://x.com/docs#install) and stays.
_INLINE_COMMENT = re.compile(r"\s+#.*$")


def _batch_lines(raw: str):
    """Non-empty input lines with comment lines dropped and inline comments cut."""
    for line in (raw or "").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            yield _INLINE_COMMENT.sub("", s)


def _parse_batch(raw: str) -> dict:
    """
    Extract scan targets from pasted text or a CSV/TXT body.

    * Comment lines ('# ...') and inline comments ('url   # ...') are ignored.
    * A CSV whose first row names a url/domain column is read from that column
      only — the test-pack CSV used to contribute 'https://0.001' for every
      ml= score. A header-less 'rank,domain' list still works field by field.
    * A field that looks like a URL attempt (has '.' or '://') but whose host is
      not a real hostname is rejected and counted, never scanned as "SAFE".
    * De-duplicated, order preserved, capped at _BATCH_MAX — and the overflow
      is counted, not silently dropped.

    Returns {"targets": [...], "invalid_count": n, "over_limit": n}.
    """
    lines = list(_batch_lines(raw))
    column = None
    if lines and "," in lines[0]:
        header = [h.strip().strip("\"'").lower() for h in next(_csv.reader([lines[0]]))]
        named = [i for i, h in enumerate(header) if h in _BATCH_HEADER_WORDS]
        if named:
            column, lines = named[0], lines[1:]

    targets: list[str] = []
    seen: set[str] = set()
    invalid = over = 0
    for line in lines:
        fields = next(_csv.reader([line])) if "," in line else [line]
        if column is not None:
            fields = [fields[column]] if column < len(fields) else []
        for field in fields:
            tok = field.strip().strip('"').strip("'").strip()
            if not tok or tok.lower() in _BATCH_HEADER_WORDS:
                continue
            if "." not in tok and "://" not in tok:
                continue                  # a rank number or a label, not a URL attempt
            url = tok if tok.lower().startswith(("http://", "https://")) else "https://" + tok
            if not is_valid_scan_url(url):
                invalid += 1
                continue
            key = url.lower()
            if key in seen:
                continue
            seen.add(key)
            if len(targets) >= _BATCH_MAX:
                over += 1
                continue
            targets.append(url)
    return {"targets": targets, "invalid_count": invalid, "over_limit": over}


def _parse_batch_targets(raw: str) -> list[str]:
    """Just the target list — see _parse_batch for the counts."""
    return _parse_batch(raw)["targets"]


def _new_batch_job(job_id: str, user_id: int, targets: list[str],
                   invalid_count: int = 0, over_limit: int = 0) -> dict:
    return {
        "id": job_id,
        "user_id": user_id,
        "status": "running",
        "total": len(targets),
        "done": 0,
        "created_at": _utcnow().isoformat(),
        "counts": {v: 0 for v in _BATCH_VERDICTS},
        "results": [],
        "invalid_count": invalid_count,
        "over_limit": over_limit,
        "error": None,
    }


def _ordered_results(job: dict) -> list[dict]:
    """Rows in the order the user listed them, not the order scans finished."""
    return sorted(job["results"], key=lambda r: r.get("index", 0))


def _batch_view(job: dict) -> dict:
    """Public-facing view of a job (no internal-only fields)."""
    return {
        "job_id": job["id"],
        "status": job["status"],
        "total": job["total"],
        "done": job["done"],
        "created_at": job["created_at"],
        "counts": job["counts"],
        "results": _ordered_results(job),
        "invalid_count": job.get("invalid_count", 0),
        "over_limit": job.get("over_limit", 0),
        "limit": _BATCH_MAX,
        "error": job.get("error"),
    }


def _batch_gc() -> None:
    """Drop oldest jobs once we exceed the cap (cheap memory guard)."""
    if len(_BATCH_JOBS) <= _BATCH_JOBS_CAP:
        return
    for jid in sorted(_BATCH_JOBS, key=lambda k: _BATCH_JOBS[k]["created_at"])[:-_BATCH_JOBS_CAP]:
        _BATCH_JOBS.pop(jid, None)


async def _run_batch(job_id: str, targets: list[str], user_id: int) -> None:
    """Background task: scan all targets concurrently, updating the job live.

    A row that comes back UNKNOWN is held back and scanned once more after the
    main pass (see _BATCH_RECHECK_CONCURRENCY), so it is counted, stored and
    shown only with its final answer.
    """
    job = _BATCH_JOBS[job_id]
    sem = asyncio.Semaphore(_BATCH_CONCURRENCY)
    held: list[tuple[dict, Optional[dict]]] = []   # UNKNOWN rows awaiting a re-check

    async def _scan(index: int, target: str) -> tuple[dict, Optional[dict]]:
        try:
            # previews=False: a batch row has no screenshot or explanation to
            # show, so it does not wait for them (tests/test_batch_no_previews.py).
            res = await full_scan(target, previews=False)
        except Exception as e:  # noqa: BLE001 — one URL must never kill the job
            return {
                "index": index,
                "target": target, "url": target, "verdict": "ERROR",
                "risk_score": 0, "confidence": None, "scan_time_ms": None,
                "sources": [], "summary": f"Scan failed: {type(e).__name__}",
            }, None
        return {
            "index": index,
            "target": target,
            "url": res.get("url", target),
            "verdict": (res.get("verdict") or "ERROR").upper(),
            "risk_score": int(res.get("risk_score", 0) or 0),
            "confidence": res.get("confidence"),
            "scan_time_ms": res.get("scan_time_ms"),
            "sources": _reduce_sources(res.get("sources", [])),
            "summary": res.get("plain_summary") or res.get("ai_explanation", ""),
        }, res

    def _finish(entry: dict, res: Optional[dict]) -> None:
        if res is not None:
            try:
                save_scan("Batch Scanner", res, entry["target"], user_id=user_id)
            except Exception:
                log.exception("Batch scan: could not store result for %s", entry["target"])
        job["results"].append(entry)
        job["counts"][entry["verdict"]] = job["counts"].get(entry["verdict"], 0) + 1
        job["done"] += 1

    async def _one(index: int, target: str) -> None:
        async with sem:
            entry, res = await _scan(index, target)
        if entry["verdict"] == "UNKNOWN":
            held.append((entry, res))
        else:
            _finish(entry, res)

    async def _recheck() -> None:
        if not held:
            return
        queue = sorted(held, key=lambda h: h[0]["index"])
        misses = 0      # re-checks in a row that were UNKNOWN again

        async def worker() -> None:
            nonlocal misses
            while queue and misses < _BATCH_RECHECK_GIVE_UP:
                entry, res = queue.pop(0)
                new_entry, new_res = await _scan(entry["index"], entry["target"])
                if new_res is None:             # the re-check itself failed
                    _finish(entry, res)
                else:
                    misses = misses + 1 if new_entry["verdict"] == "UNKNOWN" else 0
                    _finish(new_entry, new_res)
                await asyncio.sleep(_BATCH_RECHECK_PAUSE_S)

        await asyncio.sleep(2 * _BATCH_RECHECK_PAUSE_S)   # let the budget refill
        await asyncio.gather(*[worker() for _ in range(_BATCH_RECHECK_CONCURRENCY)])
        rechecked = len(held) - len(queue)
        for entry, res in queue:                # gave up: keep the first answer
            _finish(entry, res)
        log.info("Batch %s: re-checked %d UNKNOWN row(s); %d still UNKNOWN",
                 job_id, rechecked, job["counts"].get("UNKNOWN", 0))

    try:
        await asyncio.gather(*[_one(i, t) for i, t in enumerate(targets)],
                             return_exceptions=True)
        await _recheck()
        job["status"] = "completed"
    except Exception as e:  # noqa: BLE001
        job["status"] = "error"
        job["error"] = str(e)


class BatchScanBody(BaseModel):
    urls: list[str]


@app.post("/scan-batch")
async def scan_batch(
    file: Optional[UploadFile] = File(None),
    urls: Optional[str] = Form(None),
    user: User = Depends(require_premium),
):
    """
    Start a batch scan (Premium). Accepts EITHER a CSV/TXT file upload OR a
    pasted `urls` form field (newline/comma separated). Returns a job_id; poll
    GET /scan-batch/{job_id} for live progress and results.
    """
    raw = ""
    if file is not None:
        try:
            raw = (await file.read()).decode("utf-8", errors="replace")
        except Exception:
            raw = ""
    if urls:
        raw = (raw + "\n" + urls) if raw else urls

    parsed = _parse_batch(raw)
    targets = parsed["targets"]
    if not targets:
        skipped = parsed["invalid_count"]
        raise HTTPException(
            status_code=400,
            detail=("No valid URLs found"
                    + (f" ({skipped} line(s) were not valid web addresses)" if skipped else "")
                    + ". Upload a CSV/TXT or paste one URL per line."),
        )

    job_id = _uuid.uuid4().hex[:12]
    _BATCH_JOBS[job_id] = _new_batch_job(
        job_id, user.id, targets,
        invalid_count=parsed["invalid_count"], over_limit=parsed["over_limit"])
    _batch_gc()
    asyncio.create_task(_run_batch(job_id, targets, user.id))
    return {"job_id": job_id, "total": len(targets), "status": "running",
            "invalid_count": parsed["invalid_count"],
            "over_limit": parsed["over_limit"], "limit": _BATCH_MAX}


def _get_owned_job(job_id: str, user: User) -> dict:
    job = _BATCH_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Batch job not found or expired")
    if job["user_id"] != user.id and user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Not your batch job")
    return job


@app.get("/scan-batch/{job_id}")
def scan_batch_status(job_id: str, user: User = Depends(require_premium)):
    """Poll a batch job's progress + results (Premium, owner only)."""
    return _batch_view(_get_owned_job(job_id, user))


@app.get("/scan-batch/{job_id}/export.csv")
def scan_batch_csv(job_id: str, user: User = Depends(require_premium)):
    """Download the batch results as a CSV file."""
    job = _get_owned_job(job_id, user)
    buf = _io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["url", "verdict", "risk_score", "confidence", "scan_time_ms", "summary"])
    for r in _ordered_results(job):
        w.writerow([
            r.get("url", ""), r.get("verdict", ""), r.get("risk_score", ""),
            r.get("confidence", ""), r.get("scan_time_ms", ""), r.get("summary", ""),
        ])
    fname = f"NexGuard_Batch_{job_id}.csv"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/scan-batch/{job_id}/report.pdf")
def scan_batch_pdf(job_id: str, user: User = Depends(require_premium)):
    """Download the batch results as a PDF report."""
    job = _get_owned_job(job_id, user)
    safe_name = f"NexGuard_Batch_{job_id}.pdf"
    file_path = str(Path(tempfile.gettempdir()) / safe_name)
    generate_batch_report(job, file_path)
    return FileResponse(file_path, media_type="application/pdf", filename=safe_name)


@app.get("/stats")
def stats(user: Optional[User] = Depends(get_optional_user)):
    """
    Returns scan statistics.
    - Anonymous: all zeros.
    - User: stats for their scans only.
    - Admin: global stats across all users.
    """
    _empty = {"total_scans": 0, "threats_blocked": 0, "avg_scan_time_ms": None, "scans_today": 0}
    if user is None:
        return _empty

    today_midnight = _utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    try:
        db = SessionLocal()
        base = db.query(ScanHistory)
        if user.role not in ("admin", "superadmin"):
            base = base.filter(ScanHistory.user_id == user.id)

        total_scans     = base.with_entities(func.count(ScanHistory.id)).scalar() or 0
        threats_blocked = (
            base.filter(ScanHistory.verdict.in_(["SUSPICIOUS", "MALICIOUS"]))
            .with_entities(func.count(ScanHistory.id)).scalar() or 0
        )
        scans_today = (
            base.filter(ScanHistory.created_at >= today_midnight)
            .with_entities(func.count(ScanHistory.id)).scalar() or 0
        )
        db.close()
    except Exception:
        total_scans, threats_blocked, scans_today = 0, 0, 0

    avg_scan_time_ms = (
        round(sum(_scan_times_ms) / len(_scan_times_ms), 1)
        if _scan_times_ms else None
    )

    return {
        "total_scans":      total_scans,
        "threats_blocked":  threats_blocked,
        "avg_scan_time_ms": avg_scan_time_ms,
        "scans_today":      scans_today,
    }


# ---------------------------------------------------------------------------
# Analytics — real charts derived from the history DB
# ---------------------------------------------------------------------------

# substring (lowercase) -> canonical threat-type label, matched against the
# stored scan summary/flags text.
_THREAT_TYPE_RULES = [
    ("phish",                       "Phishing"),
    ("malware",                     "Malware"),
    ("malicious download",          "Malware"),
    ("urlhaus",                     "Blacklisted"),
    ("blacklist",                   "Blacklisted"),
    ("blocklist",                   "Blacklisted"),
    ("safe browsing",               "Blacklisted"),
    ("shorten",                     "URL Shortener"),
    ("tld",                         "Suspicious TLD"),
    ("impersonat",                  "Brand Impersonation"),
    ("typosquat",                   "Typosquatting"),
    ("look-alike",                  "Typosquatting"),
    ("redirect",                    "Suspicious Redirect"),
    ("raw ip",                      "Raw IP Address"),
    ("ip address",                  "Raw IP Address"),
    ("no https",                    "Insecure (no HTTPS)"),
    ("not https",                   "Insecure (no HTTPS)"),
    ("insecure",                    "Insecure (no HTTPS)"),
    ("keyword",                     "Suspicious Keywords"),
    ("login",                       "Credential Harvesting"),
    ("password",                    "Credential Harvesting"),
    ("verify",                      "Credential Harvesting"),
    ("scam",                        "Scam / Fraud"),
    ("otp",                         "OTP / 2FA Theft"),
]

# brand keywords commonly impersonated in phishing, matched against target+summary.
_BRAND_KEYWORDS = [
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google",
    "gmail", "amazon", "facebook", "instagram", "whatsapp", "netflix", "linkedin",
    "chase", "wells fargo", "hsbc", "barclays", "citibank", "bank of america",
    "dhl", "fedex", "ups", "usps", "coinbase", "binance", "metamask", "walmart",
    "ebay", "steam", "telegram", "dropbox", "adobe", "spotify",
]


def _top_counts(counter: Counter, key_name: str, n: int = 6) -> list:
    return [{key_name: k, "count": c} for k, c in counter.most_common(n)]


def _aggregate_analytics(rows, day_keys) -> dict:
    """
    Pure aggregation over history rows (Task 4). Facet columns stored at scan
    time drive the type/brand/origin panels; rows saved before the facet
    migration fall back to the old keyword rules so history isn't blank.
    """
    dist = {"safe": 0, "suspicious": 0, "malicious": 0}
    over_time = {d.isoformat(): 0 for d in day_keys}
    activity = {d.isoformat(): {"safe": 0, "suspicious": 0, "malicious": 0} for d in day_keys}
    type_counter: Counter = Counter()
    brand_counter: Counter = Counter()
    geo_counter: Counter = Counter()

    for r in rows:
        v = (r.verdict or "").upper()
        bucket = v.lower() if v in ("MALICIOUS", "SUSPICIOUS", "SAFE") else None
        if bucket:
            dist[bucket] += 1

        dkey = r.created_at.date().isoformat() if r.created_at else None
        if bucket and dkey in activity:
            activity[dkey][bucket] += 1

        is_threat = v in ("MALICIOUS", "SUSPICIOUS")
        if not is_threat:
            continue

        if dkey in over_time:
            over_time[dkey] += 1

        stored_types = [t for t in (getattr(r, "threat_types", "") or "").split(",") if t]
        stored_brand = getattr(r, "brand", "") or ""
        if stored_types:
            for t in stored_types:
                type_counter[t] += 1
        else:
            # legacy row (pre-facet migration): shallow keyword fallback
            text = f"{r.summary or ''} {r.target or ''}".lower()
            seen_types = set()
            for needle, label in _THREAT_TYPE_RULES:
                if needle in text and label not in seen_types:
                    type_counter[label] += 1
                    seen_types.add(label)
        if stored_brand:
            brand_counter[stored_brand] += 1
        elif not stored_types:
            text = f"{r.summary or ''} {r.target or ''}".lower()
            for brand in _BRAND_KEYWORDS:
                if brand in text:
                    brand_counter[brand.title()] += 1

        country = getattr(r, "geo_country", "") or ""
        if country:
            geo_counter[country] += 1

    geo = []
    for country, count in geo_counter.most_common(12):
        point = country_centroid(country)
        geo.append({
            "country": country,
            "lat": point[0] if point else None,
            "lng": point[1] if point else None,
            "count": count,
        })

    return {
        "verdict_distribution": dist,
        "threats_over_time": [{"date": k, "count": over_time[k]} for k in over_time],
        "scan_activity": [{"date": k, **activity[k]} for k in activity],
        "top_threat_types": _top_counts(type_counter, "type"),
        "top_targeted_brands": _top_counts(brand_counter, "brand"),
        "threat_geo": geo,
    }


@app.get("/analytics")
async def analytics(days: int = 7, user: Optional[User] = Depends(get_optional_user)):
    """
    Dashboard analytics from the history DB (Task 4: facets stored at scan
    time; origin countries cached in the DB — no live lookups here).
    - Anonymous: empty structure.
    - Free / user: their own scans.
    - Admin / superadmin: global, across all users.
    - days: activity window, 7 (default) or 30.
    """
    days = 30 if days >= 30 else 7
    today = _utcnow().date()
    day_keys = [(today - timedelta(days=i)) for i in range(days - 1, -1, -1)]
    empty = {
        "scope": "none",
        "days": days,
        "verdict_distribution": {"safe": 0, "suspicious": 0, "malicious": 0},
        "threats_over_time": [{"date": d.isoformat(), "count": 0} for d in day_keys],
        "scan_activity": [
            {"date": d.isoformat(), "safe": 0, "suspicious": 0, "malicious": 0} for d in day_keys
        ],
        "top_threat_types": [],
        "top_targeted_brands": [],
        "recent_scans": [],
        "threat_geo": [],
    }
    if user is None:
        return empty

    is_global = user.role in ("admin", "superadmin")

    try:
        db = SessionLocal()
        try:
            base = db.query(ScanHistory)
            if not is_global:
                base = base.filter(ScanHistory.user_id == user.id)
            # Most-recent window keeps the work bounded on large datasets
            rows = base.order_by(ScanHistory.id.desc()).limit(2000).all()
        finally:
            db.close()
    except Exception:
        return empty

    aggregated = _aggregate_analytics(rows, day_keys)

    recent = [
        {
            "module":  r.module,
            "target":  r.target or "",
            "verdict": (r.verdict or "UNKNOWN").upper(),
            "score":   r.score or 0,
            "time":    (r.created_at or _utcnow()).isoformat(timespec="seconds"),
        }
        for r in rows[:8]
    ]

    return {
        "scope": "global" if is_global else "user",
        "days": days,
        "recent_scans": recent,
        **aggregated,
    }


# ---------------------------------------------------------------------------
# Live threat feed — real data (URLHaus + OpenPhish), cached 5 min. There is
# NO demo fallback (Task 5): if both feeds are unreachable the endpoint says
# so honestly and retries sooner.
# ---------------------------------------------------------------------------
_THREAT_CACHE: dict = {"data": None, "ts": 0.0}
_CACHE_TTL = 300        # seconds — successful fetches
_CACHE_TTL_FAIL = 60    # seconds — failed fetches retry sooner

_HEADERS = {"User-Agent": "NexGuard-AI/2.0"}


def _fetch_urlhaus() -> list:
    resp = requests.get(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        timeout=10,
        headers=_HEADERS,
    )
    resp.raise_for_status()
    items = resp.json().get("urls", [])[:10]
    return [
        {
            "type": "MALWARE",
            "target": item["url"],
            "severity": "CRITICAL" if item.get("threat") == "malware_download" else "HIGH",
            "source": "URLHaus",
        }
        for item in items
        if item.get("url")
    ]


def _fetch_openphish() -> list:
    resp = requests.get(
        "https://openphish.com/feed.txt",
        timeout=10,
        headers=_HEADERS,
    )
    resp.raise_for_status()
    urls = [u.strip() for u in resp.text.splitlines() if u.strip()][:10]
    return [
        {
            "type": "PHISHING",
            "target": url,
            "severity": "HIGH",
            "source": "OpenPhish",
        }
        for url in urls
    ]


@app.get("/live-threats")
async def live_threats():
    """
    Honest live feed (Task 5): {status: live|unavailable, threats, sources,
    fetched_at, detail?}. No demo rows — if both feeds are unreachable the
    response says so and the cache retries sooner.
    """
    global _THREAT_CACHE

    cached = _THREAT_CACHE["data"]
    if cached is not None:
        ttl = _CACHE_TTL if cached.get("status") == "live" else _CACHE_TTL_FAIL
        if (time.monotonic() - _THREAT_CACHE["ts"]) < ttl:
            return cached

    # Fetch both sources concurrently without blocking the event loop
    urlhaus_res, openphish_res = await asyncio.gather(
        asyncio.to_thread(_fetch_urlhaus),
        asyncio.to_thread(_fetch_openphish),
        return_exceptions=True,
    )

    threats: list = []
    sources: list = []
    if not isinstance(urlhaus_res, BaseException):
        threats.extend(urlhaus_res)
        sources.append("URLHaus")
    if not isinstance(openphish_res, BaseException):
        threats.extend(openphish_res)
        sources.append("OpenPhish")

    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if threats or sources:
        payload = {
            "status": "live",
            "threats": threats,
            "sources": sources,
            "fetched_at": fetched_at,
        }
    else:
        payload = {
            "status": "unavailable",
            "threats": [],
            "sources": [],
            "fetched_at": fetched_at,
            "detail": (
                "Threat feeds (URLHaus, OpenPhish) are unreachable right now — "
                "retrying automatically."
            ),
        }

    _THREAT_CACHE = {"data": payload, "ts": time.monotonic()}
    return payload


def _ws_authenticate(token: Optional[str]) -> Optional[User]:
    """
    Resolve a WebSocket ?token= JWT to an active user, or None.

    Mirrors get_current_user, but a WebSocket handshake carries no
    Authorization header, so the token arrives as a query parameter. Suspended
    and deleted accounts are refused, same as the HTTP dependencies.
    """
    if not token:
        return None
    try:
        user_id = int(_decode_token(token)["sub"])
    except Exception:
        return None

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
    except Exception:
        log.exception("WebSocket auth: user lookup failed")
        return None
    finally:
        db.close()

    if not user or user.status == "suspended":
        return None
    return user


@app.websocket("/ws/live-alerts")
async def websocket_alerts(websocket: WebSocket, token: Optional[str] = None):
    user = _ws_authenticate(token)
    if user is None:
        # Refuse before accept() — the handshake fails instead of opening a
        # socket we would then have to police.
        await websocket.close(code=1008)  # policy violation
        return

    q = await manager.connect(websocket, user_id=user.id)
    try:
        while True:
            try:
                payload = await asyncio.wait_for(q.get(), timeout=20)
                await websocket.send_json(payload)
            except asyncio.TimeoutError:
                # keep the connection alive when no real events arrive
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        pass  # the client going away is the normal way this loop ends
    except Exception:
        log.warning("Live-alert socket for user %s closed on error", user.id,
                    exc_info=True)
    finally:
        manager.disconnect(q)


# ---------------------------------------------------------------------------
# SPA static serving — MUST stay the last mount so every API route above wins.
# Serves frontend/dist when it exists; unknown non-API paths fall back to
# index.html so client-side routes (/scan, /activity, ...) deep-link cleanly.
# Without a build the backend still boots (dev mode uses `npm run dev`).
# ---------------------------------------------------------------------------
from fastapi.staticfiles import StaticFiles  # noqa: E402
from starlette.exceptions import HTTPException as StarletteHTTPException  # noqa: E402

_FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


class _SpaStaticFiles(StaticFiles):
    """Serve the built SPA; unknown non-API paths fall back to index.html so
    client-side routes (/scan, /activity, ...) deep-link correctly."""

    async def get_response(self, path, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as e:
            if e.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


if _FRONTEND_DIST.is_dir():
    app.mount("/", _SpaStaticFiles(directory=str(_FRONTEND_DIST), html=True), name="spa")
