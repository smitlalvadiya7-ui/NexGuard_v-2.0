from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Date, ForeignKey, Enum
from db_config import Base


def _utcnow() -> datetime:
    """Naive UTC now. Replaces datetime.utcnow(), which is deprecated since
    Python 3.12. Returns a naive value, exactly as utcnow() did, because the
    stored rows and the WHOIS dates it is compared against are naive."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    email         = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role          = Column(Enum("user", "admin", "superadmin", name="user_role"),
                           default="user", nullable=False)
    tier          = Column(Enum("free", "premium", name="user_tier"),
                           default="free", nullable=False)
    status        = Column(Enum("active", "suspended", name="user_status"),
                           default="active", nullable=False)
    daily_scan_count = Column(Integer, default=0)
    last_scan_date   = Column(Date, nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow)
    # Stripe billing (TEST mode) — set once a user subscribes to Premium
    stripe_customer_id     = Column(String, nullable=True, index=True)
    stripe_subscription_id = Column(String, nullable=True)

    def as_dict(self):
        return {
            "id":               self.id,
            "email":            self.email,
            "role":             self.role,
            "tier":             self.tier,
            "status":           self.status,
            "daily_scan_count": self.daily_scan_count or 0,
            "last_scan_date":   self.last_scan_date.isoformat() if self.last_scan_date else None,
            "created_at":       (self.created_at or _utcnow()).isoformat(timespec="seconds"),
        }


class ScanHistory(Base):
    """Single source of truth for all scan history across every module."""

    __tablename__ = "scan_history"

    id         = Column(Integer, primary_key=True, index=True)
    module     = Column(String, index=True)
    verdict    = Column(String)
    score      = Column(Integer)
    target     = Column(String)
    summary    = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    # Nullable: existing rows and anonymous scans have no owner
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    # Structured facets derived at save time (WORK_PLAN Task 4) — the
    # dashboard aggregates these instead of keyword-matching summary text.
    threat_types = Column(String, default="")   # comma-separated labels
    brand        = Column(String, default="")   # impersonated/targeted brand
    geo_country  = Column(String, default="")   # resolved origin country

    def as_dict(self):
        return {
            "id":           self.id,
            "module":       self.module,
            "verdict":      self.verdict,
            "score":        self.score,
            "target":       self.target,
            "summary":      self.summary or "",
            "timestamp":    (self.created_at or _utcnow()).isoformat(timespec="seconds"),
            "user_id":      self.user_id,
            "threat_types": [t for t in (self.threat_types or "").split(",") if t],
            "brand":        self.brand or "",
            "geo_country":  self.geo_country or "",
        }


class Watchlist(Base):
    """Domains / URLs a user wants monitored for newly-detected threats."""

    __tablename__ = "watchlist"

    id            = Column(Integer, primary_key=True, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target        = Column(String, nullable=False)
    created_at    = Column(DateTime, default=datetime.utcnow)
    last_checked  = Column(DateTime, nullable=True)
    last_verdict  = Column(String, nullable=True)
    last_score    = Column(Integer, nullable=True)

    def as_dict(self):
        return {
            "id":           self.id,
            "user_id":      self.user_id,
            "target":       self.target,
            "created_at":   (self.created_at or _utcnow()).isoformat(timespec="seconds"),
            "last_checked": self.last_checked.isoformat(timespec="seconds") if self.last_checked else None,
            "last_verdict": self.last_verdict,
            "last_score":   self.last_score,
        }


class ApiKey(Base):
    """Developer API keys for the public POST /api/v1/scan endpoint."""

    __tablename__ = "api_keys"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    key_hash   = Column(String, nullable=False, unique=True, index=True)
    prefix     = Column(String, nullable=True)   # first chars of the raw key, for display
    label      = Column(String, default="")
    tier       = Column(Enum("free", "premium", name="apikey_tier"),
                        default="free", nullable=False)
    active     = Column(Integer, default=1)       # 1 = active, 0 = revoked (SQLite-friendly bool)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used  = Column(DateTime, nullable=True)
    request_count = Column(Integer, default=0)

    def as_dict(self):
        return {
            "id":            self.id,
            "label":         self.label or "",
            "prefix":        self.prefix,
            "tier":          self.tier,
            "active":        bool(self.active),
            "created_at":    (self.created_at or _utcnow()).isoformat(timespec="seconds"),
            "last_used":     self.last_used.isoformat(timespec="seconds") if self.last_used else None,
            "request_count": self.request_count or 0,
        }


class Request(Base):
    """Approval requests — tier upgrades and new-admin promotions."""

    __tablename__ = "requests"

    id                = Column(Integer, primary_key=True, index=True)
    type              = Column(Enum("upgrade", "new_admin", name="request_type"), nullable=False)
    requester_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    status            = Column(Enum("pending", "approved", "rejected", name="request_status"),
                               default="pending", nullable=False, index=True)
    created_at        = Column(DateTime, default=datetime.utcnow)
    decided_by        = Column(Integer, ForeignKey("users.id"), nullable=True)
    decided_at        = Column(DateTime, nullable=True)
    note              = Column(String, default="")

    def as_dict(self):
        return {
            "id":                self.id,
            "type":              self.type,
            "requester_user_id": self.requester_user_id,
            "status":            self.status,
            "created_at":        (self.created_at or _utcnow()).isoformat(timespec="seconds"),
            "decided_by":        self.decided_by,
            "decided_at":        self.decided_at.isoformat(timespec="seconds") if self.decided_at else None,
            "note":              self.note or "",
        }


class AuditLog(Base):
    """Immutable record of privileged actions (approve/reject/tier/suspend)."""

    __tablename__ = "audit_log"

    id             = Column(Integer, primary_key=True, index=True)
    action         = Column(String, nullable=False, index=True)
    actor_user_id  = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    detail         = Column(String, default="")
    created_at     = Column(DateTime, default=datetime.utcnow)

    def as_dict(self):
        return {
            "id":             self.id,
            "action":         self.action,
            "actor_user_id":  self.actor_user_id,
            "target_user_id": self.target_user_id,
            "detail":         self.detail or "",
            "created_at":     (self.created_at or _utcnow()).isoformat(timespec="seconds"),
        }


class VerdictFeedback(Base):
    """
    User-reported "this verdict is wrong" feedback, used for admin review and the
    active-learning retrain loop. Stores the URL, the URL-lexical features at
    report time, what the scanner predicted, and what the user says is correct.
    """

    __tablename__ = "verdict_feedback"

    id                 = Column(Integer, primary_key=True, index=True)
    url                = Column(String, nullable=False)
    module             = Column(String, default="URL Scanner")
    predicted_verdict  = Column(String, default="")
    predicted_score    = Column(Integer, default=0)
    user_label         = Column(Enum("safe", "malicious", name="feedback_label"),
                                nullable=False)
    extracted_features = Column(String, default="")   # JSON list of lexical features
    # Nullable: anonymous users can report too
    user_id            = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    status             = Column(Enum("pending", "accepted", "rejected",
                                     name="feedback_status"),
                                default="pending", index=True)
    admin_note         = Column(String, default="")
    reviewed_by        = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at         = Column(DateTime, default=datetime.utcnow)
    reviewed_at        = Column(DateTime, nullable=True)

    def as_dict(self):
        return {
            "id":                self.id,
            "url":               self.url,
            "module":            self.module,
            "predicted_verdict": self.predicted_verdict,
            "predicted_score":   self.predicted_score,
            "user_label":        self.user_label,
            "status":            self.status,
            "admin_note":        self.admin_note or "",
            "user_id":           self.user_id,
            "reviewed_by":       self.reviewed_by,
            "created_at":        (self.created_at or _utcnow()).isoformat(timespec="seconds"),
            "reviewed_at":       self.reviewed_at.isoformat(timespec="seconds") if self.reviewed_at else None,
        }


class SupportTicket(Base):
    """
    A user's support / contact-us message (WORK_PLAN Task 12). Anyone —
    including anonymous visitors — can open one. Admins/superadmins reply from
    the Support inbox and move it open -> answered -> resolved; the user sees
    the reply on the Support page. The tool's mail account also emails the
    ticket to the owner (never exposing the owner's address on the site).
    """

    __tablename__ = "support_tickets"

    id          = Column(Integer, primary_key=True, index=True)
    email       = Column(String, nullable=False)          # how to reach the reporter
    subject     = Column(String, default="")
    message     = Column(String, nullable=False)
    category    = Column(String, default="question")      # question | problem | wrong_info | other
    status      = Column(Enum("open", "answered", "resolved", name="ticket_status"),
                         default="open", index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    admin_reply = Column(String, default="")
    replied_by  = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
    replied_at  = Column(DateTime, nullable=True)

    def as_dict(self):
        return {
            "id":          self.id,
            "email":       self.email,
            "subject":     self.subject or "",
            "message":     self.message,
            "category":    self.category or "question",
            "status":      self.status,
            "user_id":     self.user_id,
            "admin_reply": self.admin_reply or "",
            "replied_by":  self.replied_by,
            "created_at":  (self.created_at or _utcnow()).isoformat(timespec="seconds"),
            "replied_at":  self.replied_at.isoformat(timespec="seconds") if self.replied_at else None,
        }
