"""
NexGuard AI — Authentication module
JWT (HS256, 24 h expiry) + bcrypt password hashing + FastAPI dependencies.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
import bcrypt as _bcrypt_lib
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apis import rate_limit
from db_config import SessionLocal
from models import User

log = logging.getLogger("nexguard.auth")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _debug_mode() -> bool:
    return os.getenv("NEXGUARD_DEBUG", "").strip().lower() in ("1", "true", "yes")


def _resolve_jwt_secret() -> str:
    """
    The signing secret, or a hard failure.

    A random per-process fallback is only acceptable for local development:
    under multiple workers each worker would sign with a DIFFERENT secret, so
    tokens get rejected at random, and every restart silently invalidates all
    sessions.
    Outside debug we refuse to start rather than run in that state.
    """
    secret = os.getenv("JWT_SECRET", "").strip()
    if secret:
        return secret

    if not _debug_mode():
        raise RuntimeError(
            "JWT_SECRET is not set. Add JWT_SECRET=<strong-random-value> to "
            "backend/.env (or your secret manager) before starting NexGuard. "
            "For local development only, set NEXGUARD_DEBUG=1 to allow a "
            "temporary random secret."
        )

    print(
        "\n[NexGuard] WARNING: JWT_SECRET not set and NEXGUARD_DEBUG is on — a "
        "temporary random secret was generated. Sessions will not survive a "
        "restart, and multiple workers will reject each other's tokens.\n"
        "Add   JWT_SECRET=<strong-random-value>   to backend/.env.\n"
    )
    return secrets.token_hex(32)


JWT_SECRET = _resolve_jwt_secret()

ALGORITHM           = "HS256"
TOKEN_EXPIRE_HOURS  = 24

# Minimum password length. Short passwords plus (previously) unthrottled login
# made brute-forcing trivial; the lockout below closes the other half.
MIN_PASSWORD_LENGTH = 12

# Failed-login lockout: N failures per email+IP inside the window locks that
# pair out for the remainder of the window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_S     = 900   # 15 minutes

_bearer = HTTPBearer(auto_error=False)   # returns None when no token present

# ---------------------------------------------------------------------------
# Password helpers  (direct bcrypt — avoids passlib/bcrypt 4.x compat bug)
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    return _bcrypt_lib.hashpw(plain.encode("utf-8"), _bcrypt_lib.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt_lib.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(user_id: int, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "exp": exp},
        JWT_SECRET,
        algorithm=ALGORITHM,
    )

def _decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])

# ---------------------------------------------------------------------------
# DB session dependency
# ---------------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email.lower().strip()).first()

def create_user(db: Session, email: str, password: str, role: str = "user") -> User:
    user = User(
        email=email.lower().strip(),
        password_hash=hash_password(password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# ---------------------------------------------------------------------------
# Pydantic request schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

# ---------------------------------------------------------------------------
# Register / Login logic
# ---------------------------------------------------------------------------

def do_register(db: Session, email: str, password: str) -> dict:
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email address required")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
        )
    if get_user_by_email(db, email):
        raise HTTPException(status_code=409, detail="Email already registered")
    user = create_user(db, email, password)
    return {"id": user.id, "email": user.email, "role": user.role, "message": "Account created"}


# ---------------------------------------------------------------------------
# Failed-login lockout  (A07 — brute force / credential stuffing)
# ---------------------------------------------------------------------------

def _login_key(email: str, ip: str) -> str:
    """Counter key for one email+IP pair.

    Keyed by BOTH so an attacker hammering one account cannot lock every other
    user out (email alone), and cannot dodge the limit by rotating targets from
    one host (IP alone).
    """
    return f"login:{(email or '').strip().lower()}:{ip or 'unknown'}"


def is_login_locked(email: str, ip: str) -> bool:
    """True if this email+IP has used up its failed-login budget."""
    return rate_limit.count(_login_key(email, ip)) >= LOGIN_MAX_ATTEMPTS


def record_login_failure(email: str, ip: str) -> None:
    """Charge one failed attempt against this email+IP."""
    rate_limit.allow(_login_key(email, ip),
                     limit=LOGIN_MAX_ATTEMPTS, window_s=LOGIN_WINDOW_S)


def clear_login_failures(email: str, ip: str) -> None:
    """A successful login wipes the failure tally so typos don't accumulate."""
    rate_limit.reset(_login_key(email, ip))


def do_login(db: Session, email: str, password: str, ip: str = "unknown") -> dict:
    # Checked before the password is verified, so a locked-out attacker gains
    # nothing by eventually guessing correctly.
    if is_login_locked(email, ip):
        log.warning("Login lockout active for %s from %s", email, ip,
                    extra={"fields": {"event": "login_lockout",
                                      "email": email, "ip": ip}})
        raise HTTPException(
            status_code=429,
            detail=(
                f"Too many failed login attempts. Try again in "
                f"{LOGIN_WINDOW_S // 60} minutes."
            ),
        )

    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.password_hash):
        record_login_failure(email, ip)
        log.warning("Failed login for %s from %s", email, ip,
                    extra={"fields": {"event": "login_failure",
                                      "email": email, "ip": ip}})
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.status == "suspended":
        log.warning("Suspended account attempted login: %s from %s", email, ip,
                    extra={"fields": {"event": "login_suspended",
                                      "email": email, "ip": ip}})
        raise HTTPException(
            status_code=403,
            detail="Your account has been suspended. Please contact an administrator.",
        )

    clear_login_failures(email, ip)
    log.info("Login success for %s from %s", email, ip,
             extra={"fields": {"event": "login_success",
                               "email": email, "ip": ip, "user_id": user.id}})
    token = create_access_token(user.id, user.role)
    return {
        "token":  token,
        "role":   user.role,
        "tier":   user.tier,
        "status": user.status,
        "email":  user.email,
        "id":     user.id,
    }

# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Returns the authenticated User, or None if no/invalid token is provided.
    Use on endpoints that work both anonymously and authenticated.
    """
    if not credentials:
        return None
    try:
        payload  = _decode_token(credentials.credentials)
        user_id  = int(payload["sub"])
        return db.query(User).filter(User.id == user_id).first()
    except Exception:
        return None


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """
    Returns the authenticated User. Raises HTTP 401 if no/invalid token.

    Suspended accounts are refused here (403), not just on the scan-path
    dependency: everything gated by this — watchlist, api-keys, billing,
    tickets and every admin action via require_admin — was still reachable by a
    suspended account, including a suspended admin who kept admin power.
    """
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = _decode_token(credentials.credentials)
        user    = db.query(User).filter(User.id == int(payload["sub"])).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if user.status == "suspended":
            raise HTTPException(
                status_code=403,
                detail="Your account has been suspended. Please contact an administrator.",
            )
        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_optional_active_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Like get_optional_user, but blocks suspended accounts.

    - No / invalid token -> None  (anonymous use stays allowed)
    - Active user        -> User
    - Suspended user     -> HTTP 403 with a clear message
    Use on endpoints (e.g. scanning) that suspended users must not access.
    """
    if not credentials:
        return None
    try:
        payload = _decode_token(credentials.credentials)
        user    = db.query(User).filter(User.id == int(payload["sub"])).first()
    except Exception:
        return None
    if user and user.status == "suspended":
        raise HTTPException(
            status_code=403,
            detail="Your account is suspended — scanning is disabled. Contact an administrator.",
        )
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Requires admin or superadmin role. Raises HTTP 403 otherwise."""
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def require_superadmin(user: User = Depends(get_current_user)) -> User:
    """Requires superadmin role. Raises HTTP 403 otherwise."""
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required")
    return user
