"""
Database engine configuration.

Defaults to local SQLite (zero-config) so the existing local flow is untouched.
For scale, set DATABASE_URL to a Postgres DSN and NexGuard switches over with no
code changes:

    # SQLite (default)
    # (DATABASE_URL unset)  -> sqlite:///./nexguard.db

    # Postgres via SQLAlchemy + psycopg
    DATABASE_URL=postgresql+psycopg://user:pass@db:5432/nexguard

Connection pooling (pool_size / max_overflow / pool_pre_ping) is enabled
automatically for non-SQLite engines.
"""

import logging
import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

log = logging.getLogger("nexguard.db")

DATABASE_URL = os.getenv("DATABASE_URL", "").strip() or "sqlite:///./nexguard.db"
IS_SQLITE = DATABASE_URL.startswith("sqlite")

if IS_SQLITE:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    # Postgres / other server DBs: pool + pre-ping so a dropped connection is
    # transparently recycled rather than surfacing as an error mid-request.
    engine = create_engine(
        DATABASE_URL,
        pool_size=int(os.getenv("NEXGUARD_DB_POOL_SIZE", "5")),
        max_overflow=int(os.getenv("NEXGUARD_DB_MAX_OVERFLOW", "10")),
        pool_pre_ping=True,
        pool_recycle=1800,
    )
    log.info("Database backend: %s", DATABASE_URL.split("@")[-1])

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def db_backend() -> str:
    """Short label for /health: 'sqlite' or 'postgresql' etc."""
    return DATABASE_URL.split(":", 1)[0].split("+", 1)[0]
