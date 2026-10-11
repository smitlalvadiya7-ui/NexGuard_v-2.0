"""
Structured logging for NexGuard.

By default logs human-readable lines. Set NEXGUARD_LOG_JSON=1 to emit one JSON
object per line (ready for shipping to Loki / CloudWatch / ELK at scale). The
log level is controlled by NEXGUARD_LOG_LEVEL (default INFO).

Call configure_logging() once at process start (main.py does this on import).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                  + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach any structured extras passed via logger.x(..., extra={"fields": {...}})
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    level_name = os.getenv("NEXGUARD_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    if os.getenv("NEXGUARD_LOG_JSON", "").strip() in ("1", "true", "yes"):
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        ))

    root = logging.getLogger()
    # Replace any pre-existing handlers so we don't double-log.
    root.handlers = [handler]
    root.setLevel(level)

    # Tame noisy third-party loggers.
    for noisy in ("urllib3", "httpx", "websockets", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
