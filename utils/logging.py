"""Privacy-safe structured (JSON lines) logging.

Only allow-listed fields are emitted. Any value that looks like a recovery
key, PEM private key or bearer token is redacted before writing, as a
second line of defence. Plaintext filenames are dropped unless the user
enabled ``privacy.log_filenames``.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from collections import deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable

LOGGER_NAME = "wezcrypt"
ALLOWED_FIELDS = {
    "operation", "file_id", "encrypted_size", "server", "status", "error_category",
    "filename", "detail",
}
_SECRET_PATTERNS = [
    re.compile(r"wezcrypt-v1-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-~+/]+=*"),
    re.compile(r"(?i)(password|passphrase|token|secret)\s*[=:]\s*\S+"),
]

_state = {"log_filenames": False}
_listeners: list[Callable[[str], None]] = []
_recent: deque[str] = deque(maxlen=2000)
_lock = threading.Lock()


def redact(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="seconds"),
            "level": record.levelname,
        }
        fields = getattr(record, "wez_fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        else:
            payload["detail"] = record.getMessage()
        return redact(json.dumps(payload, ensure_ascii=False, default=str))


class _MemoryHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        line = self.format(record)
        with _lock:
            _recent.append(line)
            listeners = list(_listeners)
        for fn in listeners:
            try:
                fn(line)
            except Exception:  # a broken UI listener must never break logging
                pass


def configure_logging(log_dir: Path, *, log_filenames: bool = False, level: int = logging.INFO) -> logging.Logger:
    _state["log_filenames"] = bool(log_filenames)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    log_dir.mkdir(parents=True, exist_ok=True)
    fmt = _JsonFormatter()
    fh = RotatingFileHandler(log_dir / "wezcrypt.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    mh = _MemoryHandler()
    mh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(mh)
    return logger


def set_log_filenames(enabled: bool) -> None:
    _state["log_filenames"] = bool(enabled)


def log_event(operation: str, *, level: int = logging.INFO, **fields: object) -> None:
    clean: dict[str, object] = {"operation": operation}
    for k, v in fields.items():
        if k not in ALLOWED_FIELDS or v is None:
            continue
        if k == "filename" and not _state["log_filenames"]:
            continue
        clean[k] = v
    logging.getLogger(LOGGER_NAME).log(level, operation, extra={"wez_fields": clean})


def add_listener(fn: Callable[[str], None]) -> None:
    with _lock:
        _listeners.append(fn)


def recent_lines() -> list[str]:
    with _lock:
        return list(_recent)
