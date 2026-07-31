"""Structured audit logging for scan activities.

Provides a lightweight, append-only audit trail that records who/what/when
for every significant scan event.  Logs are written as JSONL (one JSON
object per line) for easy ingestion by SIEM / ELK / Splunk.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_lock = threading.Lock()
_audit_file: Optional[Path] = None
_enabled = True
_disable_authorized = False

_SENSITIVE_KEY_SUBSTRINGS = (
    "authorization",
    "api_key",
    "api-key",
    "apikey",
    "cookie",
    "extra_header",
    "password",
    "secret",
    "token",
    "auth",
    "session",
    "credential",
)

_SECRET_VALUE_RE = re.compile(
    r"(?i)bearer\s+[a-z0-9._~+/=-]+"
    r"|AKIA[0-9A-Z]{16}"
    r"|sk-[a-z0-9]{16,}"
    r"|session[=:]\s*[a-z0-9._%+-]{8,}"
)


def _is_sensitive_key(key: str) -> bool:
    k = str(key).lower()
    return any(sub in k for sub in _SENSITIVE_KEY_SUBSTRINGS)


def _is_sensitive_value(value: Any) -> bool:
    return isinstance(value, str) and bool(_SECRET_VALUE_RE.search(value))


def init_audit_log(outdir: Path) -> Path:
    """Initialise the audit log file inside *outdir*/``audit.jsonl``."""
    global _audit_file
    path = outdir / "audit.jsonl"
    with _lock:
        _audit_file = path
        path.touch(mode=0o600, exist_ok=True)
    return path


_disable_count = 0


def disable() -> None:
    """Temporarily disable audit logging (e.g. during tests)."""
    global _enabled, _disable_count
    _disable_count += 1
    _enabled = False


def enable() -> None:
    global _enabled, _disable_count
    _disable_count = max(0, _disable_count - 1)
    if _disable_count == 0:
        _enabled = True


def log_event(
    event_type: str,
    *,
    domain: str = "",
    detail: Optional[Dict[str, Any]] = None,
    severity: str = "info",
) -> None:
    """Append a single audit event.

    Parameters
    ----------
    event_type:
        Category of the event, e.g. ``scan_start``, ``phase_complete``,
        ``tool_executed``, ``credential_used``, ``file_written``,
        ``access_denied``, ``config_changed``.
    domain:
        Target domain the event relates to.
    detail:
        Arbitrary JSON-serialisable payload.
    severity:
        One of ``debug``, ``info``, ``warn``, ``error``, ``critical``.
    """
    record: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "epoch": time.time(),
        "event": event_type,
        "severity": severity,
        "pid": os.getpid(),
        "uid": os.getuid(),
    }
    if domain:
        record["domain"] = domain

    def _redact_nested(data):
        if isinstance(data, dict):
            return {
                k: "***REDACTED***"
                if _is_sensitive_key(k) or _is_sensitive_value(v)
                else _redact_nested(v)
                for k, v in data.items()
            }
        if isinstance(data, list):
            return [_redact_nested(v) for v in data]
        return data

    if detail:
        record["detail"] = _redact_nested(detail)

    line = json.dumps(record, default=str, separators=(",", ":"))

    with _lock:
        if not _enabled:
            return
        if _audit_file is not None:
            try:
                with _audit_file.open("a") as f:
                    f.write(line + "\n")
            except OSError:
                pass  # best-effort — never crash the pipeline
