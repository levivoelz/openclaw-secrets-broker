"""Append-only audit log. One JSONL line per request."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

from .config import AUDIT_PATH

_audit_lock = threading.Lock()


def log_audit(source: str, action: str, outcome: str, details: dict | None = None) -> None:
    """Append a single JSONL entry to the audit log. Thread-safe."""
    line = json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "action": action,
        "outcome": outcome,
        "details": details or {},
    })
    with _audit_lock:
        with open(AUDIT_PATH, "a") as f:
            f.write(line + "\n")
