"""Process-wide config. Resolved once at import time from env vars."""
from __future__ import annotations

import os
from pathlib import Path


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return Path(raw).expanduser() if raw else default


HOST: str = os.environ.get("SECRETS_BROKER_HOST", "127.0.0.1")
PORT: int = int(os.environ.get("SECRETS_BROKER_PORT", "9876"))

BASE_DIR: Path = _env_path("SECRETS_BROKER_BASE", Path.home() / ".secrets-broker")
SECRETS_PATH: Path = _env_path("SECRETS_BROKER_SECRETS_PATH", Path.home() / ".secrets" / "secrets.json")
AUTH_PATH: Path = _env_path("SECRETS_BROKER_AUTH_PATH", BASE_DIR / "auth.json")
AUDIT_PATH: Path = _env_path("SECRETS_BROKER_AUDIT_PATH", BASE_DIR / "audit.log")

USER_AGENT: str = os.environ.get("SECRETS_BROKER_USER_AGENT", "secrets-broker/1")

# 25 MB matches OpenAI's whisper limit; audio uploads need the headroom.
MAX_BODY_BYTES: int = 25 * 1024 * 1024

# Webhook secrets the generic hmac endpoint is permitted to verify against.
# Constrained set keeps the surface minimal — the call only ever returns
# valid/invalid, never the secret, but a misconfigured caller shouldn't be
# able to probe arbitrary secret names.
ALLOWED_WEBHOOK_SECRETS: frozenset[str] = frozenset({
    "github-webhook-secret",
    "vercel-webhook-secret",
    "supabase-webhook-secret",
})
