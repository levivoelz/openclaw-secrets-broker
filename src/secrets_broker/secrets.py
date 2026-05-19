"""Secrets + bearer-token state. Loaded at startup, reloaded on SIGHUP."""
from __future__ import annotations

import json
import threading

from .audit import log_audit
from .config import AUTH_PATH, SECRETS_PATH

_state_lock = threading.Lock()
_secrets: dict[str, str] = {}
_bearer_token: str = ""


def load_state() -> None:
    """(Re)load secrets.json + auth.json. Safe to call on SIGHUP."""
    global _secrets, _bearer_token
    with _state_lock:
        with open(SECRETS_PATH) as f:
            data = json.load(f)
            _secrets = data.get("secrets", {})
        with open(AUTH_PATH) as f:
            _bearer_token = json.load(f)["bearer_token"]
    log_audit("system", "config_loaded", "ok", {"secret_keys": list(_secrets.keys())})


def get_secret(name: str) -> str:
    """Look up a secret by name. Raises KeyError if not configured."""
    with _state_lock:
        if name not in _secrets:
            raise KeyError(f"secret '{name}' not configured in secrets.json")
        return _secrets[name]


def get_bearer_token() -> str:
    """Return the currently loaded bearer token. Empty string before load."""
    with _state_lock:
        return _bearer_token
