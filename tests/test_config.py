"""Config resolves defaults + honors env overrides."""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _reload_config():
    """Re-import config so it picks up current os.environ."""
    sys.modules.pop("secrets_broker.config", None)
    return importlib.import_module("secrets_broker.config")


def test_defaults(monkeypatch):
    for var in [
        "SECRETS_BROKER_HOST", "SECRETS_BROKER_PORT", "SECRETS_BROKER_BASE",
        "SECRETS_BROKER_SECRETS_PATH", "SECRETS_BROKER_AUTH_PATH",
        "SECRETS_BROKER_AUDIT_PATH", "SECRETS_BROKER_USER_AGENT",
    ]:
        monkeypatch.delenv(var, raising=False)
    cfg = _reload_config()

    assert cfg.HOST == "127.0.0.1"
    assert cfg.PORT == 9876
    assert cfg.BASE_DIR == Path.home() / ".secrets-broker"
    assert cfg.SECRETS_PATH == Path.home() / ".secrets" / "secrets.json"
    assert cfg.AUTH_PATH == cfg.BASE_DIR / "auth.json"
    assert cfg.AUDIT_PATH == cfg.BASE_DIR / "audit.log"
    assert cfg.USER_AGENT == "secrets-broker/1"


def test_env_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRETS_BROKER_HOST", "0.0.0.0")
    monkeypatch.setenv("SECRETS_BROKER_PORT", "12345")
    monkeypatch.setenv("SECRETS_BROKER_BASE", str(tmp_path / "base"))
    monkeypatch.setenv("SECRETS_BROKER_SECRETS_PATH", str(tmp_path / "s.json"))
    monkeypatch.setenv("SECRETS_BROKER_USER_AGENT", "test/9")
    cfg = _reload_config()

    assert cfg.HOST == "0.0.0.0"
    assert cfg.PORT == 12345
    assert cfg.BASE_DIR == tmp_path / "base"
    assert cfg.SECRETS_PATH == tmp_path / "s.json"
    # AUTH/AUDIT default RELATIVE TO BASE_DIR when not set
    assert cfg.AUTH_PATH == tmp_path / "base" / "auth.json"
    assert cfg.USER_AGENT == "test/9"


def test_allowed_webhook_secrets_is_frozenset():
    cfg = _reload_config()
    assert isinstance(cfg.ALLOWED_WEBHOOK_SECRETS, frozenset)
    # Won't accept arbitrary additions at runtime — guard against misuse
    assert "stripe-webhook-secret" not in cfg.ALLOWED_WEBHOOK_SECRETS  # stripe has its own dedicated endpoint
