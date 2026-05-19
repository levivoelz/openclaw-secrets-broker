"""LLM completion forwarders: Anthropic, OpenAI, local Ollama.

Required secrets: anthropic-api-key, openai-api-key. Ollama is local
(no API key).
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from ..http_pool import https_request
from ..secrets import get_secret

# Tight allowlist for Ollama model strings — they're passed unescaped into
# the request body, so we constrain to what Ollama actually accepts.
_OLLAMA_SAFE_MODEL = re.compile(r"^[a-z0-9][a-z0-9_.:/-]{0,127}$", re.IGNORECASE)


def handle_anthropic_complete(body: dict) -> tuple[int, dict]:
    """Forward a Messages API call. Body: standard Anthropic /v1/messages payload."""
    api_key = get_secret("anthropic-api-key")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode(),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.status, json.loads(resp.read())


def handle_openai_complete(body: dict) -> tuple[int, dict]:
    """Forward a Chat Completions API call.
    Body: standard OpenAI /v1/chat/completions payload — {model, messages, ...}."""
    api_key = get_secret("openai-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "openai-api-key not configured"}
    payload = json.dumps(body).encode()
    try:
        status, _, data = https_request(
            "api.openai.com", "POST", "/v1/chat/completions",
            body=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
            },
            timeout=60,
        )
        if status >= 400:
            return 502, {
                "error": "upstream_error",
                "status": status,
                "detail": data.decode(errors="replace")[:1000],
            }
        return status, json.loads(data)
    except Exception as e:
        return 502, {"error": "upstream_error", "detail": str(e)[:500]}


def handle_ollama_complete(body: dict) -> tuple[int, dict]:
    """Forward a chat completion to local Ollama at 127.0.0.1:11434.
    Body: {model, messages, options?, ...} — same shape as Ollama /api/chat.
    No API key needed (purely local). Response is Ollama's native format.
    Use for INTERNAL-ONLY work — output that the caller consumes itself. Never
    repackage local-model output straight to a human surface; voice will drift."""
    model = str(body.get("model", ""))
    if not _OLLAMA_SAFE_MODEL.match(model):
        return 400, {"error": "bad_model_name", "detail": "model name failed safety check"}

    payload = {**body, "stream": False}
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return 502, {
            "error": "upstream_error",
            "status": e.code,
            "detail": e.read().decode(errors="replace")[:500],
        }
    except urllib.error.URLError as e:
        return 502, {"error": "ollama_unreachable", "detail": str(e)}


ENDPOINTS = {
    "/anthropic/complete": handle_anthropic_complete,
    "/openai/complete": handle_openai_complete,
    "/ollama/complete": handle_ollama_complete,
}
