"""Endpoint registry.

Each module under this package exports an ENDPOINTS dict mapping path string
to handler callable. This package's get_registry() merges them and asserts
there are no path collisions.

Each handler has the signature:
    handler(body: dict) -> tuple[int, dict]

Special-case: some endpoints (e.g. /openai/speech-stream) write directly to
the response body and bypass the standard handler signature. Those register
a None value in ENDPOINTS and are dispatched specially by the server.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from . import (
    agentmail,
    completions,
    elevenlabs,
    extract,
    github,
    google_calendar,
    health,
    linear,
    pdl,
    replicate,
    slack,
    speech,
    supabase,
    webhooks,
)


def get_registry() -> dict[str, Callable[[dict], tuple[int, dict]] | None]:
    """Merge all per-module ENDPOINTS dicts into one. Errors on collision."""
    modules: list[Any] = [
        health,
        agentmail,
        webhooks,
        google_calendar,
        slack,
        github,
        completions,
        extract,
        supabase,
        linear,
        pdl,
        replicate,
        speech,
        elevenlabs,
    ]
    registry: dict[str, Callable | None] = {}
    for mod in modules:
        for path, handler in getattr(mod, "ENDPOINTS", {}).items():
            if path in registry:
                raise RuntimeError(
                    f"endpoint path collision: {path!r} registered by "
                    f"both {mod.__name__} and an earlier module"
                )
            registry[path] = handler
    return registry
