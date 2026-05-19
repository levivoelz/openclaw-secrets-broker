"""Health check."""
from __future__ import annotations


def handle_health(_body: dict) -> tuple[int, dict]:
    # Late import to avoid circularity with the registry.
    from . import get_registry
    return 200, {
        "status": "ok",
        "version": 1,
        "endpoints": sorted(get_registry().keys()),
    }


ENDPOINTS = {
    "/health": handle_health,
}
