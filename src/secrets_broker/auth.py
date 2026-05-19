"""Bearer-token verification for incoming requests."""
from __future__ import annotations

from .secrets import get_bearer_token


def check_bearer(authorization_header: str | None) -> bool:
    """Constant-time verify the Authorization header against the loaded bearer.

    Returns True only if the header is `Bearer <token>` and `<token>` matches
    the configured bearer token byte-for-byte.
    """
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return False
    presented = authorization_header[len("Bearer "):]
    expected = get_bearer_token()
    if len(presented) != len(expected):
        return False
    return all(a == b for a, b in zip(presented, expected))
