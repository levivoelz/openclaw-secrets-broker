"""Shared helpers used by more than one endpoint module."""
from __future__ import annotations

import base64
import os


def b64url(data: bytes) -> str:
    """URL-safe base64 with stripped padding. Used for JWT signing inputs."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def random_multipart_boundary() -> str:
    """Generate a random multipart/form-data boundary string.

    Prefixed with the broker identity so a packet capture obviously
    originated here.
    """
    return "----secretsbroker" + os.urandom(8).hex()
