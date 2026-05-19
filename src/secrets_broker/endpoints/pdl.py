"""People Data Labs — person enrichment.

Requires secret: pdl-api-key.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

from ..secrets import get_secret


def handle_pdl_enrich(body: dict) -> tuple[int, dict]:
    """Person enrich. Body: standard PDL person enrich query
    (email, name, profile URL, etc.)."""
    api_key = get_secret("pdl-api-key")
    qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in body.items())
    url = f"https://api.peopledatalabs.com/v5/person/enrich?{qs}"
    req = urllib.request.Request(
        url,
        headers={"X-Api-Key": api_key, "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status, json.loads(resp.read())


ENDPOINTS = {
    "/pdl/enrich": handle_pdl_enrich,
}
