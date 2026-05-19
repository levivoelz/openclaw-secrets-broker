"""Supabase — REST query through anon/service key.

Requires secret: supabase-api-key.

Note: the Supabase URL is configured here as a constant rather than via a
secret because it's a public endpoint, not credential material. Override
by editing this file if you point at a different project.
"""
from __future__ import annotations

import json
import urllib.request

from ..secrets import get_secret

SUPABASE_URL = "https://fkvuniwscmscjgbtmrpf.supabase.co"


def handle_supabase_query(body: dict) -> tuple[int, dict]:
    """Read from a Supabase table. Body: {table, select?, filter?, order?, limit?}.
    filter is a dict like {"column": "eq.value"} appended as-is to the query string.
    Returns rows as a list."""
    api_key = get_secret("supabase-api-key")
    table = body["table"]
    qs_parts = []
    if "select" in body:
        qs_parts.append(f"select={body['select']}")
    if "filter" in body:
        for k, v in body["filter"].items():
            qs_parts.append(f"{k}={v}")
    if "order" in body:
        qs_parts.append(f"order={body['order']}")
    if "limit" in body:
        qs_parts.append(f"limit={body['limit']}")
    qs = ("?" + "&".join(qs_parts)) if qs_parts else ""

    url = f"{SUPABASE_URL}/rest/v1/{table}{qs}"
    req = urllib.request.Request(
        url,
        headers={
            "apikey": api_key,
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status, {"rows": json.loads(resp.read())}


ENDPOINTS = {
    "/supabase/query": handle_supabase_query,
}
