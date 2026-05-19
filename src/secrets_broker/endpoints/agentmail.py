"""AgentMail (agentmail.to) — reply/send + webhook signature verification.

Requires secrets: agentmail-api-key, agentmail-webhook-secret.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ..secrets import get_secret


def handle_agentmail_reply(body: dict) -> tuple[int, dict]:
    """Reply to a message. Body: {inbox_id, message_id, text?, html?, labels?, headers?, to?, cc?, bcc?, reply_to?, reply_all?, attachments?}."""
    api_key = get_secret("agentmail-api-key")
    inbox_id = body["inbox_id"]
    message_id = body["message_id"]

    payload = {k: v for k, v in body.items() if k in (
        "text", "html", "labels", "headers", "to", "cc", "bcc",
        "reply_to", "reply_all", "attachments",
    )}
    # message_id is an RFC Message-ID like "<abc@example.com>" — `<`, `>`, `@` are
    # URL-reserved and AgentMail rejects the raw form with 400. inbox_id has `@`.
    url = (
        f"https://api.agentmail.to/v0/inboxes/"
        f"{urllib.parse.quote(inbox_id, safe='')}/messages/"
        f"{urllib.parse.quote(message_id, safe='')}/reply"
    )
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status, json.loads(resp.read())


def handle_agentmail_send(body: dict) -> tuple[int, dict]:
    """Send a new message. Body: {inbox_id, to, subject?, text?, html?, labels?, headers?}."""
    api_key = get_secret("agentmail-api-key")
    inbox_id = body["inbox_id"]
    payload = {k: v for k, v in body.items() if k != "inbox_id"}
    url = (
        f"https://api.agentmail.to/v0/inboxes/"
        f"{urllib.parse.quote(inbox_id, safe='')}/messages/send"
    )
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status, json.loads(resp.read())


def handle_agentmail_verify_signature(body: dict) -> tuple[int, dict]:
    """Verify a Svix webhook signature (the format AgentMail uses).
    Body: {svix_id, svix_timestamp, body_b64, signature_header}.
    Returns {valid: bool}. The secret never leaves this process."""
    secret = get_secret("agentmail-webhook-secret")
    if not secret:
        return 500, {"error": "missing_secret"}
    try:
        svix_id = body["svix_id"]
        svix_timestamp = body["svix_timestamp"]
        body_b64 = body["body_b64"]
        sig_header = body["signature_header"]
    except KeyError as e:
        return 400, {"error": "missing_arg", "field": str(e)}

    try:
        ts = int(svix_timestamp)
    except (TypeError, ValueError):
        return 200, {"valid": False, "reason": "bad_timestamp"}
    if abs(int(time.time()) - ts) > 300:
        return 200, {"valid": False, "reason": "timestamp_out_of_tolerance"}

    try:
        raw_body = base64.b64decode(body_b64)
    except Exception:
        return 400, {"error": "bad_body_b64"}

    secret_key = base64.b64decode(secret[6:] if secret.startswith("whsec_") else secret)
    signed_payload = f"{svix_id}.{svix_timestamp}.".encode() + raw_body
    expected = base64.b64encode(hmac.new(secret_key, signed_payload, hashlib.sha256).digest()).decode()

    for part in sig_header.split(" "):
        if "," not in part:
            continue
        version, value = part.split(",", 1)
        if version != "v1":
            continue
        if hmac.compare_digest(value, expected):
            return 200, {"valid": True}
    return 200, {"valid": False, "reason": "no_match"}


ENDPOINTS = {
    "/agentmail/reply": handle_agentmail_reply,
    "/agentmail/send": handle_agentmail_send,
    "/agentmail/verify-signature": handle_agentmail_verify_signature,
}
