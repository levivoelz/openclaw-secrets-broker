"""Generic webhook signature verifiers (Stripe + generic HMAC-SHA256).

The verifier endpoints take a body + signature, return {valid: bool}, and
never expose the underlying secret. The generic HMAC endpoint gates on a
config-level allowlist so a misconfigured caller can't probe arbitrary
secret names.

Requires secrets: stripe-webhook-secret, plus whatever's in
config.ALLOWED_WEBHOOK_SECRETS for the generic endpoint.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time

from ..config import ALLOWED_WEBHOOK_SECRETS
from ..secrets import get_secret


def handle_webhook_verify_hmac_sha256(body: dict) -> tuple[int, dict]:
    """Verify a generic HMAC-SHA256 webhook signature (GitHub, Vercel, Supabase, etc.).
    Body: {secret_name, body_b64, signature, prefix?}. Returns {valid: bool}.
    secret_name must be in ALLOWED_WEBHOOK_SECRETS."""
    secret_name = body.get("secret_name")
    if secret_name not in ALLOWED_WEBHOOK_SECRETS:
        return 400, {"error": "secret_name_not_allowed", "allowed": sorted(ALLOWED_WEBHOOK_SECRETS)}
    secret = get_secret(secret_name)
    if not secret:
        return 500, {"error": "missing_secret"}
    try:
        raw_body = base64.b64decode(body["body_b64"])
        sig = body["signature"]
    except (KeyError, Exception) as e:
        return 400, {"error": "bad_args", "detail": str(e)}
    prefix = body.get("prefix", "")
    if prefix and sig.startswith(prefix):
        sig = sig[len(prefix):]
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return 200, {"valid": True}
    return 200, {"valid": False, "reason": "no_match"}


def handle_stripe_verify_signature(body: dict) -> tuple[int, dict]:
    """Verify a Stripe webhook signature (custom t=...,v1=... header format).
    Body: {body_b64, signature_header}. Returns {valid: bool}."""
    secret = get_secret("stripe-webhook-secret")
    if not secret:
        return 500, {"error": "missing_secret"}
    try:
        raw_body = base64.b64decode(body["body_b64"])
        sig_header = body["signature_header"]
    except (KeyError, Exception) as e:
        return 400, {"error": "bad_args", "detail": str(e)}

    # Parse Stripe format: t=timestamp,v1=signature[,v1=signature]
    parts: dict[str, list[str]] = {}
    for pair in sig_header.split(","):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        parts.setdefault(k, []).append(v)
    if "t" not in parts or not parts["t"]:
        return 200, {"valid": False, "reason": "missing_timestamp"}
    try:
        ts = int(parts["t"][0])
    except ValueError:
        return 200, {"valid": False, "reason": "bad_timestamp"}
    if abs(int(time.time()) - ts) > 300:
        return 200, {"valid": False, "reason": "timestamp_out_of_tolerance"}

    signed_payload = f"{parts['t'][0]}.".encode() + raw_body
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    for v1 in parts.get("v1", []):
        if hmac.compare_digest(v1, expected):
            return 200, {"valid": True}
    return 200, {"valid": False, "reason": "no_match"}


ENDPOINTS = {
    "/webhook/verify-hmac-sha256": handle_webhook_verify_hmac_sha256,
    "/stripe/verify-signature": handle_stripe_verify_signature,
}
