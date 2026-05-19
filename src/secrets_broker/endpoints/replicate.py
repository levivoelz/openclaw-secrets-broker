"""Replicate — predictions API + Files API uploads.

Requires secret: replicate-api-token.
"""
from __future__ import annotations

import base64
import json
import mimetypes
import urllib.error
import urllib.request

from ..secrets import get_secret
from ..utils import random_multipart_boundary


def _replicate_request(method: str, path: str, body: dict | None = None,
                       extra_headers: dict | None = None) -> tuple[int, dict]:
    api_key = get_secret("replicate-api-token")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"https://api.replicate.com{path}",
        data=data,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.status, json.loads(resp.read())


def handle_replicate_predict(body: dict) -> tuple[int, dict]:
    """Start a prediction.
    Body: {input, model?, version?, webhook?, webhook_events_filter?, wait?}.
    Use `model` (e.g. "black-forest-labs/flux-schnell") for official models,
    or `version` (sha) for community models. If wait=true, sets `Prefer: wait`
    for a synchronous response (up to 60s)."""
    if "input" not in body:
        raise KeyError("input is required")
    model = body.get("model")
    version = body.get("version")
    if not (model or version):
        raise KeyError("either model or version is required")
    payload: dict = {"input": body["input"]}
    for k in ("webhook", "webhook_events_filter", "stream"):
        if k in body:
            payload[k] = body[k]
    extra_headers = {"Prefer": "wait"} if body.get("wait") else None
    if model:
        path = f"/v1/models/{model}/predictions"
    else:
        payload["version"] = version
        path = "/v1/predictions"
    return _replicate_request("POST", path, payload, extra_headers)


def handle_replicate_get(body: dict) -> tuple[int, dict]:
    """Get a prediction's status. Body: {id}."""
    if "id" not in body:
        raise KeyError("id is required")
    return _replicate_request("GET", f"/v1/predictions/{body['id']}")


def handle_replicate_cancel(body: dict) -> tuple[int, dict]:
    """Cancel a running prediction. Body: {id}."""
    if "id" not in body:
        raise KeyError("id is required")
    return _replicate_request("POST", f"/v1/predictions/{body['id']}/cancel", {})


def handle_replicate_upload_file(body: dict) -> tuple[int, dict]:
    """Upload a file to Replicate's Files API (24h URL).
    Body: {filename, content_type?, content_b64}.
    Returns: {url, id, expires_at, size}. The url is what you pass to a
    Replicate prediction as the audio/image input."""
    api_key = get_secret("replicate-api-token")
    if not api_key:
        return 500, {"error": "missing_secret"}
    try:
        filename = body["filename"]
        content_b64 = body["content_b64"]
        content_type = body.get("content_type") or (
            mimetypes.guess_type(filename)[0] or "application/octet-stream"
        )
    except KeyError as e:
        return 400, {"error": "missing_arg", "field": str(e)}

    try:
        content = base64.b64decode(content_b64)
    except Exception as e:
        return 400, {"error": "bad_content_b64", "detail": str(e)}

    boundary = random_multipart_boundary()
    parts = [
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="content"; filename="{filename}"\r\n'.encode(),
        f"Content-Type: {content_type}\r\n\r\n".encode(),
        content,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    multipart = b"".join(parts)

    req = urllib.request.Request(
        "https://api.replicate.com/v1/files",
        data=multipart,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return 502, {
            "error": "upstream_error",
            "status": e.code,
            "detail": e.read().decode(errors="replace")[:500],
        }
    return 200, {
        "id": data.get("id"),
        "url": (data.get("urls") or {}).get("get"),
        "expires_at": data.get("expires_at"),
        "size": data.get("size"),
    }


ENDPOINTS = {
    "/replicate/predict": handle_replicate_predict,
    "/replicate/get": handle_replicate_get,
    "/replicate/cancel": handle_replicate_cancel,
    "/replicate/upload-file": handle_replicate_upload_file,
}
