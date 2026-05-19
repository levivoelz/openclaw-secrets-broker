#!/usr/bin/env python3
"""
secrets-daemon — a localhost HTTP broker that performs credentialed operations
on behalf of a less-trusted caller (another user account, an agent runtime,
a subprocess) without ever handing the caller the underlying credentials.

Architecture:
  - secrets.json (mode 600) holds API credentials
  - auth.json holds a bearer token shared with the caller out-of-band
  - HTTP server on 127.0.0.1 (loopback only) with bearer auth
  - One endpoint per operation, never raw API-key passthrough
  - Every request logged to audit.log

Reload secrets without restart:
  kill -HUP <pid>

Reload code (KeepAlive launchd respawns):
  kill <pid>

Configuration (all paths and the listen port are env-overridable):
  SECRETS_DAEMON_HOST          default 127.0.0.1
  SECRETS_DAEMON_PORT          default 9876
  SECRETS_DAEMON_BASE          default ~/.secrets-daemon
  SECRETS_DAEMON_SECRETS_PATH  default ~/.secrets/secrets.json
  SECRETS_DAEMON_AUTH_PATH     default $SECRETS_DAEMON_BASE/auth.json
  SECRETS_DAEMON_AUDIT_PATH    default $SECRETS_DAEMON_BASE/audit.log
  SECRETS_DAEMON_USER_AGENT    default "secrets-daemon/1"
"""

import base64
import http.client
import http.server
import json
import logging
import os
import signal
import socket
import socketserver
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return Path(raw).expanduser() if raw else default


HOST = os.environ.get("SECRETS_DAEMON_HOST", "127.0.0.1")
PORT = int(os.environ.get("SECRETS_DAEMON_PORT", "9876"))
BASE_DIR = _env_path("SECRETS_DAEMON_BASE", Path.home() / ".secrets-daemon")
SECRETS_PATH = _env_path("SECRETS_DAEMON_SECRETS_PATH", Path.home() / ".secrets" / "secrets.json")
AUTH_PATH = _env_path("SECRETS_DAEMON_AUTH_PATH", BASE_DIR / "auth.json")
AUDIT_PATH = _env_path("SECRETS_DAEMON_AUDIT_PATH", BASE_DIR / "audit.log")
USER_AGENT = os.environ.get("SECRETS_DAEMON_USER_AGENT", "secrets-daemon/1")
MAX_BODY_BYTES = 25 * 1024 * 1024  # 25 MB (matches OpenAI's whisper limit; audio uploads need headroom)

# ---------------------------------------------------------------------------
# HTTP connection pool (keepalive per upstream host)
# ---------------------------------------------------------------------------
# One persistent HTTPS connection per host, shared across threads via a per-host
# lock. On any connection error the connection is discarded and a fresh one is
# opened, so callers never see a stale-socket failure on the second request.

_pool_lock = threading.Lock()
_connections: dict = {}   # host -> (http.client.HTTPSConnection, threading.Lock)


def _conn(host: str) -> tuple:
    """Return (connection, lock) for *host*, creating them lazily."""
    with _pool_lock:
        if host not in _connections:
            conn = http.client.HTTPSConnection(host, timeout=120)
            _connections[host] = (conn, threading.Lock())
        return _connections[host]


def _https_request(host: str, method: str, path: str, body=None, headers=None, timeout=120, stream=False):
    """Send an HTTPS request over the keepalive pool for *host*.

    Returns (status, response_headers, data_or_response):
      - If stream=False: data is bytes (full response body read).
      - If stream=True: data is the http.client.HTTPResponse object
        (caller must .read() and .close() it while still holding *nothing*;
        the connection lock is released before returning).

    Reconnects transparently on BrokenPipeError / ConnectionResetError.
    """
    conn, lock = _conn(host)
    hdrs = headers or {}
    for attempt in range(2):
        with lock:
            try:
                conn.request(method, path, body=body, headers=hdrs)
                resp = conn.getresponse()
                if stream:
                    # Caller handles body; return immediately so lock is released.
                    # http.client buffers nothing — caller must drain before next use.
                    # We return the response and a reference to conn so the caller
                    # can close it properly. The lock is released here; concurrent
                    # requests will queue on the next lock acquisition after the
                    # streaming caller finishes draining.
                    return resp.status, dict(resp.getheaders()), resp
                data = resp.read()
                return resp.status, dict(resp.getheaders()), data
            except (BrokenPipeError, ConnectionResetError, http.client.RemoteDisconnected,
                    http.client.CannotSendRequest, OSError):
                if attempt == 1:
                    raise
                # Reconnect and retry once
                try:
                    conn.close()
                except Exception:
                    pass
                conn = http.client.HTTPSConnection(host, timeout=120)
                with _pool_lock:
                    _connections[host] = (conn, lock)


# ---------------------------------------------------------------------------
# State (loaded at startup, reloaded on SIGHUP)
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()
_secrets = {}
_bearer_token = ""


def _load_state():
    global _secrets, _bearer_token
    with _state_lock:
        with open(SECRETS_PATH) as f:
            data = json.load(f)
            _secrets = data.get("secrets", {})
        with open(AUTH_PATH) as f:
            _bearer_token = json.load(f)["bearer_token"]
    log_audit("system", "config_loaded", "ok", {"secret_keys": list(_secrets.keys())})


def get_secret(name):
    with _state_lock:
        if name not in _secrets:
            raise KeyError(f"secret '{name}' not configured in secrets.json")
        return _secrets[name]


# ---------------------------------------------------------------------------
# Audit log (one JSONL line per request)
# ---------------------------------------------------------------------------

_audit_lock = threading.Lock()


def log_audit(source, action, outcome, details=None):
    line = json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "action": action,
        "outcome": outcome,
        "details": details or {},
    })
    with _audit_lock:
        with open(AUDIT_PATH, "a") as f:
            f.write(line + "\n")


# ---------------------------------------------------------------------------
# Endpoint handlers
# ---------------------------------------------------------------------------
#
# Each handler receives the parsed JSON request body and must return a tuple of
# (http_status, response_dict). It MUST NOT include any secret value in the
# response (that defeats the whole point of this daemon).
#
# Handlers raise exceptions on failure; the dispatcher catches them and returns
# a sanitized 500 to the caller.


def handle_health(_body: dict):
    return 200, {"status": "ok", "version": 1, "endpoints": list(ENDPOINTS.keys())}


def handle_agentmail_reply(body: dict):
    """Reply to a message via AgentMail. Body: {inbox_id, message_id, text?, html?, labels?, headers?}."""
    api_key = get_secret("agentmail-api-key")
    inbox_id = body["inbox_id"]
    message_id = body["message_id"]

    payload = {k: v for k, v in body.items() if k in ("text", "html", "labels", "headers", "to", "cc", "bcc", "reply_to", "reply_all", "attachments")}
    # message_id is an RFC Message-ID like "<abc@example.com>" — `<`, `>`, `@` are
    # URL-reserved and AgentMail rejects the raw form with 400. inbox_id has `@`.
    url = f"https://api.agentmail.to/v0/inboxes/{urllib.parse.quote(inbox_id, safe='')}/messages/{urllib.parse.quote(message_id, safe='')}/reply"
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


# Webhook signature secrets that the webhook server is allowed to verify against.
# A whitelist guards the generic hmac endpoint from accidental misuse — the call
# only ever returns valid/invalid, never the secret itself, but constraining the
# set of permitted secret names keeps the surface minimal.
_ALLOWED_WEBHOOK_SECRETS = {
    "github-webhook-secret",
    "vercel-webhook-secret",
    "supabase-webhook-secret",
}


def handle_webhook_verify_hmac_sha256(body: dict):
    """Verify a generic HMAC-SHA256 webhook signature (GitHub, Vercel, Supabase).
    Body: {secret_name, body_b64, signature, prefix?}. Returns {valid: bool}.
    secret_name must be in _ALLOWED_WEBHOOK_SECRETS."""
    import base64, hashlib, hmac
    secret_name = body.get("secret_name")
    if secret_name not in _ALLOWED_WEBHOOK_SECRETS:
        return 400, {"error": "secret_name_not_allowed", "allowed": sorted(_ALLOWED_WEBHOOK_SECRETS)}
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


def handle_stripe_verify_signature(body: dict):
    """Verify a Stripe webhook signature (custom t=...,v1=... format).
    Body: {body_b64, signature_header}. Returns {valid: bool}."""
    import base64, hashlib, hmac
    secret = get_secret("stripe-webhook-secret")
    if not secret:
        return 500, {"error": "missing_secret"}
    try:
        raw_body = base64.b64decode(body["body_b64"])
        sig_header = body["signature_header"]
    except (KeyError, Exception) as e:
        return 400, {"error": "bad_args", "detail": str(e)}

    # Parse Stripe format: t=timestamp,v1=signature[,v1=signature]
    parts = {}
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


def handle_agentmail_verify_signature(body: dict):
    """Verify a Svix webhook signature (used by AgentMail).
    Body: {svix_id, svix_timestamp, body_b64, signature_header}.
    Returns {valid: bool}. The secret never leaves this process."""
    import base64, hashlib, hmac
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


def handle_agentmail_send(body):
    """Send a new message. Body: {inbox_id, to, subject?, text?, html?, labels?, headers?}."""
    api_key = get_secret("agentmail-api-key")
    inbox_id = body["inbox_id"]
    payload = {k: v for k, v in body.items() if k != "inbox_id"}
    url = f"https://api.agentmail.to/v0/inboxes/{urllib.parse.quote(inbox_id, safe='')}/messages/send"
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


# --- Google Calendar -----------------------------------------------------
#
# Uses OAuth refresh-token flow. Required secrets:
#   - google-oauth-client-id      (Desktop App OAuth client from GCP Console)
#   - google-oauth-client-secret  (same)
#   - google-oauth-refresh-token  (obtained via setup-google-oauth.py — run once)
#
# Access tokens are cached in-process (~50 min); on cache miss the daemon
# exchanges the refresh token for a new access token.

_google_token_cache = {"token": None, "expires_at": 0}


def _google_access_token():
    now = time.time()
    if _google_token_cache["token"] and _google_token_cache["expires_at"] > now + 60:
        return _google_token_cache["token"]

    client_id = get_secret("google-oauth-client-id")
    client_secret = get_secret("google-oauth-client-secret")
    refresh_token = get_secret("google-oauth-refresh-token")
    if not all([client_id, client_secret, refresh_token]):
        raise RuntimeError("missing google oauth secrets")

    data = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = json.loads(resp.read())
    _google_token_cache["token"] = body["access_token"]
    _google_token_cache["expires_at"] = now + int(body.get("expires_in", 3600))
    return _google_token_cache["token"]


def handle_calendar_list_events(body: dict):
    """List upcoming events from a Google Calendar.
    Body: {calendar_id?='primary', time_min?, time_max?, max_results?=20, q?}.
    time_min/time_max default to now and now+24h (RFC3339)."""
    try:
        access_token = _google_access_token()
    except Exception as e:
        return 500, {"error": "google_oauth_failure", "detail": str(e)}

    calendar_id = body.get("calendar_id", "primary")
    now = datetime.now(timezone.utc)
    time_min = body.get("time_min") or now.isoformat().replace("+00:00", "Z")
    time_max = body.get("time_max") or (now + timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    try:
        max_results = min(int(body.get("max_results", 20)), 100)
    except (TypeError, ValueError):
        max_results = 20

    params = {
        "timeMin": time_min,
        "timeMax": time_max,
        "maxResults": str(max_results),
        "singleEvents": "true",
        "orderBy": "startTime",
    }
    if body.get("q"):
        params["q"] = body["q"]

    url = (
        f"https://www.googleapis.com/calendar/v3/calendars/"
        f"{urllib.parse.quote(calendar_id, safe='')}/events"
        f"?{urllib.parse.urlencode(params)}"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return 502, {
            "error": "google_api_error",
            "status": e.code,
            "detail": e.read().decode(errors="replace")[:500],
        }

    events = []
    for item in data.get("items", []):
        events.append({
            "id": item.get("id"),
            "summary": item.get("summary", "(no title)"),
            "description": (item.get("description") or "")[:1000],
            "start": item.get("start", {}),
            "end": item.get("end", {}),
            "location": item.get("location"),
            "attendees": [a.get("email") for a in item.get("attendees", []) if a.get("email")],
            "status": item.get("status"),
            "html_link": item.get("htmlLink"),
        })
    return 200, {"events": events, "count": len(events), "calendar_id": calendar_id}


# --- Slack ----------------------------------------------------------------

def _slack_call(method, body):
    token = get_secret("slack-bot-token")
    req = urllib.request.Request(
        f"https://slack.com/api/{method}",
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def handle_slack_post(body):
    """Post a message to Slack. Body: {channel, text?, blocks?, thread_ts?, ...}."""
    if "channel" not in body:
        raise KeyError("channel")
    result = _slack_call("chat.postMessage", body)
    if not result.get("ok"):
        return 502, {"error": "slack_error", "slack_error": result.get("error"), "detail": result}
    return 200, {"ok": True, "ts": result.get("ts"), "channel": result.get("channel")}


def handle_slack_upload_file(body: dict):
    """Upload a file to Slack and share into a channel using Slack's modern
    files.getUploadURLExternal + files.completeUploadExternal flow.

    Body: {channel, filename, file_b64 OR file_path, title?, initial_comment?, thread_ts?}.
    Callers that don't have filesystem access (different user account, sandboxed
    subprocess) should send file_b64. file_path is a convenience for callers
    that share filesystem access with the daemon (same user, same machine).
    Returns: {ok, file_id, files, filename, size}."""
    import base64
    token = get_secret("slack-bot-token")
    if not token:
        return 500, {"error": "missing_secret"}

    channel = body.get("channel")
    filename = body.get("filename")
    if not channel or not filename:
        return 400, {"error": "missing_arg", "detail": "channel and filename required"}

    # Source of bytes: file_path streams from disk (memory-bounded), file_b64
    # must hold bytes in memory (base64 transport requires the full JSON body).
    file_bytes = None
    file_size = None
    file_handle = None
    if "file_path" in body:
        path = Path(body["file_path"]).expanduser()
        if not path.exists():
            return 400, {"error": "file_not_found", "path": str(path)}
        try:
            file_size = path.stat().st_size
            file_handle = open(path, "rb")
        except PermissionError as e:
            return 400, {"error": "permission_denied", "detail": str(e)}
    elif "file_b64" in body:
        try:
            file_bytes = base64.b64decode(body["file_b64"])
            file_size = len(file_bytes)
        except Exception as e:
            return 400, {"error": "bad_file_b64", "detail": str(e)}
    else:
        return 400, {"error": "missing_arg", "detail": "file_b64 or file_path required"}

    if file_size == 0:
        if file_handle: file_handle.close()
        return 400, {"error": "empty_file"}

    # Step 1: get upload URL
    step1_data = urllib.parse.urlencode({"filename": filename, "length": str(file_size)}).encode()
    step1_req = urllib.request.Request(
        "https://slack.com/api/files.getUploadURLExternal",
        data=step1_data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(step1_req, timeout=15) as resp:
            step1 = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return 502, {"error": "upload_url_request_failed", "status": e.code,
                     "detail": e.read().decode(errors="replace")[:500]}
    if not step1.get("ok"):
        return 502, {"error": "slack_error", "stage": "getUploadURLExternal", "detail": step1}

    upload_url = step1["upload_url"]
    file_id = step1["file_id"]

    # Step 2: POST file bytes to the upload URL.
    # For file_path we pass the file handle so urllib streams in chunks
    # (memory stays bounded regardless of file size). For file_b64 we already
    # have bytes in memory — pass them directly.
    step2_req = urllib.request.Request(
        upload_url,
        data=(file_handle if file_handle is not None else file_bytes),
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(file_size),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(step2_req, timeout=600) as resp:
            _ = resp.read()
    except urllib.error.HTTPError as e:
        return 502, {"error": "upload_failed", "status": e.code,
                     "detail": e.read().decode(errors="replace")[:500]}
    finally:
        if file_handle is not None:
            file_handle.close()

    # Step 3: complete + share
    complete_payload = {
        "files": [{"id": file_id, "title": body.get("title") or filename}],
        "channel_id": channel,
    }
    if body.get("initial_comment"):
        complete_payload["initial_comment"] = body["initial_comment"]
    if body.get("thread_ts"):
        complete_payload["thread_ts"] = body["thread_ts"]

    step3_req = urllib.request.Request(
        "https://slack.com/api/files.completeUploadExternal",
        data=json.dumps(complete_payload).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(step3_req, timeout=30) as resp:
            step3 = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return 502, {"error": "complete_upload_failed", "status": e.code,
                     "detail": e.read().decode(errors="replace")[:500]}
    if not step3.get("ok"):
        return 502, {"error": "slack_error", "stage": "completeUploadExternal", "detail": step3}

    return 200, {
        "ok": True,
        "file_id": file_id,
        "files": step3.get("files", []),
        "filename": filename,
        "size": file_size,
    }


def handle_slack_react(body):
    """Add a reaction. Body: {channel, timestamp, name}."""
    for k in ("channel", "timestamp", "name"):
        if k not in body:
            raise KeyError(k)
    result = _slack_call("reactions.add", body)
    if not result.get("ok") and result.get("error") != "already_reacted":
        return 502, {"error": "slack_error", "slack_error": result.get("error")}
    return 200, {"ok": True}


def handle_slack_history(body):
    """Fetch recent messages in a channel. Body: {channel, limit?, oldest?, latest?}.
    Wraps conversations.history. Returns {ok, messages: [...], has_more}."""
    if "channel" not in body:
        raise KeyError("channel")
    params = {"channel": body["channel"], "limit": body.get("limit", 50)}
    for k in ("oldest", "latest"):
        if k in body:
            params[k] = body[k]
    token = get_secret("slack-bot-token")
    qs = urllib.parse.urlencode(params)
    req = urllib.request.Request(
        f"https://slack.com/api/conversations.history?{qs}",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        result = json.loads(resp.read())
    if not result.get("ok"):
        return 502, {"error": "slack_error", "slack_error": result.get("error"), "detail": result}
    return 200, {"ok": True, "messages": result.get("messages", []), "has_more": result.get("has_more", False)}


def handle_slack_conversations(body):
    """List conversations the bot is in. Body: {types?: 'im,mpim,public_channel,private_channel', limit?}.
    Returns {ok, channels: [...]}."""
    params = {
        "types": body.get("types", "im,mpim,public_channel,private_channel"),
        "limit": body.get("limit", 200),
    }
    token = get_secret("slack-bot-token")
    qs = urllib.parse.urlencode(params)
    req = urllib.request.Request(
        f"https://slack.com/api/conversations.list?{qs}",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        result = json.loads(resp.read())
    if not result.get("ok"):
        return 502, {"error": "slack_error", "slack_error": result.get("error"), "detail": result}
    return 200, {"ok": True, "channels": result.get("channels", [])}


def handle_slack_user_info(body):
    """Look up a user's profile. Body: {user}. Returns {ok, user: {...}}."""
    if "user" not in body:
        raise KeyError("user")
    token = get_secret("slack-bot-token")
    qs = urllib.parse.urlencode({"user": body["user"]})
    req = urllib.request.Request(
        f"https://slack.com/api/users.info?{qs}",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        result = json.loads(resp.read())
    if not result.get("ok"):
        return 502, {"error": "slack_error", "slack_error": result.get("error"), "detail": result}
    return 200, {"ok": True, "user": result.get("user", {})}


def handle_slack_replies(body):
    """Fetch replies in a thread. Body: {channel, ts, limit?}.
    Returns {ok, messages: [{user|bot_id, text, ts, ...}, ...]}.
    Common use: polling an approval-card thread for decision replies."""
    for k in ("channel", "ts"):
        if k not in body:
            raise KeyError(k)
    params = {"channel": body["channel"], "ts": body["ts"]}
    if "limit" in body:
        params["limit"] = body["limit"]
    # conversations.replies is a GET on Slack's side
    token = get_secret("slack-bot-token")
    qs = urllib.parse.urlencode(params)
    req = urllib.request.Request(
        f"https://slack.com/api/conversations.replies?{qs}",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        result = json.loads(resp.read())
    if not result.get("ok"):
        return 502, {"error": "slack_error", "slack_error": result.get("error"), "detail": result}
    return 200, {"ok": True, "messages": result.get("messages", [])}


# --- GitHub App: mint installation token ---------------------------------

def _b64url(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _mint_github_jwt():
    """Sign an RS256 JWT using openssl (no Python crypto deps)."""
    import base64, subprocess, tempfile
    app_id = get_secret("github-app-id")
    pk_pem = get_secret("github-app-private-key")
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 600, "iss": str(app_id)}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    fd, key_path = tempfile.mkstemp(prefix="secrets-daemon-gh-", suffix=".pem")
    try:
        os.write(fd, pk_pem.encode())
        os.close(fd)
        os.chmod(key_path, 0o600)
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing_input.encode(), capture_output=True, check=True,
        )
    finally:
        try: os.unlink(key_path)
        except OSError: pass
    return f"{signing_input}.{_b64url(r.stdout)}"


def handle_github_token(_body):
    """Mint a fresh GitHub App installation access token. Body: {} (no args)."""
    install_id = get_secret("github-app-installation-id")
    jwt = _mint_github_jwt()
    req = urllib.request.Request(
        f"https://api.github.com/app/installations/{install_id}/access_tokens",
        method="POST",
        headers={
            "Authorization": f"Bearer {jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    # Token IS exposed in response (it's a bearer she'll use), but it's short-lived (~1h)
    # and scoped per-installation. Expected.
    return 200, {"token": data["token"], "expires_at": data["expires_at"]}


# --- Anthropic -----------------------------------------------------------

def handle_anthropic_complete(body):
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


# --- OpenAI (chat completions) ------------------------------------------

def handle_openai_complete(body: dict):
    """Forward a Chat Completions API call.
    Body: standard OpenAI /v1/chat/completions payload — {model, messages, ...}."""
    api_key = get_secret("openai-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "openai-api-key not configured"}
    payload = json.dumps(body).encode()
    try:
        status, _, data = _https_request(
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


# --- Ollama (local LLMs, no API key) ------------------------------------

import re as _re
_OLLAMA_SAFE_MODEL = _re.compile(r"^[a-z0-9][a-z0-9_.:/-]{0,127}$", _re.IGNORECASE)


def handle_ollama_complete(body: dict):
    """Forward a chat completion to local Ollama at 127.0.0.1:11434.
    Body: {model, messages, options?, ...} — same shape as Ollama /api/chat.
    No API key needed (purely local). Response is Ollama's native format:
        {model, message: {role, content}, done, prompt_eval_count, eval_count, ...}
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


def _qwen_extract(text, question, model="qwen2.5:14b-instruct",
                  max_tokens=800, system_extra=""):
    """Internal helper: run Qwen with a system prompt asking for extraction.
    Returns (answer, error). answer is None if error occurred."""
    sys_prompt = (
        "Answer the user's question using only the text they provide. "
        "Be concise (1-3 short sentences). No preamble, no meta-commentary. "
        "If the answer is not in the text, reply exactly: NOT FOUND. "
        f"{system_extra}"
    )
    user_prompt = f"Question: {question}\n\nText:\n{text}"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "options": {"temperature": 0.0, "num_predict": max_tokens},
        "stream": False,
    }
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            d = json.loads(resp.read())
        answer = (d.get("message") or {}).get("content", "").strip()
        return answer or None, None
    except urllib.error.URLError as e:
        return None, f"ollama_unreachable: {e}"
    except urllib.error.HTTPError as e:
        return None, f"upstream_error {e.code}: {e.read().decode(errors='replace')[:200]}"


def handle_extract(body: dict):
    """Generic 'big text → small answer' extractor via local Qwen.
    Body: {text, question, max_tokens?=400, model?=qwen3:30b-a3b}.
    Returns: {answer, tokens_in_estimate} or {error}.
    Use whenever the caller would otherwise pull a large blob into an expensive
    model's context just to extract a specific fact."""
    text = body.get("text")
    question = body.get("question")
    if not text or not question:
        return 400, {"error": "missing_arg", "detail": "text and question required"}
    answer, err = _qwen_extract(
        text=text,
        question=question,
        model=body.get("model", "qwen2.5:14b-instruct"),
        max_tokens=int(body.get("max_tokens", 800)),
    )
    if err:
        return 502, {"error": err}
    return 200, {"answer": answer, "tokens_in_estimate": len(text) // 4}


def handle_web_fetch_and_extract(body: dict):
    """Fetch a URL and extract an answer from its content via Qwen.
    Body: {url, question, max_tokens?=400, max_bytes?=2_000_000}.
    Returns: {answer, url, fetched_bytes, content_type} or {error}.
    Page content never enters the caller's context — only the extracted answer."""
    url = body.get("url")
    question = body.get("question")
    if not url or not question:
        return 400, {"error": "missing_arg", "detail": "url and question required"}
    if not (url.startswith("http://") or url.startswith("https://")):
        return 400, {"error": "bad_url", "detail": "url must start with http:// or https://"}
    max_bytes = int(body.get("max_bytes", 2_000_000))

    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,text/plain,application/json,*/*",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read(max_bytes + 1)
    except urllib.error.URLError as e:
        return 502, {"error": "fetch_failed", "url": url, "detail": str(e)[:200]}
    except urllib.error.HTTPError as e:
        return 502, {"error": "fetch_http_error", "url": url, "status": e.code}

    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]

    # Decode + strip HTML to text if needed
    try:
        body_text = raw.decode("utf-8", errors="replace")
    except Exception:
        body_text = raw.decode("latin-1", errors="replace")

    if "html" in content_type.lower() or body_text.lstrip().startswith("<"):
        # Very basic HTML→text: strip scripts/styles, strip tags
        body_text = _re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", body_text,
                            flags=_re.DOTALL | _re.IGNORECASE)
        body_text = _re.sub(r"<[^>]+>", " ", body_text)
        body_text = _re.sub(r"\s+", " ", body_text).strip()

    # Cap text fed to Qwen at ~50K chars (~12K tokens) — its sweet spot
    if len(body_text) > 50000:
        body_text = body_text[:50000]

    answer, err = _qwen_extract(
        text=body_text,
        question=question,
        # qwen3:30b-a3b with thinking enabled — quality matters more than speed for
        # extracting from noisy/long web pages. message.thinking is discarded.
        # num_predict bumped to 2000 because thinking + answer share the same
        # generation budget (thinking can exceed 1500 tokens on complex pages).
        model=body.get("model", "qwen3:30b-a3b"),
        max_tokens=int(body.get("max_tokens", 2000)),
    )
    if err:
        return 502, {"error": err, "url": url}
    return 200, {
        "answer": answer,
        "url": url,
        "fetched_bytes": len(raw),
        "content_type": content_type,
        "truncated": truncated,
    }


SEARXNG_URL = "http://127.0.0.1:8888"


def _searxng_query(query, num_results=5):
    """Run a query against local SearXNG. Returns list of {title, url, content}."""
    params = urllib.parse.urlencode({"q": query, "format": "json"})
    req = urllib.request.Request(
        f"{SEARXNG_URL}/search?{params}",
        headers={"User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    results = []
    for r in data.get("results", [])[:num_results]:
        results.append({
            "title": r.get("title", ""),
            "url": r.get("url", ""),
            "content": r.get("content", "")[:500],
        })
    return results


def handle_search_web(body):
    """Search the web + synthesize an answer via local Qwen.
    Body: {query, question?, num_results?=5, fetch_pages?=True, max_tokens?=800}.
    If question is omitted, returns just the search results (for the caller to triage).
    Otherwise: fetches top results, synthesizes the answer, returns it.
    Search results + page bodies NEVER enter the caller's context — only the answer."""
    query = body.get("query")
    if not query:
        return 400, {"error": "missing_arg", "detail": "query required"}
    question = body.get("question")
    num_results = min(int(body.get("num_results", 5)), 10)
    fetch_pages = bool(body.get("fetch_pages", True))

    # 1. Search
    try:
        results = _searxng_query(query, num_results)
    except urllib.error.URLError as e:
        return 502, {"error": "search_unreachable", "detail": str(e)[:200],
                     "hint": "is SearXNG running on 127.0.0.1:8888?"}
    if not results:
        return 200, {"answer": "NOT FOUND", "sources": [], "query": query}

    # If no question, return just results (let the caller pick what to fetch)
    if not question:
        return 200, {"results": results, "query": query}

    # 2. Optionally fetch top pages for richer synthesis
    pages_text = ""
    fetched_urls = []
    if fetch_pages:
        for r in results[:3]:  # top 3 only — fetching is slow
            try:
                req = urllib.request.Request(r["url"], headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,text/plain,*/*",
                })
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = resp.read(500_000)  # 500K cap per page
                text = raw.decode("utf-8", errors="replace")
                text = _re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text,
                               flags=_re.DOTALL | _re.IGNORECASE)
                text = _re.sub(r"<[^>]+>", " ", text)
                text = _re.sub(r"\s+", " ", text).strip()
                pages_text += f"\n--- {r['url']} ---\n{text[:15000]}\n"
                fetched_urls.append(r["url"])
            except Exception:
                continue

    # Always include the search-result snippets too — covers the case where
    # fetches failed (paywalls, JS-rendered, etc.)
    snippets = "\n".join(f"[{i+1}] {r['title']} — {r['url']}\n    {r['content']}"
                        for i, r in enumerate(results))
    combined = f"SEARCH RESULT SNIPPETS:\n{snippets}\n\nFULL PAGE CONTENT (top 3):\n{pages_text}"
    if len(combined) > 60000:
        combined = combined[:60000]

    answer, err = _qwen_extract(
        text=combined,
        question=question,
        # qwen3:30b-a3b with thinking — multi-source synthesis benefits most from
        # reasoning. message.thinking is discarded; only message.content returned.
        # num_predict bumped to 3000 because thinking can be lengthy on large
        # combined input (snippets + 3 fetched pages = ~60K chars), and it counts
        # against the same budget as the visible content.
        model=body.get("model", "qwen3:30b-a3b"),
        max_tokens=int(body.get("max_tokens", 3000)),
    )
    if err:
        return 502, {"error": err, "query": query}
    return 200, {
        "answer": answer,
        "query": query,
        "sources": [r["url"] for r in results],
        "fetched_pages": fetched_urls,
    }


# --- Supabase ------------------------------------------------------------

SUPABASE_URL = "https://fkvuniwscmscjgbtmrpf.supabase.co"


def handle_supabase_query(body):
    """Read from a Supabase table. Body: {table, select?, filter?, order?, limit?}.
    Returns rows as a list. Anon key is read-only on public schema, so this is safe."""
    api_key = get_secret("supabase-api-key")
    table = body["table"]
    qs_parts = []
    if "select" in body:
        qs_parts.append(f"select={body['select']}")
    if "filter" in body:
        # filter is a dict like {"column": "eq.value"} — appended as-is
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


# --- Linear (project management) -----------------------------------------

def _linear_call(query, variables=None):
    api_key = get_secret("linear-api-key")
    payload = {"query": query, "variables": variables or {}}
    req = urllib.request.Request(
        "https://api.linear.app/graphql",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": api_key,  # Linear uses bare token, no "Bearer " prefix
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        result = json.loads(resp.read())
    if "errors" in result:
        raise RuntimeError(f"Linear GraphQL error: {result['errors']}")
    return result.get("data", {})


def handle_linear_issues_list(body):
    """List issues. Body: {teamId?, projectId?, stateType?, limit?}.
    stateType: backlog | unstarted | started | completed | canceled."""
    filter_clauses = []
    if "teamId" in body: filter_clauses.append(f'team: {{id: {{eq: "{body["teamId"]}"}}}}')
    if "projectId" in body: filter_clauses.append(f'project: {{id: {{eq: "{body["projectId"]}"}}}}')
    if "stateType" in body: filter_clauses.append(f'state: {{type: {{eq: "{body["stateType"]}"}}}}')
    filter_str = "filter: {" + ", ".join(filter_clauses) + "}, " if filter_clauses else ""
    limit = int(body.get("limit", 50))
    query = f"""query {{
      issues({filter_str}first: {limit}) {{
        nodes {{
          id identifier title description priority createdAt updatedAt
          state {{ name type }}
          assignee {{ name email }}
          team {{ name key }}
          project {{ name id }}
        }}
      }}
    }}"""
    data = _linear_call(query)
    return 200, {"issues": data.get("issues", {}).get("nodes", [])}


def handle_linear_issue_create(body):
    """Create an issue. Body: {teamId, title, description?, projectId?, assigneeId?, priority?, stateId?}.
    teamId is required. Get it from /linear/teams/list."""
    if "teamId" not in body or "title" not in body:
        raise KeyError("teamId and title are required")
    input_fields = {
        "teamId": body["teamId"],
        "title": body["title"],
    }
    for k in ("description", "projectId", "assigneeId", "priority", "stateId"):
        if k in body:
            input_fields[k] = body[k]
    query = """mutation IssueCreate($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue { id identifier title url state { name } }
      }
    }"""
    data = _linear_call(query, {"input": input_fields})
    return 200, data.get("issueCreate", {})


def handle_linear_issue_update(body):
    """Update an issue. Body: {id, title?, description?, stateId?, assigneeId?, priority?, projectId?}."""
    if "id" not in body:
        raise KeyError("id is required")
    issue_id = body["id"]
    input_fields = {k: v for k, v in body.items() if k != "id" and k in ("title", "description", "stateId", "assigneeId", "priority", "projectId")}
    if not input_fields:
        raise KeyError("at least one field to update is required")
    query = """mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
      issueUpdate(id: $id, input: $input) {
        success
        issue { id identifier title state { name } }
      }
    }"""
    data = _linear_call(query, {"id": issue_id, "input": input_fields})
    return 200, data.get("issueUpdate", {})


def handle_linear_issue_comment(body):
    """Add a comment to an issue. Body: {issueId, body}."""
    if "issueId" not in body or "body" not in body:
        raise KeyError("issueId and body are required")
    query = """mutation CommentCreate($input: CommentCreateInput!) {
      commentCreate(input: $input) {
        success
        comment { id body url }
      }
    }"""
    data = _linear_call(query, {"input": {"issueId": body["issueId"], "body": body["body"]}})
    return 200, data.get("commentCreate", {})


def handle_linear_teams_list(_body):
    """List all teams in the workspace."""
    query = """{
      teams(first: 50) {
        nodes { id name key description }
      }
    }"""
    data = _linear_call(query)
    return 200, {"teams": data.get("teams", {}).get("nodes", [])}


def handle_linear_projects_list(body):
    """List projects, optionally filtered by team. Body: {teamId?, limit?}."""
    filter_str = f'filter: {{accessibleTeams: {{some: {{id: {{eq: "{body["teamId"]}"}}}}}}}}, ' if "teamId" in body else ""
    limit = int(body.get("limit", 50))
    query = f"""{{
      projects({filter_str}first: {limit}) {{
        nodes {{ id name description state url progress targetDate }}
      }}
    }}"""
    data = _linear_call(query)
    return 200, {"projects": data.get("projects", {}).get("nodes", [])}


def handle_linear_project_create(body):
    """Create a project. Body: {name, teamIds: [<teamId>], description?, content?, leadId?, state?, targetDate?, startDate?}.
    teamIds is required (array). state values: backlog | planned | started | paused | completed | canceled."""
    if "name" not in body or "teamIds" not in body:
        raise KeyError("name and teamIds (array) are required")
    input_fields = {"name": body["name"], "teamIds": body["teamIds"]}
    for k in ("description", "content", "leadId", "memberIds", "state", "targetDate", "startDate", "color", "icon"):
        if k in body:
            input_fields[k] = body[k]
    query = """mutation ProjectCreate($input: ProjectCreateInput!) {
      projectCreate(input: $input) {
        success
        project { id name description state url targetDate startDate }
      }
    }"""
    data = _linear_call(query, {"input": input_fields})
    return 200, data.get("projectCreate", {})


def handle_linear_project_update(body):
    """Update a project. Body: {id, name?, description?, content?, state?, leadId?, targetDate?, startDate?}."""
    if "id" not in body:
        raise KeyError("id is required")
    proj_id = body["id"]
    input_fields = {k: v for k, v in body.items() if k != "id" and k in ("name", "description", "content", "state", "leadId", "targetDate", "startDate", "memberIds", "color", "icon")}
    if not input_fields:
        raise KeyError("at least one field to update is required")
    query = """mutation ProjectUpdate($id: String!, $input: ProjectUpdateInput!) {
      projectUpdate(id: $id, input: $input) {
        success
        project { id name state url }
      }
    }"""
    data = _linear_call(query, {"id": proj_id, "input": input_fields})
    return 200, data.get("projectUpdate", {})


def handle_linear_workflow_states(body):
    """List workflow states for a team. Body: {teamId}. Use to get stateId for issue create/update."""
    if "teamId" not in body:
        raise KeyError("teamId is required")
    query = f"""{{
      workflowStates(filter: {{team: {{id: {{eq: "{body["teamId"]}"}}}}}}) {{
        nodes {{ id name type position }}
      }}
    }}"""
    data = _linear_call(query)
    return 200, {"states": data.get("workflowStates", {}).get("nodes", [])}


# --- People Data Labs (lead enrichment) ----------------------------------

def handle_pdl_enrich(body):
    """Person enrich. Body: standard PDL person enrich query (email, name, etc.)."""
    api_key = get_secret("pdl-api-key")
    qs = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in body.items())
    url = f"https://api.peopledatalabs.com/v5/person/enrich?{qs}"
    req = urllib.request.Request(
        url,
        headers={"X-Api-Key": api_key, "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status, json.loads(resp.read())


# --- Replicate -----------------------------------------------------------

def _replicate_request(method, path, body=None, extra_headers=None):
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


def handle_replicate_predict(body):
    """Start a Replicate prediction.
    Body: {input, model?, version?, webhook?, webhook_events_filter?, wait?}.
    Use `model` (e.g. "black-forest-labs/flux-schnell") for official models,
    or `version` (sha) for community models. If wait=true, sets Prefer: wait
    for a synchronous response (up to 60s)."""
    if "input" not in body:
        raise KeyError("input is required")
    model = body.get("model")
    version = body.get("version")
    if not (model or version):
        raise KeyError("either model or version is required")
    payload = {"input": body["input"]}
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


def handle_replicate_get(body):
    """Get a Replicate prediction's status. Body: {id}."""
    if "id" not in body:
        raise KeyError("id is required")
    return _replicate_request("GET", f"/v1/predictions/{body['id']}")


def handle_replicate_upload_file(body: dict):
    """Upload a file to Replicate's Files API (24h URL).
    Body: {filename, content_type, content_b64}.
    Returns: {url, id, expires_at}. The url is what you pass to a Replicate
    prediction as the audio/image input."""
    import base64, mimetypes
    api_key = get_secret("replicate-api-token")
    if not api_key:
        return 500, {"error": "missing_secret"}
    try:
        filename = body["filename"]
        content_b64 = body["content_b64"]
        content_type = body.get("content_type") or (mimetypes.guess_type(filename)[0] or "application/octet-stream")
    except KeyError as e:
        return 400, {"error": "missing_arg", "field": str(e)}

    try:
        content = base64.b64decode(content_b64)
    except Exception as e:
        return 400, {"error": "bad_content_b64", "detail": str(e)}

    boundary = "----secretsdaemon" + os.urandom(8).hex()
    parts = []
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(f'Content-Disposition: form-data; name="content"; filename="{filename}"\r\n'.encode())
    parts.append(f"Content-Type: {content_type}\r\n\r\n".encode())
    parts.append(content)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
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
        return 502, {"error": "upstream_error", "status": e.code,
                     "detail": e.read().decode(errors="replace")[:500]}
    return 200, {
        "id": data.get("id"),
        "url": (data.get("urls") or {}).get("get"),
        "expires_at": data.get("expires_at"),
        "size": data.get("size"),
    }


def handle_replicate_cancel(body):
    """Cancel a running Replicate prediction. Body: {id}."""
    if "id" not in body:
        raise KeyError("id is required")
    return _replicate_request("POST", f"/v1/predictions/{body['id']}/cancel", {})


def handle_openai_speech(body):
    """TTS via OpenAI hosted API. Body: {input, voice, model?, response_format?}.
    Voices: alloy, echo, fable, onyx, nova, shimmer. Returns: {audio_b64, format}."""
    if "input" not in body or "voice" not in body:
        raise KeyError("input and voice required")
    api_key = get_secret("openai-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "openai-api-key not configured"}
    tts_payload = {
        "model": body.get("model", "tts-1"),
        "voice": body["voice"],
        "input": body["input"],
        "response_format": body.get("response_format", "mp3"),
    }
    encoded = json.dumps(tts_payload).encode()
    try:
        status, _, audio = _https_request(
            "api.openai.com", "POST", "/v1/audio/speech",
            body=encoded,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
            },
            timeout=120,
        )
        if status >= 400:
            return 502, {"error": "upstream_error", "status": status,
                         "detail": audio.decode(errors="replace")[:500]}
    except Exception as e:
        return 502, {"error": "upstream_error", "detail": str(e)[:500]}
    return 200, {
        "audio_b64": base64.b64encode(audio).decode(),
        "format": tts_payload["response_format"],
    }


def stream_openai_speech(handler_self, body: dict):
    """Streaming TTS via OpenAI. Writes MP3 bytes directly to the socket using
    HTTP chunked transfer encoding. Called directly from do_POST (bypasses the
    normal JSON dispatch loop) so it can stream without buffering the full audio.

    Body: {input, voice, model?, response_format?}.
    Response: Content-Type: audio/mpeg, Transfer-Encoding: chunked."""
    peer = handler_self.client_address[0]
    path = "/openai/speech-stream"

    if "input" not in body or "voice" not in body:
        log_audit(peer, path, "bad_request", {"error": "input and voice required"})
        handler_self._send_json(400, {"error": "missing_arg", "detail": "input and voice required"})
        return

    try:
        api_key = get_secret("openai-api-key")
    except KeyError:
        log_audit(peer, path, "missing_secret", {})
        handler_self._send_json(500, {"error": "missing_secret", "detail": "openai-api-key not configured"})
        return

    tts_payload = {
        "model": body.get("model", "tts-1"),
        "voice": body["voice"],
        "input": body["input"],
        "response_format": body.get("response_format", "mp3"),
    }
    encoded = json.dumps(tts_payload).encode()

    content_type_map = {
        "mp3": "audio/mpeg",
        "opus": "audio/ogg; codecs=opus",
        "aac": "audio/aac",
        "flac": "audio/flac",
        "wav": "audio/wav",
        "pcm": "audio/pcm",
    }
    fmt = tts_payload["response_format"]
    content_type = content_type_map.get(fmt, "audio/mpeg")

    # Streaming gets a FRESH connection per call — pooling a long-lived
    # streaming connection alongside short non-streaming calls is fragile
    # (OpenAI closes idle streams, in-flight reads block other callers).
    # The non-streaming endpoints still benefit from the pool.
    conn = http.client.HTTPSConnection("api.openai.com", timeout=120)
    headers_sent = False
    total_bytes = 0

    try:
        conn.request(
            "POST", "/v1/audio/speech",
            body=encoded,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
            },
        )
        resp = conn.getresponse()

        if resp.status >= 400:
            err_body = resp.read().decode(errors="replace")[:500]
            log_audit(peer, path, "upstream_error", {"status": resp.status, "error": err_body[:200]})
            try:
                handler_self._send_json(502, {"error": "upstream_error", "status": resp.status, "detail": err_body})
            except Exception:
                pass
            return

        handler_self.send_response(200)
        handler_self.send_header("Content-Type", content_type)
        handler_self.send_header("Transfer-Encoding", "chunked")
        handler_self.send_header("Cache-Control", "no-cache")
        handler_self.end_headers()
        headers_sent = True

        chunk_size = 8192
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            size_line = f"{len(chunk):X}\r\n".encode()
            handler_self.wfile.write(size_line)
            handler_self.wfile.write(chunk)
            handler_self.wfile.write(b"\r\n")
        handler_self.wfile.write(b"0\r\n\r\n")
        handler_self.wfile.flush()

        log_audit(peer, path, "ok", {
            "body_keys": list(body.keys()),
            "bytes": total_bytes,
            "format": fmt,
        })

    except Exception as e:
        log_audit(peer, path, "server_error", {"error": str(e), "trace": traceback.format_exc()[:500]})
        try:
            if not headers_sent:
                handler_self._send_json(500, {"error": "server_error"})
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def handle_openai_transcribe(body):
    """STT via OpenAI hosted Whisper. Body: {audio_b64, format?, model?, language?, prompt?}.
    Returns the OpenAI transcription response as-is."""
    if "audio_b64" not in body:
        raise KeyError("audio_b64 required")
    api_key = get_secret("openai-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "openai-api-key not configured"}
    audio = base64.b64decode(body["audio_b64"])
    fmt = body.get("format", "mp3")
    model = body.get("model", "whisper-1")

    boundary = "----secretsdaemon" + os.urandom(8).hex()
    parts = []

    def add_field(name, value):
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        parts.append(value.encode())
        parts.append(b"\r\n")

    def add_file(name, filename, content, ctype):
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode())
        parts.append(f"Content-Type: {ctype}\r\n\r\n".encode())
        parts.append(content)
        parts.append(b"\r\n")

    add_file("file", f"audio.{fmt}", audio, f"audio/{fmt}")
    add_field("model", model)
    if "language" in body:
        add_field("language", body["language"])
    if "prompt" in body:
        add_field("prompt", body["prompt"])
    parts.append(f"--{boundary}--\r\n".encode())

    multipart_body = b"".join(parts)
    try:
        status, _, data = _https_request(
            "api.openai.com", "POST", "/v1/audio/transcriptions",
            body=multipart_body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(multipart_body)),
            },
            timeout=300,
        )
        if status >= 400:
            return 502, {"error": "upstream_error", "status": status,
                         "detail": data.decode(errors="replace")[:500]}
        return 200, json.loads(data)
    except Exception as e:
        return 502, {"error": "upstream_error", "detail": str(e)[:500]}


def handle_openai_realtime_credentials(body: dict):
    """Mint an ephemeral OpenAI Realtime client secret for transcription-only
    sessions. Body: {model?, sampleRate?, language?}. Returns: {client_secret, expires_at}.

    The client (voice-chat plugin) takes the returned client_secret and opens
    its own WS to wss://api.openai.com/v1/realtime?intent=transcription using
    `Authorization: Bearer <client_secret>`. The secret is short-lived
    (typically ~1 minute) and scoped to a single connect attempt."""
    api_key = get_secret("openai-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "openai-api-key not configured"}
    model = body.get("model", "gpt-4o-transcribe")
    payload = {
        "session": {
            "type": "transcription",
            "audio": {
                "input": {
                    "format": {"type": "audio/pcm", "rate": int(body.get("sampleRate", 24000))},
                    "transcription": {
                        "model": model,
                        **({"language": body["language"]} if body.get("language") else {}),
                    },
                    "turn_detection": {
                        "type": "server_vad",
                        "threshold": 0.5,
                        "prefix_padding_ms": 300,
                        "silence_duration_ms": 500,
                    },
                }
            },
        }
    }
    encoded = json.dumps(payload).encode()
    try:
        status, _, raw = _https_request(
            "api.openai.com", "POST", "/v1/realtime/client_secrets",
            body=encoded,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
            },
            timeout=30,
        )
        if status >= 400:
            return 502, {"error": "upstream_error", "status": status,
                         "detail": raw.decode(errors="replace")[:500]}
        data = json.loads(raw)
    except Exception as e:
        return 502, {"error": "upstream_error", "detail": str(e)[:500]}
    return 200, {
        "client_secret": data.get("value") or data.get("client_secret", {}).get("value") or data,
        "expires_at": data.get("expires_at"),
        "session_id": data.get("session", {}).get("id") if isinstance(data.get("session"), dict) else None,
    }


def handle_elevenlabs_tts(body: dict):
    """TTS via ElevenLabs streaming endpoint.
    Body: {text, voice_id, model_id?, output_format?}.
    Returns: {audio_b64, format}."""
    if "text" not in body or "voice_id" not in body:
        raise KeyError("text and voice_id required")
    api_key = get_secret("elevenlabs-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "elevenlabs-api-key not configured"}
    output_format = body.get("output_format", "mp3_44100_128")
    el_payload = {
        "model_id": body.get("model_id", "eleven_turbo_v2_5"),
        "text": body["text"],
        "output_format": output_format,
    }
    voice_id = urllib.parse.quote(body["voice_id"], safe="")
    encoded = json.dumps(el_payload).encode()
    try:
        status, _, audio = _https_request(
            "api.elevenlabs.io", "POST", f"/v1/text-to-speech/{voice_id}/stream",
            body=encoded,
            headers={
                "xi-api-key": api_key,
                "Content-Type": "application/json",
                "Accept": "audio/mpeg",
                "Content-Length": str(len(encoded)),
            },
            timeout=120,
        )
        if status >= 400:
            return 502, {"error": "upstream_error", "status": status,
                         "detail": audio.decode(errors="replace")[:500]}
    except Exception as e:
        return 502, {"error": "upstream_error", "detail": str(e)[:500]}
    fmt = "mp3" if output_format.startswith("mp3") else output_format
    return 200, {"audio_b64": base64.b64encode(audio).decode(), "format": fmt}


def handle_elevenlabs_voices(_body):
    """List voices available on the configured ElevenLabs account.
    Returns: {voices: [{id, label, language?, gender?}, ...]}."""
    api_key = get_secret("elevenlabs-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "elevenlabs-api-key not configured"}
    try:
        status, _, raw = _https_request(
            "api.elevenlabs.io", "GET", "/v1/voices",
            headers={"xi-api-key": api_key},
            timeout=15,
        )
        if status >= 400:
            return 502, {"error": "upstream_error", "status": status,
                         "detail": raw.decode(errors="replace")[:500]}
        data = json.loads(raw)
    except Exception as e:
        return 502, {"error": "upstream_error", "detail": str(e)[:500]}
    voices = []
    for v in data.get("voices", []):
        voices.append({
            "id": v.get("voice_id"),
            "label": v.get("name"),
            "language": (v.get("labels") or {}).get("language"),
            "gender": (v.get("labels") or {}).get("gender"),
        })
    return 200, {"voices": voices}


# Registry. Add new endpoints here.
ENDPOINTS = {
    "/health": handle_health,
    "/agentmail/reply": handle_agentmail_reply,
    "/agentmail/send": handle_agentmail_send,
    "/agentmail/verify-signature": handle_agentmail_verify_signature,
    "/webhook/verify-hmac-sha256": handle_webhook_verify_hmac_sha256,
    "/stripe/verify-signature": handle_stripe_verify_signature,
    "/calendar/list-events": handle_calendar_list_events,
    "/slack/post": handle_slack_post,
    "/slack/react": handle_slack_react,
    "/slack/replies": handle_slack_replies,
    "/slack/history": handle_slack_history,
    "/slack/conversations": handle_slack_conversations,
    "/slack/user-info": handle_slack_user_info,
    "/slack/upload-file": handle_slack_upload_file,
    "/github/token": handle_github_token,
    "/anthropic/complete": handle_anthropic_complete,
    "/openai/complete": handle_openai_complete,
    "/ollama/complete": handle_ollama_complete,
    "/extract": handle_extract,
    "/web/fetch-and-extract": handle_web_fetch_and_extract,
    "/search/web": handle_search_web,
    "/supabase/query": handle_supabase_query,
    "/replicate/predict": handle_replicate_predict,
    "/replicate/get": handle_replicate_get,
    "/replicate/cancel": handle_replicate_cancel,
    "/replicate/upload-file": handle_replicate_upload_file,
    "/pdl/enrich": handle_pdl_enrich,
    "/linear/issues/list": handle_linear_issues_list,
    "/linear/issue/create": handle_linear_issue_create,
    "/linear/issue/update": handle_linear_issue_update,
    "/linear/issue/comment": handle_linear_issue_comment,
    "/linear/teams/list": handle_linear_teams_list,
    "/linear/projects/list": handle_linear_projects_list,
    "/linear/project/create": handle_linear_project_create,
    "/linear/project/update": handle_linear_project_update,
    "/linear/workflow-states": handle_linear_workflow_states,
    "/openai/speech": handle_openai_speech,
    "/openai/speech-stream": None,  # handled directly in do_POST via stream_openai_speech
    "/openai/transcribe": handle_openai_transcribe,
    "/openai/realtime-credentials": handle_openai_realtime_credentials,
    "/elevenlabs/tts": handle_elevenlabs_tts,
    "/elevenlabs/voices": handle_elevenlabs_voices,
}


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "secrets-daemon/1"

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        token = header[len("Bearer "):]
        # constant-time compare
        if len(token) != len(_bearer_token):
            return False
        return all(a == b for a, b in zip(token, _bearer_token))

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY_BYTES:
            raise ValueError(f"body too large: {length}")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    def log_message(self, format, *args):
        # Don't write request lines to stderr — we have audit.log
        pass

    def do_GET(self):
        if self.path == "/health":
            return self._handle("/health")
        self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/openai/speech-stream":
            peer = self.client_address[0]
            if not self._check_auth():
                log_audit(peer, self.path, "unauthorized", {})
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                body = self._read_body()
            except (ValueError, json.JSONDecodeError) as e:
                log_audit(peer, self.path, "bad_request", {"error": str(e)})
                self._send_json(400, {"error": "bad_request", "message": str(e)})
                return
            stream_openai_speech(self, body)
            return
        self._handle(self.path)

    def _handle(self, path):
        peer = self.client_address[0]
        if not self._check_auth():
            log_audit(peer, path, "unauthorized", {})
            self._send_json(401, {"error": "unauthorized"})
            return

        handler = ENDPOINTS.get(path)
        if handler is None:
            log_audit(peer, path, "not_found", {})
            self._send_json(404, {"error": "not_found", "path": path})
            return

        try:
            body = self._read_body()
        except (ValueError, json.JSONDecodeError) as e:
            log_audit(peer, path, "bad_request", {"error": str(e)})
            self._send_json(400, {"error": "bad_request", "message": str(e)})
            return

        try:
            status, response = handler(body)
            log_audit(peer, path, "ok", {
                "status": status,
                "body_keys": list(body.keys()),
            })
            self._send_json(status, response)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode(errors="replace")[:500]
            log_audit(peer, path, "upstream_error", {"status": e.code, "error": err_body[:200]})
            self._send_json(502, {"error": "upstream_error", "status": e.code, "message": err_body})
        except KeyError as e:
            log_audit(peer, path, "missing_arg_or_secret", {"error": str(e)})
            self._send_json(400, {"error": "missing_arg_or_secret", "message": str(e)})
        except Exception as e:
            log_audit(peer, path, "server_error", {"error": str(e), "trace": traceback.format_exc()[:500]})
            self._send_json(500, {"error": "server_error"})


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _handle_sighup(signum, frame):
    try:
        _load_state()
    except Exception as e:
        log_audit("system", "reload_failed", "error", {"error": str(e)})


def main():
    _load_state()
    signal.signal(signal.SIGHUP, _handle_sighup)
    server = ThreadedServer((HOST, PORT), Handler)
    log_audit("system", "started", "ok", {"host": HOST, "port": PORT, "pid": os.getpid()})
    print(f"secrets-daemon listening on {HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log_audit("system", "stopped", "ok", {})


if __name__ == "__main__":
    main()
