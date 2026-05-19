"""Slack — post, react, history, conversations, user-info, replies, upload-file.

Requires secret: slack-bot-token.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..secrets import get_secret


def _slack_call(method: str, body: dict) -> dict:
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


def handle_slack_post(body: dict) -> tuple[int, dict]:
    """Post a message. Body: {channel, text?, blocks?, thread_ts?, ...}."""
    if "channel" not in body:
        raise KeyError("channel")
    result = _slack_call("chat.postMessage", body)
    if not result.get("ok"):
        return 502, {"error": "slack_error", "slack_error": result.get("error"), "detail": result}
    return 200, {"ok": True, "ts": result.get("ts"), "channel": result.get("channel")}


def handle_slack_react(body: dict) -> tuple[int, dict]:
    """Add a reaction. Body: {channel, timestamp, name}."""
    for k in ("channel", "timestamp", "name"):
        if k not in body:
            raise KeyError(k)
    result = _slack_call("reactions.add", body)
    if not result.get("ok") and result.get("error") != "already_reacted":
        return 502, {"error": "slack_error", "slack_error": result.get("error")}
    return 200, {"ok": True}


def handle_slack_history(body: dict) -> tuple[int, dict]:
    """Fetch recent messages. Body: {channel, limit?, oldest?, latest?}.
    Wraps conversations.history."""
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


def handle_slack_conversations(body: dict) -> tuple[int, dict]:
    """List conversations the bot is in. Body: {types?, limit?}."""
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


def handle_slack_user_info(body: dict) -> tuple[int, dict]:
    """Look up a user's profile. Body: {user}."""
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


def handle_slack_replies(body: dict) -> tuple[int, dict]:
    """Fetch replies in a thread. Body: {channel, ts, limit?}.
    Common use: polling an approval-card thread for decision replies."""
    for k in ("channel", "ts"):
        if k not in body:
            raise KeyError(k)
    params = {"channel": body["channel"], "ts": body["ts"]}
    if "limit" in body:
        params["limit"] = body["limit"]
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


def handle_slack_upload_file(body: dict) -> tuple[int, dict]:
    """Upload a file via Slack's modern files.getUploadURLExternal +
    files.completeUploadExternal flow.

    Body: {channel, filename, file_b64 OR file_path, title?, initial_comment?, thread_ts?}.
    Callers that don't have filesystem access (different user account, sandboxed
    subprocess) should send file_b64. file_path is a convenience for callers
    that share filesystem access with the broker."""
    token = get_secret("slack-bot-token")
    if not token:
        return 500, {"error": "missing_secret"}

    channel = body.get("channel")
    filename = body.get("filename")
    if not channel or not filename:
        return 400, {"error": "missing_arg", "detail": "channel and filename required"}

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
        if file_handle:
            file_handle.close()
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
        if file_handle:
            file_handle.close()
        return 502, {"error": "upload_url_request_failed", "status": e.code,
                     "detail": e.read().decode(errors="replace")[:500]}
    if not step1.get("ok"):
        if file_handle:
            file_handle.close()
        return 502, {"error": "slack_error", "stage": "getUploadURLExternal", "detail": step1}

    upload_url = step1["upload_url"]
    file_id = step1["file_id"]

    # Step 2: POST bytes. For file_path we pass the handle so urllib streams in
    # chunks (memory stays bounded regardless of file size).
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


ENDPOINTS = {
    "/slack/post": handle_slack_post,
    "/slack/react": handle_slack_react,
    "/slack/history": handle_slack_history,
    "/slack/conversations": handle_slack_conversations,
    "/slack/user-info": handle_slack_user_info,
    "/slack/replies": handle_slack_replies,
    "/slack/upload-file": handle_slack_upload_file,
}
