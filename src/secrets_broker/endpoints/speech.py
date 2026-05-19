"""OpenAI speech — TTS (buffered + streaming), Whisper STT, realtime credentials.

Requires secret: openai-api-key.

The streaming endpoint /openai/speech-stream uses a special signature
(takes the BaseHTTPRequestHandler instance so it can write chunked
audio directly to the socket). It's registered as None in ENDPOINTS
and dispatched specially by the server module.
"""
from __future__ import annotations

import base64
import http.client
import json
import traceback
import urllib.parse

from ..audit import log_audit
from ..http_pool import https_request
from ..secrets import get_secret
from ..utils import random_multipart_boundary


def handle_openai_speech(body: dict) -> tuple[int, dict]:
    """Buffered TTS via OpenAI. Body: {input, voice, model?, response_format?}.
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
        status, _, audio = https_request(
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


def stream_openai_speech(handler_self, body: dict) -> None:
    """Streaming TTS via OpenAI. Writes audio bytes directly to the socket
    using HTTP chunked transfer encoding. Called directly from the server's
    do_POST (bypasses the standard JSON dispatch) so it can stream without
    buffering the full audio.

    Body: {input, voice, model?, response_format?}.
    Response: chunked, Content-Type per response_format."""
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

    # Streaming gets a fresh connection per call. Pooling a long-lived
    # streaming connection alongside short non-streaming calls is fragile
    # (OpenAI closes idle streams, in-flight reads block other callers).
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
            handler_self.wfile.write(f"{len(chunk):X}\r\n".encode())
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


def handle_openai_transcribe(body: dict) -> tuple[int, dict]:
    """STT via OpenAI hosted Whisper.
    Body: {audio_b64, format?, model?, language?, prompt?}.
    Returns the OpenAI transcription response as-is."""
    if "audio_b64" not in body:
        raise KeyError("audio_b64 required")
    api_key = get_secret("openai-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "openai-api-key not configured"}
    audio = base64.b64decode(body["audio_b64"])
    fmt = body.get("format", "mp3")
    model = body.get("model", "whisper-1")

    boundary = random_multipart_boundary()
    parts: list[bytes] = []

    def add_field(name: str, value: str) -> None:
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        parts.append(value.encode())
        parts.append(b"\r\n")

    def add_file(name: str, filename: str, content: bytes, ctype: str) -> None:
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
        status, _, data = https_request(
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


def handle_openai_realtime_credentials(body: dict) -> tuple[int, dict]:
    """Mint an ephemeral OpenAI Realtime client secret for transcription-only
    sessions. Body: {model?, sampleRate?, language?}.
    Returns: {client_secret, expires_at, session_id?}.

    The caller takes the returned client_secret and opens its own WS to
    wss://api.openai.com/v1/realtime?intent=transcription using
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
        status, _, raw = https_request(
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


# /openai/speech-stream is registered as None — server dispatches specially.
ENDPOINTS = {
    "/openai/speech": handle_openai_speech,
    "/openai/speech-stream": None,
    "/openai/transcribe": handle_openai_transcribe,
    "/openai/realtime-credentials": handle_openai_realtime_credentials,
}
