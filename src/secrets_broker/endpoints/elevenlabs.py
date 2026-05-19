"""ElevenLabs — streaming TTS + voice library.

Requires secret: elevenlabs-api-key.
"""
from __future__ import annotations

import base64
import json
import urllib.parse

from ..http_pool import https_request
from ..secrets import get_secret


def handle_elevenlabs_tts(body: dict) -> tuple[int, dict]:
    """TTS via the ElevenLabs streaming endpoint.
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
        status, _, audio = https_request(
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


def handle_elevenlabs_voices(_body: dict) -> tuple[int, dict]:
    """List voices available on the configured ElevenLabs account.
    Returns: {voices: [{id, label, language?, gender?}, ...]}."""
    api_key = get_secret("elevenlabs-api-key")
    if not api_key:
        return 500, {"error": "missing_secret", "detail": "elevenlabs-api-key not configured"}
    try:
        status, _, raw = https_request(
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


ENDPOINTS = {
    "/elevenlabs/tts": handle_elevenlabs_tts,
    "/elevenlabs/voices": handle_elevenlabs_voices,
}
