"""Google Calendar — OAuth refresh-token flow + event listing.

Required secrets:
  - google-oauth-client-id      (Desktop App OAuth client from GCP Console)
  - google-oauth-client-secret  (same)
  - google-oauth-refresh-token  (obtain via helpers/setup-google-oauth.py — run once)

Access tokens are cached in-process (~50 min); on cache miss the broker
exchanges the refresh token for a fresh access token.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from ..secrets import get_secret

_google_token_cache: dict = {"token": None, "expires_at": 0}


def _google_access_token() -> str:
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


def handle_calendar_list_events(body: dict) -> tuple[int, dict]:
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


ENDPOINTS = {
    "/calendar/list-events": handle_calendar_list_events,
}
