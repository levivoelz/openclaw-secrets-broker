#!/usr/bin/env python3
"""
Bootstrap a Google OAuth refresh token for the secrets-daemon.

Run ONCE to obtain a refresh token with calendar.readonly scope.

Prerequisites:
1. In Google Cloud Console (https://console.cloud.google.com):
   - Create a project (or use existing)
   - Enable the Google Calendar API
   - Create OAuth 2.0 credentials, type "Desktop app"
   - Copy the client ID and client secret
2. Add the credentials to your secrets.json (see SECRETS_PATH below or the
   SECRETS_DAEMON_SECRETS_PATH env var):
       "google-oauth-client-id": "...apps.googleusercontent.com",
       "google-oauth-client-secret": "GOCSPX-...",
3. Run this script: python3 setup-google-oauth.py
4. The script opens your browser. Approve the calendar.readonly access.
5. After redirect, the refresh token is written back to secrets.json.
6. SIGHUP the daemon to reload: kill -HUP $(pgrep -f secrets-daemon/server.py)
"""
from __future__ import annotations

import http.server
import json
import os
import secrets
import socketserver
import stat
import tempfile
import threading
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

SECRETS_PATH = Path(
    os.environ.get("SECRETS_DAEMON_SECRETS_PATH")
    or (Path.home() / ".secrets" / "secrets.json")
).expanduser()
SCOPES = ["https://www.googleapis.com/auth/calendar.readonly"]


def load_secrets():
    with open(SECRETS_PATH) as f:
        return json.load(f)


def save_secret(key: str, value: str):
    """Atomic write preserving mode 600."""
    data = load_secrets()
    data["secrets"][key] = value
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(SECRETS_PATH), prefix=".secrets.", suffix=".tmp")
    try:
        os.write(fd, json.dumps(data, indent=2).encode())
        os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, SECRETS_PATH)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def main():
    s = load_secrets()
    client_id = s["secrets"].get("google-oauth-client-id")
    client_secret = s["secrets"].get("google-oauth-client-secret")
    if not client_id or not client_secret:
        raise SystemExit(
            "missing google-oauth-client-id or google-oauth-client-secret in secrets.json — "
            "add them first (see prerequisites in this file's docstring)"
        )

    state = secrets.token_urlsafe(24)
    port = 50876  # arbitrary high port, unlikely to be in use
    redirect_uri = f"http://127.0.0.1:{port}/"

    authorize_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    })

    received = {"code": None, "error": None}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if params.get("state", [""])[0] != state:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"state mismatch")
                received["error"] = "state_mismatch"
                return
            if params.get("error"):
                received["error"] = params["error"][0]
                self.send_response(400)
                self.end_headers()
                self.wfile.write(f"oauth error: {received['error']}".encode())
                return
            code = params.get("code", [""])[0]
            received["code"] = code
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>OK</h1><p>You can close this tab. Return to the terminal.</p>")

    httpd = socketserver.TCPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    print(f"\nOpening browser to authorize. If it doesn't open automatically, visit:\n\n{authorize_url}\n")
    webbrowser.open(authorize_url)

    print("Waiting for redirect...")
    while received["code"] is None and received["error"] is None:
        pass
    httpd.shutdown()

    if received["error"]:
        raise SystemExit(f"OAuth flow failed: {received['error']}")

    print("Got authorization code. Exchanging for refresh token...")
    token_req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=urllib.parse.urlencode({
            "code": received["code"],
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(token_req, timeout=15) as resp:
        body = json.loads(resp.read())

    refresh_token = body.get("refresh_token")
    if not refresh_token:
        raise SystemExit(
            "Google did not return a refresh_token. This usually means the user "
            "previously authorized this client. Revoke at "
            "https://myaccount.google.com/permissions and re-run."
        )

    save_secret("google-oauth-refresh-token", refresh_token)
    st = os.stat(SECRETS_PATH)
    print(f"\nRefresh token written to {SECRETS_PATH} (mode {oct(stat.S_IMODE(st.st_mode))}).")
    print("Now reload the daemon: kill -HUP $(pgrep -f secrets-daemon/server.py)")
    print("Then test: curl http://127.0.0.1:9876/calendar/list-events -H 'Authorization: Bearer <token>' -d '{}'")


if __name__ == "__main__":
    main()
