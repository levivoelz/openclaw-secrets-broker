"""GitHub App: mint installation access tokens.

This is the one documented exception to "don't return raw credentials" —
the returned token is short-lived (~1h) and installation-scoped. Git tooling
has no clean way to sign every operation through a broker, so callers get a
scoped expiring token instead of the App's RSA private key.

Required secrets: github-app-id, github-app-installation-id,
                  github-app-private-key (PEM, RSA).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.request

from ..secrets import get_secret
from ..utils import b64url


def _mint_github_jwt() -> str:
    """Sign an RS256 JWT using openssl (no Python crypto deps)."""
    app_id = get_secret("github-app-id")
    pk_pem = get_secret("github-app-private-key")
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 600, "iss": str(app_id)}
    signing_input = (
        f"{b64url(json.dumps(header, separators=(',', ':')).encode())}."
        f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    )
    fd, key_path = tempfile.mkstemp(prefix="secrets-broker-gh-", suffix=".pem")
    try:
        os.write(fd, pk_pem.encode())
        os.close(fd)
        os.chmod(key_path, 0o600)
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing_input.encode(),
            capture_output=True,
            check=True,
        )
    finally:
        try:
            os.unlink(key_path)
        except OSError:
            pass
    return f"{signing_input}.{b64url(r.stdout)}"


def handle_github_token(_body: dict) -> tuple[int, dict]:
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
    # Token IS exposed in response — it's a short-lived (~1h) installation-scoped
    # bearer the caller uses for git ops. Documented exception to the no-raw-
    # secrets rule.
    return 200, {"token": data["token"], "expires_at": data["expires_at"]}


ENDPOINTS = {
    "/github/token": handle_github_token,
}
