# openclaw-secrets-daemon

A localhost HTTP broker that performs credentialed API operations on behalf
of a less-trusted caller — another user account on the same machine, an
agent runtime, a sandboxed subprocess — **without ever handing the caller
the underlying credentials.**

Built to back the [openclaw](https://github.com/openclaw/openclaw) ecosystem,
but the code itself is generic — endpoint shape and process identity
(`secrets-daemon/1`) don't assume OpenClaw. Reuse for any similar setup.

The caller hits an operation endpoint (`/slack/post`, `/anthropic/complete`,
etc.) with a bearer token. The daemon resolves the right API key from its
own secrets file, calls upstream, returns the result. The API key never
leaves the daemon's address space.

## Why

Common pattern: you want an agent (or a teammate's user account, or some
sandboxed process) to be able to *use* an API key — post to Slack, send
mail, hit OpenAI — but you don't want to give them the raw key. Once a key
is in their hands, it's everywhere they go: keychain, env vars, scrollback,
process memory, dumped to logs by some helpful library.

This daemon flips the model:

```
       ┌─────────────────┐                          ┌──────────────────┐
       │  caller         │   HTTP POST + bearer     │  secrets-daemon  │
       │  (agent/user/   │ ───────────────────────► │  (your user)     │
       │  subprocess)    │   /slack/post {channel,  │                  │
       │                 │     text: "..."}         │  • reads key     │
       │  • never sees   │                          │  • calls Slack   │
       │    the API key  │ ◄─────────────────────── │  • returns ok    │
       │                 │   {ok: true, ts: ...}    │                  │
       └─────────────────┘                          └────────┬─────────┘
                                                             │
                                                             ▼
                                              ┌─────────────────────────┐
                                              │  ~/.secrets/secrets.json│
                                              │  mode 600, your user    │
                                              └─────────────────────────┘
```

The caller can perform privileged operations through the surface the daemon
exposes, but can't exfiltrate the keys. **One endpoint per operation, not
raw API-key passthrough.**

## Install

```bash
# 1. Clone wherever you want it
git clone https://github.com/levivoelz/openclaw-secrets-daemon.git ~/.secrets-daemon
cd ~/.secrets-daemon

# 2. Create the secrets file (NOT in this repo, separate dir)
mkdir -p ~/.secrets && chmod 700 ~/.secrets
cp examples/secrets.json.example ~/.secrets/secrets.json
chmod 600 ~/.secrets/secrets.json
# ...edit ~/.secrets/secrets.json with real credentials...

# 3. Generate the bearer token
( umask 077 ; jq -n --arg t "$(openssl rand -hex 32)" '{bearer_token:$t}' \
  > auth.json )
chmod 600 auth.json

# 4. Share the bearer token with each authorized caller out-of-band
#    (their keychain, env var, separate file with strict mode).

# 5. Run it manually first to confirm it boots
python3 server.py
# → "secrets-daemon listening on 127.0.0.1:9876"
```

### Run under launchd (macOS, KeepAlive)

```bash
# Render the template
sed -e "s|__USER__|$(whoami)|g" \
    -e "s|__BASE__|$HOME/.secrets-daemon|g" \
    -e "s|__LABEL__|com.example.secrets-daemon|g" \
    examples/com.example.secrets-daemon.plist.template \
    > /tmp/com.example.secrets-daemon.plist

sudo cp /tmp/com.example.secrets-daemon.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.example.secrets-daemon.plist
```

Pick your own reverse-DNS label — anything unique on the system that matches
the plist filename.

## Configuration

All paths and the listen port are env-overridable. Defaults assume
single-user use on macOS / Linux:

| Env var | Default |
|---|---|
| `SECRETS_DAEMON_HOST` | `127.0.0.1` (loopback only — do not change unless you know why) |
| `SECRETS_DAEMON_PORT` | `9876` |
| `SECRETS_DAEMON_BASE` | `~/.secrets-daemon` |
| `SECRETS_DAEMON_SECRETS_PATH` | `~/.secrets/secrets.json` |
| `SECRETS_DAEMON_AUTH_PATH` | `$BASE/auth.json` |
| `SECRETS_DAEMON_AUDIT_PATH` | `$BASE/audit.log` |
| `SECRETS_DAEMON_USER_AGENT` | `secrets-daemon/1` (used for outbound web requests) |

## Endpoints

Calling convention: all endpoints are `POST` with `Content-Type:
application/json` and `Authorization: Bearer <token>`. Returns JSON.

| Category | Endpoint | Purpose |
|---|---|---|
| Health | `GET /health` | Bearer-authed; returns version + endpoint list |
| Email (AgentMail) | `/agentmail/reply`, `/agentmail/send`, `/agentmail/verify-signature` | Reply/send via agentmail.to; verify inbound webhooks |
| Webhook signatures | `/webhook/verify-hmac-sha256`, `/stripe/verify-signature` | Verify inbound webhook auth without leaking secrets |
| Slack | `/slack/post`, `/slack/react`, `/slack/replies`, `/slack/history`, `/slack/conversations`, `/slack/user-info`, `/slack/upload-file` | Read + write to Slack via bot token |
| GitHub | `/github/token` | Mint short-lived (~1h) installation-scoped GitHub App token. **This one DOES return a token** — see exception note below |
| LLM completions | `/anthropic/complete`, `/openai/complete`, `/ollama/complete` | Forward chat completion to provider |
| Local extraction | `/extract`, `/web/fetch-and-extract`, `/search/web` | Qwen-backed text extraction + SearXNG-backed web search synthesis. Page bodies never enter caller's context — only the extracted answer |
| Google Calendar | `/calendar/list-events` | OAuth refresh handled internally |
| Supabase | `/supabase/query` | Read-only query via service-role key |
| Replicate | `/replicate/predict`, `/replicate/get`, `/replicate/cancel`, `/replicate/upload-file` | Predictions, file upload for file-conditioned models |
| People Data Labs | `/pdl/enrich` | Person enrichment |
| Linear | `/linear/issues/list`, `/linear/issue/create`, `/linear/issue/update`, `/linear/issue/comment`, `/linear/teams/list`, `/linear/projects/list`, `/linear/project/create`, `/linear/project/update`, `/linear/workflow-states` | Issue + project management |
| OpenAI media | `/openai/speech`, `/openai/speech-stream`, `/openai/transcribe`, `/openai/realtime-credentials` | TTS, streaming TTS, Whisper STT, short-lived realtime session creds |
| ElevenLabs | `/elevenlabs/tts`, `/elevenlabs/voices` | TTS + voice library |

### The `/github/token` exception

The design rule is "endpoints don't return raw secret values to the caller."
`/github/token` is the documented exception: it returns a short-lived
installation-scoped GitHub App token (~1h TTL) that the caller uses as a
bearer for git operations. This trade is intentional — git tooling has no
clean abstraction for "ask a broker to sign every operation," so we give the
caller a scoped, expiring token instead of the App's RSA private key. If you
add other endpoints that must return raw credentials, document them the same
way and keep the set minimal.

## Adding a new secret

1. Edit your secrets file (the one at `SECRETS_DAEMON_SECRETS_PATH`):

   ```bash
   # Pass the value via env so it doesn't land in shell history
   NEW_VAL="..." python3 -c '
   import json, os, tempfile
   path = os.path.expanduser("~/.secrets/secrets.json")
   with open(path) as f: data = json.load(f)
   data["secrets"]["my-new-key"] = os.environ["NEW_VAL"]
   fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".secrets-")
   try:
     with os.fdopen(fd, "w") as f: os.chmod(tmp, 0o600); json.dump(data, f, indent=2)
     os.replace(tmp, path)
   except: os.unlink(tmp); raise
   '
   ```

2. Reload without restarting (drops in-flight requests cleanly):

   ```bash
   kill -HUP $(pgrep -f secrets-daemon/server.py)
   ```

## Adding a new endpoint

1. Add a `handle_<name>(body) -> (status, response_dict)` function in
   `server.py`. Use `get_secret("<key>")` to fetch credentials. Follow the
   existing pattern (input validation, descriptive errors, no raw secrets in
   returns).
2. Register it in the `ENDPOINTS` dict near the bottom of `server.py`.
3. Restart the daemon to load the new code:

   ```bash
   kill $(pgrep -f secrets-daemon/server.py)
   ```

   `KeepAlive=true` in the plist will respawn it. `SIGHUP` alone reloads
   secrets but **not** code.

## Verifying

```bash
# Health check (bearer-authed; returns version + endpoint list)
curl -s -H "Authorization: Bearer $(jq -r .bearer_token auth.json)" \
     http://127.0.0.1:9876/health | jq

# Audit log (one JSONL line per request)
tail -f audit.log
```

Upstream API auth failures surface as `502 upstream_error` with the upstream
body included, so the caller can see what went wrong without ever holding
the credential.

## Security model

- **Loopback-only by default.** `HOST=127.0.0.1`. Don't bind to a routable
  interface; this daemon is not the right shape for that. If you need cross-
  machine access, terminate TLS + auth at a reverse proxy and proxy to
  loopback.
- **Bearer auth on every request.** Constant-time comparison; no token = no
  service.
- **Secrets file is 0600**, owned by the user the daemon runs as. Atomic
  writes only (tmpfile + `os.replace`) so partial writes can't corrupt the
  file. Reload via `SIGHUP` rather than restart so in-flight requests aren't
  dropped.
- **One operation per endpoint** — never raw API-key passthrough. The
  caller's surface is intentionally narrow: they can do the things the
  daemon implements, not anything the underlying key permits.
- **Every request is audit-logged** to `audit.log` (JSONL, one line per
  request). Rotate periodically.
- **The bearer token leaks → all endpoints are reachable.** Rotate the token
  (`openssl rand -hex 32`) and redistribute if you suspect exposure.

## Repo layout

```
server.py                Main daemon — HTTP server + endpoint handlers
examples/
  secrets.json.example                 Template for ~/.secrets/secrets.json
  auth.json.example                    Template for bearer-token file
  com.example.secrets-daemon.plist.template   launchd template with placeholders
helpers/
  setup-google-oauth.py    One-shot Google OAuth refresh-token bootstrap
.gitignore
LICENSE                  MIT
README.md                You are here
```

## License

MIT.
