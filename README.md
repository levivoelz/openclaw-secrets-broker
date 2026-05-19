# openclaw-secrets-broker

A localhost HTTP broker that performs credentialed API operations on behalf
of a less-trusted caller — another user account on the same machine, an
agent runtime, a sandboxed subprocess — **without ever handing the caller
the underlying credentials.**

Built to back the [openclaw](https://github.com/openclaw/openclaw) ecosystem,
but the code is generic — endpoint shape and process identity
(`secrets-broker/1`) don't assume OpenClaw. Reuse for any similar setup.

The caller hits an operation endpoint (`/slack/post`, `/anthropic/complete`,
etc.) with a bearer token. The broker resolves the right API key from its
own secrets file, calls upstream, returns the result. The API key never
leaves the broker's address space.

```
       ┌─────────────────┐                          ┌──────────────────┐
       │  caller         │   HTTP POST + bearer     │  secrets-broker  │
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

## Why

You want an agent (or a teammate's user account, or some sandboxed process)
to be able to *use* an API key — post to Slack, send mail, hit OpenAI — but
not to *hold* one. Once a key is in their hands, it's everywhere they go:
keychain, env vars, scrollback, process memory, dumped to logs by some
helpful library. This broker flips the model: the caller can perform
privileged operations through the surface the broker exposes, but can't
exfiltrate the keys. **One endpoint per operation, never raw API-key
passthrough.**

## The two-user pattern (the common deployment)

The broker is most useful when the caller is **a different macOS/Linux user
than the broker**. Same machine, different uids, with the OS filesystem
permissions doing the heavy lifting:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Mac Studio (or Linux box)                                              │
│                                                                         │
│   ┌──────────────────────────┐         ┌─────────────────────────────┐ │
│   │ user: owner              │         │ user: agent                 │ │
│   │  (you — the human)       │         │  (the agent runtime)        │ │
│   │                          │         │                             │ │
│   │  • runs secrets-broker   │ loopback│  • holds bearer token only  │ │
│   │    (via launchd, your    │ POST    │  • cannot read secrets.json │ │
│   │    UserName in plist)    │ ◄──────►│    (mode 600, owner=you)    │ │
│   │  • owns ~/.secrets/      │  127.   │  • calls endpoints to act   │ │
│   │    secrets.json (0600)   │  0.0.1  │                             │ │
│   │  • reads audit.log       │         │                             │ │
│   └──────────────────────────┘         └─────────────────────────────┘ │
│                                                                         │
│   filesystem boundary:  agent has NO read access to ~owner/.secrets/    │
│   network boundary:     loopback only — no LAN, no inbound from agent's │
│                          process to anywhere except 127.0.0.1:9876      │
└─────────────────────────────────────────────────────────────────────────┘
```

**What each side has:**

| | `owner` (you) | `agent` (the less-trusted user) |
|---|---|---|
| Holds `secrets.json` | ✅ — mode 0600, owner=you. agent cannot read it | ❌ |
| Holds `auth.json` (bearer) | ✅ — mode 0600 | ✅ — needs a copy (see below) |
| Runs the broker process | ✅ — via launchd, `UserName=owner` | ❌ — calls it over loopback |
| Reads `audit.log` | ✅ | ❌ |
| Can post to Slack / send mail / etc. | ✅ (directly, holds the keys) | ✅ (indirectly, via the broker) |
| Can exfiltrate the keys | ✅ (it's their machine) | ❌ — never sees them |

**Getting the bearer token to `agent`** (out-of-band, since you can't share
the broker's own `auth.json` with mode 0600). Pick whichever fits your
threat model:

| Option | How | When |
|---|---|---|
| **Keychain** | As `agent`, run `security add-generic-password -a agent -s broker-token -w <token>`. Caller reads it via `security find-generic-password`. | Most macOS-friendly. Unlocks with GUI login. Doesn't work for headless SSH sessions where keychain is locked |
| **Mode 0600 file in `~agent/`** | `sudo install -o agent -m 0600 /dev/stdin /Users/agent/.broker-token` then paste the value. Caller `cat`s it on demand | Simplest, survives reboots, works headless |
| **Env var in agent's launchd plist** | Set `BROKER_TOKEN` in the agent runtime's plist EnvironmentVariables dict | Token only lives in the launchd plist + process env; no on-disk read after boot |
| **Shared file in `/Users/Shared/`** | Mode 0640, owner=you, group includes agent. `chgrp` requires both users in a shared group | Works cross-user without sudo, but file is readable by anyone else added to that group |

The broker doesn't care which option you pick — it only checks that the
incoming `Authorization: Bearer <x>` matches what's in its `auth.json`.

**Why mode 0600 on secrets.json matters even with the broker:** the broker
endpoint surface is narrow on purpose, but it's not omniscient — a bug in
an endpoint could in theory leak a fragment of a secret to the caller. Mode
0600 keeps that bug from being a credential-theft pivot point: even if a
caller could trick an endpoint into reflecting bytes of `secrets.json`,
they'd be limited to what the endpoint generates, not the file itself.

**Single-user variant.** If you run the broker as the same user that calls
it (an agent runtime in your own session, a subprocess of your shell), the
filesystem boundary collapses and you're really only buying yourself the
narrow operation surface + audit log. Still useful, but the harder
guarantees (caller can't exfiltrate) require the two-user setup.

## Install

Pure stdlib — no `pip install` required to run.

```bash
git clone https://github.com/levivoelz/openclaw-secrets-broker.git ~/.secrets-broker
cd ~/.secrets-broker

# 1. Create the secrets file (NOT in this repo, separate dir)
mkdir -p ~/.secrets && chmod 700 ~/.secrets
cp examples/secrets.json.example ~/.secrets/secrets.json
chmod 600 ~/.secrets/secrets.json
# ...edit ~/.secrets/secrets.json with real credentials...

# 2. Generate the bearer token
( umask 077 ; jq -n --arg t "$(openssl rand -hex 32)" '{bearer_token:$t}' \
  > auth.json )
chmod 600 auth.json

# 3. Share the bearer token with each authorized caller out-of-band
#    (their keychain, env var, separate file with strict mode).

# 4. Run it manually first to confirm it boots
PYTHONPATH=src python3 -m secrets_broker
# → "secrets-broker listening on 127.0.0.1:9876"
```

For a proper install path (`secrets-broker` on PATH, no `PYTHONPATH` needed):

```bash
pip install -e .
secrets-broker
```

### Run under launchd (macOS, KeepAlive)

```bash
sed -e "s|__USER__|$(whoami)|g" \
    -e "s|__BASE__|$HOME/.secrets-broker|g" \
    -e "s|__LABEL__|com.example.secrets-broker|g" \
    examples/com.example.secrets-broker.plist.template \
    > /tmp/com.example.secrets-broker.plist

sudo cp /tmp/com.example.secrets-broker.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.example.secrets-broker.plist
```

Pick your own reverse-DNS label — anything unique on the system that matches
the plist filename.

## Configuration

All paths and the listen port are env-overridable. Defaults assume
single-user use on macOS / Linux.

| Env var | Default |
|---|---|
| `SECRETS_BROKER_HOST` | `127.0.0.1` (loopback only — do not change unless you know why) |
| `SECRETS_BROKER_PORT` | `9876` |
| `SECRETS_BROKER_BASE` | `~/.secrets-broker` |
| `SECRETS_BROKER_SECRETS_PATH` | `~/.secrets/secrets.json` |
| `SECRETS_BROKER_AUTH_PATH` | `$BASE/auth.json` |
| `SECRETS_BROKER_AUDIT_PATH` | `$BASE/audit.log` |
| `SECRETS_BROKER_USER_AGENT` | `secrets-broker/1` (sent on outbound web requests) |

## Endpoints

All endpoints are `POST` (except `GET /health`) with
`Content-Type: application/json` and `Authorization: Bearer <token>`.
Responses are JSON.

| Category | Endpoint | Purpose |
|---|---|---|
| Health | `GET /health` | Bearer-authed; returns version + endpoint list |
| Email (AgentMail) | `/agentmail/reply`, `/agentmail/send`, `/agentmail/verify-signature` | Reply/send via agentmail.to; verify inbound Svix-signed webhooks |
| Webhook signatures | `/webhook/verify-hmac-sha256`, `/stripe/verify-signature` | Verify inbound webhook auth without leaking the secret |
| Slack | `/slack/post`, `/slack/react`, `/slack/replies`, `/slack/history`, `/slack/conversations`, `/slack/user-info`, `/slack/upload-file` | Read + write via bot token |
| GitHub | `/github/token` | Mint short-lived (~1h) installation-scoped App token. **Documented exception** — see below |
| LLM completions | `/anthropic/complete`, `/openai/complete`, `/ollama/complete` | Forward chat completions to provider |
| Local extraction | `/extract`, `/web/fetch-and-extract`, `/search/web` | Qwen-backed extraction + SearXNG-backed web synthesis. Page bodies never enter caller's context — only the answer |
| Google Calendar | `/calendar/list-events` | OAuth refresh handled internally |
| Supabase | `/supabase/query` | REST query via service-role key |
| Replicate | `/replicate/predict`, `/replicate/get`, `/replicate/cancel`, `/replicate/upload-file` | Predictions + Files API uploads (for file-conditioned models) |
| People Data Labs | `/pdl/enrich` | Person enrichment |
| Linear | `/linear/issues/list`, `/linear/issue/create`, `/linear/issue/update`, `/linear/issue/comment`, `/linear/teams/list`, `/linear/projects/list`, `/linear/project/create`, `/linear/project/update`, `/linear/workflow-states` | Issue + project management |
| OpenAI media | `/openai/speech`, `/openai/speech-stream`, `/openai/transcribe`, `/openai/realtime-credentials` | TTS, streaming TTS, Whisper STT, short-lived realtime session creds |
| ElevenLabs | `/elevenlabs/tts`, `/elevenlabs/voices` | Streaming TTS + voice library |

### The `/github/token` exception

The design rule is "endpoints don't return raw secret values to the caller."
`/github/token` is the documented exception: it returns a short-lived
installation-scoped GitHub App token (~1h TTL) that the caller uses as a
bearer for git operations. This is intentional — git tooling has no clean
abstraction for "ask a broker to sign every operation," so the caller gets a
scoped, expiring token instead of the App's RSA private key. Any future
endpoints that must return raw credentials should be documented the same way
and kept minimal.

## Adding a new secret

1. Edit your secrets file (at `SECRETS_BROKER_SECRETS_PATH`):

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

2. Reload without restarting:

   ```bash
   kill -HUP $(pgrep -f secrets_broker)
   ```

## Adding a new endpoint

1. Either extend an existing provider module under
   `src/secrets_broker/endpoints/<provider>.py`, or create a new module:

   ```python
   # src/secrets_broker/endpoints/myservice.py
   from ..secrets import get_secret

   def handle_myservice_thing(body: dict) -> tuple[int, dict]:
       """Do the thing. Body: {arg1, arg2}."""
       api_key = get_secret("myservice-api-key")
       # ...call upstream, return (status, response_dict)...
       return 200, {"ok": True}

   ENDPOINTS = {
       "/myservice/thing": handle_myservice_thing,
   }
   ```

2. Register the module in `src/secrets_broker/endpoints/__init__.py` by
   adding it to the `modules` list inside `get_registry()`. The registry
   asserts there are no path collisions.

3. Restart the broker to load new code:

   ```bash
   kill $(pgrep -f secrets_broker)
   ```

   `KeepAlive=true` in the plist will respawn it. `SIGHUP` alone reloads
   secrets but **not** code.

## Verifying

```bash
# Health (bearer-authed; returns version + endpoint list)
curl -s -H "Authorization: Bearer $(jq -r .bearer_token auth.json)" \
     -X POST http://127.0.0.1:9876/health | jq

# Audit log (one JSONL line per request)
tail -f audit.log
```

Upstream API failures surface as `502 upstream_error` with the upstream body
included, so the caller can see what went wrong without holding the
credential.

## Security model

- **Loopback-only by default.** Don't bind a routable interface; this broker
  isn't the right shape for that. For cross-machine access, put a TLS-
  terminating reverse proxy in front of loopback.
- **Bearer auth on every request.** Constant-time comparison; no token = no
  service.
- **Secrets file is 0600**, owned by the user the broker runs as. Atomic
  writes only (tmpfile + `os.replace`) so partial writes can't corrupt the
  file. Reload via `SIGHUP` rather than restart so in-flight requests aren't
  dropped.
- **One operation per endpoint** — never raw API-key passthrough. The
  caller's surface is intentionally narrow.
- **Every request is audit-logged** to `audit.log` (JSONL, one line per
  request). Rotate periodically.
- **Bearer token leak → all endpoints reachable.** Rotate
  (`openssl rand -hex 32`) and redistribute on suspected exposure.

## Repo layout

```
src/secrets_broker/
  __init__.py              Package metadata, __version__
  __main__.py              `python -m secrets_broker` entry
  server.py                HTTP server + handler dispatch
  config.py                Env-driven config (paths, host, port, user agent)
  secrets.py               secrets.json + auth.json loader (+ SIGHUP reload)
  auth.py                  Bearer-token verification
  audit.py                 JSONL request audit log
  http_pool.py             Keepalive HTTPS connection pool
  utils.py                 Shared helpers (b64url, multipart boundary)
  endpoints/
    __init__.py            Merges per-module ENDPOINTS dicts; asserts no collisions
    health.py
    agentmail.py
    webhooks.py            stripe + generic hmac-sha256
    slack.py
    github.py
    completions.py         anthropic + openai + ollama
    extract.py             /extract, /web/fetch-and-extract, /search/web
    google_calendar.py
    supabase.py
    linear.py
    pdl.py
    replicate.py
    speech.py              openai TTS + STT + realtime credentials
    elevenlabs.py

examples/
  secrets.json.example                          Template for ~/.secrets/secrets.json
  auth.json.example                             Template for bearer-token file
  com.example.secrets-broker.plist.template     launchd template (sed placeholders)

helpers/
  setup-google-oauth.py    One-shot Google OAuth refresh-token bootstrap

tests/
  test_config.py           env-driven defaults + overrides
  test_auth.py             bearer verification edge cases
  test_endpoint_registry.py  every module loads, no path collisions, shape

.gitignore                 Ignores live state (auth.json, secrets.json, audit.log, ...)
pyproject.toml             Packaging + `secrets-broker` console_script + pytest config
LICENSE                    MIT
README.md                  You are here
```

## Dev loop

```bash
# Type / syntax check
python3 -m compileall src/

# Run tests (15 smoke tests, all stdlib, no upstream calls)
uv run --with pytest --no-project python -m pytest tests/
# or:
pip install -e ".[dev]" && pytest tests/

# Boot locally
PYTHONPATH=src python3 -m secrets_broker
```

## License

MIT.
