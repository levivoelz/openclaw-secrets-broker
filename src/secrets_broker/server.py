"""HTTP server: dispatch authenticated requests to registered endpoints."""
from __future__ import annotations

import http.server
import json
import os
import signal
import socketserver
import traceback
import urllib.error

from .audit import log_audit
from .auth import check_bearer
from .config import HOST, MAX_BODY_BYTES, PORT
from .endpoints import get_registry
from .endpoints.speech import stream_openai_speech
from .secrets import load_state

# Built once at import; safe because endpoint modules are stateless after load.
ENDPOINTS = get_registry()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "secrets-broker/1"

    # ----- helpers -----

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY_BYTES:
            raise ValueError(f"body too large: {length}")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    def log_message(self, format, *args):  # noqa: A002 (override signature)
        # Don't write request lines to stderr — we have audit.log.
        pass

    # ----- dispatch -----

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            return self._handle("/health")
        self._send_json(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        # /openai/speech-stream is registered as None — it owns the response
        # socket and writes chunked audio directly. Dispatch specially.
        if self.path == "/openai/speech-stream":
            peer = self.client_address[0]
            if not check_bearer(self.headers.get("Authorization")):
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

    def _handle(self, path: str) -> None:
        peer = self.client_address[0]

        if not check_bearer(self.headers.get("Authorization")):
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
    """Reload secrets on SIGHUP (no process restart). Code changes need a kill."""
    try:
        load_state()
    except Exception as e:
        log_audit("system", "reload_failed", "error", {"error": str(e)})


def serve() -> None:
    """Boot: load state, install SIGHUP handler, serve_forever."""
    load_state()
    signal.signal(signal.SIGHUP, _handle_sighup)
    server = ThreadedServer((HOST, PORT), Handler)
    log_audit("system", "started", "ok", {"host": HOST, "port": PORT, "pid": os.getpid()})
    print(f"secrets-broker listening on {HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log_audit("system", "stopped", "ok", {})
