"""Keepalive HTTPS connection pool.

One persistent connection per host, shared across threads via a per-host
lock. On any connection error the connection is discarded and a fresh one
is opened, so callers never see a stale-socket failure on the second
request.
"""
from __future__ import annotations

import http.client
import threading

_pool_lock = threading.Lock()
_connections: dict = {}  # host -> (http.client.HTTPSConnection, threading.Lock)


def _conn(host: str) -> tuple[http.client.HTTPSConnection, threading.Lock]:
    """Return (connection, lock) for *host*, creating them lazily."""
    with _pool_lock:
        if host not in _connections:
            conn = http.client.HTTPSConnection(host, timeout=120)
            _connections[host] = (conn, threading.Lock())
        return _connections[host]


def https_request(host: str, method: str, path: str, body=None, headers=None,
                  timeout: int = 120, stream: bool = False):
    """Send an HTTPS request over the keepalive pool for *host*.

    Returns (status, response_headers, data_or_response):
      - If stream=False: data is bytes (full response body read).
      - If stream=True: data is the http.client.HTTPResponse object
        (caller must .read() and .close() it; the connection lock is
        released before returning, so concurrent requests queue on the
        next lock acquisition after the streaming caller finishes).

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
                    return resp.status, dict(resp.getheaders()), resp
                data = resp.read()
                return resp.status, dict(resp.getheaders()), data
            except (BrokenPipeError, ConnectionResetError,
                    http.client.RemoteDisconnected,
                    http.client.CannotSendRequest, OSError):
                if attempt == 1:
                    raise
                try:
                    conn.close()
                except Exception:
                    pass
                conn = http.client.HTTPSConnection(host, timeout=120)
                with _pool_lock:
                    _connections[host] = (conn, lock)
