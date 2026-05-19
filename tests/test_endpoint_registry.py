"""Endpoint registry: every provider loads, paths are unique, shape is correct."""
from __future__ import annotations

from secrets_broker.endpoints import get_registry


def test_registry_loads_without_error():
    """All endpoint modules import + register without raising."""
    reg = get_registry()
    assert len(reg) > 0


def test_health_registered():
    reg = get_registry()
    assert "/health" in reg
    assert callable(reg["/health"])


def test_path_shape():
    """Every registered path starts with / and has no trailing slash."""
    reg = get_registry()
    for path in reg.keys():
        assert path.startswith("/"), f"path missing leading /: {path!r}"
        assert path == "/" or not path.endswith("/"), f"trailing /: {path!r}"


def test_speech_stream_is_special_dispatch():
    """The streaming TTS endpoint registers as None — the server special-cases
    dispatch so the handler can stream chunked audio directly to the socket."""
    reg = get_registry()
    assert "/openai/speech-stream" in reg
    assert reg["/openai/speech-stream"] is None


def test_no_path_collisions():
    """get_registry() raises on collision, so a successful call is the
    assertion. Reinforces the contract."""
    # Call twice to be extra sure registration is idempotent
    get_registry()
    get_registry()


def test_handler_signatures():
    """Each non-None handler must be callable as handler(dict) -> (int, dict).
    We don't invoke them here (they'd hit upstream APIs); we just verify
    they accept the right number of positional args via __code__.co_argcount."""
    reg = get_registry()
    for path, handler in reg.items():
        if handler is None:
            continue
        # Closures, partials, etc. expose __code__ on the underlying function;
        # we only need confidence it accepts a single positional arg.
        assert callable(handler), f"{path}: not callable"
        co = getattr(handler, "__code__", None)
        if co is not None:
            assert co.co_argcount == 1, (
                f"{path}: handler should accept 1 positional arg (body), "
                f"got {co.co_argcount}"
            )
