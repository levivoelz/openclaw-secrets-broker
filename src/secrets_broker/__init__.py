"""secrets-broker — a localhost HTTP broker for credentialed API operations.

The caller holds a bearer token, not API keys. The broker holds the API keys,
resolves the right one per endpoint, calls upstream, returns the result.

Public entry: `from secrets_broker.server import serve` or `python -m secrets_broker`.
"""

__version__ = "0.2.0"
__all__ = ["__version__"]
