"""Typed exceptions for sqli_toolkit.

All inherit from SQLiToolkitError so callers can catch one base class.
"""


class SQLiToolkitError(Exception):
    """Base class for all toolkit errors."""


class PermissionDenied(SQLiToolkitError):
    """Target is not on the allowlist and --i-have-permission was not given."""


class SessionExpired(SQLiToolkitError):
    """The session cookie stopped working (redirect to /login, marker gone)."""


class WafBlocked(SQLiToolkitError):
    """Too many consecutive WAF-style responses (403/429/503)."""


class RateLimitHit(SQLiToolkitError):
    """Local max_total / max_rps exceeded."""


class RetryExhausted(SQLiToolkitError):
    """HTTP retries exhausted for a single request."""


class ChannelNotFound(SQLiToolkitError):
    """No working injection channel could be established."""


class ExtractionAborted(SQLiToolkitError):
    """Extraction stopped for a non-retryable reason."""
