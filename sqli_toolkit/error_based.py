"""Backward-compatible shim.

The actual templates and the ErrorChannel now live in channels/error.py.
This module re-exports them so existing imports keep working:

    from . import error_based as EB
    EB.templates_for("mysql")
    EB.build_payload(tpl, "1=1", prefix="'", suffix="'-- ")
    EB.all_error_dialects()

Nothing else should import from here directly.
"""

from .channels.error import (  # noqa: F401
    ErrorChannel,
    TEMPLATES,
    templates_for,
    build_payload,
    all_error_dialects,
)

__all__ = [
    "ErrorChannel",
    "TEMPLATES",
    "templates_for",
    "build_payload",
    "all_error_dialects",
]
