"""SQLi toolkit.

Public API:

    UnionBuilder          - UNION SELECT payload builder
    tables_payload        - ready-made payload for listing tables
    columns_payload       - ready-made payload for listing columns
    data_payload          - ready-made payload for dumping rows

    NumType               - numeric type descriptor
    pack_ascii_7bit       - pack a string 7 bits per char
    pack_ascii_8bit       - pack a string 8 bits per char
    unpack_ascii_7bit     - inverse of pack_ascii_7bit
    unpack_ascii_8bit     - inverse of pack_ascii_8bit
    sql_pack_expr         - SQL expression that packs chars on the server side

Also exposed for convenience: NUMERIC_TYPES, DIALECTS, CONCAT_LIMITS.
"""

from ._version import __version__
from .config import Config, DISCLAIMER, DEFAULT_MAX_RPS
from .exceptions import (
    SQLiToolkitError, PermissionDenied, SessionExpired,
    WafBlocked, RateLimitHit, RetryExhausted,
    ChannelNotFound, ExtractionAborted,
)
from .union_builder import (
    UnionBuilder,
    tables_payload,
    columns_payload,
    data_payload,
    DIALECTS,
    CONCAT_LIMITS,
)
from .pack_builder import (
    NumType,
    NUMERIC_TYPES,
    pack_ascii_7bit,
    pack_ascii_8bit,
    unpack_ascii_7bit,
    unpack_ascii_8bit,
    sql_pack_expr,
)

__all__ = [
    # config / errors
    "Config",
    "DISCLAIMER",
    "DEFAULT_MAX_RPS",
    "SQLiToolkitError",
    "PermissionDenied",
    "SessionExpired",
    "WafBlocked",
    "RateLimitHit",
    "RetryExhausted",
    "ChannelNotFound",
    "ExtractionAborted",
    # union_builder
    "UnionBuilder",
    "tables_payload",
    "columns_payload",
    "data_payload",
    "DIALECTS",
    "CONCAT_LIMITS",

    # pack_builder
    "NumType",
    "NUMERIC_TYPES",
    "pack_ascii_7bit",
    "pack_ascii_8bit",
    "unpack_ascii_7bit",
    "unpack_ascii_8bit",
    "sql_pack_expr",
    
    # meta
    "__version__",
]
