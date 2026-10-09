"""Boolean-based blind channel: infer bit by bit from response differences.

Signal: the response body contains a user-supplied marker when the
condition is true, and doesn't when it's false. The marker is derived
automatically (or from match.txt).

The channel delegates the actual probe to Prober (defined in auto.py),
which already handles prefix/suffix construction and retry.
"""

from __future__ import annotations

from typing import Optional

from .base import Channel, ChannelInfo


class BooleanChannel(Channel):
    name = "boolean"

    def __init__(self, cfg, client, prober=None):
        super().__init__(cfg, client, prober)
        self.dialect: str = "mysql"
        self.prefix: str = ""
        self.suffix: str = ""
        self.marker: str = ""

    def configure(self, dialect: str, prefix: str, suffix: str,
                  marker: str) -> None:
        self.dialect = dialect
        self.prefix = prefix
        self.suffix = suffix
        self.marker = marker
        if self.prober is not None:
            import sqli_toolkit.auto as auto_mod
            self.prober.dialect = dialect
            self.prober.d = auto_mod.DIALECT[dialect]
            self.prober.prefix = prefix
            self.prober.suffix = suffix
            self.prober.marker = marker
            self.prober.technique = "boolean"

    def info(self) -> ChannelInfo:
        return ChannelInfo(
            name=self.name, dialect=self.dialect,
            prefix=self.prefix, suffix=self.suffix,
            technique="boolean",
            notes=f"marker={self.marker!r}",
        )

    def detect(self) -> Optional[ChannelInfo]:
        return None  # configured externally

    def probe(self, condition: str) -> bool:
        if self.prober is None:
            return False
        return bool(self.prober.probe(condition))

    def _substr_fn(self) -> str:
        return "SUBSTR" if self.dialect == "oracle" else "SUBSTRING"

    def _ascii_fn(self) -> str:
        return "UNICODE" if self.dialect == "sqlite" else "ASCII"
