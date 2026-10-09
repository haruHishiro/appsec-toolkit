"""Time-based blind channel: infer bit by bit from response time.

Signal: the response takes >= delay seconds when the condition is true.
The channel delegates the actual probe to Prober, which uses the
per-dialect sleep_cond template.
"""

from __future__ import annotations

from typing import Optional

from .base import Channel, ChannelInfo


class TimeChannel(Channel):
    name = "time"

    def __init__(self, cfg, client, prober=None):
        super().__init__(cfg, client, prober)
        self.dialect: str = "mysql"
        self.prefix: str = ""
        self.suffix: str = ""
        self.delay: int = 5

    def configure(self, dialect: str, prefix: str, suffix: str,
                  delay: int) -> None:
        self.dialect = dialect
        self.prefix = prefix
        self.suffix = suffix
        self.delay = delay
        if self.prober is not None:
            import sqli_toolkit.auto as auto_mod
            self.prober.dialect = dialect
            self.prober.d = auto_mod.DIALECT[dialect]
            self.prober.prefix = prefix
            self.prober.suffix = suffix
            self.prober.delay = delay
            self.prober.technique = "time"

    def info(self) -> ChannelInfo:
        return ChannelInfo(
            name=self.name, dialect=self.dialect,
            prefix=self.prefix, suffix=self.suffix,
            technique="time",
            notes=f"delay={self.delay}s",
        )

    def detect(self) -> Optional[ChannelInfo]:
        return None

    def probe(self, condition: str) -> bool:
        if self.prober is None:
            return False
        return bool(self.prober.probe(condition))

    def extract_string(self, expr: str, length: int) -> str:
        # Time-based cannot be parallelised; fall back to sequential
        # extraction via the base implementation (which uses probe()).
        return super().extract_string(expr, length)

    def _substr_fn(self) -> str:
        return "SUBSTR" if self.dialect == "oracle" else "SUBSTRING"

    def _ascii_fn(self) -> str:
        return "UNICODE" if self.dialect == "sqlite" else "ASCII"
