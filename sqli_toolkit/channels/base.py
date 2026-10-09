"""Channel ABC for sqli_toolkit.

A Channel encapsulates one SQL injection vector:
  * error   — extract data via SQL error messages
  * boolean — infer bit by bit from response differences
  * time    — infer bit by bit from response time
  * union   — dump rows directly via UNION SELECT
  * oob     — exfiltrate via out-of-band callbacks (DNS/HTTP)

Channels are stateless with respect to the target: they own a Prober-like
client wrapper and a prefix/suffix pair, and expose probe()/extract_*().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ChannelInfo:
    """Metadata about a channel that has been detected as working."""
    name: str
    dialect: str
    prefix: str
    suffix: str
    technique: str                    # "boolean" | "time" | "error" | "union" | "oob"
    confidence: float = 1.0
    notes: str = ""
    extras: dict = field(default_factory=dict)


class Channel(ABC):
    """Base class for injection channels."""

    name: str = "base"

    def __init__(self, cfg, client, prober=None):
        self.cfg = cfg
        self.client = client
        self.prober = prober

    # -- detection ------------------------------------------------------

    @abstractmethod
    def detect(self) -> Optional[ChannelInfo]:
        """Return ChannelInfo if this channel works on the target, else None."""

    # -- extraction -----------------------------------------------------

    @abstractmethod
    def probe(self, condition: str) -> bool:
        """Return True if `condition` is true on the target."""

    def extract_int(self, expr: str, hi: int = 100000, lo: int = 0) -> int:
        """Binary search an integer expression. Default via probe()."""
        from ..binsearch import extract_int
        return extract_int(self.probe, expr, hi=hi, lo=lo,
                           debug=self.cfg.debug,
                           cfg=self.cfg,
                           cache=getattr(self.prober, "cache", None))

    def extract_string(self, expr: str, length: int) -> str:
        """Extract a string of given length. Default via probe()."""
        from ..binsearch import extract_string
        return extract_string(self.probe, expr, length,
                              substr=self._substr_fn(),
                              ascii_fn=self._ascii_fn(),
                              debug=self.cfg.debug,
                              cfg=self.cfg,
                              cache=getattr(self.prober, "cache", None))

    # -- helper hooks ---------------------------------------------------

    def _substr_fn(self) -> str:
        return "SUBSTRING"

    def _ascii_fn(self) -> str:
        return "ASCII"

    def extract_length(self, expr: str) -> int:
        """Get LENGTH(expr) via binary search."""
        try:
            return self.extract_int(f"LENGTH({expr})",
                                    hi=self.cfg.length_hi, lo=0)
        except Exception:
            return 0

    def __repr__(self) -> str:
        return f"<Channel {self.name}>"
