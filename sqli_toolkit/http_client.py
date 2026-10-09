"""HTTP client for sqli_toolkit.

Changes in v1.1:
  * Client takes a Config, not (raw, timeout).
  * Retry with exponential backoff + jitter.
  * WAF detector (consecutive 403/429/503).
  * Session-expiry detector (redirect to /login, baseline marker loss).
  * Global request counter (max_total).
  * Throttle respects Config.throttle_rps (already capped by max_rps).
  * Client.from_raw(raw, timeout=...) shim for backwards compatibility.
"""

from __future__ import annotations

import html
import random
import re
import threading
import time
from typing import Optional
from urllib.parse import quote, urlparse

import requests
import urllib3

from .config import Config
from .exceptions import (
    PermissionDenied,
    RateLimitHit,
    RetryExhausted,
    SessionExpired,
    WafBlocked,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


MARKER = "{{%payload%}}"


# ---------------------------------------------------------------------------
# Module-level state (single source of truth for one process run)
# ---------------------------------------------------------------------------

_STATE_LOCK = threading.Lock()
_STATE = {
    "rps": 0.0,           # 0 = disabled
    "last_call": 0.0,
    "total": 0,           # total requests sent since process start
    "max_total": 0,       # 0 = unlimited
    "waf_streak": 0,
    "waf_slowdowns": 0,
    "session_lost": False,
    "baseline_marker": "",   # if set, every response must still contain it
    "debug": False,
}


def configure(cfg: Config) -> None:
    """Apply Config to the module-level HTTP state."""
    with _STATE_LOCK:
        _STATE["rps"] = 0.0 if cfg.no_throttle else float(cfg.throttle_rps)
        _STATE["max_total"] = int(cfg.max_total)
        _STATE["debug"] = bool(cfg.debug)
        _STATE["waf_streak"] = 0
        _STATE["waf_slowdowns"] = 0
        _STATE["session_lost"] = False


def set_baseline_marker(marker: str) -> None:
    """If non-empty, every response body must contain this substring."""
    with _STATE_LOCK:
        _STATE["baseline_marker"] = marker or ""


def _throttle() -> None:
    with _STATE_LOCK:
        rps = _STATE["rps"]
        if rps <= 0:
            return
        min_gap = 1.0 / rps
        now = time.time()
        wait = _STATE["last_call"] + min_gap - now
        if wait > 0:
            time.sleep(wait)
            now = time.time()
        _STATE["last_call"] = now


# ---------------------------------------------------------------------------
# Per-worker throttle (variant B)
# ---------------------------------------------------------------------------
#
# When several extraction workers run in parallel, sharing one global
# _throttle() makes them all wait on the same lock — total RPS stays at
# cfg.max_rps, but the lock becomes the bottleneck. Instead each worker
# gets its own rps = max_rps / parallel, so the sum never exceeds the cap.
#
# worker_id=0 means 'use the global throttle' (sequential mode).

_WORKER_LOCKS: dict[int, threading.Lock] = {}
_WORKER_LAST: dict[int, float] = {}
_WORKER_LOCKS_GUARD = threading.Lock()


def _worker_lock(wid: int) -> threading.Lock:
    with _WORKER_LOCKS_GUARD:
        lk = _WORKER_LOCKS.get(wid)
        if lk is None:
            lk = threading.Lock()
            _WORKER_LOCKS[wid] = lk
            _WORKER_LAST[wid] = 0.0
        return lk


def _throttle_worker(wid: int, parallel: int) -> None:
    if wid <= 0 or parallel <= 1:
        _throttle()
        return
    with _STATE_LOCK:
        base_rps = _STATE["rps"]
    if base_rps <= 0:
        return
    rps = max(0.1, base_rps / float(parallel))
    min_gap = 1.0 / rps
    lk = _worker_lock(wid)
    with lk:
        now = time.time()
        wait = _WORKER_LAST[wid] + min_gap - now
        if wait > 0:
            time.sleep(wait)
            now = time.time()
        _WORKER_LAST[wid] = now


def reset_worker_throttles() -> None:
    with _WORKER_LOCKS_GUARD:
        _WORKER_LOCKS.clear()
        _WORKER_LAST.clear()


def _count_request() -> None:
    with _STATE_LOCK:
        _STATE["total"] += 1
        mt = _STATE["max_total"]
        if mt and _STATE["total"] > mt:
            raise RateLimitHit(
                f"max_total={mt} exceeded "
                f"(sent {_STATE['total']} requests)"
            )


def _current_rps() -> float:
    with _STATE_LOCK:
        return _STATE["rps"]


def _slowdown_on_waf() -> float:
    """Halve the current rps. Returns the new value (0 if already off)."""
    with _STATE_LOCK:
        rps = _STATE["rps"]
        if rps <= 0:
            return 0.0
        new_rps = max(0.5, rps / 2.0)
        _STATE["rps"] = new_rps
        _STATE["waf_slowdowns"] += 1
        return new_rps


def _note_waf_response(status: int) -> None:
    if status in (403, 429, 503):
        with _STATE_LOCK:
            _STATE["waf_streak"] += 1
            streak = _STATE["waf_streak"]
        if streak >= 3 and streak % 3 == 0:
            new_rps = _slowdown_on_waf()
            _dbg(f"[waf] streak={streak} rps -> {new_rps:.2f}")
        if streak >= 10:
            raise WafBlocked(
                f"{streak} consecutive 403/429/503 responses — "
                f"WAF likely blocking. Aborting to avoid a ban."
            )
    else:
        with _STATE_LOCK:
            _STATE["waf_streak"] = 0


def _note_session(response) -> None:
    """Detect session expiry: redirect to /login or baseline marker loss."""
    if getattr(response, "is_redirect", False):
        loc = (response.headers.get("Location") or "").lower()
        if "/login" in loc or "signin" in loc:
            with _STATE_LOCK:
                _STATE["session_lost"] = True
            raise SessionExpired(
                f"server redirected to {loc!r}; session likely expired"
            )
    with _STATE_LOCK:
        marker = _STATE["baseline_marker"]
    if marker:
        body = getattr(response, "text", "") or ""
        if marker not in body:
            with _STATE_LOCK:
                _STATE["session_lost"] = True
            raise SessionExpired(
                f"baseline marker {marker!r} disappeared from response"
            )


def _dbg(msg: str) -> None:
    if _STATE["debug"]:
        try:
            from .auto import dbg as _auto_dbg
            _auto_dbg(msg)
        except Exception:
            print(msg)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _normalize(s: str) -> str:
    s = html.unescape(s)
    s = _TAG_RE.sub("", s)
    s = _WS_RE.sub(" ", s)
    return s.strip()


def contains_match(body: str, needle: str) -> bool:
    if not needle:
        return False
    if needle in body:
        return True
    nb = _normalize(body)
    nn = _normalize(needle)
    if nn and nn in nb:
        return True
    if _TAG_RE.search(needle):
        stripped = _TAG_RE.sub("", needle).strip()
        if stripped and stripped in body:
            return True
    return False


def status_of(response) -> int:
    return int(getattr(response, "status_code", 0))


def body_of(response) -> str:
    return getattr(response, "text", "") or ""


# ---------------------------------------------------------------------------
# Raw HTTP request
# ---------------------------------------------------------------------------

class RawRequest:
    def __init__(self, raw: str) -> None:
        self.raw = raw.replace("\r\n", "\n")
        self.method = "GET"
        self.path = "/"
        self.version = "HTTP/1.1"
        self.headers: dict[str, str] = {}
        self.body = ""
        self.host = ""
        self.scheme = "https"
        self._parse()

    def _parse(self) -> None:
        head, _, body = self.raw.partition("\n\n")
        self.body = body

        lines = head.split("\n")
        if not lines:
            raise ValueError("empty request")

        m = re.match(r"^([A-Z]+)\s+(\S+)\s+(HTTP/\S+)$", lines[0].strip())
        if not m:
            raise ValueError(f"bad request line: {lines[0]!r}")
        self.method = m.group(1)
        self.path = m.group(2)
        self.version = m.group(3)

        for ln in lines[1:]:
            if not ln.strip():
                continue
            if ":" not in ln:
                continue
            k, _, v = ln.partition(":")
            k = re.sub(r"\s+", "-", k.strip())
            v = v.strip()
            if k.lower() == "host":
                self.host = v
            else:
                self.headers[k] = v

        if not self.host:
            raise ValueError("request has no Host header")

        fwd = self.headers.get("X-Forwarded-Proto", "").strip().lower()
        if fwd in ("http", "https"):
            self.scheme = fwd

    def render(self, payload: str) -> dict:
        def sub(s: str) -> str:
            return s.replace(MARKER, payload)

        url = f"{self.scheme}://{self.host}{sub(self.path)}"
        headers = {k: sub(v) for k, v in self.headers.items()}
        body = sub(self.body)

        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

        return {
            "method": self.method,
            "url": url,
            "headers": headers,
            "data": body if body else None,
        }

    def has_marker(self) -> bool:
        return MARKER in self.raw


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

_RETRYABLE_EXC = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
)


def _backoff_delay(attempt: int, base: float, cap: float) -> float:
    # attempt is 0-based
    raw = base * (2 ** attempt)
    raw = min(raw, cap)
    jitter = raw * 0.2 * (random.random() * 2 - 1)   # +/-20%
    return max(0.05, raw + jitter)


class Client:
    def __init__(self, raw: str, cfg: Config,
                 worker_id: int = 0, parallel: int = 1) -> None:
        self.cfg = cfg
        self.worker_id = int(worker_id)
        self.parallel = max(1, int(parallel))
        self.req = RawRequest(raw)
        self.session = requests.Session()
        self.session.verify = False
        if cfg.user_agent:
            self.session.headers["User-Agent"] = cfg.user_agent

        host = self.req.host
        if not cfg.is_target_allowed(host):
            raise PermissionDenied(
                f"target {host!r} is not on the allowlist. "
                f"Pass --i-have-permission if you have written authorization."
            )

    @classmethod
    def from_raw(cls, raw: str, timeout: int = 30,
                 debug: bool = False) -> "Client":
        """Backwards-compatible shim for old Client(raw) calls."""
        cfg = Config(
            campaign_dir=Path("."),
            timeout=timeout,
            debug=debug,
            permission_granted=True,   # legacy callers were pre-allowlist
        )
        return cls(raw, cfg, worker_id=0, parallel=1)

    # -- low level -------------------------------------------------------

    def _send_kwargs(self, method: str, url: str, headers: dict,
                     data) -> dict:
        kw = dict(
            headers=headers,
            allow_redirects=False,
            timeout=self.cfg.timeout,
        )
        if method.upper() not in ("GET", "HEAD"):
            kw["data"] = data
        return kw

    def _send_with_retry(self, method: str, url: str, headers: dict,
                         data) -> requests.Response:
        last_exc: Optional[BaseException] = None
        attempts = max(1, self.cfg.retries)
        for attempt in range(attempts):
            _throttle_worker(self.worker_id, self.parallel)
            _count_request()
            try:
                r = self.session.request(
                    method, url,
                    **self._send_kwargs(method, url, headers, data),
                )
            except _RETRYABLE_EXC as e:
                last_exc = e
                if attempt + 1 >= attempts:
                    break
                d = _backoff_delay(attempt, self.cfg.backoff_base,
                                   self.cfg.backoff_cap)
                _dbg(f"[retry] {type(e).__name__}: {e!r}; "
                     f"sleeping {d:.2f}s (attempt {attempt + 1}/{attempts})")
                time.sleep(d)
                continue

            _note_waf_response(status_of(r))
            _note_session(r)
            return r

        raise RetryExhausted(
            f"{attempts} attempts failed for {method} {url}: {last_exc!r}"
        )

    # -- public ----------------------------------------------------------

    def send(self, payload: str) -> requests.Response:
        kw = self.req.render(payload)
        return self._send_with_retry(
            kw["method"], kw["url"], kw["headers"], kw["data"]
        )

    def send_encoded(self, payload: str,
                     safe_keep: str = "-_.~") -> requests.Response:
        enc = quote(payload, safe=safe_keep)
        kw = self.req.render(enc)
        return self._send_with_retry(
            kw["method"], kw["url"], kw["headers"], kw["data"]
        )

    def contains(self, response, needle: str) -> bool:
        return contains_match(body_of(response), needle)

    def status(self, response) -> int:
        return status_of(response)

    def dump(self, response, path, preview: int = 240) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(body_of(response))
        except Exception as e:
            print(f"  !! could not write {path}: {e}")
        txt = body_of(response)
        head = txt[:preview].replace("\n", " ")
        tail = "..." if len(txt) > preview else ""
        print(f"  body: {head}{tail}")
        print(f"  saved: {path}")


def total_requests() -> int:
    with _STATE_LOCK:
        return _STATE["total"]


def reset_counters() -> None:
    with _STATE_LOCK:
        _STATE["total"] = 0
        _STATE["waf_streak"] = 0
        _STATE["waf_slowdowns"] = 0
        _STATE["session_lost"] = False
