"""Tests for the package-level public API."""

import pytest


def test_union_builder_reexport():
    from sqli_toolkit import UnionBuilder
    sql = UnionBuilder(3, [1], {1: ["a", "b"]},
                       dialect="mysql", table="t").build()
    assert "UNION SELECT" in sql


def test_tables_payload_reexport():
    from sqli_toolkit import tables_payload
    sql = tables_payload(3, 1, dialect="mysql")
    assert "information_schema.tables" in sql


def test_columns_payload_reexport():
    from sqli_toolkit import columns_payload
    sql = columns_payload(3, 1, "users", dialect="mysql")
    assert "information_schema.columns" in sql


def test_data_payload_reexport():
    from sqli_toolkit import data_payload
    sql = data_payload(3, [1], {1: ["u", "p"]}, "users", dialect="mysql")
    assert "FROM users" in sql


def test_num_type_reexport():
    from sqli_toolkit import NumType
    t = NumType("int")
    assert t.max_value == 2147483647


def test_pack_unpack_roundtrip_via_public_api():
    from sqli_toolkit import pack_ascii_7bit, unpack_ascii_7bit
    n = pack_ascii_7bit("user")
    assert unpack_ascii_7bit(n, 4) == "user"


def test_pack_8bit_roundtrip_via_public_api():
    from sqli_toolkit import pack_ascii_8bit, unpack_ascii_8bit
    n = pack_ascii_8bit("user")
    assert unpack_ascii_8bit(n, 4) == "user"


def test_sql_pack_expr_reexport():
    from sqli_toolkit import sql_pack_expr
    expr = sql_pack_expr("(SELECT 1)", 1, 2, bits=7, dialect="mysql")
    assert "ASCII" in expr


def test_constants_reexport():
    from sqli_toolkit import NUMERIC_TYPES, DIALECTS, CONCAT_LIMITS
    assert "int" in NUMERIC_TYPES
    assert "mysql" in DIALECTS
    assert CONCAT_LIMITS["oracle"] == 2


def test_dunder_all_matches_public_names():
    import sqli_toolkit
    expected = {
        "UnionBuilder", "tables_payload", "columns_payload", "data_payload",
        "DIALECTS", "CONCAT_LIMITS",
        "NumType", "NUMERIC_TYPES",
        "pack_ascii_7bit", "pack_ascii_8bit",
        "unpack_ascii_7bit", "unpack_ascii_8bit",
        "sql_pack_expr",
        "__version__",
    }
    assert set(sqli_toolkit.__all__) == expected


def test_submodule_import_still_works():
    # backward compatibility: the old import paths must keep working
    from sqli_toolkit.union_builder import UnionBuilder
    from sqli_toolkit.pack_builder import NumType
    assert UnionBuilder is not None
    assert NumType is not None


def test_star_import():
    ns = {}
    exec("from sqli_toolkit import *", ns)
    for name in ("UnionBuilder", "NumType", "pack_ascii_7bit",
                 "sql_pack_expr", "__version__"):
        assert name in ns


def test_version_present():
    import sqli_toolkit
    assert isinstance(sqli_toolkit.__version__, str)
    assert sqli_toolkit.__version__
