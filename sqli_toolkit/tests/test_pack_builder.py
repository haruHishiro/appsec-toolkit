"""Tests for pack_builder."""

import pytest

from ..pack_builder import (
    NUMERIC_TYPES,
    NumType,
    pack_ascii_7bit,
    pack_ascii_8bit,
    sql_pack_expr,
    unpack_ascii_7bit,
    unpack_ascii_8bit,
)


class TestNumType:
    def test_int_limits(self):
        t = NumType("int")
        assert t.bytes == 4
        assert t.bits == 32
        assert t.max_chars_8bit == 4
        assert t.max_chars_7bit == 4

    def test_long_limits(self):
        t = NumType("long")
        assert t.bytes == 8
        assert t.bits == 64
        assert t.max_chars_8bit == 8
        assert t.max_chars_7bit == 9

    def test_byte_limits(self):
        t = NumType("byte")
        assert t.max_chars_8bit == 1
        assert t.max_chars_7bit == 1

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError):
            NumType("float128")

    def test_case_insensitive(self):
        assert NumType("INT").name == "int"
        assert NumType("LoNg").name == "long"


class TestPack7Bit:
    # pack_ascii_7bit("user") = 117<<21 | 115<<14 | 101<<7 | 114
    EXPECTED_USER = 247263986

    def test_known_value(self):
        assert pack_ascii_7bit("user") == self.EXPECTED_USER

    def test_roundtrip_short_strings(self):
        for s in ("a", "ab", "abc", "abcd", "user", "admin", "pwd"):
            n = pack_ascii_7bit(s)
            assert unpack_ascii_7bit(n, len(s)) == s

    def test_roundtrip_all_printable(self):
        s = "".join(chr(c) for c in range(32, 127))
        for i in range(1, len(s) + 1):
            chunk = s[:i]
            n = pack_ascii_7bit(chunk)
            assert unpack_ascii_7bit(n, i) == chunk

    def test_4_chars_fit_in_signed_int(self):
        # 7-bit packing of 4 max-ascii chars uses 28 bits, fits in INT32
        t = NumType("int")
        n = pack_ascii_7bit("~~~~")
        assert n <= t.signed_max

    def test_8_chars_fit_in_signed_long(self):
        t = NumType("long")
        n = pack_ascii_7bit("~~~~~~~~")
        assert n <= t.signed_max


class TestPack8Bit:
    # pack_ascii_8bit("user") = 117<<24 | 115<<16 | 101<<8 | 114
    EXPECTED_USER = 1970496882

    def test_known_value(self):
        assert pack_ascii_8bit("user") == self.EXPECTED_USER

    def test_roundtrip(self):
        for s in ("a", "ab", "abcd", "user", "admin"):
            n = pack_ascii_8bit(s)
            assert unpack_ascii_8bit(n, len(s)) == s

    def test_4_printable_chars_fit_in_signed_int(self):
        # Printable ASCII 0x20..0x7e packed 8-bit into 32 bits:
        # max per byte is 0x7e, total 0x7e7e7e7e = 2122219134 < INT32_MAX
        t = NumType("int")
        n = pack_ascii_8bit("~~~~")
        assert n < t.signed_max

    def test_5_chars_do_not_fit_in_int(self):
        # 5 chars * 8 bits = 40 bits > 32
        t = NumType("int")
        with pytest.raises((ValueError, AssertionError)):
            n = pack_ascii_8bit("~~~~~")
            assert n <= t.signed_max


class TestSqlPackExpr:
    def test_contains_ascii_and_substr(self):
        src = "(SELECT table_name FROM information_schema.tables LIMIT 1)"
        expr = sql_pack_expr(src, 1, 4, bits=7, dialect="mysql")
        assert "ASCII" in expr
        assert "SUBSTRING" in expr
        assert "&127" in expr

    def test_postgres_dialect(self):
        src = "(SELECT 1)"
        expr = sql_pack_expr(src, 1, 2, bits=7, dialect="postgres")
        assert "SUBSTRING" in expr
        assert "ASCII" in expr

    def test_oracle_uses_substr(self):
        expr = sql_pack_expr("(SELECT 1)", 1, 2, bits=7, dialect="oracle")
        assert "SUBSTR(" in expr
        assert "SUBSTRING(" not in expr

    def test_sqlite_uses_unicode(self):
        expr = sql_pack_expr("(SELECT 1)", 1, 2, bits=7, dialect="sqlite")
        assert "UNICODE" in expr
        assert "ASCII" not in expr

    def test_8bit_no_mask(self):
        expr = sql_pack_expr("(SELECT 1)", 1, 2, bits=8, dialect="mysql")
        assert "&127" not in expr

    def test_7bit_has_mask(self):
        expr = sql_pack_expr("(SELECT 1)", 1, 2, bits=7, dialect="mysql")
        assert "&127" in expr


class TestOverflowValidation:
    def test_pack_8bit_overflow_int(self):
        t = NumType("int")
        with pytest.raises(ValueError, match="exceeds"):
            pack_ascii_8bit("~~~~~", num_type=t)

    def test_pack_8bit_ok_int(self):
        t = NumType("int")
        n = pack_ascii_8bit("~~~~", num_type=t)
        assert n == 2122219134

    def test_pack_7bit_ok_int(self):
        t = NumType("int")
        n = pack_ascii_7bit("~~~~", num_type=t)
        assert n <= t.max_value

    def test_pack_8bit_overflow_byte(self):
        t = NumType("byte")
        with pytest.raises(ValueError, match="exceeds"):
            pack_ascii_8bit("ab", num_type=t)

    def test_pack_no_num_type_skips_check(self):
        # without num_type there is no validation
        n = pack_ascii_8bit("~~~~~")
        assert n > 0

    def test_sql_pack_expr_n_chars_too_many(self):
        t = NumType("int")
        with pytest.raises(ValueError, match="cannot pack"):
            sql_pack_expr("(SELECT 1)", 1, 5, bits=8, num_type=t)

    def test_sql_pack_expr_n_chars_ok(self):
        t = NumType("int")
        expr = sql_pack_expr("(SELECT 1)", 1, 4, bits=8, num_type=t)
        assert "ASCII" in expr

    def test_sql_pack_expr_invalid_bits(self):
        with pytest.raises(ValueError, match="bits must be"):
            sql_pack_expr("(SELECT 1)", 1, 2, bits=9)

    def test_num_type_max_value_property(self):
        assert NumType("int").max_value == 2147483647
        assert NumType("uint").max_value == 4294967295
        assert NumType("byte").max_value == 127
        assert NumType("ubyte").max_value == 255

    def test_num_type_is_signed(self):
        assert NumType("int").is_signed is True
        assert NumType("uint").is_signed is False
