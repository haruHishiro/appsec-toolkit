"""Machine-readable output: single JSON dump + JSONL row writer.

Public API:
    JsonResult(campaign, dialect, technique, ...)
        .add_table(name, columns)
        .add_row(table, row_dict)
        .write(path)

    write_jsonl(path, rows)          # one JSON object per line
    write_tsv(path, columns, rows)   # tab-separated, no header quoting
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class JsonResult:
    campaign: str
    dialect: str = ""
    technique: str = ""
    prefix: str = ""
    suffix: str = ""
    marker: str = ""
    target: str = ""
    tables: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )
    finished_at: Optional[str] = None

    def add_table(self, name: str, columns: Optional[list] = None) -> None:
        t = self.tables.setdefault(name, {"columns": [], "rows": []})
        if columns:
            t["columns"] = list(columns)

    def add_row(self, table: str, row: dict) -> None:
        t = self.tables.setdefault(table, {"columns": [], "rows": []})
        t["rows"].append(dict(row))
        for k in row:
            if k not in t["columns"]:
                t["columns"].append(k)

    def error(self, msg: str) -> None:
        self.errors.append({
            "at": datetime.now().isoformat(timespec="seconds"),
            "msg": str(msg),
        })

    def finish(self) -> None:
        self.finished_at = datetime.now().isoformat(timespec="seconds")

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["tables"] = {
            k: {"columns": list(v["columns"]), "rows": list(v["rows"])}
            for k, v in self.tables.items()
        }
        return d

    def write(self, path: Path) -> None:
        self.finish()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def write_jsonl(path: Path, rows: list) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_tsv(path: Path, columns: list, rows: list) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        if columns:
            f.write("\t".join(str(c) for c in columns) + "\n")
        for r in rows:
            if isinstance(r, dict):
                f.write("\t".join(
                    _tsv_cell(r.get(c, "")) for c in columns
                ) + "\n")
            else:
                f.write("\t".join(_tsv_cell(c) for c in r) + "\n")


def _tsv_cell(v: Any) -> str:
    if v is None:
        return ""
    s = str(v)
    return s.replace("\t", "\\t").replace("\n", "\\n").replace("\r", "")
