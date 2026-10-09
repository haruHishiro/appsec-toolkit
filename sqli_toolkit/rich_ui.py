"""Optional rich-based UI with graceful fallback.

Public API:
    ui = UI(cfg)
    ui.info("...")             # plain message
    ui.ok("...")               # green
    ui.warn("...")             # yellow
    ui.err("...")              # red
    ui.banner("AUTO mode", kv={...})
    ui.section("tables")
    ui.progress(tag, done, total, t0, extra="")
    ui.table(rows, headers)    # for dumps
    ui.rule()                  # horizontal line

Falls back to ASCII print() when rich is not installed.
"""

from __future__ import annotations

import time
from typing import Iterable, Optional


try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeRemainingColumn,
    )
    from rich.text import Text
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


LINE_WIDTH = 68


class UI:
    def __init__(self, cfg=None):
        self.cfg = cfg
        self.quiet = bool(getattr(cfg, "quiet", False)) if cfg else False
        self.use_rich = _HAS_RICH and not self.quiet
        if self.use_rich:
            self.console = Console()
        else:
            self.console = None

    # -- basic messages -------------------------------------------------

    def _print(self, msg: str = "", style: str = "") -> None:
        if self.quiet and style not in ("err", "ok"):
            return
        if self.use_rich:
            self.console.print(msg, style=style or None)
        else:
            print(msg)

    def info(self, msg: str) -> None:
        self._print(msg)

    def ok(self, msg: str) -> None:
        if self.use_rich:
            self.console.print(f"[green]{msg}[/green]")
        else:
            print(f"[OK] {msg}")

    def warn(self, msg: str) -> None:
        if self.use_rich:
            self.console.print(f"[yellow]{msg}[/yellow]")
        else:
            print(f"[!] {msg}")

    def err(self, msg: str) -> None:
        if self.use_rich:
            self.console.print(f"[red]{msg}[/red]")
        else:
            print(f"[ERR] {msg}")

    def rule(self, char: str = "-") -> None:
        if self.use_rich:
            self.console.rule(style="dim")
        else:
            print(char * LINE_WIDTH)

    def banner(self, title: str, kv: Optional[dict] = None) -> None:
        if self.use_rich:
            lines = [title]
            if kv:
                for k, v in kv.items():
                    lines.append(f"[dim]{k}:[/dim] {v}")
            self.console.print(Panel("\n".join(lines), expand=False))
        else:
            print("=" * LINE_WIDTH)
            print(f"  {title}")
            if kv:
                for k, v in kv.items():
                    print(f"  {k:<10} {v}")
            print("=" * LINE_WIDTH)

    def section(self, name: str) -> None:
        if self.use_rich:
            self.console.rule(f"[bold]{name}[/bold]")
        else:
            print()
            print("-" * LINE_WIDTH)
            print(f"  {name}")
            print("-" * LINE_WIDTH)

    # -- progress -------------------------------------------------------

    def progress(self, tag: str, done: int, total: int,
                 t0: float, extra: str = "") -> None:
        if total <= 0:
            return
        elapsed = max(0.001, time.time() - t0)
        if done > 0:
            eta = elapsed / done * (total - done)
            eta_s = f"~{int(eta)}s left"
        else:
            eta_s = "..."
        if self.use_rich:
            width = 24
            frac = min(1.0, done / float(total))
            filled = int(width * frac)
            bar = "█" * filled + "░" * (width - filled)
            self.console.print(
                f"  [cyan]{tag:<12}[/cyan] "
                f"[bold]{done:>3}/{total:<3}[/bold] "
                f"[green]{bar}[/green] {eta_s}  {extra}"
            )
        else:
            width = 20
            frac = min(1.0, done / float(total))
            filled = int(width * frac)
            bar = "#" * filled + ">" + " " * max(0, width - filled - 1)
            line = f"  [{tag:12}] {done:>3}/{total:<3} [{bar}] {eta_s}"
            if extra:
                line += f"  {extra}"
            print(line, flush=True)

    # -- table ----------------------------------------------------------

    def table(self, rows: Iterable[Iterable], headers: Optional[list] = None,
              title: str = "") -> None:
        rows = list(rows)
        if not rows:
            self.info("  (empty)")
            return
        if self.use_rich:
            t = Table(title=title or None, show_header=bool(headers))
            if headers:
                for h in headers:
                    t.add_column(str(h))
            for r in rows:
                t.add_row(*[str(c) for c in r])
            self.console.print(t)
        else:
            if headers:
                print("  " + " | ".join(str(h) for h in headers))
                print("  " + "-+-".join("-" * len(str(h)) for h in headers))
            for r in rows:
                print("  " + " | ".join(str(c) for c in r))


def has_rich() -> bool:
    return _HAS_RICH
