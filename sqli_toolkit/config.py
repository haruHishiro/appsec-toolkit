"""Central configuration object for sqli_toolkit.

Replaces the old module-level globals (DEBUG / FAST / PARALLEL / SETTINGS).
All entry points take a single Config instance so the toolkit can be used
as a library without side effects.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Hard ceiling on requests-per-second regardless of settings.json.
# Keeps a runaway loop from hammering a target.
DEFAULT_MAX_RPS = 10.0


def _is_allowed_host(host: str) -> bool:
    h = host.split(":")[0].strip("[]").lower()
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    if fnmatch.fnmatch(h, "*.web-security-academy.net"):
        return True
    return False


@dataclass
class Config:
    """Everything the toolkit needs to run.

    Only `campaign_dir` is required. Everything else has a sane default.
    """

    # --- target ---------------------------------------------------------
    campaign_dir: Path = Path(".")
    permission_granted: bool = False

    # --- channel --------------------------------------------------------
    channel: str = "auto"        # auto | error | boolean | time | union | oob
    delay: int = 5               # seconds, for time-based channel
    fast: bool = False           # lo=32 instead of 0 for printable ASCII
    non_interactive: bool = False
    scan_all: bool = False

    # --- http -----------------------------------------------------------
    timeout: int = 30
    max_rps: float = DEFAULT_MAX_RPS
    max_total: int = 0           # 0 = unlimited
    no_throttle: bool = False
    retries: int = 3
    backoff_base: float = 1.0
    backoff_cap: float = 8.0
    user_agent: Optional[str] = None

    # --- extraction -----------------------------------------------------
    parallel: int = 1
    tables_max: int = 30
    columns_max: int = 30
    length_hi: int = 200

    # --- oob ------------------------------------------------------------
    oob_domain: Optional[str] = None
    oob_wait: int = 30

    # --- output ---------------------------------------------------------
    debug: bool = False
    quiet: bool = False
    json_out: bool = False
    results_dir: Optional[Path] = None
    debug_dir: Optional[Path] = None

    # --- derived (not part of __init__) ---------------------------------
    throttle_rps: float = field(init=False, default=0.0)

    def __post_init__(self) -> None:
        self.campaign_dir = Path(self.campaign_dir).expanduser().resolve()
        if self.results_dir is None:
            self.results_dir = self.campaign_dir / "results"
        if self.debug_dir is None:
            self.debug_dir = self.campaign_dir / "debug"
        self.results_dir = Path(self.results_dir).expanduser().resolve()
        self.debug_dir = Path(self.debug_dir).expanduser().resolve()

        # Fields like parallel/max_rps/delay/timeout may be None here:
        # helper.build_config_from_args deliberately passes None for
        # flags the user did not set, so that merge_settings() can fill
        # them from settings.json.  Numeric validation happens in
        # apply_safe_defaults(), called after merge_settings().
        self._recompute_throttle()

    def _recompute_throttle(self) -> None:
        if self.no_throttle:
            self.throttle_rps = 0.0
            return
        try:
            rps = float(self.max_rps)
        except (TypeError, ValueError):
            self.throttle_rps = 0.0
            return
        self.throttle_rps = max(0.0, min(rps, DEFAULT_MAX_RPS))

    # -- helpers ---------------------------------------------------------

    def is_target_allowed(self, host: str) -> bool:
        if self.permission_granted:
            return True
        return _is_allowed_host(host)

    def assert_target_allowed(self, host: str) -> None:
        from .exceptions import PermissionDenied
        if not self.is_target_allowed(host):
            raise PermissionDenied(
                f"target {host!r} is not on the allowlist. "
                f"Pass --i-have-permission if you have written authorization."
            )

    def to_dict(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if isinstance(v, Path):
                d[k] = str(v)
            else:
                d[k] = v
        return d

    # -- settings.json merge ----------------------------------------

    SETTINGS_KEYS = (
        "rps", "parallel", "delay", "timeout",
        "max_total", "retries", "no_throttle",
        "oob_domain", "oob_wait",
    )

    def merge_settings(self, settings: dict,
                       explicit: set[str] | None = None) -> None:
        """Apply settings.json on top of defaults, but only for
        fields the user did NOT set on the CLI.

        Priority: CLI (explicit) > settings.json > defaults.
        """
        if not settings:
            return
        explicit = explicit or set()
        for key in self.SETTINGS_KEYS:
            if key in explicit:
                continue
            if key not in settings:
                continue
            val = settings[key]
            try:
                if key == "rps":
                    self.max_rps = float(val)
                elif key == "parallel":
                    self.parallel = max(1, int(val))
                elif key == "delay":
                    self.delay = int(val)
                elif key == "timeout":
                    self.timeout = int(val)
                elif key == "max_total":
                    self.max_total = int(val)
                elif key == "retries":
                    self.retries = int(val)
                elif key == "no_throttle":
                    self.no_throttle = bool(val)
                elif key == "oob_domain":
                    self.oob_domain = str(val)
                elif key == "oob_wait":
                    self.oob_wait = int(val)
            except (TypeError, ValueError):
                # ignore malformed entries; keep the default
                continue
        # throttle_rps was computed in __post_init__; recompute now
        self._recompute_throttle()

    def apply_safe_defaults(self) -> None:
        """Fill any None values with sane defaults.
        Call this after merge_settings.
        """
        if self.delay is None:
            self.delay = 5
        if self.timeout is None:
            self.timeout = 30
        if self.parallel is None:
            self.parallel = 1
        try:
            self.parallel = int(self.parallel)
            if self.parallel < 1:
                self.parallel = 1
        except (TypeError, ValueError):
            self.parallel = 1
        if self.max_rps is None:
            self.max_rps = DEFAULT_MAX_RPS
        try:
            self.max_rps = float(self.max_rps)
        except (TypeError, ValueError):
            self.max_rps = DEFAULT_MAX_RPS
        if self.retries is None:
            self.retries = 3
        try:
            self.retries = int(self.retries)
            if self.retries < 1:
                self.retries = 1
        except (TypeError, ValueError):
            self.retries = 3
        try:
            self.delay = int(self.delay)
        except (TypeError, ValueError):
            self.delay = 5
        try:
            self.timeout = int(self.timeout)
        except (TypeError, ValueError):
            self.timeout = 30
        if self.max_total is None:
            self.max_total = 0
        try:
            self.max_total = int(self.max_total)
        except (TypeError, ValueError):
            self.max_total = 0
        self._recompute_throttle()


DISCLAIMER = (
    "sqli_toolkit is for legal training only: PortSwigger Web Security "
    "Academy, your own labs, or systems you have written permission to test."
)
