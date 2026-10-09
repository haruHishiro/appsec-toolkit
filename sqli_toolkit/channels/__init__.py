"""Channel registry and discovery.

Public API:
    Channel, ChannelInfo, ErrorChannel, BooleanChannel, TimeChannel,
    UnionChannel, OobChannel
    discover_channels(cfg, client, prober) -> list[ChannelInfo]

The discovery order follows the priority list from Config.channel:
    "auto"          -> error, boolean, time, union, oob
    "error,union"   -> those two, in that order
    "union"         -> only union
"""

from __future__ import annotations

from typing import Iterable

from .base import Channel, ChannelInfo
from .error import ErrorChannel
from .boolean import BooleanChannel
from .time import TimeChannel
from .union import UnionChannel
from .oob import OobChannel


ALL_CHANNELS = {
    "error": ErrorChannel,
    "boolean": BooleanChannel,
    "time": TimeChannel,
    "union": UnionChannel,
    "oob": OobChannel,
}


DEFAULT_ORDER = ["error", "boolean", "time", "union", "oob"]


def parse_channel_list(spec: str) -> list[str]:
    """Parse a CLI --channel spec into a list of channel names.

    Accepts 'auto', 'error', 'error,boolean', 'error, boolean, union'.
    Unknown names are silently dropped.
    """
    if not spec or spec.strip().lower() == "auto":
        return list(DEFAULT_ORDER)
    out = []
    for name in spec.split(","):
        name = name.strip().lower()
        if name in ALL_CHANNELS and name not in out:
            out.append(name)
    return out or list(DEFAULT_ORDER)


def build_channel(name: str, cfg, client, prober=None) -> Channel:
    cls = ALL_CHANNELS.get(name)
    if cls is None:
        raise ValueError(f"unknown channel: {name!r}")
    return cls(cfg, client, prober=prober)


__all__ = [
    "Channel", "ChannelInfo",
    "ErrorChannel", "BooleanChannel", "TimeChannel",
    "UnionChannel", "OobChannel",
    "ALL_CHANNELS", "DEFAULT_ORDER",
    "parse_channel_list", "build_channel",
]
