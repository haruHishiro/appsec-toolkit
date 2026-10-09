"""Minimal tests for channels and payload builders.

We don't spin up a real HTTP server here — instead we monkey-patch
Client.raw_send to return canned responses.  This is enough to catch
regressions in detection/parsing logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from sqli_toolkit.config import Config
from sqli_toolkit.channels import (
    ALL_CHANNELS, DEFAULT_ORDER, build_channel, parse_channel_list,
)
from sqli_toolkit.channels.union import UnionChannel
from sqli_toolkit.channels.oob import OobChannel


# -- helpers ---------------------------------------------------------------

@dataclass
class FakeResponse:
    status_code: int
    text: str

    @property
    def headers(self):
        return {}


class FakeClient:
    def __init__(self, responses):
        # responses: list of FakeResponse, consumed in order
        self.responses = list(responses)
        self.calls = []

    def send(self, payload):
        self.calls.append(payload)
        if not self.responses:
            return FakeResponse(500, "")
        return self.responses.pop(0)

    def send_encoded(self, payload, safe_keep="-_.~"):
        return self.send(payload)


class FakeProber:
    def __init__(self, client, cfg):
        self.client = client
        self.cfg = cfg
        self.raw_calls = []
        self.technique = "boolean"
        self.prefix = "'"
        self.suffix = "'-- "
        self.dialect = "mysql"
        self.marker = "OK"
        self.error_template = ""
        self.cache = None

    def raw_send(self, payload):
        self.raw_calls.append(payload)
        return self.client.send(payload)

    def probe(self, cond):
        r = self.raw_send(f"{self.prefix} AND ({cond}){self.suffix}")
        return "OK" in r.text


def make_cfg(tmp_path: Path, **kw) -> Config:
    c = Config(campaign_dir=tmp_path, permission_granted=True, **kw)
    c.apply_safe_defaults()
    return c


# -- parse_channel_list ----------------------------------------------------

def test_parse_auto_returns_default_order():
    assert parse_channel_list("auto") == DEFAULT_ORDER


def test_parse_single():
    assert parse_channel_list("union") == ["union"]


def test_parse_list_keeps_order():
    assert parse_channel_list("boolean,union") == ["boolean", "union"]


def test_parse_unknown_dropped():
    assert parse_channel_list("bogus,union,nope") == ["union"]


# -- build_channel ---------------------------------------------------------

def test_build_each_channel(tmp_path):
    cfg = make_cfg(tmp_path)
    client = FakeClient([])
    for name in DEFAULT_ORDER:
        ch = build_channel(name, cfg, client, prober=None)
        assert ch.name == name


# -- UnionChannel detection ------------------------------------------------

def test_union_finds_col_count(tmp_path):
    cfg = make_cfg(tmp_path)
    # ORDER BY 1..3 ok, ORDER BY 4 -> 500
    responses = [
        FakeResponse(200, "ok"),
        FakeResponse(200, "ok"),
        FakeResponse(200, "ok"),
        FakeResponse(500, "error"),
    ]
    client = FakeClient(responses)
    pr = FakeProber(client, cfg)
    ch = UnionChannel(cfg, client, prober=pr)
    ch.set_prefix_suffix(dialect="mysql", prefix="'", suffix="'-- ")
    n = ch._find_cols_order_by()
    assert n == 3


def test_union_finds_string_col(tmp_path):
    cfg = make_cfg(tmp_path)
    # 3 columns; NULL,NULL,NULL -> no marker; NULL,'marker',NULL -> marker
    responses = [
        FakeResponse(200, "empty"),
        FakeResponse(200, "here: xnlL7Mark3r"),
        FakeResponse(200, "empty"),
    ]
    client = FakeClient(responses)
    pr = FakeProber(client, cfg)
    ch = UnionChannel(cfg, client, prober=pr)
    ch.marker = "xnlL7Mark3r"
    col = ch._find_string_col(3)
    assert col == 2


# -- OobChannel refuses without domain -------------------------------------

def test_oob_refuses_without_domain(tmp_path):
    cfg = make_cfg(tmp_path, oob_domain=None)
    client = FakeClient([])
    ch = OobChannel(cfg, client, prober=None)
    assert ch.detect() is None
    with pytest.raises(RuntimeError):
        ch.send_payload("SELECT 1")


def test_oob_payload_built_when_configured(tmp_path):
    cfg = make_cfg(tmp_path, oob_domain="collab.example")
    client = FakeClient([FakeResponse(200, "")])
    pr = FakeProber(client, cfg)
    ch = OobChannel(cfg, client, prober=pr)
    ch.configure("mysql", "'", "'-- ", "collab.example")
    sql = ch.send_payload("SELECT 1")
    assert "collab.example" in sql
    assert "LOAD_FILE" in sql


# -- PackBuilder regression (already tested elsewhere) ---------------------

def test_pack_roundtrip():
    from sqli_toolkit.pack_builder import pack_ascii_7bit, unpack_ascii_7bit
    n = pack_ascii_7bit("user")
    assert unpack_ascii_7bit(n, 4) == "user"
