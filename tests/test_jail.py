from __future__ import annotations

import asyncio
import ipaddress
from pathlib import Path

import pytest

from shield.banner import Banner
from shield.config import (
    AIConfig,
    FilterConfig,
    GlobalConfig,
    JailConfig,
    RecidiveConfig,
    ShieldConfig,
)
from shield.filters import Filter
from shield.jail import Jail
from shield.store import Store


def _make_cfg(tmp_path: Path) -> ShieldConfig:
    g = GlobalConfig(
        state_db=tmp_path / "s.db",
        log_level="WARNING",
        dry_run=True,
        default_ban_seconds=600,
        whitelist=[ipaddress.ip_network("127.0.0.1/32")],
        recidive=RecidiveConfig(enabled=False, lookback_seconds=86400, max_bans=3),
    )
    fc = FilterConfig(
        name="sshd",
        patterns=[r"Failed password for .* from (?P<ip>\S+) port"],
    )
    jc = JailConfig(
        name="sshd", enabled=True, filter="sshd",
        paths=[], max_retries=3, findtime_seconds=60, ban_seconds=120,
    )
    ai = AIConfig(
        enabled=False, provider="anthropic", model="x",
        interval_seconds=300, lookback_seconds=900,
        max_log_chars=1000, min_confidence=0.5, ban_seconds=600, sources=[],
    )
    return ShieldConfig(global_=g, jails={"sshd": jc}, ai=ai, filters={"sshd": fc})


@pytest.mark.asyncio
async def test_bans_after_threshold(tmp_path: Path):
    cfg = _make_cfg(tmp_path)
    store = Store(cfg.global_.state_db)
    banner = Banner(dry_run=True)
    jail = Jail(cfg.jails["sshd"], Filter(cfg.filters["sshd"]), store, banner, cfg)

    line = "Failed password for root from 203.0.113.7 port 51001 ssh2"
    for _ in range(2):
        await jail.process_line(line)
    assert store.get_active_ban("203.0.113.7") is None

    await jail.process_line(line)  # third strike → ban
    rec = store.get_active_ban("203.0.113.7")
    assert rec is not None
    assert rec.source == "jail"


@pytest.mark.asyncio
async def test_whitelisted_ip_never_banned(tmp_path: Path):
    cfg = _make_cfg(tmp_path)
    store = Store(cfg.global_.state_db)
    banner = Banner(dry_run=True)
    jail = Jail(cfg.jails["sshd"], Filter(cfg.filters["sshd"]), store, banner, cfg)

    line = "Failed password for root from 127.0.0.1 port 51001 ssh2"
    for _ in range(10):
        await jail.process_line(line)
    assert store.get_active_ban("127.0.0.1") is None


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)
