from pathlib import Path

from shield.config import RecidiveConfig
from shield.recidive import resolve_ban_seconds
from shield.store import Store


def test_disabled_returns_requested(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    cfg = RecidiveConfig(enabled=False, lookback_seconds=86400, max_bans=3)
    secs, note = resolve_ban_seconds(cfg, s, "1.2.3.4", 3600)
    assert secs == 3600 and note is None


def test_below_threshold_no_escalation(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    s.log_event("ban", ip="1.2.3.4")
    cfg = RecidiveConfig(enabled=True, lookback_seconds=86400, max_bans=3)
    secs, note = resolve_ban_seconds(cfg, s, "1.2.3.4", 3600)
    # 1 件しか履歴がない → 次は 2 回目なので昇格しない (max_bans=3)
    assert secs == 3600 and note is None


def test_escalation_to_permanent(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    s.log_event("ban", ip="1.2.3.4")
    s.log_event("ai-ban", ip="1.2.3.4")
    cfg = RecidiveConfig(enabled=True, lookback_seconds=86400, max_bans=3)
    secs, note = resolve_ban_seconds(cfg, s, "1.2.3.4", 3600)
    # 既に 2 件 → これから 3 回目 → 昇格
    assert secs == 0
    assert note and "permanent" in note


def test_already_permanent_request_is_kept(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    cfg = RecidiveConfig(enabled=True, lookback_seconds=86400, max_bans=3)
    secs, note = resolve_ban_seconds(cfg, s, "1.2.3.4", 0)
    assert secs == 0 and note is None
