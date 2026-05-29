import time
from pathlib import Path

from shield.store import Store


def test_attempts_and_window(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    s.record_attempt("sshd", "1.2.3.4", "line1", ts=1000)
    s.record_attempt("sshd", "1.2.3.4", "line2", ts=1010)
    s.record_attempt("sshd", "1.2.3.4", "line3", ts=1020)
    assert s.count_recent_attempts("sshd", "1.2.3.4", 1005) == 2
    assert s.count_recent_attempts("sshd", "1.2.3.4", 0) == 3
    assert s.count_recent_attempts("sshd", "5.5.5.5", 0) == 0


def test_ban_lifecycle(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    rec = s.add_ban("1.2.3.4", "sshd", "5 fails", "jail", ban_seconds=60)
    assert s.get_active_ban("1.2.3.4") is not None
    assert rec.expires_at - rec.banned_at == 60

    s.deactivate_ban("1.2.3.4")
    assert s.get_active_ban("1.2.3.4") is None


def test_list_expired(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    s.add_ban("1.1.1.1", "sshd", "x", "jail", ban_seconds=1)
    time.sleep(1.2)
    expired = s.list_expired(int(time.time()))
    assert any(b.ip == "1.1.1.1" for b in expired)


def test_file_position_roundtrip(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    assert s.get_file_position("/var/log/x") == (0, None)
    s.set_file_position("/var/log/x", 1234, "ino:42")
    assert s.get_file_position("/var/log/x") == (1234, "ino:42")


def test_permanent_ban_excluded_from_expired(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    s.add_ban("9.9.9.9", "manual", "perma", "manual", ban_seconds=0)
    rec = s.get_active_ban("9.9.9.9")
    assert rec is not None and rec.expires_at == 0

    # 遥か未来でも永久 ban は expired にならない
    assert s.list_expired(2_000_000_000) == [] or all(
        b.ip != "9.9.9.9" for b in s.list_expired(2_000_000_000)
    )

    # unban は手動でのみ可能
    s.deactivate_ban("9.9.9.9")
    assert s.get_active_ban("9.9.9.9") is None


def test_ban_seconds_zero_means_permanent(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    rec = s.add_ban("1.2.3.4", "sshd", "x", "jail", ban_seconds=0)
    assert rec.expires_at == 0
    rec2 = s.add_ban("1.2.3.5", "sshd", "x", "jail", ban_seconds=-1)
    assert rec2.expires_at == 0


def test_count_bans_since_uses_events(tmp_path: Path):
    s = Store(tmp_path / "s.db")
    s.log_event("ban", ip="2.2.2.2", detail="first")
    s.log_event("ai-ban", ip="2.2.2.2", detail="second")
    s.log_event("ban-manual", ip="2.2.2.2", detail="third")
    s.log_event("unban", ip="2.2.2.2", detail="should not count")
    assert s.count_bans_since("2.2.2.2", 0) == 3
    assert s.count_bans_since("9.9.9.9", 0) == 0
