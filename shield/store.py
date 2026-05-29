from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    jail        TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    ts          INTEGER NOT NULL,
    line        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_jail_ip_ts ON attempts(jail, ip, ts);

CREATE TABLE IF NOT EXISTS bans (
    ip          TEXT    PRIMARY KEY,
    jail        TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    source      TEXT    NOT NULL,   -- 'jail' or 'ai'
    confidence  REAL,
    banned_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_bans_active_expires ON bans(active, expires_at);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    kind        TEXT    NOT NULL,
    ip          TEXT,
    detail      TEXT
);
-- count_bans_since() で ip + ts 範囲を頻繁に引くため
CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS file_positions (
    path        TEXT    PRIMARY KEY,
    offset      INTEGER NOT NULL,
    inode       TEXT
);
"""


@dataclass
class BanRecord:
    ip: str
    jail: str
    reason: str
    source: str
    confidence: float | None
    banned_at: int
    expires_at: int
    active: bool


class Store:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # auto_vacuum は最初の CREATE 前に設定する必要がある。既存 DB に対しては
        # 効果がない (フル VACUUM で書き直しが要る) が、新規 DB では有効になる。
        self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        # WAL: writer と reader が衝突しない (外部から sqlite3 で SELECT しても
        # daemon の書き込みをブロックしない)。
        self.conn.execute("PRAGMA journal_mode=WAL")
        # 高頻度の小コミットでも壊れにくく速いバランス。
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def incremental_vacuum(self) -> None:
        """auto_vacuum=INCREMENTAL で free になったページを実 size に還元する。
        auto_vacuum が NONE の DB では no-op。"""
        try:
            self.conn.execute("PRAGMA incremental_vacuum")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

    def close(self) -> None:
        """WAL を main DB に巻き取って (-wal / -shm を縮める) から接続を閉じる。

        WAL モードで稼動した DB を畳む際の作法。checkpoint しないと WAL
        ファイルが残り続けて起動のたびに自動 recovery が走る。"""
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass
        try:
            self.conn.close()
        except sqlite3.OperationalError:
            pass

    # -------- attempts --------
    def record_attempt(self, jail: str, ip: str, line: str, ts: int | None = None) -> None:
        ts = ts or int(time.time())
        self.conn.execute(
            "INSERT INTO attempts(jail, ip, ts, line) VALUES (?,?,?,?)",
            (jail, ip, ts, line),
        )
        self.conn.commit()

    def count_recent_attempts(self, jail: str, ip: str, since_ts: int) -> int:
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE jail=? AND ip=? AND ts>=?",
            (jail, ip, since_ts),
        )
        return int(cur.fetchone()[0])

    def gc_attempts(self, older_than_ts: int) -> int:
        cur = self.conn.execute("DELETE FROM attempts WHERE ts < ?", (older_than_ts,))
        self.conn.commit()
        return cur.rowcount

    def gc_events(self, older_than_ts: int) -> int:
        """recidive 判定の lookback より古い events を刈る。

        count_bans_since が events を集計するため、recidive の lookback_seconds
        より新しい行は必ず残す必要がある。呼び出し側でカットオフを計算する。
        """
        cur = self.conn.execute("DELETE FROM events WHERE ts < ?", (older_than_ts,))
        self.conn.commit()
        return cur.rowcount

    # -------- bans --------
    # NOTE: expires_at = 0 はセンチネルで「永久 ban」を表す
    PERMANENT_EXPIRES = 0

    def add_ban(
        self,
        ip: str,
        jail: str,
        reason: str,
        source: str,
        ban_seconds: int,
        confidence: float | None = None,
    ) -> BanRecord:
        now = int(time.time())
        expires = self.PERMANENT_EXPIRES if ban_seconds <= 0 else now + ban_seconds
        self.conn.execute(
            "INSERT OR REPLACE INTO bans(ip,jail,reason,source,confidence,banned_at,expires_at,active) "
            "VALUES (?,?,?,?,?,?,?,1)",
            (ip, jail, reason, source, confidence, now, expires),
        )
        self.conn.commit()
        return BanRecord(ip, jail, reason, source, confidence, now, expires, True)

    def get_active_ban(self, ip: str) -> BanRecord | None:
        row = self.conn.execute(
            "SELECT * FROM bans WHERE ip=? AND active=1", (ip,)
        ).fetchone()
        return self._row_to_ban(row) if row else None

    def list_expired(self, now_ts: int) -> list[BanRecord]:
        # expires_at > 0 を要求することで永久 ban を除外
        cur = self.conn.execute(
            "SELECT * FROM bans WHERE active=1 AND expires_at > 0 AND expires_at <= ?",
            (now_ts,),
        )
        return [self._row_to_ban(r) for r in cur.fetchall()]

    def list_active(self) -> list[BanRecord]:
        cur = self.conn.execute("SELECT * FROM bans WHERE active=1")
        return [self._row_to_ban(r) for r in cur.fetchall()]

    def deactivate_ban(self, ip: str, banned_at: int | None = None) -> None:
        """ban を active=0 にする。

        banned_at を渡すと「その時点で存在していた ban」だけを無効化する。
        unban_loop が unblock を await している間に、別タスクが同じ IP を
        再 ban (INSERT OR REPLACE で新しい banned_at の行に置換) する
        可能性があり、無条件に active=0 すると新しい ban まで巻き添えで
        消える。これを防ぐためのガード。
        """
        if banned_at is None:
            self.conn.execute("UPDATE bans SET active=0 WHERE ip=?", (ip,))
        else:
            self.conn.execute(
                "UPDATE bans SET active=0 WHERE ip=? AND banned_at=?",
                (ip, banned_at),
            )
        self.conn.commit()

    def count_bans_since(self, ip: str, since_ts: int) -> int:
        """同一 IP が since_ts 以降に何回 ban されたか (再犯判定用)。

        bans テーブルは ip プライマリキーで上書きされるため履歴を残さない。
        events テーブルの kind IN ('ban','ai-ban') を集計する。
        """
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE ip=? AND ts >= ? AND kind IN "
            "('ban','ban-perm','ai-ban','ai-ban-perm','ban-manual')",
            (ip, since_ts),
        )
        return int(cur.fetchone()[0])

    @staticmethod
    def _row_to_ban(row: sqlite3.Row) -> BanRecord:
        return BanRecord(
            ip=row["ip"],
            jail=row["jail"],
            reason=row["reason"],
            source=row["source"],
            confidence=row["confidence"],
            banned_at=row["banned_at"],
            expires_at=row["expires_at"],
            active=bool(row["active"]),
        )

    # -------- events --------
    def log_event(self, kind: str, ip: str | None = None, detail: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO events(ts, kind, ip, detail) VALUES (?,?,?,?)",
            (int(time.time()), kind, ip, detail),
        )
        self.conn.commit()

    # -------- file positions --------
    def get_file_position(self, path: str) -> tuple[int, str | None]:
        row = self.conn.execute(
            "SELECT offset, inode FROM file_positions WHERE path=?", (path,)
        ).fetchone()
        if row is None:
            return 0, None
        return int(row["offset"]), row["inode"]

    def set_file_position(self, path: str, offset: int, inode: str | None) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO file_positions(path, offset, inode) VALUES (?,?,?)",
            (path, offset, inode),
        )
        self.conn.commit()
