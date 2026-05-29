from __future__ import annotations

import logging
import time

from .banner import Banner
from .config import JailConfig, ShieldConfig, is_whitelisted
from .filters import Filter
from .recidive import resolve_ban_seconds
from .store import Store

log = logging.getLogger("shield.jail")


class Jail:
    # 永久 ban 中の継続攻撃を events に記録する間隔 (秒)。毎ヒット記録すると
    # events が肥大化するので throttle する。
    _PERMA_HIT_LOG_INTERVAL = 300

    def __init__(
        self,
        cfg: JailConfig,
        filter_: Filter,
        store: Store,
        banner: Banner,
        shield_cfg: ShieldConfig,
    ):
        self.cfg = cfg
        self.filter = filter_
        self.store = store
        self.banner = banner
        self.shield_cfg = shield_cfg
        # ip -> 最後に perma-ban-hit を記録した unix 秒
        self._last_perma_hit_log: dict[str, int] = {}

    async def process_line(self, line: str) -> None:
        m = self.filter.match(line)
        if not m:
            return

        ip = m.ip
        if is_whitelisted(ip, self.shield_cfg.global_.whitelist):
            log.debug("[%s] whitelisted ip %s — ignored", self.cfg.name, ip)
            return

        now = int(time.time())
        existing = self.store.get_active_ban(ip)
        if existing and existing.expires_at == 0:
            # 永久 ban 中: 再 ban (= add_ban による格下げ) はしないが、
            # 攻撃継続の事実は記録する。
            self.store.record_attempt(self.cfg.name, ip, line)
            # オペレータ向けに events にも throttle 付きで残す ("永久 ban して
            # いるはずなのにまだ叩いてきている" と気付けるように)。
            last = self._last_perma_hit_log.get(ip, 0)
            if now - last >= self._PERMA_HIT_LOG_INTERVAL:
                self._last_perma_hit_log[ip] = now
                self.store.log_event(
                    "perma-ban-hit",
                    ip=ip,
                    detail=f"jail={self.cfg.name}",
                )
            return
        if existing and existing.expires_at > now:
            # 一時 ban 中: そもそも何もしない
            return

        self.store.record_attempt(self.cfg.name, ip, line)
        since = now - self.cfg.findtime_seconds
        count = self.store.count_recent_attempts(self.cfg.name, ip, since)

        log.debug("[%s] hit ip=%s count=%d/%d", self.cfg.name, ip, count, self.cfg.max_retries)

        if count >= self.cfg.max_retries:
            reason = (
                f"{count} failures in {self.cfg.findtime_seconds}s "
                f"(filter={self.filter.name})"
            )
            await self._ban(ip, reason)

    async def _ban(self, ip: str, reason: str) -> None:
        # 並行 jail dedup: bans テーブルを再チェックすることで「process_line で
        # 弾けなかったが、その直後に別 jail が add_ban したケース」を捕捉する。
        # bans の更新は同期 (commit ベース) なので events ベースのチェックより
        # race window が狭く確実。
        existing = self.store.get_active_ban(ip)
        if existing is not None:
            log.debug(
                "[%s] ip=%s already banned by another path — skipping",
                self.cfg.name, ip,
            )
            return

        effective_seconds, esc_note = resolve_ban_seconds(
            self.shield_cfg.global_.recidive,
            self.store,
            ip,
            self.cfg.ban_seconds,
        )
        if esc_note:
            reason = f"{reason} | {esc_note}"
            log.warning("[%s] %s for ip=%s", self.cfg.name, esc_note, ip)

        rec = self.store.add_ban(
            ip=ip,
            jail=self.cfg.name,
            reason=reason,
            source="jail",
            ban_seconds=effective_seconds,
        )
        # add_ban した以上、block の成否に関わらず DB と firewall の整合性を
        # 保つ必要がある。block 中に CancelledError や想定外例外が来ても
        # finally で必ずロールバック判定が走るようにする。
        block_ok = False
        try:
            block_ok = await self.banner.block(ip)
        finally:
            if not block_ok:
                # firewall に rule を入れられなかった (or 失敗) → DB レコードを
                # 取り消して、次の attempt で再度 ban を試行できる状態に戻す。
                # banned_at 指定で並走 ban を巻き添えにしないように消す。
                self.store.deactivate_ban(ip, banned_at=rec.banned_at)
                self.store.log_event("ban-failed", ip=ip, detail=reason)
        kind = "ban" if effective_seconds > 0 else "ban-perm"
        if block_ok:
            tag = "PERMA-BAN" if effective_seconds <= 0 else "BAN"
            log.warning("%s ip=%s jail=%s reason=%s", tag, ip, self.cfg.name, reason)
            self.store.log_event(kind, ip=ip, detail=f"jail={self.cfg.name}; {reason}")
        else:
            log.error("ban command failed for ip=%s; rolled back DB record", ip)
