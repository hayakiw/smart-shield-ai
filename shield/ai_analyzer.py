from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import deque
from pathlib import Path

from .ai_provider import AIProvider, make_provider
from .banner import Banner
from .config import AIConfig, ShieldConfig, is_bannable_ip, is_whitelisted
from .recidive import resolve_ban_seconds
from .store import Store

log = logging.getLogger("shield.ai")

SYSTEM_PROMPT = """\
あなたは熟練の SOC アナリストです。与えられた複数のサーバログ抜粋を読み、
明確に悪意ある (またはほぼ確実に悪意ある) IP アドレスを特定してください。

判定の方針:
- 同一 IP からの短時間の認証失敗、ディレクトリトラバーサル、既知の
  脆弱性スキャナのシグネチャ、credential stuffing、典型的な web shell
  探索 (/.env, /wp-admin, /phpmyadmin, /.git/) などは強い悪意の兆候。
- 単発の 401/403、ヘルスチェック、CDN/モニタリングサービスは無害。
- プライベート IP (10/8, 172.16/12, 192.168/16, 127/8, ::1) は出力しない。
- 確証がないものは出さない (False positive は重大なコスト)。

出力フォーマットは厳密に以下の JSON のみ。前後に文章を付けないこと:
{
  "blocks": [
    {
      "ip": "1.2.3.4",
      "reason": "短い日本語の説明 (最大 100 文字)",
      "confidence": 0.0-1.0,
      "evidence_lines": 3
    }
  ]
}

blocks が空でも JSON オブジェクトを返してください。
"""

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


class AIAnalyzer:
    def __init__(
        self,
        cfg: AIConfig,
        shield_cfg: ShieldConfig,
        store: Store,
        banner: Banner,
    ):
        self.cfg = cfg
        self.shield_cfg = shield_cfg
        self.store = store
        self.banner = banner
        self.provider: AIProvider | None = None
        # path -> deque of (timestamp, line)
        self._buffers: dict[str, deque[tuple[int, str]]] = {
            p: deque() for p in cfg.sources
        }

    def ingest(self, path: str, line: str) -> None:
        buf = self._buffers.get(path)
        if buf is None:
            buf = deque()
            self._buffers[path] = buf
        now = int(time.time())
        buf.append((now, line))
        # cheap GC: drop > lookback*4 to keep memory bounded
        horizon = now - self.cfg.lookback_seconds * 4
        while buf and buf[0][0] < horizon:
            buf.popleft()

    async def run_forever(self) -> None:
        if not self.cfg.enabled:
            log.info("AI analyzer disabled")
            return
        try:
            self.provider = make_provider(self.cfg.provider, self.cfg.model)
        except (RuntimeError, ValueError, ImportError) as e:
            # API キー未設定 / 未知の provider / SDK 未インストール: AI だけ無効化
            log.error("AI analyzer disabled: %s", e)
            return
        log.info(
            "AI analyzer started: provider=%s model=%s interval=%ds lookback=%ds",
            self.provider.name, self.cfg.model,
            self.cfg.interval_seconds, self.cfg.lookback_seconds,
        )
        while True:
            try:
                await self._tick()
            except Exception:
                log.exception("AI analyzer tick failed")
            await asyncio.sleep(self.cfg.interval_seconds)

    def _gather_recent(self) -> str:
        cutoff = int(time.time()) - self.cfg.lookback_seconds
        chunks: list[str] = []
        for path, buf in self._buffers.items():
            recent = [line for ts, line in buf if ts >= cutoff]
            if not recent:
                continue
            label = Path(path).name
            chunks.append(f"===== {label} =====\n" + "\n".join(recent))
        joined = "\n\n".join(chunks)
        if len(joined) > self.cfg.max_log_chars:
            # 末尾を残してトリム後、先頭が行の途中になりがちなので最初の
            # 改行までは捨てて完全な行から始める
            joined = joined[-self.cfg.max_log_chars :]
            nl = joined.find("\n")
            if nl >= 0:
                joined = joined[nl + 1 :]
        return joined

    async def _tick(self) -> None:
        assert self.provider is not None
        snippet = self._gather_recent()
        if not snippet.strip():
            log.debug("no recent log lines to analyze")
            return

        log.info(
            "AI tick (%s): analyzing %d chars of logs",
            self.provider.name, len(snippet),
        )
        text = await self.provider.analyze(
            SYSTEM_PROMPT,
            f"以下のログを分析してください:\n\n{snippet}",
        )
        parsed = self._parse_response(text)
        if parsed is None:
            log.warning("AI returned non-JSON; skipping. raw=%r", text[:300])
            return

        blocks = parsed.get("blocks") or []
        self.store.log_event(
            "ai-tick",
            detail=f"provider={self.provider.name}; analyzed={len(snippet)}chars; "
                   f"candidates={len(blocks)}",
        )

        for entry in blocks:
            await self._maybe_ban(entry)

    @staticmethod
    def _parse_response(text: str) -> dict | None:
        text = text.strip()
        # strip fenced code blocks if present
        if text.startswith("```"):
            text = text.strip("`")
            # removeprefix を使う (lstrip("json") は文字集合なので "sonjs..." を
            # 全部食ってしまう誤用)
            text = text.removeprefix("json").lstrip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        m = _JSON_RE.search(text)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None

    async def _maybe_ban(self, entry: dict) -> None:
        ip = str(entry.get("ip", "")).strip()
        reason = str(entry.get("reason", "")).strip() or "AI flagged"
        try:
            confidence = float(entry.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0

        if not ip:
            return
        # 安いチェックから順に弾く: 形式 → confidence → whitelist → DB。
        # LLM が CIDR・ホスト名・マルチキャスト・引数風文字列など、
        # ban する意味のないものを返したら捨てる。firewall コマンドや
        # DB に流す前のガード。
        if not is_bannable_ip(ip):
            log.warning("AI returned non-bannable value, ignored: %r", ip)
            return
        if confidence < self.cfg.min_confidence:
            log.info(
                "AI flagged ip=%s confidence=%.2f < %.2f — skipped",
                ip, confidence, self.cfg.min_confidence,
            )
            return
        if is_whitelisted(ip, self.shield_cfg.global_.whitelist):
            log.info("AI flagged whitelisted ip %s — ignored", ip)
            return
        if self.store.get_active_ban(ip):
            return

        effective_seconds, esc_note = resolve_ban_seconds(
            self.shield_cfg.global_.recidive,
            self.store,
            ip,
            self.cfg.ban_seconds,
        )
        if esc_note:
            reason = f"{reason} | {esc_note}"

        rec = self.store.add_ban(
            ip=ip,
            jail="ai",
            reason=reason,
            source="ai",
            ban_seconds=effective_seconds,
            confidence=confidence,
        )
        # block が CancelledError や想定外例外で抜けても、finally で必ず
        # ロールバック判定が走るようにする (DB と firewall の整合性維持)。
        block_ok = False
        try:
            block_ok = await self.banner.block(ip)
        finally:
            if not block_ok:
                self.store.deactivate_ban(ip, banned_at=rec.banned_at)
                self.store.log_event("ai-ban-failed", ip=ip, detail=reason)
        kind = "ai-ban" if effective_seconds > 0 else "ai-ban-perm"
        if block_ok:
            tag = "AI-PERMA-BAN" if effective_seconds <= 0 else "AI-BAN"
            log.warning("%s ip=%s confidence=%.2f reason=%s", tag, ip, confidence, reason)
            self.store.log_event(kind, ip=ip, detail=f"conf={confidence:.2f}; {reason}")
        else:
            log.error("AI ban command failed for ip=%s; rolled back DB record", ip)
