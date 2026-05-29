from __future__ import annotations

import time

from .config import RecidiveConfig
from .store import Store


def resolve_ban_seconds(
    cfg: RecidiveConfig,
    store: Store,
    ip: str,
    requested_seconds: int,
) -> tuple[int, str | None]:
    """再犯ポリシーに照らして実際に使う ban_seconds を決定する。

    Returns:
        (ban_seconds, escalation_note)
        - ban_seconds <= 0 を返したら永久 ban を意味する
        - エスカレーションが発動したら note に説明文を入れる
    """
    if requested_seconds <= 0:
        # 既に永久 ban 要求 (手動 --permanent や ban_seconds: 0 など) はそのまま尊重
        return requested_seconds, None
    if not cfg.enabled:
        return requested_seconds, None

    since = int(time.time()) - cfg.lookback_seconds
    prior_bans = store.count_bans_since(ip, since)
    # この呼び出しは「これから N+1 回目の ban」なので >= max_bans - 1 で昇格
    if prior_bans >= max(1, cfg.max_bans - 1):
        note = (
            f"recidive escalation: {prior_bans + 1} bans in "
            f"{cfg.lookback_seconds}s ≥ max_bans={cfg.max_bans} → permanent"
        )
        return 0, note

    return requested_seconds, None
