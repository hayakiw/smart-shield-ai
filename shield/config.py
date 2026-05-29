from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class JailConfig:
    name: str
    enabled: bool
    filter: str
    paths: list[str]
    max_retries: int
    findtime_seconds: int
    ban_seconds: int


@dataclass
class AIConfig:
    enabled: bool
    provider: str          # "anthropic" | "gemini"
    model: str
    interval_seconds: int
    lookback_seconds: int
    max_log_chars: int
    min_confidence: float
    ban_seconds: int
    sources: list[str]


@dataclass
class FilterConfig:
    name: str
    patterns: list[str]
    ignore: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class RecidiveConfig:
    enabled: bool
    lookback_seconds: int
    max_bans: int


@dataclass
class GlobalConfig:
    state_db: Path
    log_level: str
    dry_run: bool
    default_ban_seconds: int
    whitelist: list[ipaddress._BaseNetwork]
    recidive: RecidiveConfig


@dataclass
class ShieldConfig:
    global_: GlobalConfig
    jails: dict[str, JailConfig]
    ai: AIConfig
    filters: dict[str, FilterConfig]


def _parse_whitelist(items: list[str]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for item in items:
        if "/" not in item:
            item = f"{item}/{32 if ':' not in item else 128}"
        nets.append(ipaddress.ip_network(item, strict=False))
    return nets


def load_config(config_path: Path) -> ShieldConfig:
    config_path = Path(config_path)
    with config_path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    g = raw["global"]
    r = g.get("recidive") or {}
    recidive = RecidiveConfig(
        enabled=bool(r.get("enabled", False)),
        lookback_seconds=int(r.get("lookback_seconds", 7 * 24 * 3600)),
        max_bans=int(r.get("max_bans", 3)),
    )
    global_ = GlobalConfig(
        state_db=Path(g["state_db"]),
        log_level=g.get("log_level", "INFO"),
        dry_run=bool(g.get("dry_run", True)),
        default_ban_seconds=int(g.get("default_ban_seconds", 600)),
        whitelist=_parse_whitelist(g.get("whitelist", [])),
        recidive=recidive,
    )

    jails: dict[str, JailConfig] = {}
    for name, body in (raw.get("jails") or {}).items():
        jails[name] = JailConfig(
            name=name,
            enabled=bool(body.get("enabled", True)),
            filter=body["filter"],
            paths=list(body.get("paths", [])),
            max_retries=int(body.get("max_retries", 5)),
            findtime_seconds=int(body.get("findtime_seconds", 600)),
            ban_seconds=int(body.get("ban_seconds", global_.default_ban_seconds)),
        )

    a = raw.get("ai") or {}
    provider = (a.get("provider") or "anthropic").lower()
    # provider 別の妥当なデフォルトモデル
    default_models = {
        "anthropic": "claude-sonnet-4-6",
        "gemini": "gemini-2.5-flash",
    }
    ai = AIConfig(
        enabled=bool(a.get("enabled", False)),
        provider=provider,
        model=a.get("model") or default_models.get(provider, "claude-sonnet-4-6"),
        interval_seconds=int(a.get("interval_seconds", 300)),
        lookback_seconds=int(a.get("lookback_seconds", 900)),
        max_log_chars=int(a.get("max_log_chars", 60000)),
        min_confidence=float(a.get("min_confidence", 0.75)),
        ban_seconds=int(a.get("ban_seconds", 3600)),
        sources=list(a.get("sources", [])),
    )

    filters: dict[str, FilterConfig] = {}
    filter_dir = config_path.parent / "filters"
    if filter_dir.is_dir():
        for fp in filter_dir.glob("*.yaml"):
            with fp.open("r", encoding="utf-8") as f:
                fbody = yaml.safe_load(f)
            filters[fbody["name"]] = FilterConfig(
                name=fbody["name"],
                patterns=list(fbody.get("patterns", [])),
                ignore=list(fbody.get("ignore", []) or []),
                description=fbody.get("description", ""),
            )

    for jail in jails.values():
        if jail.enabled and jail.filter not in filters:
            raise ValueError(f"jail '{jail.name}' references unknown filter '{jail.filter}'")

    return ShieldConfig(global_=global_, jails=jails, ai=ai, filters=filters)


def is_whitelisted(ip: str, whitelist: list[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in whitelist)


def is_valid_ip(value: str) -> bool:
    """単一 IP (v4 / v6) として妥当か。CIDR・ホスト名・空白混じりは弾く。

    iptables / netsh に流す前のガードとして、AI 出力やフィルタ抽出値を検証する。
    """
    if not value or any(c.isspace() for c in value):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_bannable_ip(value: str) -> bool:
    """is_valid_ip かつ、firewall で block する意味のあるユニキャストか。

    マルチキャスト / unspecified (0.0.0.0, ::) / 予約 / IPv4 ブロードキャスト
    (255.255.255.255) は除外する。AI が「マルチキャストグループから攻撃」の
    ような壊れた判定をしたときに広域 ban されないためのガード。
    プライベートアドレスやループバックは内部脅威で ban したいケースもある
    ので除外しない (whitelist で個別運用する想定)。
    """
    if not is_valid_ip(value):
        return False
    addr = ipaddress.ip_address(value)
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False
    if isinstance(addr, ipaddress.IPv4Address) and int(addr) == 0xFFFFFFFF:
        return False
    return True
