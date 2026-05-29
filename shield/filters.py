from __future__ import annotations

import re
from dataclasses import dataclass

from .config import FilterConfig, is_valid_ip


@dataclass
class FilterMatch:
    ip: str
    pattern: str


class Filter:
    def __init__(self, cfg: FilterConfig):
        self.name = cfg.name
        self._patterns = [re.compile(p) for p in cfg.patterns]
        self._ignores = [re.compile(p) for p in cfg.ignore]
        for cp in self._patterns:
            if "ip" not in cp.groupindex:
                raise ValueError(
                    f"filter '{cfg.name}' pattern is missing (?P<ip>...) group: {cp.pattern}"
                )

    def match(self, line: str) -> FilterMatch | None:
        for ip_re in self._ignores:
            if ip_re.search(line):
                return None
        for cp in self._patterns:
            m = cp.search(line)
            if m:
                # \S+ などゆるいキャプチャでホスト名やゴミを拾わないよう、
                # ip グループは厳格に IP アドレスとして検証する。
                ip = m.group("ip")
                if not is_valid_ip(ip):
                    continue
                return FilterMatch(ip=ip, pattern=cp.pattern)
        return None
