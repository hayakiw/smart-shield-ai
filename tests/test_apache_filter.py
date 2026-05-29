from pathlib import Path

import yaml

from shield.config import FilterConfig
from shield.filters import Filter

APACHE_FILTER_PATH = Path(__file__).resolve().parents[1] / "config" / "filters" / "apache-auth.yaml"


def _load() -> Filter:
    raw = yaml.safe_load(APACHE_FILTER_PATH.read_text(encoding="utf-8"))
    return Filter(FilterConfig(
        name=raw["name"],
        patterns=list(raw["patterns"]),
        ignore=list(raw.get("ignore", []) or []),
    ))


def test_access_log_401():
    f = _load()
    line = '203.0.113.42 - - [28/May/2026:11:01:05 +0000] "GET /manager/html HTTP/1.1" 401 162 "-" "curl/8.4"'
    m = f.match(line)
    assert m is not None and m.ip == "203.0.113.42"


def test_access_log_403_phpmyadmin():
    f = _load()
    line = '203.0.113.42 - - [28/May/2026:11:01:03 +0000] "GET /phpmyadmin/ HTTP/1.1" 403 162 "-" "curl/8.4"'
    m = f.match(line)
    assert m is not None and m.ip == "203.0.113.42"


def test_access_log_scanner_path_with_200():
    """200 でも /.env のような探索パターンは怪しいので拾う想定"""
    f = _load()
    line = '198.51.100.7 - - [28/May/2026:11:01:01 +0000] "GET /.env HTTP/1.1" 404 162 "-" "curl/8.4"'
    m = f.match(line)
    assert m is not None and m.ip == "198.51.100.7"


def test_error_log_auth_failure():
    f = _load()
    line = '[Thu May 28 11:02:01.123456 2026] [auth_basic:error] [pid 12345] [client 203.0.113.55:54321] AH01617: user admin: authentication failure for "/protected": Password Mismatch'
    m = f.match(line)
    assert m is not None and m.ip == "203.0.113.55"


def test_error_log_denied():
    f = _load()
    line = '[Thu May 28 11:02:07.456789 2026] [authz_core:error] [pid 12346] [client 203.0.113.55:54324] AH01630: client denied by server configuration: /var/www/html/private'
    m = f.match(line)
    assert m is not None and m.ip == "203.0.113.55"


def test_error_log_modsecurity():
    f = _load()
    line = '[Thu May 28 11:02:11.678901 2026] [:error] [pid 12348] [client 203.0.113.55] ModSecurity: Access denied with code 403. Matched signature "X" [client "203.0.113.55"] [uri "/login"]'
    m = f.match(line)
    assert m is not None and m.ip == "203.0.113.55"


def test_normal_200_is_ignored():
    f = _load()
    line = '198.51.100.4 - - [28/May/2026:11:00:05 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    assert f.match(line) is None


def test_ipv6_client_in_error_log():
    f = _load()
    line = '[Thu May 28 11:02:01.123456 2026] [auth_basic:error] [pid 12345] [client 2001:db8::1] AH01617: user admin: authentication failure for "/protected": Password Mismatch'
    m = f.match(line)
    assert m is not None
    assert m.ip == "2001:db8::1"
