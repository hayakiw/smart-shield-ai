from shield.config import FilterConfig
from shield.filters import Filter


def _ssh_filter() -> Filter:
    return Filter(FilterConfig(
        name="sshd",
        patterns=[
            r"Failed password for .* from (?P<ip>\S+) port \d+",
            r"Invalid user .* from (?P<ip>\S+)",
        ],
        ignore=[r"Accepted password for .* from"],
    ))


def test_matches_failed_password():
    f = _ssh_filter()
    m = f.match("May 28 10:00 host sshd[1]: Failed password for root from 203.0.113.7 port 51001 ssh2")
    assert m is not None
    assert m.ip == "203.0.113.7"


def test_matches_invalid_user():
    f = _ssh_filter()
    m = f.match("May 28 10:00 host sshd[1]: Invalid user oracle from 198.51.100.5")
    assert m is not None
    assert m.ip == "198.51.100.5"


def test_ignore_accepted():
    f = _ssh_filter()
    m = f.match("May 28 10:00 host sshd[1]: Accepted password for alice from 192.168.1.1 port 22")
    assert m is None


def test_no_match_unrelated():
    f = _ssh_filter()
    assert f.match("some unrelated log line") is None


def test_pattern_must_have_ip_group():
    import pytest
    with pytest.raises(ValueError):
        Filter(FilterConfig(name="bad", patterns=[r"Failed password"]))
