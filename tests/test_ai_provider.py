from __future__ import annotations

import pytest

from shield import ai_provider


def test_unknown_provider_raises(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    with pytest.raises(ValueError):
        ai_provider.make_provider("openai", "gpt-x")


def test_anthropic_requires_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        ai_provider.make_provider("anthropic", "claude-sonnet-4-6")


def test_gemini_requires_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        ai_provider.make_provider("gemini", "gemini-2.5-flash")


def test_gemini_accepts_google_api_key_fallback(monkeypatch):
    """GOOGLE_API_KEY だけセットされていても受け付ける。

    実 SDK が未インストールなら ImportError、入っていれば成功する。
    どちらにせよ「キー無し」由来の RuntimeError は出てはいけない。
    """
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "x")
    try:
        ai_provider.make_provider("gemini", "gemini-2.5-flash")
    except ImportError:
        pass  # SDK 未インストールは許容
    except RuntimeError as e:
        pytest.fail(f"should not raise RuntimeError when GOOGLE_API_KEY is set: {e}")
