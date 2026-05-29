"""AI 解析バックエンドの抽象化。

`analyze(system_prompt, user_prompt) -> str` という単一インタフェースを
公開し、内部で Anthropic / Gemini どちらの SDK を使うかは設定で切り替える。

SDK は遅延 import なので、片方しかインストールしていない環境でも、
そちら側のプロバイダを選んでいる限り起動できる。
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod


class AIProvider(ABC):
    name: str

    @abstractmethod
    async def analyze(self, system_prompt: str, user_prompt: str) -> str:
        """LLM を呼び出して生のテキスト応答を返す。"""


class AnthropicProvider(AIProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str, max_tokens: int = 2048):
        from anthropic import AsyncAnthropic  # 遅延 import
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens

    async def analyze(self, system_prompt: str, user_prompt: str) -> str:
        resp = await self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            # 大きく変わらないシステムプロンプトはキャッシュして 2 回目以降を安く
            system=[
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {"role": "user", "content": [{"type": "text", "text": user_prompt}]}
            ],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


class GeminiProvider(AIProvider):
    name = "gemini"

    def __init__(self, api_key: str, model: str, max_tokens: int = 2048):
        from google import genai           # 遅延 import (google-genai)
        from google.genai import types
        self._types = types
        self.client = genai.Client(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens

    async def analyze(self, system_prompt: str, user_prompt: str) -> str:
        config = self._types.GenerateContentConfig(
            system_instruction=system_prompt,
            response_mime_type="application/json",   # JSON を強制
            max_output_tokens=self.max_tokens,
            temperature=0.0,
        )
        resp = await self.client.aio.models.generate_content(
            model=self.model,
            contents=user_prompt,
            config=config,
        )
        return resp.text or ""


def make_provider(provider: str, model: str, max_tokens: int = 2048) -> AIProvider:
    """設定文字列から実プロバイダを生成。API キーは環境変数から拾う。"""
    provider = (provider or "anthropic").lower()
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        return AnthropicProvider(api_key=key, model=model, max_tokens=max_tokens)
    if provider in ("gemini", "google"):
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            raise RuntimeError("GEMINI_API_KEY (or GOOGLE_API_KEY) is not set")
        return GeminiProvider(api_key=key, model=model, max_tokens=max_tokens)
    raise ValueError(f"unknown ai.provider: {provider!r} (expected 'anthropic' or 'gemini')")
