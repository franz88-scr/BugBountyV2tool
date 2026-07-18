"""
reconchain.ai — LLM provider abstraction for AI-powered analysis.

Supports OpenAI, Anthropic, Ollama (local), and a dry-run mode for
testing or offline operation. All providers are optional; the module
degrades gracefully when no LLM backend is available.

Usage:
    from reconchain.ai import get_provider, ai_complete

    provider = get_provider("ollama", model="llama3")
    result = await provider.complete("Classify this finding: ...")
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

from reconchain.utils import log


class LLMProvider(ABC):
    """Abstract base for LLM providers."""

    name: str = "base"

    @abstractmethod
    async def complete(
        self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.3
    ) -> str:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self, model: str = "gpt-4o", api_key: Optional[str] = None
    ) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    def is_available(self) -> bool:
        return bool(self._api_key)

    async def complete(
        self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.3
    ) -> str:
        import asyncio

        def _call() -> str:
            payload = json.dumps(
                {
                    "model": self._model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
            ).encode()
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = json.loads(resp.read())
                return body["choices"][0]["message"]["content"]
            except Exception as exc:
                log("err", f"err: OpenAI API call failed: {exc}")
                return ""

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _call)


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(
        self, model: str = "claude-3-5-sonnet-20241022", api_key: Optional[str] = None
    ) -> None:
        self._model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    def is_available(self) -> bool:
        return bool(self._api_key)

    async def complete(
        self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.3
    ) -> str:
        import asyncio

        def _call() -> str:
            payload = json.dumps(
                {
                    "model": self._model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = json.loads(resp.read())
                return body["content"][0]["text"]
            except Exception as exc:
                log("err", f"err: Anthropic API call failed: {exc}")
                return ""

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _call)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(
        self, model: str = "llama3", base_url: str = "http://localhost:11434"
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self._base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                body = json.loads(resp.read())
            models = [m.get("name", "") for m in body.get("models", [])]
            return any(self._model in m for m in models) or bool(models)
        except Exception:
            return False

    async def complete(
        self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.3
    ) -> str:
        import asyncio

        def _call() -> str:
            payload = json.dumps(
                {
                    "model": self._model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": max_tokens},
                }
            ).encode()
            req = urllib.request.Request(
                f"{self._base_url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    body = json.loads(resp.read())
                return body.get("response", "")
            except Exception as exc:
                log("err", f"err: Ollama API call failed: {exc}")
                return ""

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _call)


class DryRunProvider(LLMProvider):
    """Returns a stub response. Writes prompts to file for inspection."""

    name = "dry-run"

    def __init__(self, log_dir: Optional[Path] = None) -> None:
        self._log_dir = log_dir
        if log_dir:
            log_dir.mkdir(parents=True, exist_ok=True)

    def is_available(self) -> bool:
        return True

    async def complete(
        self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.3
    ) -> str:
        if self._log_dir:
            ts = int(time.time() * 1000)
            p = self._log_dir / f"prompt_{ts}.txt"
            p.write_text(prompt)

        return json.dumps(
            {
                "note": "dry-run mode — no LLM backend configured",
                "truncated_prompt": prompt[:200],
            }
        )


_PROVIDERS = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
    "dry-run": DryRunProvider,
}

_current_provider: Optional[LLMProvider] = None
_configured = False


def configure(
    provider_name: str = "dry-run",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    cache_dir: Optional[Path] = None,
) -> LLMProvider:
    """Initialize the global LLM provider. Returns the configured provider."""
    global _current_provider, _configured

    if provider_name == "none":
        _current_provider = DryRunProvider()
        _configured = True
        return _current_provider

    cls = _PROVIDERS.get(provider_name)
    if cls is None:
        log("warn", f"warn: unknown AI provider '{provider_name}', falling back to dry-run")
        cls = DryRunProvider
        provider_name = "dry-run"

    kwargs: Dict[str, Any] = {}
    if provider_name in ("openai", "anthropic"):
        if model:
            kwargs["model"] = model
        if api_key:
            kwargs["api_key"] = api_key
    elif provider_name == "ollama":
        if model:
            kwargs["model"] = model
        if base_url:
            kwargs["base_url"] = base_url
    elif provider_name == "dry-run":
        kwargs["log_dir"] = cache_dir

    provider = cls(**kwargs)
    _current_provider = provider
    _configured = True

    if provider.is_available():
        log("ok", f"ok: AI provider '{provider_name}' ready")
    else:
        log("warn", f"warn: AI provider '{provider_name}' configured but not available, using dry-run")
        _current_provider = DryRunProvider(cache_dir=cache_dir)

    return _current_provider


def get_provider() -> LLMProvider:
    """Get the current global provider. Configures dry-run if not yet set up."""
    global _current_provider, _configured
    if not _configured:
        _current_provider = DryRunProvider()
        _configured = True
    return _current_provider


async def ai_complete(
    prompt: str, *, max_tokens: int = 1024, temperature: float = 0.3
) -> str:
    """Convenience function: complete via the global provider."""
    provider = get_provider()
    return await provider.complete(prompt, max_tokens=max_tokens, temperature=temperature)


def parse_json_response(text: str) -> Any:
    """Extract and parse JSON from an LLM response. Handles markdown code blocks."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass

        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass

    return text
