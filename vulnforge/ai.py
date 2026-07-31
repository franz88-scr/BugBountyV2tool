"""
vulnforge.ai — LLM provider abstraction for AI-powered analysis.

Supports OpenAI, Anthropic, Ollama (local), and a dry-run mode for
testing or offline operation. All providers are optional; the module
degrades gracefully when no LLM backend is available.

Usage:
    from vulnforge.ai import get_provider, ai_complete

    provider = get_provider("ollama", model="llama3")
    result = await provider.complete("Classify this finding: ...")
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

from vulnforge.utils import log


class LLMProvider(ABC):
    """Abstract base for LLM providers."""

    name: str = "base"

    @abstractmethod
    async def complete(
        self, prompt: str, *, max_tokens: int = 1024, temperature: float = 0.3
    ) -> str: ...

    @abstractmethod
    def is_available(self) -> bool: ...


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, model: str = "gpt-4o", api_key: Optional[str] = None) -> None:
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
                choices = body.get("choices", [])
                if choices and isinstance(choices[0], dict):
                    msg = choices[0].get("message", {})
                    if isinstance(msg, dict) and msg.get("content"):
                        return msg["content"]
                log("warn", "warn: OpenAI returned empty output, treating as provider failure")
                return ""
            except Exception as exc:
                log("err", f"err: OpenAI API call failed: {exc}")
                return ""

        loop = asyncio.get_running_loop()
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
                content = body.get("content", [])
                if content and isinstance(content[0], dict):
                    text = content[0].get("text", "")
                    if text:
                        return text  # type: ignore[no-any-return]
                log("warn", "warn: Anthropic returned empty output, treating as provider failure")
                return ""
            except Exception as exc:
                log("err", f"err: Anthropic API call failed: {exc}")
                return ""

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _call)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434") -> None:
        self._model = model
        self._base_url = self._validate_base_url(base_url.rstrip("/"))

    @staticmethod
    def _validate_base_url(url: str) -> str:
        import ipaddress
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname in ("localhost", "127.0.0.1", "::1"):
            return url
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback or ip.is_private:
                return url
        except ValueError:
            pass
        raise ValueError(
            f"Ollama base_url '{url}' resolves to a non-local address (SSRF risk). "
            f"Only localhost addresses are allowed by default."
        )

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
                return body.get("response", "")  # type: ignore[no-any-return]
            except Exception as exc:
                log("err", f"err: Ollama API call failed: {exc}")
                return ""

        loop = asyncio.get_running_loop()
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
            prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:64]
            p.write_text(
                f"# Dry-run prompt — security: full prompt omitted (may contain secrets)\n"
                f"# sha256: {prompt_hash}\n"
                f"# length: {len(prompt)} chars\n"
                f"# truncated:\n{prompt[:500]}"
            )

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
        log(
            "warn",
            f"warn: AI provider '{provider_name}' configured but not available, using dry-run",
        )
        _current_provider = DryRunProvider(log_dir=cache_dir)

    return _current_provider


def get_provider() -> LLMProvider:
    """Get the current global provider. Configures dry-run if not yet set up."""
    global _current_provider, _configured
    if not _configured:
        _current_provider = DryRunProvider()
        _configured = True
    return _current_provider  # type: ignore[return-value]


async def ai_complete(prompt: str, *, max_tokens: int = 1024, temperature: float = 0.3) -> str:
    """Convenience function: complete via the global provider."""
    provider = get_provider()
    return await provider.complete(prompt, max_tokens=max_tokens, temperature=temperature)


def _find_matching_bracket(text: str, open_pos: int, open_ch: str, close_ch: str) -> int:
    """Return the index of the bracket matching text[open_pos], or -1.

    Tracks nesting of open_ch/close_ch and skips over quoted strings so that
    brackets appearing inside JSON string values are not mistaken for structure.
    """
    depth = 0
    in_str = False
    escaped = False
    for i in range(open_pos, len(text)):
        c = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return -1


def parse_json_response(text: str) -> Any:
    """Extract and parse JSON from an LLM response. Handles markdown code blocks.

    Returns an empty list if no JSON can be extracted, so callers can treat
    the response as a failure rather than passing the raw string through.
    """
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for open_ch, close_ch in (("[", "]"), ("{", "}")):
        pos = 0
        while True:
            start = text.find(open_ch, pos)
            if start == -1:
                break
            end = _find_matching_bracket(text, start, open_ch, close_ch)
            if end != -1:
                try:
                    return json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    pass
            pos = start + 1

    return []
