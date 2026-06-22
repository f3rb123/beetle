"""
AI provider registry — Phase 11.75 Task 10.

Provider-agnostic LLM access. No provider is required: `get_provider()` returns
the configured/available provider, or None (callers then fall back to the
deterministic analyst intelligence). Default selection preserves current
behavior — Claude is used when ANTHROPIC_API_KEY is set.

Selection order:
  1. CORTEX_AI_PROVIDER (explicit id), if that provider is available
  2. first available provider in PROVIDER_ORDER
  3. None  → graceful fallback
"""
from __future__ import annotations

import os

from .base import BaseProvider
from .claude import ClaudeProvider
from .openai import OpenAIProvider
from .gemini import GeminiProvider
from .deepseek import DeepSeekProvider
from .ollama import OllamaProvider

_REGISTRY = {
    "claude": ClaudeProvider(),
    "openai": OpenAIProvider(),
    "gemini": GeminiProvider(),
    "deepseek": DeepSeekProvider(),
    "ollama": OllamaProvider(),
}
# Claude first preserves existing behavior.
PROVIDER_ORDER = ["claude", "openai", "gemini", "deepseek", "ollama"]


def list_providers() -> list[dict]:
    return [{"id": p.id, "name": p.name, "available": p.available(),
             "default_model": p.default_model} for p in (_REGISTRY[i] for i in PROVIDER_ORDER)]


def get_provider(name: str | None = None) -> BaseProvider | None:
    """Return a provider. Explicit `name` (or CORTEX_AI_PROVIDER) wins when
    available; otherwise the first available provider; otherwise None."""
    requested = (name or os.environ.get("CORTEX_AI_PROVIDER", "")).strip().lower()
    if requested and requested in _REGISTRY and _REGISTRY[requested].available():
        return _REGISTRY[requested]
    for pid in PROVIDER_ORDER:
        if _REGISTRY[pid].available():
            return _REGISTRY[pid]
    return None


def any_available() -> bool:
    return any(p.available() for p in _REGISTRY.values())
