"""
AI provider abstraction — Phase 11.75 Task 10 (base).

A minimal, network-free-at-import interface so Beetle can talk to any LLM without
hardcoding one. Existing Claude support continues via the Claude provider, which
delegates to the established `ai_enrichment` path. No provider is required: when
none is configured, the pipeline falls back to its deterministic analyst
intelligence (analyst_intel) and nothing breaks.
"""
from __future__ import annotations

import os


class BaseProvider:
    """One LLM backend. Subclasses override `available()` and `complete()`."""

    id = "base"
    name = "Base Provider"
    #: environment variable holding this provider's API key (None for local/no-key)
    api_key_env: str | None = None
    default_model = ""

    def available(self) -> bool:
        """True only when this provider could actually run (key/host present).
        Never performs I/O — safe to call cheaply and repeatedly."""
        if self.api_key_env is None:
            return False
        return bool(os.environ.get(self.api_key_env, "").strip())

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        """Return {text, model, provider} or {error, provider}. Must never raise."""
        return {"error": f"{self.name} not configured", "provider": self.id}

    def enrich_finding(self, finding: dict, app_context: dict | None = None) -> dict:
        """Optional richer hook; default builds a prompt and calls complete()."""
        prompt = (
            f"Explain this mobile security finding for an analyst.\n"
            f"Title: {finding.get('title')}\nSeverity: {finding.get('severity')}\n"
            f"Category: {finding.get('category')}\n"
        )
        return self.complete(prompt, model=self.default_model)
