"""Claude provider — delegates to the existing ai_enrichment Claude path so
current behavior is preserved exactly (Phase 11.75 Task 10)."""
from __future__ import annotations

from .base import BaseProvider, log


class ClaudeProvider(BaseProvider):
    id = "claude"
    name = "Claude (Anthropic)"
    api_key_env = "ANTHROPIC_API_KEY"
    default_model = "claude-haiku"

    def available(self) -> bool:
        try:
            import ai_enrichment  # top-level backend module
            return bool(getattr(ai_enrichment, "AI_AVAILABLE", False))
        except Exception:
            return super().available()

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        try:
            import ai_enrichment
            if not getattr(ai_enrichment, "AI_AVAILABLE", False):
                return {"error": "Claude not configured (set ANTHROPIC_API_KEY)", "provider": self.id}
            client = getattr(ai_enrichment, "_CLIENT", None)
            mdl = getattr(ai_enrichment, "_MODEL", model or self.default_model)
            if client is None:
                return {"error": "Claude client unavailable", "provider": self.id}
            kwargs = {"model": mdl, "max_tokens": 1024,
                      "messages": [{"role": "user", "content": prompt}]}
            if system:
                kwargs["system"] = system
            msg = client.messages.create(**kwargs)
            text = "".join(getattr(b, "text", "") for b in msg.content)
            usage = getattr(msg, "usage", None)
            tokens = (getattr(usage, "input_tokens", 0) or 0) + (getattr(usage, "output_tokens", 0) or 0) if usage else None
            return {"text": text, "model": mdl, "provider": self.id,
                    "usage": {"total_tokens": tokens} if tokens else {}}
        except Exception as e:  # never raise into the pipeline
            log.warning("[claude] call failed: %s: %s", type(e).__name__, e)
            return {"error": f"Claude call failed: {type(e).__name__}: {e}", "provider": self.id}

    def enrich_finding(self, finding: dict, app_context: dict | None = None) -> dict:
        import ai_enrichment
        return ai_enrichment.enrich_finding(finding, app_context)
