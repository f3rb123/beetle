"""OpenAI provider — Phase 11.75 Task 10. Gated on OPENAI_API_KEY; graceful
no-op until wired. No network at import."""
from __future__ import annotations

import json
import time
import urllib.request
import os

from .base import BaseProvider, http_error_detail, log


class OpenAIProvider(BaseProvider):
    id = "openai"
    name = "OpenAI"
    api_key_env = "OPENAI_API_KEY"
    default_model = "gpt-4o-mini"

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            return {"error": "OpenAI not configured (set OPENAI_API_KEY)", "provider": self.id}
        mdl = model or self.default_model
        try:
            msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
            body = json.dumps({"model": mdl, "messages": msgs}).encode()
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions", data=body, method="POST",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            log.info("[openai] POST chat/completions model=%s prompt_chars=%d", mdl, len(prompt))
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            usage = data.get("usage") or {}
            latency_ms = int((time.time() - t0) * 1000)
            log.info("[openai] ok model=%s latency_ms=%d total_tokens=%s", mdl, latency_ms, usage.get("total_tokens"))
            return {"text": data["choices"][0]["message"]["content"], "model": mdl,
                    "provider": self.id, "usage": usage, "latency_ms": latency_ms}
        except Exception as e:
            detail = http_error_detail(e)
            log.warning("[openai] call failed (model=%s): %s", mdl, detail)
            return {"error": f"OpenAI call failed: {detail}", "provider": self.id}
