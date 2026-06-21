"""DeepSeek provider — Phase 11.75 Task 10. Gated on DEEPSEEK_API_KEY.
OpenAI-compatible chat completions API."""
from __future__ import annotations

import json
import urllib.request
import os

from .base_provider import BaseProvider


class DeepSeekProvider(BaseProvider):
    id = "deepseek"
    name = "DeepSeek"
    api_key_env = "DEEPSEEK_API_KEY"
    default_model = "deepseek-chat"

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            return {"error": "DeepSeek not configured (set DEEPSEEK_API_KEY)", "provider": self.id}
        try:
            msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
            body = json.dumps({"model": model or self.default_model, "messages": msgs}).encode()
            req = urllib.request.Request(
                "https://api.deepseek.com/chat/completions", data=body, method="POST",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            return {"text": data["choices"][0]["message"]["content"], "model": model or self.default_model, "provider": self.id}
        except Exception as e:
            return {"error": f"DeepSeek call failed: {type(e).__name__}", "provider": self.id}
