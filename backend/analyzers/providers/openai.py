"""OpenAI provider — Phase 11.75 Task 10. Gated on OPENAI_API_KEY; graceful
no-op until wired. No network at import."""
from __future__ import annotations

import json
import urllib.request
import urllib.error
import os

from .base import BaseProvider


class OpenAIProvider(BaseProvider):
    id = "openai"
    name = "OpenAI"
    api_key_env = "OPENAI_API_KEY"
    default_model = "gpt-4o-mini"

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            return {"error": "OpenAI not configured (set OPENAI_API_KEY)", "provider": self.id}
        try:
            msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
            body = json.dumps({"model": model or self.default_model, "messages": msgs}).encode()
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions", data=body, method="POST",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            return {"text": data["choices"][0]["message"]["content"], "model": model or self.default_model, "provider": self.id}
        except Exception as e:
            return {"error": f"OpenAI call failed: {type(e).__name__}", "provider": self.id}
