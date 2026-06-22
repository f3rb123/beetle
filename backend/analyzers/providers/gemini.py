"""Google Gemini provider — Phase 11.75 Task 10. Gated on GEMINI_API_KEY."""
from __future__ import annotations

import json
import urllib.request
import os

from .base import BaseProvider


class GeminiProvider(BaseProvider):
    id = "gemini"
    name = "Google Gemini"
    api_key_env = "GEMINI_API_KEY"
    default_model = "gemini-1.5-flash"

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            return {"error": "Gemini not configured (set GEMINI_API_KEY)", "provider": self.id}
        try:
            mdl = model or self.default_model
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{mdl}:generateContent?key={key}"
            body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
            req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            return {"text": text, "model": mdl, "provider": self.id}
        except Exception as e:
            return {"error": f"Gemini call failed: {type(e).__name__}", "provider": self.id}
