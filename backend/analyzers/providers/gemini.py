"""Google Gemini provider — Phase 11.75 Task 10. Gated on GEMINI_API_KEY."""
from __future__ import annotations

import json
import time
import urllib.request
import os

from .base import BaseProvider, http_error_detail, log


class GeminiProvider(BaseProvider):
    id = "gemini"
    name = "Google Gemini"
    api_key_env = "GEMINI_API_KEY"
    default_model = "gemini-1.5-flash"

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            return {"error": "Gemini not configured (set GEMINI_API_KEY)", "provider": self.id}
        mdl = model or self.default_model
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{mdl}:generateContent?key={key}"
            body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
            req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
            log.info("[gemini] POST generateContent model=%s prompt_chars=%d", mdl, len(prompt))
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            usage = data.get("usageMetadata") or {}
            latency_ms = int((time.time() - t0) * 1000)
            log.info("[gemini] ok model=%s latency_ms=%d total_tokens=%s", mdl, latency_ms, usage.get("totalTokenCount"))
            return {"text": text, "model": mdl, "provider": self.id,
                    "usage": {"total_tokens": usage.get("totalTokenCount")} if usage else {}, "latency_ms": latency_ms}
        except Exception as e:
            detail = http_error_detail(e)
            log.warning("[gemini] call failed (model=%s): %s", mdl, detail)
            return {"error": f"Gemini call failed: {detail}", "provider": self.id}
