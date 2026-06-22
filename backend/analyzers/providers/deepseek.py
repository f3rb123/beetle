"""DeepSeek provider — Phase 11.75 Task 10. Gated on DEEPSEEK_API_KEY.
OpenAI-compatible chat completions API.

Phase 11.985: the call is now logged (so we can confirm a request actually
reaches api.deepseek.com) and failures surface the real HTTP status + body
instead of just the exception class — a failing key/balance previously looked
identical to offline deterministic mode."""
from __future__ import annotations

import json
import time
import urllib.request
import os

from .base import BaseProvider, http_error_detail, log

_ENDPOINT = "https://api.deepseek.com/chat/completions"


class DeepSeekProvider(BaseProvider):
    id = "deepseek"
    name = "DeepSeek"
    api_key_env = "DEEPSEEK_API_KEY"
    default_model = "deepseek-chat"

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        key = os.environ.get(self.api_key_env, "").strip()
        if not key:
            return {"error": "DeepSeek not configured (set DEEPSEEK_API_KEY)", "provider": self.id}
        mdl = model or self.default_model
        try:
            msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
            body = json.dumps({"model": mdl, "messages": msgs}).encode()
            req = urllib.request.Request(
                _ENDPOINT, data=body, method="POST",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            log.info("[deepseek] POST %s model=%s prompt_chars=%d", _ENDPOINT, mdl, len(prompt))
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read().decode("utf-8", "replace")
            data = json.loads(raw)
            text = data["choices"][0]["message"]["content"]
            usage = data.get("usage") or {}
            latency_ms = int((time.time() - t0) * 1000)
            log.info("[deepseek] ok model=%s latency_ms=%d total_tokens=%s",
                     mdl, latency_ms, usage.get("total_tokens"))
            return {"text": text, "model": mdl, "provider": self.id,
                    "usage": usage, "latency_ms": latency_ms}
        except Exception as e:
            detail = http_error_detail(e)
            log.warning("[deepseek] call failed (model=%s): %s", mdl, detail)
            return {"error": f"DeepSeek call failed: {detail}", "provider": self.id}
