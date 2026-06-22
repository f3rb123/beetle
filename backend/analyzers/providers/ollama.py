"""Ollama provider — Phase 11.75 Task 10. Local LLM; gated on OLLAMA_HOST
(default http://localhost:11434). No API key required."""
from __future__ import annotations

import json
import time
import urllib.request
import os

from .base import BaseProvider, http_error_detail, log


class OllamaProvider(BaseProvider):
    id = "ollama"
    name = "Ollama (local)"
    api_key_env = None
    default_model = "llama3"

    def _host(self) -> str:
        return os.environ.get("OLLAMA_HOST", "").strip()

    def available(self) -> bool:
        # Opt-in only: requires OLLAMA_HOST to be set (never probes at import).
        return bool(self._host())

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        host = self._host() or "http://localhost:11434"
        if not self._host():
            return {"error": "Ollama not configured (set OLLAMA_HOST)", "provider": self.id}
        mdl = model or self.default_model
        try:
            body = json.dumps({"model": mdl, "prompt": prompt,
                               "system": system or "", "stream": False}).encode()
            req = urllib.request.Request(f"{host.rstrip('/')}/api/generate", data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
            log.info("[ollama] POST %s/api/generate model=%s prompt_chars=%d", host.rstrip('/'), mdl, len(prompt))
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            latency_ms = int((time.time() - t0) * 1000)
            log.info("[ollama] ok model=%s latency_ms=%d", mdl, latency_ms)
            return {"text": data.get("response", ""), "model": mdl, "provider": self.id, "latency_ms": latency_ms}
        except Exception as e:
            detail = http_error_detail(e)
            log.warning("[ollama] call failed (model=%s): %s", mdl, detail)
            return {"error": f"Ollama call failed: {detail}", "provider": self.id}
