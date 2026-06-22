"""Ollama provider — Phase 11.75 Task 10. Local LLM; gated on OLLAMA_HOST
(default http://localhost:11434). No API key required."""
from __future__ import annotations

import json
import urllib.request
import os

from .base import BaseProvider


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
        try:
            body = json.dumps({"model": model or self.default_model, "prompt": prompt,
                               "system": system or "", "stream": False}).encode()
            req = urllib.request.Request(f"{host.rstrip('/')}/api/generate", data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            return {"text": data.get("response", ""), "model": model or self.default_model, "provider": self.id}
        except Exception as e:
            return {"error": f"Ollama call failed: {type(e).__name__}", "provider": self.id}
