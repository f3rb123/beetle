"""
Semgrep adapter (Beetle 2.0, Phase 2.4).

The concrete :class:`SastAdapter` for Semgrep. It ONLY executes Semgrep, parses its
SARIF, and converts to canonical findings (via the shared ``adapter.sarif_to_canonical``)
— it does not embed, vendor or modify rules, and it builds no Semgrep-specific reporting.
Findings flow into the same canonical pipeline as Beetle Native / APKLeaks.

Graceful + cheap when Semgrep is absent: ``available()`` is cached, so a scan without
Semgrep on PATH pays a single ``shutil.which`` and then short-circuits — zero impact on
Android/iOS scan performance (the existing behavior). Project detection runs only the
rule packs relevant to the detected languages, so we never scan Java rules on an iOS app.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time

from . import config
from .adapter import SastAdapter, sarif_to_canonical

log = logging.getLogger("cortex.sast.semgrep")

SEMGREP_TIMEOUT = int(os.environ.get("CORTEX_SEMGREP_TIMEOUT", "90"))   # overall cap (s)
SEMGREP_FILE_TIMEOUT = os.environ.get("CORTEX_SEMGREP_FILE_TIMEOUT", "10")  # per-file (s)
MAX_FINDINGS = int(os.environ.get("CORTEX_SEMGREP_MAX_FINDINGS", "300"))


class SemgrepAdapter(SastAdapter):
    name = "Semgrep"

    def __init__(self) -> None:
        self._available: bool | None = None  # cached binary check

    # ── availability (cached) ────────────────────────────────────────────────
    def available(self) -> bool:
        if self._available is None:
            self._available = shutil.which("semgrep") is not None
        return self._available

    def languages_for(self, platform: str | None, framework: str | None = None) -> list[str]:
        return config.languages_for(platform, framework)

    def configs_for(self, platform: str | None, framework: str | None = None) -> list[str]:
        return config.configs_for_project(platform, framework)

    # ── run ──────────────────────────────────────────────────────────────────
    def run(self, scan_dirs: list[str], *, platform: str | None = None,
            framework: str | None = None) -> list[dict]:
        """Execute Semgrep over the project-relevant rule packs and return canonical
        findings. Safe + no-op ([]) when Semgrep is absent or no packs apply."""
        if not self.available():
            return []
        valid_dirs = [d for d in (scan_dirs or []) if d and os.path.exists(d)]
        if not valid_dirs:
            return []
        configs = self.configs_for(platform, framework)
        if not configs:
            log.info("[semgrep] no rule packs apply to platform=%s framework=%s", platform, framework)
            return []

        sarif_path = os.path.join(tempfile.gettempdir(), f"beetle_semgrep_{os.getpid()}_{int(time.time()*1000)}.sarif")
        cmd = ["semgrep", "--sarif", "--output", sarif_path, "--no-git-ignore",
               "--quiet", "--timeout", str(SEMGREP_FILE_TIMEOUT), "--max-memory", "1000", "--jobs", "4"]
        for cfg in configs:
            cmd += ["--config", cfg]
        cmd += valid_dirs
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SEMGREP_TIMEOUT)
            if proc.returncode > 1:  # 0 = no findings, 1 = findings; 2+ = fatal
                log.warning("[semgrep] exit %s: %s", proc.returncode, (proc.stderr or "")[:200])
                return []
            if not (os.path.exists(sarif_path) and os.path.getsize(sarif_path) > 0):
                return []
            with open(sarif_path, "r", encoding="utf-8", errors="replace") as f:
                sarif = json.load(f)
            return sarif_to_canonical(sarif, valid_dirs, source_name=self.name, max_findings=MAX_FINDINGS)
        except subprocess.TimeoutExpired:
            log.warning("[semgrep] timed out after %ss", SEMGREP_TIMEOUT)
            return []
        except Exception:
            log.exception("[semgrep] run failed")
            return []
        finally:
            try:
                os.unlink(sarif_path)
            except OSError:
                pass

    # ── pipeline convenience: append + metrics ───────────────────────────────
    def run_into(self, results: dict, scan_dirs: list[str], *, platform: str | None = None,
                 framework: str | None = None) -> dict:
        """Run and append canonical findings to ``results["findings"]`` (no cross-engine
        de-dup here — Finding Fusion merges duplicates and credits every engine).
        Returns metrics for scan_metrics."""
        metrics = {"ran": False, "available": self.available(), "finding_count": 0,
                   "configs": self.configs_for(platform, framework)}
        if not self.available():
            return metrics
        t0 = time.perf_counter()
        found = self.run(scan_dirs, platform=platform, framework=framework)
        metrics["duration_ms"] = int((time.perf_counter() - t0) * 1000)
        metrics["ran"] = True
        metrics["finding_count"] = len(found)
        results.setdefault("findings", []).extend(found)
        # Surface engine + pack provenance for the report / diagnostics.
        results.setdefault("sast_engines", {})[self.name] = {
            "ran": True, "findings": len(found), "configs": metrics["configs"],
        }
        log.info("[semgrep] %s/%s | findings=%d configs=%s", platform, framework, len(found), metrics["configs"])
        return metrics


# Module-level singleton.
SEMGREP = SemgrepAdapter()
