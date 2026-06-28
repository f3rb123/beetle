"""
Semgrep runner — compatibility shim (Beetle 2.0).

Phase 2.4 moved Semgrep behind the first-class SAST adapter layer
(``analyzers.sast``): a dedicated adapter that executes Semgrep, parses SARIF and
converts to CANONICAL findings tagged ``detected_by:["Semgrep"]`` (with Rule ID, CWE,
OWASP, references preserved), which then flow through the unchanged pipeline — Ownership,
Confidence, Evidence, **Finding Fusion** (it now MERGES + credits duplicates instead of
the old runner silently dropping them), Attack Chains, Bug Bounty, Source/Security
Explorer and Reports.

This module remains only so existing imports keep working; it delegates to the adapter.
New code should call ``analyzers.sast.semgrep`` directly.
"""
from __future__ import annotations

from .sast import config as _sast_config
from .sast import semgrep as _semgrep


def semgrep_available() -> bool:
    """True when Semgrep is on PATH (cached by the adapter)."""
    return _semgrep.available()


def run_semgrep(scan_dirs, results, *, platform: str | None = None,
                framework: str | None = None) -> dict:
    """Run Semgrep over ``scan_dirs`` and append CANONICAL findings to
    ``results["findings"]``. Project detection selects only the relevant rule packs.
    Returns metrics. Safe no-op when Semgrep is absent.

    ``platform`` defaults to the scan's platform; ``framework`` to the detected
    framework (so a Flutter/React-Native APK runs Dart/JS packs, not just Java)."""
    platform = platform or results.get("platform") or "android"
    framework = framework or (results.get("framework") or {}).get("type")
    return _semgrep.run_into(results, scan_dirs, platform=platform, framework=framework)


# Re-exported for diagnostics / callers that want the configured packs.
def semgrep_config_summary() -> dict:
    return _sast_config.summary()
