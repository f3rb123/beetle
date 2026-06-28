"""
Detection Sources package (Beetle 2.0, Phase 1.9).

Pluggable detection engines that feed Beetle's ONE intelligence pipeline. After the
architecture review the APKLeaks integration was restructured so it does NOT add a
second filesystem traversal: APKLeaks is a *contributor to the unified secret
catalog* (``analyzers.secret_catalog``), and the analyzers apply native + APKLeaks
rules in a SINGLE combined walk, then route/fuse the hits. The pieces here are:

* ``apkleaks_patterns`` — the APKLeaks rule slice of the unified catalog.
* ``routing``          — splits a combined-walk hit stream into native vs APKLeaks.
* ``fusion``           — cross-source de-dup/merge + masked secret→finding bridge.
* ``registry``         — the ``DetectionSource`` contract for FUTURE non-pattern
  engines (Semgrep / MobSF / YARA); pattern engines should contribute to the
  catalog instead of walking again.

The analyzers use:

* ``run_detection_sources`` — the registry-driven orchestrator. It runs every
  REGISTERED :class:`~.registry.DetectionSource` for the platform and fuses each
  one's secrets/findings/endpoints into the native streams. This is the pluggable
  path the registry exists for (APKLeaks today; Semgrep / MobSF / YARA next) and
  the fallback/standalone path (no-JADX Android, tests). It is deliberately NOT
  called on the primary Android/iOS path — there APKLeaks is folded into the SINGLE
  combined secret walk (``secret_catalog.combined()``), so there is no second
  filesystem traversal in the live pipeline.
* ``fusion.bridge_secrets_to_findings`` / ``fusion.reconcile_bridged_findings`` —
  the "intelligence bridge" (see fusion docstring).
"""
from __future__ import annotations

import logging

from . import apkleaks_source  # noqa: F401 — import registers APKLEAKS_SOURCE
from . import fusion
from . import registry
from .registry import SourceResult

log = logging.getLogger("cortex.detection_sources")


def run_detection_sources(results: dict, source_dirs: list[str], *, platform: str) -> dict:
    """Run every registered detection source for ``platform`` and fuse the result.

    Registry-driven: for each :class:`~.registry.DetectionSource` that supports the
    platform, scan ``source_dirs`` (already decompiled) and fold its detections into
    ``results`` with source attribution + cross-source de-dup via the fusion layer.

    Used on the paths that do NOT run the unified combined walk — the no-JADX
    Android fallback and standalone/test use. On the primary Android/iOS path
    APKLeaks is already applied inside the single combined secret walk, so the
    analyzers do not call this there (avoiding a second filesystem traversal).

    Returns ``{source_name: {"secrets", "findings", "endpoints_added"}}``.
    """
    dirs = [d for d in (source_dirs or []) if d]
    stats: dict[str, dict] = {}
    for source in registry.sources_for(platform):
        res: SourceResult = registry.run_source(source, dirs, platform=platform, context=results)
        s = fusion.merge_secret_streams(results, res.secrets)
        f = fusion.merge_finding_streams(results, res.findings, platform=platform)
        e = fusion.merge_endpoint_streams(results, res.endpoints)
        stats[source.name] = {"secrets": s, "findings": f, "endpoints_added": e}
    results.setdefault("apkleaks_integration", {})["detection"] = stats
    log.info("[detection_sources] %s registry run | %s", platform, stats)
    return stats
