"""
APKLeaks detection source (Beetle 2.0, Phase 1.9).

Beetle-native re-implementation of APKLeaks' value: it scans the *already
decompiled* tree (the same jadx/apktool/apk_extract dirs Beetle's own secret
scanner uses) with the ported APKLeaks pattern catalog, and returns detections in
Beetle's existing internal shapes — secret dicts, finding dicts, endpoint strings —
each tagged ``detected_by=["APKLeaks"]``.

Why this is NOT an APKLeaks wrapper
-----------------------------------
* No ``apkleaks`` package, no subprocess, no jadx re-run, no second report.
* It reuses Beetle's own ``evidence_scanner.scan_file_for_patterns`` for the
  actual matching, so every hit inherits Beetle's line/snippet capture, entropy
  gate, length cap, binary-dump suppression and per-file dedup — the context
  APKLeaks itself does not produce.
* Output flows into the SAME ``results["secrets"]`` / ``results["findings"]`` /
  ``results["endpoints"]`` streams, where Secret Intelligence, masking, ownership,
  confidence, triage, attack chains and bug-bounty all act on it unchanged.

Cross-source de-duplication (Beetle Native vs APKLeaks) is handled by ``fusion.py``
after this source runs — not here. This source only produces and attributes.
"""
from __future__ import annotations

import logging

from .. import evidence_scanner
from .. import secret_catalog
from . import apkleaks_patterns as cat  # noqa: F401 — ensures apkleaks rules register
from . import routing
from .registry import DetectionSource, SourceResult, register

log = logging.getLogger("cortex.apkleaks_source")

SOURCE_NAME = cat.SOURCE_NAME  # "APKLeaks"


class ApkLeaksSource:
    """Detection source: ported APKLeaks regexes over the decompiled tree.

    Phase 1.9 (post-review): this no longer hand-rolls a filesystem walk. It reuses
    ``evidence_scanner.scan_directory_for_secrets`` — the same framework Beetle
    Native uses — with the APKLeaks slice of the unified catalog, then routes the
    hits via the shared routing layer. In the live pipeline APKLeaks is folded into
    the SINGLE combined walk (see ``android_analyzer._scan_precise_source_secrets``
    / ``ios_analyzer``); this class is the standalone / fallback path and keeps the
    registry contract intact for future non-pattern sources.
    """

    name = SOURCE_NAME

    def supports(self, platform: str) -> bool:
        # The catalog is platform-agnostic (PEM keys, cloud creds, JWTs, URLs all
        # appear in iOS bundles too), so it runs for both. APKLeaks the tool is
        # Android-only, but the *patterns* are not.
        return platform in ("android", "ios")

    def scan(self, source_dirs: list[str], *, platform: str,
             context: dict | None = None) -> SourceResult:
        dirs = [d for d in (source_dirs or []) if d]
        if not dirs:
            return SourceResult()
        # ONE walk with the APKLeaks-only slice, via the shared framework.
        hits = evidence_scanner.scan_directory_for_secrets(
            "", dirs, patterns=secret_catalog.patterns("apkleaks"))
        _native, result = routing.extract_apkleaks(hits)
        log.info("[apkleaks] %s | secrets=%d findings=%d endpoints=%d",
                 platform, len(result.secrets), len(result.findings), len(result.endpoints))
        return result


# Module-level singleton, registered with the DetectionSource registry so the
# registry-driven orchestrator (``run_detection_sources``) can discover it on the
# fallback / standalone path. The PRIMARY Android/iOS path does NOT go through the
# registry — it folds the APKLeaks catalog into the single combined secret walk —
# so registering here never causes a second filesystem traversal in the live
# pipeline. Registration is idempotent on ``name``.
APKLEAKS_SOURCE: DetectionSource = register(ApkLeaksSource())
