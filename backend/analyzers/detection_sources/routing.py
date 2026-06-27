"""
Hit routing for the unified secret walk (Beetle 2.0, Phase 1.9).

The single combined walk (``evidence_scanner.scan_directory_for_secrets`` with
``secret_catalog.combined()``) returns hits from BOTH Beetle Native and APKLeaks,
each tagged with ``provenance`` and ``kind``. This module splits that one stream:

* Beetle Native hits are returned **untouched** so each analyzer keeps its existing
  native handling (Android's reshape/dedup, iOS's ev+legacy merge) — zero native
  behavior change.
* APKLeaks hits are reshaped + attributed and bucketed by ``kind`` into
  secrets / findings / endpoints for the fusion layer to merge in.

Routing performs no walking and no masking; redaction of private-key context already
happened in the matcher (``scan_file_for_patterns`` honoring ``redact_context``).
"""
from __future__ import annotations

from .registry import SourceResult

SOURCE_NAME = "APKLeaks"


def _attribute(hit: dict) -> dict:
    """Stamp canonical source attribution onto an APKLeaks hit (in place)."""
    rule = hit.get("name", "")
    hit["source"] = SOURCE_NAME
    hit.setdefault("source_module", SOURCE_NAME)
    hit["detected_by"] = [SOURCE_NAME]
    hit["sources"] = [{"engine": SOURCE_NAME, "rule_id": rule,
                       "confidence": hit.get("confidence")}]
    hit["discovery_method"] = "apkleaks_regex"
    return hit


def extract_apkleaks(hits: list[dict]) -> tuple[list[dict], SourceResult]:
    """Split combined-walk hits into (native_hits, APKLeaks SourceResult).

    ``native_hits`` preserves order and content exactly (the caller handles them
    natively). The APKLeaks ``SourceResult`` carries reshaped, attributed
    secrets / findings / endpoints ready for the fusion layer.
    """
    native_hits: list[dict] = []
    secrets: list[dict] = []
    findings: list[dict] = []
    endpoints: list[str] = []

    for hit in hits or []:
        if not isinstance(hit, dict):
            continue
        if hit.get("provenance") != "apkleaks":
            native_hits.append(hit)
            continue
        kind = hit.get("kind", "secret")
        value = hit.get("value", "")
        if kind == "endpoint":
            if value and value not in endpoints:
                endpoints.append(value)
            continue
        _attribute(hit)
        if kind == "finding":
            findings.append(hit)
        else:  # "secret"
            secrets.append(hit)

    return native_hits, SourceResult(secrets=secrets, findings=findings, endpoints=endpoints)
