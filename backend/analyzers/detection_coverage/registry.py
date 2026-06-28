"""
Detection Coverage Registry (Beetle 2.0, Phase 1.98).

A single, machine-readable record of EVERY detection capability Beetle has — so we
can (a) reason about coverage, (b) benchmark against MobSF / APKLeaks / future
engines, and (c) add new detectors as DATA that plug into the existing pipelines
without architecture changes.

This registry is a *capability catalog*, NOT a second matcher. An entry describes a
detection (category, name, source, platform, pattern, confidence, references); the
actual matching is still done by the existing engines:

* ``kind="secret"`` entries carrying a ``pattern`` are contributed to the unified
  ``analyzers.secret_catalog`` (provenance ``"coverage"``), so they are matched by
  the ONE combined secret walk and flow through Secret Intelligence + masking +
  fusion — no duplicate scanning.
* ``kind="crypto"`` / ``"manifest"`` / ``"network"`` entries reference an existing
  SAST/analyzer rule by ``detector_ref`` (e.g. a ``code_rules`` id) — the registry
  documents the capability; the rule does the work.

Future detectors register the SAME way (``register(CoverageEntry(...))``), keeping
ONE coverage model regardless of how many engines feed it.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

log = logging.getLogger("cortex.detection_coverage")

# Canonical detection kinds (how the entry is matched / where it routes).
KIND_SECRET = "secret"
KIND_CRYPTO = "crypto"
KIND_MANIFEST = "manifest"
KIND_NETWORK = "network"
KIND_STORAGE = "storage"
KIND_PLATFORM = "platform"   # iOS plist / entitlements / Android component flags
KIND_CODE = "code"

# Detection sources (which engine surfaces it). Free-form but these are canonical.
SOURCE_BEETLE_NATIVE = "Beetle Native"
SOURCE_APKLEAKS = "APKLeaks"
SOURCE_COVERAGE = "Coverage Expansion"


@dataclass
class CoverageEntry:
    """One detection capability. Pure metadata + an optional routing pattern."""
    id: str
    category: str
    name: str
    kind: str = KIND_SECRET
    source: str = SOURCE_COVERAGE
    platform: str = "android"            # "android" | "ios" | "both"
    pattern: str = ""                     # regex, when this entry IS the detector (secrets)
    detector_ref: str = ""                # id of the existing rule/analyzer that detects it
    severity: str = "medium"
    confidence: int = 75
    exploitability: int = 50
    cwe: str = ""
    masvs: str = ""
    owasp: str = ""
    references: list = field(default_factory=list)
    description: str = ""
    recommendation: str = ""
    check_entropy: bool = False
    max_len: int = 300
    redact_context: bool = False
    new: bool = False                     # True = a gap this phase closes (vs documenting existing)

    def supports(self, platform: str) -> bool:
        return self.platform in ("both", platform)


# ── Registry ─────────────────────────────────────────────────────────────────
_REGISTRY: dict[str, CoverageEntry] = {}


def register(entry: CoverageEntry) -> CoverageEntry:
    """Register a coverage entry (idempotent on id)."""
    _REGISTRY[entry.id] = entry
    return entry


def all_entries() -> list[CoverageEntry]:
    return list(_REGISTRY.values())


def get(entry_id: str) -> CoverageEntry | None:
    return _REGISTRY.get(entry_id)


def by_kind(kind: str) -> list[CoverageEntry]:
    return [e for e in _REGISTRY.values() if e.kind == kind]


def by_category(category: str) -> list[CoverageEntry]:
    c = (category or "").strip().lower()
    return [e for e in _REGISTRY.values() if e.category.strip().lower() == c]


def by_platform(platform: str) -> list[CoverageEntry]:
    return [e for e in _REGISTRY.values() if e.supports(platform)]


def categories() -> set[str]:
    return {e.category for e in _REGISTRY.values()}


def to_secret_patterns() -> list[dict]:
    """Secret-kind entries with a pattern, in the Beetle pattern-dict shape the
    evidence scanner / secret_catalog consume. This is how coverage secrets reach
    the existing single combined walk — no separate matching path."""
    out: list[dict] = []
    for e in _REGISTRY.values():
        if e.kind != KIND_SECRET or not e.pattern:
            continue
        out.append({
            "name": e.name,
            "pattern": e.pattern,
            "severity": e.severity,
            "category": e.category,
            "description": e.description,
            "recommendation": e.recommendation,
            "confidence": e.confidence,
            "exploitability": e.exploitability,
            "cwe": e.cwe,
            "masvs": e.masvs,
            "owasp": e.owasp,
            "check_entropy": e.check_entropy,
            "max_len": e.max_len,
            "redact_context": e.redact_context,
            "kind": "secret",
        })
    return out


def summary() -> dict:
    """Coverage rollup for diagnostics / docs."""
    entries = all_entries()
    by_k: dict[str, int] = {}
    by_src: dict[str, int] = {}
    for e in entries:
        by_k[e.kind] = by_k.get(e.kind, 0) + 1
        by_src[e.source] = by_src.get(e.source, 0) + 1
    return {
        "total": len(entries),
        "by_kind": by_k,
        "by_source": by_src,
        "new_this_phase": sum(1 for e in entries if e.new),
        "categories": sorted(categories()),
    }
