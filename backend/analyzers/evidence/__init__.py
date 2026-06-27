"""
Unified Evidence Intelligence Engine (Beetle 2.0, Phase 1.5).

Makes evidence a first-class, structured, reusable backend component. For every
finding it builds one aggregated, multi-source `Evidence` bundle — typed,
deduplicated evidence items with quality, verification status, reproduction
steps, correlation, a data-flow view and a deterministic content hash — so every
finding is explainable, reproducible and easy to verify by humans, AI,
consultants and bug bounty hunters.

It ONLY enriches evidence: no new detections, no suppression, no severity/report/
UI changes. Constants live in `config.py`; the model in `model.py`.

Public API:
    from analyzers.evidence import (
        build, annotate, get_engine,
        EvidenceEngine, Evidence, EvidenceItem,
        EvidenceType, Quality, Verification, Source, EVIDENCE_VERSION,
    )

Typical uses:
    * Single finding:  build(canonical_finding)              -> Evidence
    * Whole scan:      annotate(results)                      # additive evidence_bundle
"""
from .config import (
    EVIDENCE_VERSION,
    EvidenceType,
    Quality,
    Source,
    Verification,
)
from .engine import (
    EvidenceEngine,
    annotate,
    build,
    classify_type,
    collect_items,
    get_engine,
)
from .model import Evidence, EvidenceItem

__all__ = [
    "EvidenceEngine", "Evidence", "EvidenceItem", "EvidenceType", "Quality",
    "Verification", "Source", "build", "annotate", "get_engine",
    "classify_type", "collect_items", "EVIDENCE_VERSION",
]
