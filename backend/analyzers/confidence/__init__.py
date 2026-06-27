"""
Confidence Engine (Beetle 2.0, Phase 1.3).

A deterministic, explainable, data-driven service that scores HOW MUCH BEETLE
TRUSTS each finding across five independent dimensions — detection, ownership,
evidence, context, exploitability — plus a weighted overall, always retaining the
full breakdown and a human-readable reason.

It does NOT determine severity, exploitability scoring, or suppression. It only
measures confidence. Every constant lives in `config.py` (the single tuning file).

Public API:
    from analyzers.confidence import (
        classify, enrich, annotate, get_engine,
        ConfidenceEngine, ConfidenceResult, CONFIDENCE_VERSION,
    )

Typical uses:
    * Single finding:  enrich(canonical_finding)
    * Whole scan:      annotate(results)        # additive confidence_* on each finding
"""
from .config import CONFIDENCE_VERSION
from .engine import (
    ConfidenceEngine,
    ConfidenceResult,
    annotate,
    classify,
    enrich,
    get_engine,
)

__all__ = [
    "ConfidenceEngine", "ConfidenceResult", "classify", "enrich", "annotate",
    "get_engine", "CONFIDENCE_VERSION",
]
