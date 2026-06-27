"""
Ownership Engine (Beetle 2.0, Phase 1.2).

A reusable, data-driven service that classifies WHO OWNS the code behind every
finding — Application, ThirdPartySDK, AndroidFramework, GoogleSDK, AppleFramework,
VendorSDK, OpenSourceLibrary, GeneratedCode or Unknown — with an explainable
reason and confidence.

Public API:
    from analyzers.ownership import (
        classify, enrich, annotate, get_engine,
        OwnershipEngine, OwnershipResult, OwnershipContext, OwnerType,
        context_from_results,
    )

Typical uses:
    * Single finding:  enrich(canonical_finding, ctx)
    * Whole scan:      annotate(results)          # additive owner_* on each finding
    * Custom engine:   OwnershipEngine(my_fingerprints).classify(finding, ctx)

This package ONLY determines ownership. It does not filter, suppress, score
findings, or change severity — those are later phases that consume this data.
"""
from .engine import (
    OwnershipEngine,
    annotate,
    classify,
    context_from_results,
    derive_signals,
    enrich,
    get_engine,
)
from .types import (
    Confidence,
    OwnershipContext,
    OwnershipResult,
    OwnerType,
    Stage,
)

__all__ = [
    "OwnershipEngine", "OwnershipResult", "OwnershipContext", "OwnerType",
    "Stage", "Confidence", "classify", "enrich", "annotate", "get_engine",
    "context_from_results", "derive_signals",
]
