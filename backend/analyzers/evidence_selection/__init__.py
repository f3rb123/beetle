"""
Evidence Selection & Proof Validation Engine (Beetle 2.0, Phase 1.96).

Consistently selects the strongest, most reportable, application-relevant proof for
every finding — and explains why — instead of letting an AndroidX / Google Play
Services / generated-code file win on raw confidence. Demotes weaker proofs to
supporting/rejected so reports stop overwhelming analysts with irrelevant files.

Public API::

    from analyzers import evidence_selection
    evidence_selection.annotate(results, platform="android")   # the pipeline stage
    evidence_selection.select(finding, ctx)                     # one finding
    evidence_selection.register_contributor(fn)                # future scoring inputs

Reuses the Ownership Engine (library detection), Fusion (corroboration), and the
Reachability / Attack-Chain / Validation signals already on each finding — no
detection logic is duplicated. See ``internal/EVIDENCE_SELECTION_ENGINE.md``.
"""
from __future__ import annotations

from . import library, scoring
from .config import SELECTION_VERSION
from .engine import annotate, bug_bounty_enabled, select
from .scoring import register_contributor

__all__ = [
    "annotate", "select", "register_contributor", "bug_bounty_enabled",
    "library", "scoring", "SELECTION_VERSION",
]
