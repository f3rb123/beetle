"""
Intelligent Finding Triage & Noise Reduction Engine (Beetle 2.0, Phase 1.6).

A modular, deterministic, explainable decision engine that gives every finding a
triage decision + visibility recommendation by reasoning over the prior engines
(Ownership, Confidence, Evidence, Secret Intelligence). It dramatically reduces
analyst noise while guaranteeing important findings are never hidden.

Philosophy: *"Never suppress because something is a library. Suppress because the
finding lacks meaningful security value."*

It NEVER deletes a finding: `HiddenByDefault` means "kept, hidden until opt-in".
No severity/confidence/ownership/evidence changes. This is the final quality gate
before Attack Chain v2.

Public API:
    from analyzers.triage import (
        triage, annotate, get_engine, register,
        TriageEngine, TriageContext, Rule, Decision, Visibility, TRIAGE_VERSION,
    )
"""
from .engine import TriageContext, TriageEngine, annotate, extract_context, get_engine, triage
from .rules import RULES, Rule, register
from .states import TRIAGE_VERSION, Decision, Visibility

__all__ = [
    "TriageEngine", "TriageContext", "Rule", "Decision", "Visibility",
    "triage", "annotate", "get_engine", "register", "extract_context",
    "RULES", "TRIAGE_VERSION",
]
