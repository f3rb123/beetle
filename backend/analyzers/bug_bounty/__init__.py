"""
Bug Bounty Intelligence & Reportability Engine (Beetle 2.0, Phase 1.8).

Beetle's final intelligence layer. It estimates whether an experienced
researcher/triager would consider a finding (or attack chain) actionable &
reportable — a deterministic 0-100 reportability score, a state, research value /
verification effort / business impact, explainable positive & negative signals,
and a recommended next step — by consuming EVERY prior engine (Ownership,
Confidence, Secret Intelligence, Evidence, Triage, Attack Chains).

It assists analysts; it never replaces human judgment, and it never modifies or
removes findings/chains (guidance only). Deterministic, explainable, modular
(signal registry + a program-policy hook for future banking/healthcare/… modes).

Public API:
    from analyzers.bug_bounty import (
        assess_finding, assess_chain, annotate, get_engine, register,
        BugBountyEngine, ProgramPolicy, State, NextStep, Signal, BB_VERSION,
    )
"""
from .config import BB_VERSION, DEFAULT_POLICY, Level, NextStep, ProgramPolicy, State
from .engine import (
    BBContext,
    BugBountyEngine,
    annotate,
    assess_chain,
    assess_finding,
    get_engine,
)
from .signals import Signal, register

__all__ = [
    "BugBountyEngine", "BBContext", "ProgramPolicy", "DEFAULT_POLICY", "State",
    "NextStep", "Level", "Signal", "assess_finding", "assess_chain", "annotate",
    "get_engine", "register", "BB_VERSION",
]
