"""
Attack Chain Engine v2 (Beetle 2.0, Phase 1.7) — Beetle's flagship analysis.

Builds realistic, evidence-backed, explainable attacker journeys by reasoning
over EVERY prior engine (Ownership, Confidence, Secret Intelligence, Evidence,
Triage) plus the manifest attack surface and reachability. Each chain answers:
where the attack begins, what conditions are required, which findings
participate (required vs supporting), the attacker's objective, what breaks the
chain, and how confident/exploitable it is — with a graph and an analyst
narrative.

It does NOT chain "everything": framework noise, suppressed findings,
documentation examples, false-positive secrets and generated code are never
required links (SAFE CHAINING). Deterministic, modular (capabilities + templates),
and additive — it writes `results['attack_chains_v2']` and leaves the legacy
chain output, findings, severity, reports and UI untouched.

Public API:
    from analyzers.attack_chains import (
        build_chains, annotate, get_engine, register,
        AttackChainEngine, AttackChain, ChainTemplate, tag_capabilities,
        chain_role, CHAIN_VERSION,
    )
"""
from .bridge import annotate_findings, to_first_class_findings, to_quick_summary
from .config import CHAIN_VERSION
from .engine import (
    AttackChainEngine,
    annotate,
    build_chains,
    chain_role,
    get_engine,
    tag_capabilities,
)
from .model import AttackChain, ChainEdge, ChainGraph, ChainNode
from .templates import ChainTemplate, register

__all__ = [
    "AttackChainEngine", "AttackChain", "ChainTemplate", "ChainGraph",
    "ChainNode", "ChainEdge", "build_chains", "annotate", "get_engine",
    "register", "tag_capabilities", "chain_role", "CHAIN_VERSION",
    "annotate_findings", "to_first_class_findings", "to_quick_summary",
]
