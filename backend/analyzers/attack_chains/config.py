"""
Attack Chain Engine v2 — configuration (Beetle 2.0, Phase 1.7).

THE single tuning file: scoring weights, evidence/severity maps, and the
eligibility rules that keep framework noise / suppressed / false-positive
findings out of chains. All derived from the prior engines' outputs — no
arbitrary scores. `engine.py` is logic only.
"""
from __future__ import annotations

CHAIN_VERSION = "2.0.0"

# ── Evidence quality → numeric score (from the Evidence Engine, Phase 1.5) ────
EVIDENCE_SCORE = {"Excellent": 100, "Good": 80, "Moderate": 60, "Weak": 35, "Missing": 10}
EVIDENCE_RANK = {"Excellent": 0, "Good": 1, "Moderate": 2, "Weak": 3, "Missing": 4}
EVIDENCE_BY_RANK = {0: "Excellent", 1: "Good", 2: "Moderate", 3: "Weak", 4: "Missing"}

# ── Chain confidence: blend member confidence with member evidence, then scale
# by how reachable the entry point is. Weights sum to 1.0 within the blend. ────
CONFIDENCE_BLEND = {"member_confidence": 0.55, "member_evidence": 0.45}
ENTRY_REACH_MULTIPLIER = {
    "external_reachable": 1.0,   # exported/deeplink/network proven reachable
    "external": 0.85,            # external entry, reachability unproven
    "distribution": 0.95,        # secret/material extractable from the shipped APK
    "device": 0.75,              # needs ADB / physical / rooted device
}

# ── Exploitability base by entry kind + bonuses (capped at 100) ───────────────
EXPLOIT_BASE = {
    "external_reachable": 80, "external": 55, "distribution": 70, "device": 45,
}
EXPLOIT_APP_CONTROL_BONUS = 10   # the required sink is in application code
EXPLOIT_BLOCKED_PENALTY = 35     # a mitigation breaks the chain

# ── Severity floor by attacker goal (chain-level only; never changes a finding) ─
GOAL_SEVERITY = {
    "rce": "critical", "command_injection": "critical", "code_loading": "critical",
    "sql_injection": "high", "file_disclosure": "high", "token_theft": "high",
    "credential_abuse": "high", "auth_bypass": "high", "mitm": "high",
    "data_exposure": "medium", "insecure_storage": "medium", "weak_crypto": "medium",
    "info_disclosure": "medium", "default": "medium",
}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_BY_RANK = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}

# Below this exploitability the chain severity is dropped one notch (it exists but
# is hard to exploit); a blocked chain is also dropped one notch.
SEVERITY_DOWNGRADE_EXPLOIT = 40

# Confidence ceiling for an injection/RCE chain with no taint proof (reachability
# gate, Flaw B). "cap confidence below 60" — a heuristic chain never reads as
# high-confidence on capability co-occurrence alone.
HEURISTIC_CONFIDENCE_CAP = 59


# ── Eligibility — which findings may participate (SAFE CHAINING) ──────────────
# Triage decisions (Phase 1.6) that exclude a finding from being a REQUIRED link.
# These are noise / non-findings; they may only appear as supporting *context*
# when they provide a structural vehicle (a WebView, an exported component, …).
EXCLUDED_DECISIONS = frozenset((
    "FalsePositive", "Documentation", "GeneratedCode",
))
# Noise that can still be SUPPORTING context (a framework WebView is the vehicle).
SUPPORTING_ONLY_DECISIONS = frozenset(("FrameworkNoise", "SDKNoise"))
# Visibilities that are required-eligible.
REQUIRED_VISIBILITIES = frozenset(("Show", "Highlight", "Review"))

# Secret statuses that disqualify a "secret" link (not a real secret).
REJECT_SECRET_STATUSES = frozenset((
    "False Positive", "Documentation Example", "Public Value", "Generated Constant",
))
REAL_SECRET_STATUSES = frozenset(("Validated Secret", "Probable Secret", "Possible Secret"))


def sev_rank(s: str) -> int:
    return _SEV_RANK.get(str(s or "").lower(), 4)


def sev_by_rank(r: int) -> str:
    return _SEV_BY_RANK.get(max(0, min(4, r)), "info")
