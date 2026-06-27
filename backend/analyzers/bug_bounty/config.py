"""
Bug Bounty Intelligence Engine — configuration (Beetle 2.0, Phase 1.8).

THE single tuning file: reportability states, the weighted signal table, score
thresholds, the value/effort/impact maps, and the (extensible, not-yet-populated)
program-policy hook. All data, all documented; `engine.py` is logic only.

Philosophy: estimate whether an experienced researcher/triager would consider a
finding actionable & reportable. Guidance only — it assists analysts, never
replaces human judgment.
"""
from __future__ import annotations

from dataclasses import dataclass, field

BB_VERSION = "1.0.0"


# ════════════════════════════════════════════════════════════════════════════
# Reportability states (extensible vocabulary)
# ════════════════════════════════════════════════════════════════════════════
class State:
    LIKELY_REPORTABLE = "Likely Reportable"
    LIKELY_VALID = "Likely Valid"
    NEEDS_MANUAL_VERIFICATION = "Needs Manual Verification"
    NEEDS_EXPLOITATION = "Needs Exploitation"
    NEEDS_RUNTIME_VALIDATION = "Needs Runtime Validation"
    INFORMATIONAL = "Informational"
    PROBABLY_DUPLICATE = "Probably Duplicate"
    FRAMEWORK_ISSUE = "Framework Issue"
    SDK_ISSUE = "SDK Issue"
    GENERATED_CODE = "Generated Code"
    DOCUMENTATION_EXAMPLE = "Documentation Example"
    LIKELY_OUT_OF_SCOPE = "Likely Out of Scope"
    FALSE_POSITIVE = "False Positive"
    UNKNOWN = "Unknown"


# ════════════════════════════════════════════════════════════════════════════
# Weighted signals — the score is base + Σ(positive) − Σ(negative), clamped.
# Weights are precision priors from real triage experience; tune here only.
# ════════════════════════════════════════════════════════════════════════════
BASE_SCORE = 50

SIGNAL_WEIGHTS = {
    # ── positive ──────────────────────────────────────────────────────────
    "app_owned": 15,              # first-party application code
    "reachable": 12,              # an attacker can actually reach it
    "validated_secret": 22,       # a live-verified secret is gold
    "real_secret": 10,            # probable/possible real secret
    "excellent_evidence": 12,     # exact file/line/snippet/symbol
    "good_evidence": 6,
    "verified": 8,                # evidence verified against source
    "in_attack_chain": 16,        # required link in a v2 attack chain
    "high_impact_category": 12,   # SQLi/RCE/auth/file-disclosure/… in app code
    "exported_reachable": 10,     # reachable exported component
    "triage_highlight": 8,        # triage flagged it high value
    "high_confidence": 8,         # overall confidence >= 75
    "app_security_surface": 6,    # app manifest / NSC / cert / webview / permission

    # ── negative ──────────────────────────────────────────────────────────
    "framework": 20,              # platform framework internals
    "sdk": 15,                    # third-party SDK code
    "generated": 25,              # machine-generated code
    "fp_secret": 32,              # false-positive / placeholder secret
    "doc_example": 26,            # documentation example / public value
    "weak_evidence": 12,
    "unreachable": 12,            # reachability == NO
    "no_app_control": 10,         # not app code and not app security surface
    "triage_hidden": 14,          # triage HiddenByDefault
    "low_confidence": 10,         # overall confidence < 40
    "unresolved_evidence": 15,    # claimed location unresolved / needs review
    "framework_noise": 18,        # triage FrameworkNoise
    "sdk_noise": 12,              # triage SDKNoise
    "informational_category": 8,  # logging/meta/info
}


# ── Score → reportability band (the score-based fallback state) ──────────────
SCORE_LIKELY_REPORTABLE = 80
SCORE_LIKELY_VALID = 65
SCORE_NEEDS_VERIFICATION = 45
SCORE_INFORMATIONAL = 30   # below this → Informational
# Framework/SDK findings below this are Likely Out of Scope.
SCORE_OUT_OF_SCOPE = 35


# ── Categories that carry inherent business impact when app-owned ────────────
HIGH_IMPACT_CATEGORIES = frozenset((
    "sql injection", "command injection", "rce", "code execution",
    "file disclosure", "path traversal", "authentication", "authorization",
    "privilege escalation", "sensitive data exposure", "webview", "ipc",
    "broadcast", "content provider", "deeplinks", "deeplink", "insecure storage",
    "data storage", "cryptography", "certificate", "taint analysis",
    "business logic", "attack surface",
))
INFORMATIONAL_CATEGORIES = frozenset((
    "meta", "logging", "info", "informational", "intelligence", "trackers",
    "sdks", "emails", "app info",
))
# Application security *surface* (manifest/config), distinct from high-impact code
# vulnerability classes — drives the `app_security_surface` positive signal.
APP_SECURITY_CATEGORIES = frozenset((
    "network security", "certificate", "permissions", "webview", "deeplinks",
    "deeplink", "data storage", "code signing", "biometric", "attack surface",
    "components", "component", "privacy", "configuration",
))


# ── Research value / verification effort / business impact bands ─────────────
class Level:
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class NextStep:
    INVESTIGATE = "Investigate Further"
    RUNTIME = "Runtime Validation Recommended"
    CONFIRM_EXPLOIT = "Exploitability Needs Confirmation"
    STRONG_CANDIDATE = "Strong Candidate for Reporting"
    MANUAL_REVIEW = "Requires Manual Review"
    NOT_WORTH = "Likely Not Worth Reporting"
    SDK_NOISE = "Likely SDK Noise"
    DOC_ARTIFACT = "Likely Documentation Artifact"


# Review priority bands (P1 highest).
def priority_for(score: int, business_impact: str) -> str:
    if score >= 80 and business_impact == Level.HIGH:
        return "P1"
    if score >= 65:
        return "P2"
    if score >= 45:
        return "P3"
    return "P4"


# ════════════════════════════════════════════════════════════════════════════
# Program policy — EXTENSIBILITY HOOK (not populated yet)
# ════════════════════════════════════════════════════════════════════════════
# Future program-specific policies (banking / healthcare / government /
# enterprise / consumer / a specific bounty platform) can adjust signal weights
# and category emphasis WITHOUT touching engine logic. The default policy is
# neutral. Engines accept a policy; this phase ships only the neutral default.
@dataclass
class ProgramPolicy:
    name: str = "default"
    weight_overrides: dict = field(default_factory=dict)   # signal_id -> weight
    category_boosts: dict = field(default_factory=dict)    # category(lower) -> +score
    min_reportable_score: int = SCORE_LIKELY_VALID

    def weight(self, signal_id: str) -> int:
        return self.weight_overrides.get(signal_id, SIGNAL_WEIGHTS.get(signal_id, 0))


DEFAULT_POLICY = ProgramPolicy()
