"""
Triage Engine — modular rule registry (Beetle 2.0, Phase 1.6).

Each rule is a small, independent policy: id, name, priority, a pure condition
over the :class:`TriageContext`, the decision it assigns, a confidence, a reason
(static or computed) and documentation. The engine evaluates them by priority —
there is NO giant if/else. Future engines register additional rules with
:func:`register`; nothing else changes.

Priority bands (higher = evaluated first):
  1000  SAFE-BY-DESIGN / high-value  — never suppressed
   800  application code (visible)
   ~810 secret false-positive/doc/generated (override app visibility — no value)
   600  generated code
   450  framework noise   /  400 SDK noise   (HiddenByDefault)
   300  low-signal / needs review
    50  default (visible)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .states import (
    APP_CONFIG_CATEGORIES,
    Decision,
    REAL_SECRET_STATUSES,
    WEAK_QUALITIES,
)


@dataclass
class Rule:
    id: str
    name: str
    priority: int
    decision: str
    confidence: int
    documentation: str
    condition: Callable           # (ctx) -> bool
    reason_fn: Callable | None = None   # (ctx) -> str
    static_reason: str = ""

    def reason(self, ctx) -> str:
        if self.reason_fn is not None:
            return self.reason_fn(ctx)
        return self.static_reason


# ── Reason builders (explainable, mirror the spec's examples) ────────────────
def _framework_reason(c) -> str:
    return (f"Finding originates from {c.owner_name or c.owner_type} ({c.owner_type}). "
            f"Ownership confidence is {c.owner_confidence}%. Evidence quality is "
            f"{(c.evidence_quality or 'missing').lower()}. No application-controlled "
            f"execution path exists (reachability: {c.reachability or 'none'}).")


def _sdk_reason(c) -> str:
    return (f"Finding is in third-party SDK {c.owner_name or c.owner_type} with weak "
            f"evidence ({(c.evidence_quality or 'missing').lower()}) and low overall "
            f"confidence ({c.overall_confidence}). No application reachability.")


def _real_secret_reason(c) -> str:
    return (f"Likely real secret ({c.secret_status}) — secrets are never auto-suppressed "
            f"regardless of the owning component; requires analyst review.")


# ── The rule set (priority order is enforced by the engine, not by list order) ─
RULES: list[Rule] = [
    # ─ SAFE-BY-DESIGN / high value ─────────────────────────────────────────
    Rule("SAFE-VALIDATED-SECRET", "Validated secret always highlighted", 1000,
         Decision.HIGHLIGHT, 100,
         "A live-validated secret is the highest-value finding and is never hidden.",
         lambda c: c.secret_status == "Validated Secret",
         static_reason="Validated live secret — always surfaced."),

    Rule("SAFE-REACHABLE-EXPORTED", "Reachable exported component", 960,
         Decision.REVIEW, 95,
         "An attacker-reachable exported component declared in the app manifest is "
         "always reviewable, even when its implementing class is a third-party SDK.",
         lambda c: c.is_exported and c.reachability == "YES",
         reason_fn=lambda c: (f"Reachable exported component ({c.category}) declared in the "
                              f"application manifest; never suppressed.")),

    Rule("SAFE-APP-OWNED-EXPOSURE", "App-declared exposure", 955,
         Decision.REVIEW, 90,
         "A manifest-declared exposure owned by the application is never suppressed.",
         lambda c: c.app_owned_exposure,
         static_reason="Application-declared attack surface; kept for review."),

    Rule("SAFE-APP-SECURITY-CONFIG", "Application security control/config", 950,
         Decision.SHOW, 90,
         "Application-scoped security surface (manifest, NSC, certificate, WebView, "
         "deep links, permissions, crypto, auth, storage) is never auto-suppressed.",
         lambda c: c.is_app_security_category and (c.is_app_code or c.is_manifest or c.is_app_config),
         reason_fn=lambda c: f"Application security surface ({c.category}); always visible."),

    Rule("HIGH-APP-SECRET", "High-value application secret", 940,
         Decision.HIGHLIGHT, 95,
         "A probable/possible secret in application code with strong evidence is high value.",
         lambda c: c.is_app_code and c.is_real_secret and c.evidence_quality in ("Excellent", "Good"),
         reason_fn=lambda c: (f"Application-owned {c.secret_status.lower()} with "
                              f"{c.evidence_quality.lower()} evidence.")),

    Rule("HIGH-APP-EXCELLENT", "High-confidence application finding", 900,
         Decision.HIGHLIGHT, 90,
         "Application code with excellent evidence and high confidence is highlighted.",
         lambda c: c.is_app_code and c.evidence_quality == "Excellent" and c.overall_confidence >= 75,
         reason_fn=lambda c: (f"Application code with excellent evidence and high "
                              f"confidence ({c.overall_confidence}).")),

    Rule("REAL-SECRET-REVIEW", "Real secret always reviewable", 880,
         Decision.REVIEW, 85,
         "A probable/possible secret is never auto-suppressed, even inside an SDK.",
         lambda c: c.is_real_secret,   # Validated already handled at 1000
         reason_fn=_real_secret_reason),

    # ─ Secret reject classes (override app visibility — no security value) ──
    Rule("FP-SECRET", "False-positive secret", 820,
         Decision.FALSE_POSITIVE, 90,
         "A value classified as a false positive by Secret Intelligence has no value.",
         lambda c: c.secret_status == "False Positive",
         static_reason="Secret Intelligence classified this value as a false positive."),

    Rule("DOC-SECRET", "Documentation / public value", 815,
         Decision.DOCUMENTATION, 90,
         "A documentation example or public key/cert is not a secret.",
         lambda c: c.secret_status in ("Documentation Example", "Public Value"),
         reason_fn=lambda c: f"Secret Intelligence classified this as a {c.secret_status.lower()}."),

    Rule("GENERATED-SECRET-CONSTANT", "Generated/crypto constant", 810,
         Decision.GENERATED_CODE, 88,
         "A crypto test vector / generated constant is not a real secret.",
         lambda c: c.secret_status == "Generated Constant",
         static_reason="Secret Intelligence classified this as a generated/crypto constant."),

    # ─ Application code (visible) ──────────────────────────────────────────
    Rule("APP-CODE-SHOW", "Application code", 800,
         Decision.SHOW, 85,
         "First-party application code is always at least shown.",
         lambda c: c.is_app_code,
         reason_fn=lambda c: f"First-party application code ({c.owner_name or 'application'})."),

    # ─ Generated code ──────────────────────────────────────────────────────
    Rule("GENERATED-CODE", "Generated code", 600,
         Decision.GENERATED_CODE, 85,
         "Machine-generated code (R, BuildConfig, DataBinding, Dagger/Hilt) is hidden by default.",
         lambda c: c.is_generated,
         reason_fn=lambda c: f"Finding is in machine-generated code ({c.owner_name or 'generated'})."),

    # ─ Framework / SDK noise (HiddenByDefault) ─────────────────────────────
    Rule("FRAMEWORK-NOISE", "Framework noise", 450,
         Decision.FRAMEWORK_NOISE, 85,
         "A framework/AndroidX/Jetpack finding with weak evidence and no app reachability "
         "is noise — hidden by default but retained.",
         lambda c: (c.is_framework and c.evidence_quality in WEAK_QUALITIES
                    and c.reachability != "YES" and not c.is_secret),
         reason_fn=_framework_reason),

    Rule("SDK-NOISE", "Third-party SDK noise", 400,
         Decision.SDK_NOISE, 80,
         "A third-party SDK finding with weak evidence and low confidence and no app "
         "reachability is noise — hidden by default but retained.",
         lambda c: (c.is_sdk and not c.is_app_code and c.evidence_quality in WEAK_QUALITIES
                    and c.overall_confidence < 60 and c.reachability != "YES"
                    and not c.is_secret),
         reason_fn=_sdk_reason),

    # ─ Low-signal / needs review ───────────────────────────────────────────
    Rule("UNRESOLVED-EVIDENCE", "Unresolved evidence", 350,
         Decision.NEEDS_HUMAN_REVIEW, 70,
         "A finding whose claimed source location could not be resolved needs human review.",
         lambda c: c.unresolved_evidence or c.verification == "Needs Review",
         static_reason="Claimed evidence could not be resolved; needs human review."),

    Rule("LOW-SIGNAL", "Low confidence + weak evidence", 300,
         Decision.NEEDS_HUMAN_REVIEW, 65,
         "Very low confidence with weak/missing evidence is sent to human review.",
         lambda c: c.overall_confidence < 40 and c.evidence_quality in ("Weak", "Missing"),
         reason_fn=lambda c: (f"Low overall confidence ({c.overall_confidence}) and "
                              f"{(c.evidence_quality or 'missing').lower()} evidence.")),

    # ─ Library default (visible, not noise) ────────────────────────────────
    Rule("LIBRARY-DEFAULT", "Library finding with usable evidence", 120,
         Decision.REVIEW, 60,
         "A library/framework finding that is not noise (e.g. it has good evidence) "
         "stays visible for review rather than being hidden.",
         lambda c: c.is_framework or c.is_sdk,
         static_reason="Library/framework finding with usable evidence; kept for review."),

    # ─ Default ─────────────────────────────────────────────────────────────
    Rule("DEFAULT", "Default — keep visible", 50,
         Decision.REVIEW, 50,
         "Anything not otherwise classified stays visible for review (never hidden).",
         lambda c: True,
         static_reason="No specific policy matched; kept visible for review."),
]


def register(rule: Rule) -> None:
    """Register an additional rule (future engines plug in here)."""
    RULES.append(rule)
