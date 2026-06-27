"""
Bug Bounty Intelligence Engine — modular signal registry (Beetle 2.0, Phase 1.8).

Each signal is a small, independent rule over the :class:`BBContext`: an id (its
weight lives in `config.SIGNAL_WEIGHTS`, so a program policy can override it), a
kind (positive/negative), a pure condition, and a human reason. The engine sums
the firing signals — there is no giant if/else, and future engines/policies add
signals with :func:`register`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class Signal:
    id: str
    name: str
    kind: str               # "positive" | "negative"
    condition: Callable     # (ctx) -> bool
    reason: str

    def fires(self, ctx) -> bool:
        try:
            return bool(self.condition(ctx))
        except Exception:
            return False


# ── Positive signals (increase reportability) ────────────────────────────────
POSITIVE_SIGNALS: list[Signal] = [
    Signal("app_owned", "Application-owned code", "positive",
           lambda c: c.is_app_code, "Application-owned code"),
    Signal("reachable", "Reachable attack path", "positive",
           lambda c: c.reachability == "YES", "Reachable attack path"),
    Signal("validated_secret", "Validated secret", "positive",
           lambda c: c.secret_status == "Validated Secret", "Validated live secret"),
    Signal("real_secret", "Real secret", "positive",
           lambda c: c.is_real_secret and c.secret_status != "Validated Secret",
           "Likely real secret"),
    Signal("excellent_evidence", "Excellent evidence", "positive",
           lambda c: c.evidence_quality == "Excellent", "Excellent, reproducible evidence"),
    Signal("good_evidence", "Good evidence", "positive",
           lambda c: c.evidence_quality == "Good", "Good evidence"),
    Signal("verified", "Verified evidence", "positive",
           lambda c: c.verification == "Verified", "Evidence verified against source"),
    Signal("in_attack_chain", "Participates in an attack chain", "positive",
           lambda c: c.in_chain_required, "Required link in a correlated attack chain"),
    Signal("high_impact_category", "High-impact vulnerability class", "positive",
           lambda c: c.is_high_impact_category and (c.is_app_code or c.is_app_security_category),
           "High-impact vulnerability class in application code"),
    Signal("exported_reachable", "Reachable exported component", "positive",
           lambda c: c.is_exported and c.reachability == "YES", "Reachable exported component"),
    Signal("triage_highlight", "Triage highlighted", "positive",
           lambda c: c.triage_decision == "Highlight", "Triage flagged as high value"),
    Signal("high_confidence", "High confidence", "positive",
           lambda c: c.overall_confidence >= 75, "High detection confidence"),
    Signal("app_security_surface", "Application security surface", "positive",
           lambda c: c.is_app_security_category and (c.is_app_code or c.is_manifest),
           "Application security surface (manifest/NSC/cert/WebView/permission)"),
]

# ── Negative signals (reduce reportability) ──────────────────────────────────
NEGATIVE_SIGNALS: list[Signal] = [
    Signal("framework", "Framework internals", "negative",
           lambda c: c.is_framework and not c.in_chain_required, "Platform framework internals"),
    Signal("sdk", "Third-party SDK", "negative",
           lambda c: c.is_sdk and not c.is_app_code and not c.in_chain_required, "Third-party SDK code"),
    Signal("generated", "Generated code", "negative",
           lambda c: c.is_generated, "Machine-generated code"),
    Signal("fp_secret", "False-positive secret", "negative",
           lambda c: c.secret_status in ("False Positive",), "False-positive / placeholder secret"),
    Signal("doc_example", "Documentation example", "negative",
           lambda c: c.secret_status in ("Documentation Example", "Public Value")
           or c.triage_decision == "Documentation", "Documentation example / public value"),
    Signal("weak_evidence", "Weak evidence", "negative",
           lambda c: c.evidence_quality in ("Weak", "Missing"), "Weak or missing evidence"),
    Signal("unreachable", "Unreachable", "negative",
           lambda c: c.reachability == "NO", "No reachable attack path"),
    Signal("no_app_control", "No application control", "negative",
           lambda c: not c.is_app_code and not c.is_app_security_category and not c.in_chain_required,
           "No application-controlled execution path"),
    Signal("triage_hidden", "Hidden by triage", "negative",
           lambda c: c.triage_visibility == "HiddenByDefault" and not c.in_chain_required,
           "Triage hides this by default"),
    Signal("low_confidence", "Low confidence", "negative",
           lambda c: c.overall_confidence < 40, "Low detection confidence"),
    Signal("unresolved_evidence", "Unresolved evidence", "negative",
           lambda c: c.unresolved or c.verification == "Needs Review",
           "Claimed evidence could not be resolved"),
    Signal("framework_noise", "Framework noise", "negative",
           lambda c: c.triage_decision == "FrameworkNoise", "Triage classified as framework noise"),
    Signal("sdk_noise", "SDK noise", "negative",
           lambda c: c.triage_decision == "SDKNoise", "Triage classified as SDK noise"),
    Signal("informational_category", "Informational category", "negative",
           lambda c: c.is_informational_category, "Informational / metadata finding"),
]

ALL_SIGNALS = POSITIVE_SIGNALS + NEGATIVE_SIGNALS


def register(signal: Signal) -> None:
    """Register an additional signal (future engines / program policies)."""
    ALL_SIGNALS.append(signal)
    (POSITIVE_SIGNALS if signal.kind == "positive" else NEGATIVE_SIGNALS).append(signal)
