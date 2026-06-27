"""
Triage Engine — deterministic decision engine (Beetle 2.0, Phase 1.6).

For every finding it extracts a normalized :class:`TriageContext` from the prior
engines (ownership, confidence, evidence, secret intelligence), evaluates the
modular rule registry by priority, and assigns one explainable triage decision +
visibility recommendation. NOTHING is deleted — `HiddenByDefault` simply means
"kept, hidden until the analyst opts in".

A final SAFE-BY-DESIGN guard guarantees that application code, validated secrets
and reachable exported components can never end up HiddenByDefault, independent
of the rules (belt-and-suspenders).

Pure and deterministic. Constants/states in `states.py`; policies in `rules.py`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from ..canonical_finding import CanonicalFinding
from . import rules as _rules
from . import states as S

log = logging.getLogger("cortex.triage")


# ════════════════════════════════════════════════════════════════════════════
# Triage context — the normalized view every rule reads
# ════════════════════════════════════════════════════════════════════════════
@dataclass
class TriageContext:
    owner_type: str = "Unknown"
    owner_name: str = ""
    owner_confidence: int = 0
    overall_confidence: int = 0
    exploitability_confidence: int = 0
    evidence_quality: str = "Missing"
    verification: str = "Unknown"
    reproducible: bool = False
    secret_status: str = ""
    is_secret: bool = False
    category: str = ""
    reachability: str = ""
    is_app_code: bool = False
    is_framework: bool = False
    is_sdk: bool = False
    is_generated: bool = False
    is_manifest: bool = False
    is_app_config: bool = False
    is_app_security_category: bool = False
    is_exported: bool = False
    app_owned_exposure: bool = False
    unresolved_evidence: bool = False
    is_real_secret: bool = False
    is_reject_secret: bool = False


_FRAMEWORK_OWNERS = {"AndroidFramework", "AppleFramework"}
_SDK_OWNERS = {"ThirdPartySDK", "VendorSDK", "OpenSourceLibrary", "GoogleSDK"}


def extract_context(finding: CanonicalFinding) -> TriageContext:
    raw = finding.raw or {}
    eb = finding.evidence_bundle or {}
    si = finding.secret_intelligence or {}
    owner = finding.owner_type or "Unknown"
    owner_name = finding.owner_name or ""
    cat = (finding.category or "").lower()

    name_l = owner_name.lower()
    # Frameworks for triage = platform frameworks + AndroidX/Jetpack + the hybrid
    # app frameworks (Flutter/React Native/Cordova/Capacitor/Unity/Xamarin), which
    # the Ownership Engine tags via framework_name.
    is_framework = owner in _FRAMEWORK_OWNERS or name_l.startswith("androidx") \
        or "jetpack" in name_l or "android support" in name_l \
        or bool(finding.framework_name)
    is_sdk = owner in _SDK_OWNERS and not is_framework

    secret_status = si.get("status", "") or ""
    is_secret = bool(si) or cat == "secrets" or \
        str(finding.source_module or "").upper() in ("EVIDENCE", "SECRET", "JWT_SCANNER")

    prim_type = (eb.get("primary") or {}).get("type", "")
    is_manifest = (finding.evidence_type or "").lower() == "manifest" \
        or prim_type in ("Manifest", "InfoPlist")
    is_app_config = is_manifest or cat in S.APP_CONFIG_CATEGORIES

    return TriageContext(
        owner_type=owner, owner_name=owner_name,
        owner_confidence=int(finding.owner_confidence or 0),
        overall_confidence=int(finding.overall_confidence or 0),
        exploitability_confidence=int(finding.exploitability_confidence or 0),
        evidence_quality=eb.get("quality") or "Missing",
        verification=eb.get("verification_status") or "Unknown",
        reproducible=bool(eb.get("reproducible")),
        secret_status=secret_status,
        is_secret=is_secret,
        category=finding.category or "",
        reachability=str(raw.get("reachability") or "").upper(),
        is_app_code=(owner == "Application"),
        is_framework=is_framework, is_sdk=is_sdk,
        is_generated=(owner == "GeneratedCode"),
        is_manifest=is_manifest, is_app_config=is_app_config,
        is_app_security_category=cat in S.SECURITY_CATEGORIES,
        is_exported=(cat == "attack surface" or bool(raw.get("exported"))),
        app_owned_exposure=bool(raw.get("app_owned_exposure")),
        unresolved_evidence=bool(raw.get("unresolved_evidence"))
        or eb.get("verification_status") == "Needs Review",
        is_real_secret=secret_status in S.REAL_SECRET_STATUSES,
        is_reject_secret=secret_status in S.REJECT_SECRET_STATUSES,
    )


def _is_protected(ctx: TriageContext) -> bool:
    """SAFE-BY-DESIGN: these can never be HiddenByDefault (reject-secrets aside)."""
    if ctx.is_reject_secret:
        return False
    if ctx.secret_status == "Validated Secret":
        return True
    if ctx.is_exported and ctx.reachability == "YES":
        return True
    if ctx.app_owned_exposure:
        return True
    if ctx.is_app_code:
        return True
    if ctx.is_app_security_category and (ctx.is_manifest or ctx.is_app_config):
        return True
    return False


# ════════════════════════════════════════════════════════════════════════════
# The engine
# ════════════════════════════════════════════════════════════════════════════
class TriageEngine:
    """Deterministic, priority-ordered rule evaluator. Build once."""

    version = S.TRIAGE_VERSION

    def __init__(self, rules: list | None = None):
        rule_list = rules if rules is not None else _rules.RULES
        # Highest priority first; stable tie-break by id → deterministic.
        self._rules = sorted(rule_list, key=lambda r: (-r.priority, r.id))

    def evaluate(self, finding: CanonicalFinding) -> dict:
        ctx = extract_context(finding)
        matched = [r for r in self._rules if _safe_match(r, ctx)]
        chosen = matched[0]  # DEFAULT rule guarantees a match
        decision = chosen.decision
        visibility = S.visibility_for(decision)
        reason = chosen.reason(ctx)
        safe_override = False

        # SAFE-BY-DESIGN guard: a protected finding must never be hidden.
        if visibility == S.Visibility.HIDDEN_BY_DEFAULT and _is_protected(ctx):
            decision = S.Decision.REVIEW
            visibility = S.Visibility.REVIEW
            reason = ("SAFE-BY-DESIGN override: this finding is application-owned / "
                      "validated / reachable and is never hidden. (" + reason + ")")
            safe_override = True

        return {
            "decision": decision,
            "visibility": visibility,
            "reason": reason,
            "rule_id": chosen.id,
            "rule_name": chosen.name,
            "rule_priority": chosen.priority,
            "confidence": chosen.confidence,
            "documentation": chosen.documentation,
            "matched_rules": [r.id for r in matched],
            "safe_override": safe_override,
            "inputs": {
                "owner_type": ctx.owner_type, "owner_name": ctx.owner_name,
                "owner_confidence": ctx.owner_confidence,
                "overall_confidence": ctx.overall_confidence,
                "evidence_quality": ctx.evidence_quality,
                "verification": ctx.verification,
                "secret_status": ctx.secret_status,
                "reachability": ctx.reachability or "none",
                "is_app_code": ctx.is_app_code,
            },
            "version": self.version,
        }


def _safe_match(rule, ctx) -> bool:
    """Evaluate a rule condition defensively — a buggy rule never breaks triage."""
    try:
        return bool(rule.condition(ctx))
    except Exception:
        log.debug("triage rule %s condition raised; skipping", rule.id)
        return False


# ── cached singleton + public API ────────────────────────────────────────────
_ENGINE: TriageEngine | None = None


def get_engine() -> TriageEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = TriageEngine()
    return _ENGINE


def triage(finding: CanonicalFinding) -> dict:
    """Public convenience: triage one CanonicalFinding."""
    return get_engine().evaluate(finding)


def annotate(results: dict) -> dict:
    """Pipeline integration — attach a `triage` decision to every finding.

    ADDITIVE ONLY and NON-DESTRUCTIVE: it writes a `triage` dict and never
    removes, hides, re-severities or reorders findings. Reports/UI decide what to
    show from `triage.visibility`. Runs last (after ownership/confidence/evidence/
    secret intelligence) — the final quality gate before Attack Chain v2.
    """
    engine = get_engine()
    by_decision: dict[str, int] = {}
    by_visibility: dict[str, int] = {}
    n = 0
    for key in ("findings", "suppressed_findings"):
        for f in results.get(key) or []:
            if not isinstance(f, dict):
                continue
            cf = CanonicalFinding.from_legacy(f, platform=results.get("platform"))
            t = engine.evaluate(cf)
            f["triage"] = t
            if key == "findings":
                by_decision[t["decision"]] = by_decision.get(t["decision"], 0) + 1
                by_visibility[t["visibility"]] = by_visibility.get(t["visibility"], 0) + 1
            n += 1
    total = sum(by_visibility.values())
    hidden = by_visibility.get(S.Visibility.HIDDEN_BY_DEFAULT, 0)
    results["triage_summary"] = {
        "by_decision": by_decision,
        "by_visibility": by_visibility,
        "total": total,
        "hidden_by_default": hidden,
        "visible": total - hidden,
        "noise_reduction_pct": round(hidden / total * 100) if total else 0,
        "version": engine.version,
    }
    log.info("[triage] %d findings | visibility=%s | noise hidden=%d/%d",
             n, by_visibility, hidden, total)
    return results
