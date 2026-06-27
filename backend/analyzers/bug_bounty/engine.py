"""
Bug Bounty Intelligence Engine — engine (Beetle 2.0, Phase 1.8).

Estimates whether an experienced researcher/triager would consider a finding (or
an attack chain) actionable & reportable, by reasoning over EVERY prior engine's
output. Produces a deterministic 0-100 reportability score, a state, research
value / verification effort / business impact, explainable positive & negative
signals, and a recommended next step.

Guidance only — it NEVER modifies or removes findings/chains; it adds a
`bug_bounty` object. Deterministic, explainable, modular. Constants/states in
`config.py`; signals in `signals.py`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from . import config as C
from . import signals as SIG

log = logging.getLogger("cortex.bug_bounty")

_EVIDENCE_SCORE = {"Excellent": 100, "Good": 80, "Moderate": 60, "Weak": 35, "Missing": 10}
_FRAMEWORK_OWNERS = {"AndroidFramework", "AppleFramework"}
_SDK_OWNERS = {"ThirdPartySDK", "VendorSDK", "OpenSourceLibrary", "GoogleSDK"}
_REAL_SECRETS = {"Validated Secret", "Probable Secret", "Possible Secret"}
_REJECT_SECRETS = {"False Positive", "Documentation Example", "Public Value", "Generated Constant"}


def _clamp(n) -> int:
    return max(0, min(100, int(round(n))))


# ════════════════════════════════════════════════════════════════════════════
# Context
# ════════════════════════════════════════════════════════════════════════════
@dataclass
class BBContext:
    is_app_code: bool = False
    is_framework: bool = False
    is_sdk: bool = False
    is_generated: bool = False
    overall_confidence: int = 0
    exploitability_confidence: int = 0
    evidence_quality: str = "Missing"
    verification: str = "Unknown"
    reachability: str = ""
    secret_status: str = ""
    is_real_secret: bool = False
    is_reject_secret: bool = False
    category: str = ""
    triage_decision: str = ""
    triage_visibility: str = ""
    in_chain_required: bool = False
    in_chain_supporting: bool = False
    chain_confidence: int = 0
    is_high_impact_category: bool = False
    is_informational_category: bool = False
    is_app_security_category: bool = False
    is_exported: bool = False
    is_manifest: bool = False
    unresolved: bool = False
    is_taint: bool = False


def _extract(f: dict, chain_ctx: dict) -> BBContext:
    owner = f.get("owner_type") or "Unknown"
    eb = f.get("evidence_bundle") or {}
    si = f.get("secret_intelligence") or {}
    tri = f.get("triage") or {}
    cat = (f.get("category") or "").lower()
    secret_status = si.get("status") or f.get("secret_status") or ""
    fid = f.get("canonical_id") or f.get("rule_id") or f.get("id") or f.get("title")
    framework = owner in _FRAMEWORK_OWNERS or bool(f.get("framework_name")) \
        or str(f.get("owner_name") or "").lower().startswith("androidx")
    return BBContext(
        is_app_code=(owner == "Application"),
        is_framework=framework,
        is_sdk=(owner in _SDK_OWNERS and not framework),
        is_generated=(owner == "GeneratedCode"),
        overall_confidence=int(f.get("overall_confidence") or 0),
        exploitability_confidence=int(f.get("exploitability_confidence") or 0),
        evidence_quality=eb.get("quality") or "Missing",
        verification=eb.get("verification_status") or "Unknown",
        reachability=str(f.get("reachability") or "").upper(),
        secret_status=secret_status,
        is_real_secret=secret_status in _REAL_SECRETS,
        is_reject_secret=secret_status in _REJECT_SECRETS,
        category=cat,
        triage_decision=tri.get("decision", ""),
        triage_visibility=tri.get("visibility", ""),
        in_chain_required=fid in chain_ctx.get("required", set()),
        in_chain_supporting=fid in chain_ctx.get("supporting", set()),
        chain_confidence=chain_ctx.get("conf", {}).get(fid, 0),
        is_high_impact_category=cat in C.HIGH_IMPACT_CATEGORIES,
        is_informational_category=cat in C.INFORMATIONAL_CATEGORIES,
        is_app_security_category=cat in C.APP_SECURITY_CATEGORIES,
        is_exported=(cat == "attack surface" or bool(f.get("exported"))),
        is_manifest=(f.get("evidence_type") == "manifest"
                     or (eb.get("primary") or {}).get("type") in ("Manifest", "InfoPlist")),
        unresolved=bool(f.get("unresolved_evidence")) or eb.get("verification_status") == "Needs Review",
        is_taint=(cat == "taint analysis"),
    )


# ════════════════════════════════════════════════════════════════════════════
# The engine
# ════════════════════════════════════════════════════════════════════════════
class BugBountyEngine:
    version = C.BB_VERSION

    def __init__(self, policy: C.ProgramPolicy | None = None):
        self.policy = policy or C.DEFAULT_POLICY

    # ── finding assessment ───────────────────────────────────────────────────
    def assess_finding(self, f: dict, chain_ctx: dict | None = None) -> dict:
        ctx = _extract(f, chain_ctx or {})
        positives, negatives, pos_sum, neg_sum = [], [], 0, 0
        for s in SIG.ALL_SIGNALS:
            if not s.fires(ctx):
                continue
            w = self.policy.weight(s.id)
            entry = {"id": s.id, "name": s.name, "weight": w, "reason": s.reason}
            if s.kind == "positive":
                positives.append(entry); pos_sum += w
            else:
                negatives.append(entry); neg_sum += w

        boost = self.policy.category_boosts.get(ctx.category, 0)
        score = _clamp(C.BASE_SCORE + pos_sum - neg_sum + boost)

        state = self._state(ctx, score)
        business = self._business_impact(ctx, state)
        research = self._research_value(ctx, score, state)
        effort = self._verification_effort(ctx)
        next_step = self._next_step(state)
        priority = C.priority_for(score, business)

        return {
            "reportability_score": score,
            "reportability_state": state,
            "research_value": research,
            "verification_effort": effort,
            "business_impact": business,
            "review_priority": priority,
            "recommended_next_step": next_step,
            "positive_signals": positives,
            "negative_signals": negatives,
            "reasoning": [("✓ " + p["reason"]) for p in positives]
                         + [("✗ " + n["reason"]) for n in negatives],
            "score_breakdown": {"base": C.BASE_SCORE, "positive": pos_sum,
                                "negative": neg_sum, "category_boost": boost},
            "version": self.version,
            "policy": self.policy.name,
        }

    # ── state ────────────────────────────────────────────────────────────────
    def _state(self, ctx: BBContext, score: int) -> str:
        S = C.State
        # Deterministic hard classifiers first (specific secret classes before the
        # generic false-positive bucket).
        if ctx.secret_status in ("Documentation Example", "Public Value") \
                or ctx.triage_decision == "Documentation":
            return S.DOCUMENTATION_EXAMPLE
        if ctx.secret_status == "Generated Constant" or ctx.is_generated \
                or ctx.triage_decision == "GeneratedCode":
            return S.GENERATED_CODE
        if ctx.secret_status == "False Positive" or ctx.triage_decision == "FalsePositive":
            return S.FALSE_POSITIVE
        if not ctx.in_chain_required:
            if (ctx.is_framework or ctx.is_sdk) and score < C.SCORE_OUT_OF_SCOPE:
                return S.LIKELY_OUT_OF_SCOPE
            if ctx.is_framework and score < C.SCORE_NEEDS_VERIFICATION:
                return S.FRAMEWORK_ISSUE
            if ctx.is_sdk and score < C.SCORE_NEEDS_VERIFICATION:
                return S.SDK_ISSUE
        # Realistic triager gates: an unreachable finding (or an unproven taint
        # flow) is not "reportable" until reachability/exploitation is shown.
        if not ctx.in_chain_required and ctx.secret_status != "Validated Secret":
            if ctx.reachability == "NO":
                return S.NEEDS_RUNTIME_VALIDATION
            if ctx.is_taint and ctx.reachability != "YES" and score < C.SCORE_LIKELY_REPORTABLE:
                return S.NEEDS_EXPLOITATION
        # Score bands.
        if score >= C.SCORE_LIKELY_REPORTABLE:
            return S.LIKELY_REPORTABLE
        if score >= C.SCORE_LIKELY_VALID:
            return S.LIKELY_VALID
        if score < C.SCORE_INFORMATIONAL:
            return S.INFORMATIONAL
        # Mid band — what kind of verification is needed?
        if ctx.unresolved or ctx.verification == "Needs Review":
            return S.NEEDS_MANUAL_VERIFICATION
        if ctx.reachability == "NO":
            return S.NEEDS_RUNTIME_VALIDATION
        if ctx.is_taint or ctx.is_exported:
            return S.NEEDS_EXPLOITATION
        return S.NEEDS_MANUAL_VERIFICATION

    # ── value / effort / impact ──────────────────────────────────────────────
    @staticmethod
    def _business_impact(ctx: BBContext, state: str) -> str:
        L = C.Level
        if state in (C.State.FALSE_POSITIVE, C.State.DOCUMENTATION_EXAMPLE,
                     C.State.GENERATED_CODE, C.State.INFORMATIONAL):
            return L.LOW
        critical = {"rce", "command injection", "sql injection", "code execution",
                    "authentication", "authorization", "privilege escalation", "file disclosure"}
        if ctx.secret_status == "Validated Secret" or ctx.category in critical or ctx.chain_confidence >= 75:
            return L.HIGH
        if (ctx.is_app_code and ctx.is_high_impact_category) or ctx.is_real_secret \
                or ctx.in_chain_required:
            return L.MEDIUM if not ctx.is_high_impact_category else L.HIGH
        if ctx.is_framework or ctx.is_sdk:
            return L.LOW
        return L.MEDIUM if ctx.is_high_impact_category else L.LOW

    @staticmethod
    def _research_value(ctx: BBContext, score: int, state: str) -> str:
        L = C.Level
        if state in (C.State.FALSE_POSITIVE, C.State.DOCUMENTATION_EXAMPLE,
                     C.State.GENERATED_CODE, C.State.LIKELY_OUT_OF_SCOPE,
                     C.State.FRAMEWORK_ISSUE, C.State.SDK_ISSUE):
            return L.LOW
        if score >= 70 and (ctx.in_chain_required or (ctx.is_app_code and ctx.is_high_impact_category)
                            or ctx.secret_status == "Validated Secret"):
            return L.HIGH
        if score < C.SCORE_OUT_OF_SCOPE:
            return L.LOW
        return L.MEDIUM

    @staticmethod
    def _verification_effort(ctx: BBContext) -> str:
        L = C.Level
        if ctx.evidence_quality == "Excellent" and ctx.verification == "Verified" \
                and ctx.reachability == "YES":
            return L.LOW
        if ctx.reachability == "NO" or ctx.unresolved or ctx.evidence_quality == "Missing" \
                or ctx.verification == "Needs Review":
            return L.HIGH
        if ctx.is_taint and ctx.reachability != "YES":
            return L.HIGH
        if ctx.evidence_quality in ("Excellent", "Good") and ctx.verification == "Verified":
            return L.LOW
        return L.MEDIUM

    @staticmethod
    def _next_step(state: str) -> str:
        S, N = C.State, C.NextStep
        return {
            S.LIKELY_REPORTABLE: N.STRONG_CANDIDATE,
            S.LIKELY_VALID: N.INVESTIGATE,
            S.NEEDS_MANUAL_VERIFICATION: N.MANUAL_REVIEW,
            S.NEEDS_EXPLOITATION: N.CONFIRM_EXPLOIT,
            S.NEEDS_RUNTIME_VALIDATION: N.RUNTIME,
            S.INFORMATIONAL: N.NOT_WORTH,
            S.PROBABLY_DUPLICATE: N.MANUAL_REVIEW,
            S.FRAMEWORK_ISSUE: N.NOT_WORTH,
            S.SDK_ISSUE: N.SDK_NOISE,
            S.GENERATED_CODE: N.NOT_WORTH,
            S.DOCUMENTATION_EXAMPLE: N.DOC_ARTIFACT,
            S.LIKELY_OUT_OF_SCOPE: N.NOT_WORTH,
            S.FALSE_POSITIVE: N.NOT_WORTH,
        }.get(state, N.INVESTIGATE)

    # ── chain assessment ─────────────────────────────────────────────────────
    def assess_chain(self, chain: dict) -> dict:
        conf = int(chain.get("overall_confidence") or 0)
        expl = int(chain.get("overall_exploitability") or 0)
        ev = chain.get("overall_evidence_quality") or "Missing"
        ev_score = _EVIDENCE_SCORE.get(ev, 10)
        blocked = bool(chain.get("blocked"))
        severity = (chain.get("severity") or "medium").lower()
        own = chain.get("ownership_summary") or {}
        app_member = own.get("Application", 0) > 0

        score = round(0.40 * conf + 0.35 * expl + 0.25 * ev_score)
        if blocked:
            score -= 25
        if app_member:
            score += 8
        score = _clamp(score)

        S, L = C.State, C.Level
        if blocked and score < C.SCORE_NEEDS_VERIFICATION:
            state = S.LIKELY_OUT_OF_SCOPE
        elif score >= C.SCORE_LIKELY_REPORTABLE:
            state = S.LIKELY_REPORTABLE
        elif score >= C.SCORE_LIKELY_VALID:
            state = S.LIKELY_VALID
        elif score >= C.SCORE_NEEDS_VERIFICATION:
            state = S.NEEDS_EXPLOITATION if expl < 50 else S.NEEDS_MANUAL_VERIFICATION
        else:
            state = S.INFORMATIONAL

        business = L.HIGH if severity in ("critical", "high") else (
            L.MEDIUM if severity == "medium" else L.LOW)
        research = (L.HIGH if (severity in ("critical", "high") and expl >= 60 and not blocked)
                    else (L.LOW if (blocked or expl < 40) else L.MEDIUM))
        effort = (L.LOW if (expl >= 70 and ev in ("Excellent", "Good") and not blocked)
                  else (L.HIGH if (blocked or expl < 40 or ev == "Missing") else L.MEDIUM))
        remediation = C.priority_for(score, business)

        pos, neg = [], []
        if app_member:
            pos.append("Chain includes application-owned code")
        if expl >= 60:
            pos.append(f"High exploitability ({expl})")
        if ev in ("Excellent", "Good"):
            pos.append(f"{ev} evidence across the chain")
        if conf >= 70:
            pos.append(f"High chain confidence ({conf})")
        if blocked:
            neg.append(f"A mitigation blocks the chain ({', '.join(chain.get('blocked_by') or [])})")
        if not app_member:
            neg.append("No application-owned link")
        if expl < 40:
            neg.append("Low exploitability")

        return {
            "reportability_score": score, "reportability_state": state,
            "business_impact": business, "research_value": research,
            "verification_effort": effort, "remediation_priority": remediation,
            "recommended_next_step": self._next_step(state),
            "positive_signals": pos, "negative_signals": neg,
            "reasoning": [("✓ " + p) for p in pos] + [("✗ " + n) for n in neg],
            "version": self.version, "policy": self.policy.name,
        }


# ── chain context for findings ───────────────────────────────────────────────
def _build_chain_ctx(chains: list[dict]) -> dict:
    required: set = set()
    supporting: set = set()
    conf: dict = {}
    for c in chains or []:
        cc = int(c.get("overall_confidence") or 0)
        for fid in c.get("required_findings") or []:
            required.add(fid)
            conf[fid] = max(conf.get(fid, 0), cc)
        for fid in c.get("supporting_findings") or []:
            supporting.add(fid)
            conf[fid] = max(conf.get(fid, 0), cc)
    return {"required": required, "supporting": supporting, "conf": conf}


# ── cached singleton + public API ────────────────────────────────────────────
_ENGINE: BugBountyEngine | None = None


def get_engine() -> BugBountyEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = BugBountyEngine()
    return _ENGINE


def assess_finding(f: dict, chain_ctx: dict | None = None) -> dict:
    return get_engine().assess_finding(f, chain_ctx)


def assess_chain(chain: dict) -> dict:
    return get_engine().assess_chain(chain)


_REPORTABLE_STATES = {C.State.LIKELY_REPORTABLE, C.State.LIKELY_VALID,
                      C.State.NEEDS_MANUAL_VERIFICATION, C.State.NEEDS_EXPLOITATION,
                      C.State.NEEDS_RUNTIME_VALIDATION}


def annotate(results: dict) -> dict:
    """Pipeline integration — attach `bug_bounty` to every finding AND chain.

    ADDITIVE and NON-DESTRUCTIVE: it reads the prior engines' metadata and writes
    a `bug_bounty` object; nothing is modified, removed, hidden or re-severitied.
    Runs last (after Attack Chain v2) — the final intelligence layer. Deterministic.
    """
    engine = get_engine()
    chains = results.get("attack_chains_v2") or []
    chain_ctx = _build_chain_ctx(chains)
    by_state: dict[str, int] = {}
    seen: set = set()
    reportable = 0

    for key in ("findings", "suppressed_findings"):
        for f in results.get(key) or []:
            if not isinstance(f, dict):
                continue
            bb = engine.assess_finding(f, chain_ctx)
            # Deterministic duplicate hint within the active set (first wins).
            if key == "findings" and bb["reportability_state"] in _REPORTABLE_STATES:
                sig = (f.get("rule_id") or "", f.get("title") or "", f.get("owner_type") or "")
                if sig in seen:
                    bb["reportability_state"] = C.State.PROBABLY_DUPLICATE
                    bb["recommended_next_step"] = C.NextStep.MANUAL_REVIEW
                    bb["reasoning"].append("✗ A similar finding already appears in this scan (probable duplicate)")
                else:
                    seen.add(sig)
            f["bug_bounty"] = bb
            if key == "findings":
                st = bb["reportability_state"]
                by_state[st] = by_state.get(st, 0) + 1
                if st in _REPORTABLE_STATES or st == C.State.LIKELY_REPORTABLE:
                    reportable += 1

    for c in chains:
        c["bug_bounty"] = engine.assess_chain(c)

    results["bug_bounty_summary"] = {
        "by_state": by_state,
        "likely_reportable": by_state.get(C.State.LIKELY_REPORTABLE, 0),
        "reportable_candidates": reportable,
        "chains_assessed": len(chains),
        "version": engine.version,
    }
    log.info("[bug_bounty] findings=%s | chains=%d | reportable=%d",
             by_state, len(chains), reportable)
    return results
