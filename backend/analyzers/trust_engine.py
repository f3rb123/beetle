"""
Trust Engine — Phase 7.5.

Answers the analyst's last question: "Can I trust this finding?"

Runs in finalize AFTER reachability_engine (needs reachability fields) and after
attack chains carry chain_confidence. Purely additive — annotates each finding
with:
  * evidence_quality        — HIGH | MEDIUM | LOW  (Task 2)
  * reachability_confidence — HIGH | MEDIUM | LOW  (Task 3)
and emits aggregate posture objects:
  * results["resolution_scores"]  — source / evidence / view-code coverage % (Task 6)
  * results["trust_score"]        — 0-100 + rating + factor breakdown (Task 7)

Chain confidence (Task 4) is set upstream in chain_analyzer.build_attack_chain_findings.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cortex.trust")

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
_QUALITY_VALUE = {HIGH: 100, MEDIUM: 60, LOW: 25}


# ── Helpers ──────────────────────────────────────────────────────────────────
def _has_snippet(f: dict) -> bool:
    if f.get("snippet"):
        return True
    for e in f.get("file_evidence") or []:
        if isinstance(e, dict) and e.get("snippet"):
            return True
    ev = f.get("evidence")
    return isinstance(ev, str) and bool(ev.strip())


def _has_line(f: dict) -> bool:
    ln = f.get("line") or f.get("line_number")
    return isinstance(ln, int) and ln > 0


def _has_any_evidence(f: dict) -> bool:
    return bool(
        f.get("file_evidence") or f.get("call_chain") or f.get("taint_flow")
        or _has_snippet(f) or f.get("file_path") or f.get("is_attack_chain")
    )


# ── Task 2 — Evidence quality ────────────────────────────────────────────────
def evidence_quality(f: dict) -> str:
    """HIGH = exact source file + line + code; MEDIUM = file/verifiable config;
    LOW = heuristic / inferred / unresolved."""
    if f.get("is_attack_chain"):
        # A chain is only as trustworthy as its evidenced members.
        return f.get("chain_confidence", MEDIUM)
    if f.get("unresolved_evidence"):
        return LOW
    category = f.get("category")
    et = f.get("evidence_type")
    # Certificate findings: verifiable metadata block (not source), not heuristic.
    if category == "Certificate":
        return MEDIUM if _has_snippet(f) else LOW
    # Manifest config: exact line+snippet is verifiable but it is configuration,
    # not proof the behaviour executes — capped at MEDIUM.
    if et == "manifest":
        return MEDIUM if (_has_line(f) and _has_snippet(f)) else LOW
    # Real decompiled code with an exact location and snippet.
    if f.get("source_resolved") and _has_line(f) and _has_snippet(f):
        return HIGH
    if f.get("source_resolved"):
        return MEDIUM
    if _has_snippet(f):
        return MEDIUM
    return LOW


# ── Task 3 — Reachability confidence ─────────────────────────────────────────
def reachability_confidence(f: dict) -> str:
    """HIGH = path fully proven; MEDIUM = entry+sink proven, path inferred;
    LOW = heuristic correlation only."""
    reach = str(f.get("reachability") or "").upper()
    if reach == "YES":
        # Proven data-flow or correlated chain membership = fully proven path.
        if f.get("taint_flow") or f.get("call_chain"):
            return HIGH
        if f.get("is_attack_chain"):
            return f.get("chain_confidence", HIGH)
        if f.get("in_attack_chain"):
            return HIGH
        # The finding IS the entry point / a shipped artifact — directly reached.
        if f.get("category") in ("Attack Surface", "Deeplinks", "Certificate"):
            return HIGH
        if str(f.get("source") or "") in ("EVIDENCE", "SECRET") or "secret" in str(category := f.get("category") or "").lower():
            return HIGH
        # Entry + sink both exist but the connecting path is inferred.
        return MEDIUM
    return LOW  # MAYBE / NO are heuristic by definition


# ── Annotation + aggregate scores ────────────────────────────────────────────
def annotate_trust(results: dict) -> None:
    findings = [f for f in (results.get("findings") or []) if isinstance(f, dict)]
    for f in findings:
        f["evidence_quality"] = evidence_quality(f)
        f["reachability_confidence"] = reachability_confidence(f)

    _compute_resolution_scores(results, findings)
    _compute_trust_score(results, findings)


def _compute_resolution_scores(results: dict, findings: list) -> None:
    """Task 6 — source / evidence / view-code coverage percentages.

    Coverage is measured over findings where a source line is APPLICABLE.
    Native-binary symbols and certificate metadata (source_applicable == False)
    have no source line by nature; they are evidence-complete and reported
    separately rather than counted as coverage gaps.
    """
    total = len(findings)
    applicable = [f for f in findings if f.get("source_applicable", True)]
    denom = len(applicable) or 1
    src = sum(1 for f in applicable if f.get("source_resolved"))
    vc = sum(1 for f in applicable if f.get("view_code"))
    evi = sum(1 for f in findings if _has_any_evidence(f))
    results["resolution_scores"] = {
        "total_findings": total,
        "source_applicable": len(applicable),
        "source_not_applicable": total - len(applicable),
        "source_resolved": src,
        "view_code_enabled": vc,
        "evidence_backed": evi,
        "source_resolution_pct": round(src / denom * 100),
        "evidence_coverage_pct": round(evi / (total or 1) * 100),
        "view_code_coverage_pct": round(vc / denom * 100),
    }


def _compute_trust_score(results: dict, findings: list) -> None:
    """Trust score — "can analysts trust the findings?" — 0-100.

    Measures report trustworthiness only: evidence quality, source resolution,
    ownership certainty and chain confidence. Reachability is intentionally NOT
    a factor here — it answers "can attackers exploit this?", a separate concern
    already surfaced via reachability / exploitability. Including it conflated
    exploitability with trust and double-penalised obfuscated apps (the same
    UNKNOWN-ownership findings dragged both ownership and reachability). See the
    Phase-8.1 root-cause analysis. Reachability analysis itself is unchanged.

    Weights: evidence 35% · source 30% · ownership 20% · chain 15%.
    """
    total = len(findings)
    if not total:
        results["trust_score"] = {"score": 100, "rating": HIGH, "factors": {},
                                  "meaning": "No findings to assess."}
        return

    eq = sum(_QUALITY_VALUE.get(f.get("evidence_quality", LOW), 25) for f in findings) / total
    src = sum(1 for f in findings if f.get("source_resolved")) / total * 100
    owned = sum(1 for f in findings if f.get("ownership_label") not in (None, "", "UNKNOWN")) / total * 100

    chains = [f for f in findings if f.get("is_attack_chain")]
    if chains:
        chain_conf = sum(_QUALITY_VALUE.get(c.get("chain_confidence", LOW), 25) for c in chains) / len(chains)
    else:
        chain_conf = 100  # no chains → no chain-confidence drag

    factors = {
        "evidence_quality": round(eq),
        "source_resolution": round(src),
        "ownership_certainty": round(owned),
        "chain_confidence": round(chain_conf),
    }
    score = round(
        0.35 * eq + 0.30 * src + 0.20 * owned + 0.15 * chain_conf
    )
    score = max(0, min(100, score))
    rating = HIGH if score >= 75 else (MEDIUM if score >= 50 else LOW)
    meaning = {
        HIGH: "Analysts can trust the report — findings are evidenced, located and ownership-classified.",
        MEDIUM: "Generally trustworthy — some findings are heuristic or unresolved; verify before action.",
        LOW: "Treat with caution — a large share of findings are heuristic or lack resolved evidence.",
    }[rating]
    results["trust_score"] = {
        "score": score, "rating": rating, "factors": factors, "meaning": meaning,
    }
