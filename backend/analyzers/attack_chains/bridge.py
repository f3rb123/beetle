"""
Attack Chain v2 → report/UI bridge (Beetle 2.0).

The v2 engine (``engine.py``) writes the authoritative chains to
``results['attack_chains_v2']``. Historically the *displayed* chains — the PDF's
"Attack Chains" section, the workspace chain panel (which filters
``findings[].is_attack_chain``), the dashboard's ``quick_summary.attack_chain`` and
the AI context — all read the LEGACY ``chain_analyzer`` synthesizer instead, so the
good engine was computed and then never shown, and every legacy chain finding wore
a hardcoded 90% confidence.

This module makes v2 the single source those surfaces read, WITHOUT changing v2
itself. It provides two projections of the v2 chains:

* :func:`to_first_class_findings` — one ``is_attack_chain`` finding per v2 chain,
  carrying v2's COMPUTED ``overall_confidence`` (never a constant), its members,
  and per-member evidence. These are prepended to ``results['findings']`` so the
  findings list and the chain section reference the same chains.
* :func:`to_quick_summary` — back-compat chain dicts (legacy key names: ``title``,
  ``impact``, ``chain_confidence``, ``exploitability``, ``steps``) so existing
  readers of ``quick_summary.attack_chain`` (AI chat, executive summaries, scan
  compare) keep working while now reflecting v2.

:func:`annotate_findings` wires both member-marking and finding injection into a
pipeline. Deterministic; mutates only the additive fields it documents.
"""
from __future__ import annotations

from .engine import _finding_id

# Numeric confidence (v2 overall_confidence, 0-100) → the coarse label the trust
# engine and UI expect. Thresholds mirror the confidence engine's bands.
_CONF_HIGH, _CONF_MED = 70, 40


def _confidence_label(score: int) -> str:
    if score >= _CONF_HIGH:
        return "HIGH"
    if score >= _CONF_MED:
        return "MEDIUM"
    return "LOW"


def _index_findings(results: dict) -> dict:
    """Map every real finding's chain-id → the finding dict (v2's own id scheme)."""
    index: dict = {}
    for f in results.get("findings") or []:
        if isinstance(f, dict) and not f.get("is_attack_chain"):
            index.setdefault(_finding_id(f), f)
    return index


def _member_ref(fid: str, f: dict | None) -> dict:
    if not f:
        return {"id": fid, "title": fid, "severity": "", "file_path": ""}
    return {
        "id": fid,
        "title": f.get("title", ""),
        "severity": f.get("severity", ""),
        "file_path": f.get("file_path") or f.get("file") or "",
    }


def _evidence_from_references(chain: dict) -> list:
    """Per-member evidence pointers from the chain's aggregated references.

    v2 aggregates one reference per evidenced member (file + line), so an N-link
    chain yields N pointers here — not one file for the whole chain."""
    out: list = []
    seen: set = set()
    for ref in chain.get("evidence_references") or []:
        path = ref.get("file") or ""
        line = ref.get("line")
        key = (path, line)
        if not path or key in seen:
            continue
        seen.add(key)
        out.append({
            "path": path,
            "lines": [line] if line else [],
            "snippet": ref.get("evidence_id", ""),
        })
    return out


def to_first_class_findings(results: dict) -> list:
    """Build one ``is_attack_chain`` finding per v2 chain (deterministic order).

    Confidence comes straight from v2's computed ``overall_confidence`` — there is
    no constant anywhere in this path."""
    chains = results.get("attack_chains_v2") or []
    index = _index_findings(results)
    findings: list = []

    for chain in chains:
        cid = chain.get("id", "chain")
        member_ids = list(chain.get("required_findings") or []) + list(chain.get("supporting_findings") or [])
        member_refs = [_member_ref(mid, index.get(mid)) for mid in member_ids]

        file_evidence = _evidence_from_references(chain)
        # Guarantee at least one pointer per participating link even when a member
        # carried no evidence_reference (e.g. a manifest-declared exposure) — but
        # never point at an R-constants class (N0/a.java resource IDs).
        from ..code_analyzer import is_resource_id_target
        _r_classes = results.get("resource_id_classes")
        for ref in member_refs:
            fp = ref["file_path"]
            if fp and is_resource_id_target(fp, "", _r_classes):
                continue
            if fp and not any(e["path"] == fp for e in file_evidence):
                file_evidence.append({"path": fp, "lines": [], "snippet": ref["title"]})

        confidence = int(chain.get("overall_confidence") or 0)
        findings.append({
            "rule_id": f"chain_{cid}",
            "canonical_id": cid,
            "title": f"Attack Chain: {chain.get('name') or chain.get('summary') or 'Correlated Exploit Chain'}",
            "severity": chain.get("severity", "high"),
            "category": "Attack Chain",
            "is_attack_chain": True,
            "attack_chain_id": cid,
            "attack_chain_members": member_refs,
            # Confidence is v2's computed blend of member confidence + evidence,
            # scaled by reachability — NOT a hardcoded value.
            "confidence": confidence,
            "confidence_score": confidence,
            "overall_confidence": confidence,
            "chain_confidence": _confidence_label(confidence),
            "reachability_proof": chain.get("reachability_proof", ""),
            "exploitability": chain.get("overall_exploitability", 0),
            "overall_exploitability": chain.get("overall_exploitability", 0),
            "description": chain.get("summary", ""),
            "impact": chain.get("overall_impact", ""),
            "recommendation": (
                "Break the chain by remediating any one link — the highest-severity "
                "step is the priority. Address the contributing findings listed below."
            ),
            "steps": chain.get("steps") or chain.get("narrative") or [],
            "prerequisites": chain.get("prerequisites") or [],
            "blocked": chain.get("blocked", False),
            "blocked_by": chain.get("blocked_by") or [],
            "mitigations": chain.get("mitigations") or [],
            "confidence_explanation": chain.get("confidence_explanation") or {},
            "evidence_references": chain.get("evidence_references") or [],
            "file_evidence": file_evidence,
            "files": [e["path"] for e in file_evidence],
            "evidence_count": len(file_evidence),
            "entry_point": chain.get("entry_point") or {},
            "graph": chain.get("graph") or {},
            "version": chain.get("version", ""),
            # App-level synthesized issue — owned by the application, always shown.
            "ownership_label": "APPLICATION",
            "owner_type": "Application",
        })
    return findings


def mark_members(results: dict) -> int:
    """Flag every finding that participates in a v2 chain (in_attack_chain=True).

    Replaces the legacy synthesizer's member marking so the ``in_attack_chain``
    flag the UI reads reflects the SAME engine as the displayed chains."""
    index = _index_findings(results)
    marked = 0
    for chain in results.get("attack_chains_v2") or []:
        cid = chain.get("id", "chain")
        for mid in list(chain.get("required_findings") or []) + list(chain.get("supporting_findings") or []):
            f = index.get(mid)
            if f is not None and not f.get("in_attack_chain"):
                f["in_attack_chain"] = True
                f.setdefault("attack_chain_id", cid)
                marked += 1
    return marked


def to_quick_summary(results: dict) -> list:
    """Back-compat ``quick_summary.attack_chain`` list projected from v2.

    Carries legacy key names so readers of ``quick_summary.attack_chain`` (AI chat,
    executive summaries, scan compare) keep working — now sourced from v2."""
    out: list = []
    for chain in results.get("attack_chains_v2") or []:
        confidence = int(chain.get("overall_confidence") or 0)
        out.append({
            "id": chain.get("id", ""),
            "title": chain.get("name") or chain.get("summary") or "Attack Chain",
            "severity": chain.get("severity", "high"),
            "impact": chain.get("overall_impact", ""),
            "narrative": chain.get("summary", ""),
            "chain_confidence": _confidence_label(confidence),
            "overall_confidence": confidence,
            "exploitability": chain.get("overall_exploitability", 0),
            "reachability_proof": chain.get("reachability_proof", ""),
            "steps": chain.get("steps") or [],
            "prerequisites": chain.get("prerequisites") or [],
        })
    return out


def annotate_findings(results: dict) -> int:
    """Mark chain members and prepend v2-derived first-class chain findings.

    Returns the number of chain findings injected. Idempotent: existing
    ``is_attack_chain`` findings are dropped first so re-running (or a legacy
    injection) cannot leave duplicates from two engines."""
    mark_members(results)
    chain_findings = to_first_class_findings(results)
    existing = [f for f in (results.get("findings") or [])
                if not (isinstance(f, dict) and f.get("is_attack_chain"))]
    results["findings"] = chain_findings + existing
    return len(chain_findings)
