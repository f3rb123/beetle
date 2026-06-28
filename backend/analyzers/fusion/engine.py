"""
Finding Fusion Engine — the merge engine (Beetle 2.0, Phase 1.95).

THE central intelligence layer that lets Beetle grow from two detection engines to
many without increasing report noise. Every detection source only has to *emit*
canonical-shaped findings; this engine is solely responsible for recognizing when
several of them describe the SAME logical issue and folding them into ONE canonical
finding that is "Detected By" all of them — with complete, explainable provenance.

It runs as ONE deterministic pipeline stage over ``results["findings"]`` (replacing
the bare ``dedupe_findings`` collapse), so it catches duplicates from ANY engine —
the Beetle-native + APKLeaks combined-walk fusions done upstream AND any future
engine (Semgrep / MobSF / YARA / custom / AI) that emits findings directly.

Pipeline position: after canonicalization, BEFORE the Confidence Engine, so the
multi-engine agreement signal it stamps (``detection_count`` / ``fusion``) can feed
confidence.

What it produces on every (fused or singleton) finding:

    detected_by        list of engines that found it
    detection_count    number of distinct engines
    sources            per-engine detail (union)
    fusion_score       0-100 corroboration strength
    evidence_count     distinct evidence locations
    merged_files       every file the issue was seen in
    merged_locations   every (file, line) it was seen at
    fusion             full explainable record (engines, conflicts, resolutions, reason)

Two-layer relationship with ``detection_sources/fusion.py``: that module merges
detection *streams* at detection time (secrets/endpoints + the secret→finding
bridge) keyed on exact rule/value. THIS module is the finding-LEVEL semantic fusion
at finalize — a superset that also unifies cross-engine equivalents (different rule
ids, line drift). The two compose; neither is redundant.
"""
from __future__ import annotations

import logging

from ..canonical_finding import CanonicalFinding
from . import config as C
from . import conflict
from . import identity

log = logging.getLogger("cortex.fusion")

NATIVE = "Beetle Native"


# ── attribution helpers ───────────────────────────────────────────────────────
def _ensure_attribution(f: dict) -> None:
    """Guarantee a finding carries detected_by/sources (additive, in place)."""
    db = f.get("detected_by")
    if not isinstance(db, list) or not db:
        f["detected_by"] = [f.get("source") or f.get("source_module") or NATIVE]
    if not isinstance(f.get("sources"), list) or not f.get("sources"):
        f["sources"] = [{
            "engine": f["detected_by"][0],
            "rule_id": f.get("rule_id") or f.get("name") or f.get("title") or "",
            "confidence": f.get("confidence"),
        }]


def _evidence_count(cf: CanonicalFinding) -> int:
    locs = {(e.get("path"), tuple(e.get("lines") or []))
            for e in cf.file_evidence if isinstance(e, dict)}
    if cf.file_path:
        locs.add((cf.file_path, (cf.line,)))
    return max(len(locs), 1)


def _fusion_score(detection_count: int, evidence_count: int, has_conflict: bool) -> int:
    score = C.FUSION_SCORE_BASE
    score += max(0, detection_count - 1) * C.FUSION_SCORE_PER_ENGINE
    score += min(max(0, evidence_count - 1) * C.FUSION_SCORE_EVIDENCE,
                 C.FUSION_SCORE_EVIDENCE_CAP)
    if has_conflict:
        score -= C.FUSION_SCORE_CONFLICT_PENALTY
    return max(0, min(C.FUSION_SCORE_MAX, score))


def _merged_locations(group: list[CanonicalFinding]) -> list[dict]:
    out: list[dict] = []
    seen: set = set()
    for cf in group:
        for fp, ln in [(cf.file_path, cf.line)] + \
                [(e.get("path"), (e.get("lines") or [None])[0]) for e in cf.file_evidence if isinstance(e, dict)]:
            if not fp:
                continue
            key = (fp, ln or 0)
            if key in seen:
                continue
            seen.add(key)
            out.append({"file_path": fp, "line": ln or 0})
    return out


def _reason(detection_count: int, engines: list[str], conflicts: list) -> str:
    if detection_count >= 2:
        base = f"Detected independently by {detection_count} engines ({', '.join(engines)})."
        if conflicts:
            fields = ", ".join(sorted({c['field'] for c in conflicts}))
            return f"{base} Metadata conflicts on {fields} resolved deterministically."
        return base + " No metadata conflicts."
    return f"Detected by a single engine ({engines[0] if engines else NATIVE})."


def _fuse_group(group_dicts: list[dict], platform: str) -> dict:
    """Fold a group of duplicate finding dicts into ONE canonical legacy dict."""
    cfs = [CanonicalFinding.from_legacy(d, platform=platform) for d in group_dicts]

    # Fold via the canonical merge (unions evidence/sources/standards, max sev/conf).
    merged = cfs[0]
    for cf in cfs[1:]:
        merged = merged.merge(cf)

    # Conflict resolution across the ORIGINAL members (documented + applied).
    decision = conflict.analyze(cfs)
    res = decision["resolutions"]
    if res.get("severity"):
        merged.severity = res["severity"]
    if res.get("category"):
        merged.category = res["category"]
    if res.get("owner_type"):
        merged.owner_type = res["owner_type"]
        merged.owner_name = res.get("owner_name") or merged.owner_name
        merged.owner_confidence = res.get("owner_confidence") or merged.owner_confidence
    primary = res.get("primary_location") or {}
    if primary.get("file_path"):
        merged.file_path = primary["file_path"]
        merged.line = primary.get("line")

    # Provenance.
    engines = list(merged.detected_by)
    detection_count = len(engines)
    evidence_count = max(_evidence_count(c) for c in cfs)
    has_conflict = bool(decision["conflicts"])
    merged.detection_count = detection_count
    merged.fusion_score = _fusion_score(detection_count, evidence_count, has_conflict)
    merged_files = sorted({c.file_path for c in cfs if c.file_path})
    locations = _merged_locations(cfs)
    merged.fusion = {
        "version": C.FUSION_VERSION,
        "detection_count": detection_count,
        "engines": engines,
        "sources": merged.sources,
        "evidence_count": evidence_count,
        "merged_files": merged_files,
        "merged_locations": locations,
        "conflicts": decision["conflicts"],
        "resolutions": decision["resolutions"],
        "score": merged.fusion_score,
        "reason": _reason(detection_count, engines, decision["conflicts"]),
    }

    out = merged.to_legacy()
    # to_legacy is non-destructive (never overwrites a key already in the base raw),
    # so force the fused/unioned values through over the first member's originals.
    out["severity"] = merged.severity
    out["category"] = merged.category
    if res.get("owner_type"):
        out["owner_type"] = merged.owner_type
        out["owner_name"] = merged.owner_name
        out["owner_confidence"] = merged.owner_confidence
    out["detected_by"] = engines
    out["sources"] = merged.sources
    out["detection_count"] = detection_count
    out["fusion_score"] = merged.fusion_score
    out["fusion"] = merged.fusion
    out["merged_files"] = merged_files
    out["merged_locations"] = locations
    out["evidence_count"] = evidence_count
    if merged.file_path:
        out["file_path"] = merged.file_path
        out["line"] = merged.line
        out["line_number"] = merged.line
    if detection_count > 1:
        out["duplicates"] = detection_count  # backward-compat with dedupe_findings
    return out


def _stamp_singleton(f: dict, platform: str) -> dict:
    """A finding seen by one engine still gets full (count=1) provenance."""
    _ensure_attribution(f)
    cf = CanonicalFinding.from_legacy(f, platform=platform)
    engines = list(cf.detected_by) or [NATIVE]
    evidence_count = _evidence_count(cf)
    f["detection_count"] = len(engines)
    f["fusion_score"] = _fusion_score(len(engines), evidence_count, False)
    f["evidence_count"] = evidence_count
    f["merged_files"] = sorted({cf.file_path}) if cf.file_path else []
    f["merged_locations"] = _merged_locations([cf])
    f["fusion"] = {
        "version": C.FUSION_VERSION,
        "detection_count": len(engines),
        "engines": engines,
        "sources": f.get("sources", []),
        "evidence_count": evidence_count,
        "merged_files": f["merged_files"],
        "merged_locations": f["merged_locations"],
        "conflicts": [],
        "resolutions": {},
        "score": f["fusion_score"],
        "reason": _reason(len(engines), engines, []),
    }
    return f


# ── public entry point ────────────────────────────────────────────────────────
def fuse(results: dict, *, platform: str = "unknown") -> dict:
    """Fuse ``results["findings"]`` into one canonical finding per logical issue.

    Replaces the bare ``dedupe_findings`` collapse: groups findings by SEMANTIC
    identity (engine-independent), merges each group, resolves and documents
    conflicts, and stamps full provenance + a multi-engine agreement signal. The
    findings list is rewritten in place; returns a stats dict (also stored under
    ``results["fusion_summary"]``).

    Synthesized attack-chain findings (``is_attack_chain``) are passed through
    untouched — they are not engine duplicates and must not be merged into members.
    """
    findings = results.get("findings") or []
    if not isinstance(findings, list):
        return {"before": 0, "after": 0, "groups": 0, "merged": 0, "multi_engine": 0}

    passthrough: list[dict] = []
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for f in findings:
        if not isinstance(f, dict):
            passthrough.append(f)
            continue
        if f.get("is_attack_chain"):
            passthrough.append(f)
            continue
        _ensure_attribution(f)
        key = identity.fusion_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    fused: list[dict] = []
    merged_count = multi_engine = 0
    for key in order:
        members = groups[key]
        if len(members) == 1:
            fused.append(_stamp_singleton(members[0], platform))
            continue
        out = _fuse_group(members, platform)
        fused.append(out)
        merged_count += len(members) - 1
        if out.get("detection_count", 1) > 1:
            multi_engine += 1

    results["findings"] = passthrough + fused
    summary = {
        "version": C.FUSION_VERSION,
        "before": len(findings),
        "after": len(results["findings"]),
        "groups": len(order),
        "merged": merged_count,
        "multi_engine": multi_engine,
        "passthrough": len(passthrough),
    }
    results["fusion_summary"] = summary
    log.info("[fusion] %s | %s", platform, summary)
    return summary
