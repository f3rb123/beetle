"""
Evidence Selection Engine — the selector (Beetle 2.0, Phase 1.96).

For each finding Beetle often has several candidate proof files (the app package,
AndroidX, Google Play Services, generated code, …). This engine identifies the ONE
proof an analyst should review — the most relevant, exploitable, reportable,
application-owned evidence — and explains why, demoting the rest to supporting or
rejected. Quality over quantity: one excellent proof beats ten weak ones.

It is additive and non-destructive: it writes a new ``evidence_selection`` block
(``primary`` / ``supporting`` / ``rejected`` + reasons) and a flat
``primary_evidence`` convenience onto each finding. The finding's existing
``file_path`` / ``file_evidence`` / ``evidence_bundle`` are left untouched for
backward compatibility; reports read ``evidence_selection`` to render Primary /
Supporting / Additional sections.

Reuses the Ownership Engine (library/owner classification), the Fusion Engine
(per-file engine corroboration) and the Reachability / Attack-Chain / Validation
signals already on each finding — no detection logic is duplicated here. Runs LATE
(after those engines) so every signal is available.
"""
from __future__ import annotations

import logging
import os

from ..canonical_finding import severity_rank
from ..ownership import context_from_results
from ..ownership.types import OwnershipContext
from . import config as C
from . import scoring
from .library import classify_file
from .scoring import Candidate, SelectionContext

log = logging.getLogger("cortex.evidence_selection")


def _truthy_env(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in ("1", "true", "yes", "on")


def bug_bounty_enabled(results: dict | None = None) -> bool:
    """Bug Bounty Mode is on when the scan options or env request it."""
    if results:
        opts = results.get("options") or {}
        if isinstance(opts, dict) and opts.get("bug_bounty_mode"):
            return True
        if results.get("bug_bounty_mode"):
            return True
    return _truthy_env("CORTEX_BUG_BOUNTY_MODE")


def _int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _candidates_from_finding(f: dict) -> list[Candidate]:
    """De-duped candidate proof locations for a finding (file_path + file_evidence
    + fusion merged_locations)."""
    out: list[Candidate] = []
    seen: set = set()

    def add(path, line, snippet, source):
        path = (path or "").strip()
        if not path:
            return
        line = _int(line)
        key = (path, line)
        if key in seen:
            return
        seen.add(key)
        out.append(Candidate(file_path=path, line=line, snippet=snippet or "", source=source))

    add(f.get("file_path") or f.get("file"), f.get("line") or f.get("line_number"),
        f.get("snippet") or f.get("code_context"), "finding")
    for e in f.get("file_evidence") or []:
        if isinstance(e, dict):
            lines = e.get("lines") or []
            add(e.get("path"), lines[0] if lines else None, e.get("snippet"), "file_evidence")
    for loc in f.get("merged_locations") or []:
        if isinstance(loc, dict):
            add(loc.get("file_path"), loc.get("line"), "", "fusion")
    return out


def _file_engine_counts(f: dict) -> dict:
    """Per-file count of detection engines that referenced it (from fusion sources)."""
    counts: dict[str, int] = {}
    n_engines = max(_int(f.get("detection_count")), len(f.get("detected_by") or []))
    # Fusion does not record per-file engine attribution, so a corroborated finding
    # credits its merged files; single-file findings credit that file.
    if n_engines >= 2:
        for mf in f.get("merged_files") or ([f.get("file_path")] if f.get("file_path") else []):
            if mf:
                counts[mf] = n_engines
    return counts


def _entry(c: Candidate) -> dict:
    return {
        "file_path": c.file_path,
        "line": c.line,
        "snippet": (c.snippet or "")[:240],
        "score": c.score,
        "file_score": c.file_score,
        "finding_score": c.finding_score,
        "owner_type": c.classification.owner_type,
        "owner_name": c.classification.owner_name,
        "source": c.source,
        "selected_because": c.reasons,
        "rejected_because": c.penalties,
    }


def select(f: dict, ctx: OwnershipContext | None = None, *,
           bug_bounty: bool = False, already_selected: set | None = None) -> dict:
    """Score a finding's candidate proofs and choose primary/supporting/rejected.

    Returns the ``evidence_selection`` block. Pure w.r.t. the finding except that it
    adds ``(file,line)`` of the chosen primary to ``already_selected`` (cross-finding
    de-noise) when that set is supplied.
    """
    candidates = _candidates_from_finding(f)
    if not candidates:
        return {"version": C.SELECTION_VERSION, "primary": {}, "supporting": [],
                "rejected": [], "candidate_count": 0,
                "reason": "No proof location available for this finding."}

    sctx = SelectionContext(
        bug_bounty=bug_bounty,
        reachability=str(f.get("reachability") or "").upper(),
        in_attack_chain=bool(f.get("in_attack_chain") or f.get("is_attack_chain")),
        validated=(str(f.get("validation_status") or "").lower() == "valid"
                   or f.get("validated") is True),
        detection_count=max(_int(f.get("detection_count")), 1),
        already_selected=already_selected if already_selected is not None else set(),
        file_engine_counts=_file_engine_counts(f),
    )

    for c in candidates:
        c.classification = classify_file(c.file_path, ctx)
        scoring.score(c, sctx)

    # Deterministic ranking: total score desc, then file-intrinsic score, then
    # app-owned, then has-line, then path. (file_score breaks ties where finding-
    # wide bonuses are equal — preferring the higher-quality FILE.)
    candidates.sort(key=lambda c: (
        -c.score, -c.file_score, 0 if c.classification.is_application else 1,
        0 if c.line else 1, c.file_path))

    primary = candidates[0]
    rest = candidates[1:]
    # Reject on the FILE-intrinsic score so finding-wide corroboration (reachable,
    # attack-chain, validated) never rescues a library/framework file from rejection.
    supporting = [c for c in rest if c.file_score >= C.REJECT_BELOW][:C.MAX_SUPPORTING]
    rejected = [c for c in rest if c.file_score < C.REJECT_BELOW] + \
               [c for c in rest if c.file_score >= C.REJECT_BELOW][C.MAX_SUPPORTING:]

    if already_selected is not None:
        already_selected.add((primary.file_path, primary.line))

    return {
        "version": C.SELECTION_VERSION,
        "bug_bounty_mode": bug_bounty,
        "candidate_count": len(candidates),
        "primary": _entry(primary),
        "supporting": [_entry(c) for c in supporting],
        "rejected": [_entry(c) for c in rejected],
        "reason": _selection_reason(primary, len(candidates)),
    }


def _selection_reason(primary: Candidate, n: int) -> str:
    bullets = primary.reasons[:4]
    head = f"Selected from {n} candidate proof file(s)" if n > 1 else "Only available proof"
    if bullets:
        return f"{head}: " + "; ".join(bullets) + "."
    return head + "."


# ── pipeline integration ──────────────────────────────────────────────────────
def annotate(results: dict, *, platform: str | None = None) -> dict:
    """Attach ``evidence_selection`` to every finding (additive, non-destructive).

    Processes findings in severity order so the strongest finding gets first claim
    on a shared proof file (cross-finding de-noise). Runs LATE in the pipeline so
    ownership / confidence / reachability / attack-chain / fusion signals are all
    present. Bug Bounty Mode is auto-detected from scan options / env.
    """
    findings = results.get("findings") or []
    if not isinstance(findings, list):
        return results
    ctx = context_from_results(results)
    if platform and (not ctx.platform or ctx.platform == "unknown"):
        ctx = OwnershipContext(platform=platform, app_packages=ctx.app_packages,
                               bundle_ids=ctx.bundle_ids, app_modules=ctx.app_modules,
                               app_name=ctx.app_name)
    bb = bug_bounty_enabled(results)
    already: set = set()

    ordered = sorted(
        [f for f in findings if isinstance(f, dict)],
        key=lambda f: (severity_rank(f.get("severity", "info")),
                       -_int(f.get("overall_confidence"))))
    annotated = multi = 0
    for f in ordered:
        sel = select(f, ctx, bug_bounty=bb, already_selected=already)
        f["evidence_selection"] = sel
        if sel.get("primary"):
            f["primary_evidence"] = sel["primary"]
        annotated += 1
        if sel.get("candidate_count", 0) > 1:
            multi += 1

    summary = {
        "version": C.SELECTION_VERSION,
        "bug_bounty_mode": bb,
        "findings_annotated": annotated,
        "multi_candidate_findings": multi,
    }
    results["evidence_selection_summary"] = summary
    log.info("[evidence_selection] %s | %s", ctx.platform, summary)
    return results
