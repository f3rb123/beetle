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
from ..ownership.types import OwnershipContext, OwnerType
import re

from . import config as C
from . import scoring
from . import snippet as snip
from .library import classify_file
from .scoring import Candidate, SelectionContext
from .view import build_evidence_view

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


def _is_manifest_derived(f: dict) -> bool:
    if str(f.get("evidence_type") or "").lower() == "manifest":
        return True
    cat = str(f.get("category") or "").lower()
    if any(m in cat for m in C.MANIFEST_CATEGORIES):
        return True
    # If a candidate location is already the manifest, the finding is declaration-
    # driven even when its category is ambiguous (e.g. a real manifest finding that
    # was filed under "Configuration"/"Network Security").
    paths = [f.get("file_path") or ""] + [
        e.get("path", "") for e in (f.get("file_evidence") or []) if isinstance(e, dict)]
    return any((p or "").replace("\\", "/").lower().rsplit("/", 1)[-1] in C.MANIFEST_FILENAMES
               for p in paths)


def _manifest_filename(platform: str) -> str:
    return "Info.plist" if (platform or "").lower() == "ios" else "AndroidManifest.xml"


def _path_excluded(path: str, exclude_paths: set) -> bool:
    """A candidate path matches an excluded (resource-ID class) path when they are
    equal or one is a path-suffix of the other — robust to differing scan roots."""
    if not exclude_paths:
        return False
    p = (path or "").replace("\\", "/").lower()
    for ex in exclude_paths:
        if p == ex or p.endswith("/" + ex) or ex.endswith("/" + p):
            return True
    return False


def _candidates_from_finding(f: dict, platform: str = "android",
                             exclude_paths: set | None = None) -> list[Candidate]:
    """De-duped candidate proof locations for a finding (file_path + file_evidence
    + fusion merged_locations + a synthesized manifest candidate for declaration-
    driven findings).

    ``exclude_paths`` (resource-ID constant classes) are dropped: an R.java / obfuscated
    R class is never a real proof location for a secret or a chain."""
    out: list[Candidate] = []
    seen: set = set()

    def add(path, line, snippet, source):
        path = (path or "").strip()
        if not path:
            return
        if source != "manifest" and _path_excluded(path, exclude_paths):
            return
        line = _int(line)
        key = (path.replace("\\", "/").lower(), line)
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
    # Declaration-driven findings: the manifest is the authoritative proof. Add it as
    # a candidate (if not already present) so an exported component / permission /
    # deep-link finding can point at AndroidManifest.xml instead of the SDK class
    # that implements it. The manifest scoring signal makes it win for these.
    if _is_manifest_derived(f):
        mname = _manifest_filename(platform)
        if not any(c.file_path.replace("\\", "/").lower().endswith(mname.lower()) for c in out):
            add(mname, f.get("line") or 0, f.get("snippet") or "", "manifest")
    return out


def _rule_specificity(f: dict) -> int:
    """Source-confidence / rule-specificity bonus (finding-wide). Higher for precise,
    high-confidence detectors and for findings carrying a specific (non-broad) CWE."""
    spec = 0
    conf = _int(f.get("confidence")) or _int(f.get("overall_confidence"))
    if conf >= 90:
        spec += C.RULE_SPECIFICITY_HIGH
    elif conf >= 75:
        spec += C.RULE_SPECIFICITY_MED
    cwe = str(f.get("cwe") or "").strip().lower()
    m = re.search(r"cwe[-\s]?(\d+)", cwe)
    norm = f"cwe-{m.group(1)}" if m else ""
    if norm and norm not in C.BROAD_CWES_FOR_SPECIFICITY:
        spec += C.RULE_SPECIFICITY_CWE_BONUS
    return spec


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
           bug_bounty: bool = False, already_selected: set | None = None,
           exclude_paths: set | None = None) -> dict:
    """Score a finding's candidate proofs and choose primary/supporting/rejected.

    Returns the ``evidence_selection`` block. Pure w.r.t. the finding except that it
    adds ``(file,line)`` of the chosen primary to ``already_selected`` (cross-finding
    de-noise) when that set is supplied. ``exclude_paths`` drops resource-ID constant
    classes from the candidate set.
    """
    platform = (ctx.platform if ctx and ctx.platform else "android")
    candidates = _candidates_from_finding(f, platform, exclude_paths)
    if not candidates:
        return {"version": C.SELECTION_VERSION, "primary": {}, "supporting": [],
                "rejected": [], "candidate_count": 0,
                "reason": "No proof location available for this finding."}

    is_chain = bool(f.get("is_attack_chain") or f.get("in_attack_chain"))
    sctx = SelectionContext(
        bug_bounty=bug_bounty,
        reachability=str(f.get("reachability") or "").upper(),
        in_attack_chain=is_chain,
        validated=(str(f.get("validation_status") or "").lower() == "valid"
                   or f.get("validated") is True),
        detection_count=max(_int(f.get("detection_count")), 1),
        manifest_derived=_is_manifest_derived(f),
        chain=is_chain,
        already_selected=already_selected if already_selected is not None else set(),
        file_engine_counts=_file_engine_counts(f),
        match_tokens=snip.relevant_tokens(f),
        rule_specificity=_rule_specificity(f),
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
    # Snippet quality (Phase 1.96): refine the primary's displayed snippet to the most
    # relevant line — dropping import/comment/brace noise — using the richer finding
    # code_context when the primary IS the finding's own detection site, else the
    # candidate's own captured snippet. Never blanks a snippet (falls back to the
    # original). Only the primary is refined; supporting entries keep their raw snippet.
    ctx_text = (f.get("code_context") if primary.source == "finding" else "") or primary.snippet
    refined = snip.refine_snippet(ctx_text, primary.snippet, sctx.match_tokens)
    if refined:
        primary.snippet = refined
    # Reject on the FILE-intrinsic score so finding-wide corroboration (reachable,
    # attack-chain, validated) never rescues a library/framework file from rejection.
    supporting = [c for c in rest if c.file_score >= C.REJECT_BELOW][:C.MAX_SUPPORTING]
    rejected = [c for c in rest if c.file_score < C.REJECT_BELOW] + \
               [c for c in rest if c.file_score >= C.REJECT_BELOW][C.MAX_SUPPORTING:]

    if already_selected is not None:
        already_selected.add((primary.file_path, primary.line))

    # Framework-only: the finding's ONLY proof is framework/library code (no
    # application/manifest/unknown candidate). The primary is then legitimately a
    # framework file (the "no application-owned evidence exists" exception), but it
    # is flagged + honestly explained so rendering never presents it as app proof.
    def _is_nonframework(c):
        ot = c.classification.owner_type
        return (c.classification.is_application or ot in (OwnerType.UNKNOWN, "")
                or (c.file_path or "").replace("\\", "/").lower().rsplit("/", 1)[-1] in C.MANIFEST_FILENAMES)
    framework_only = not any(_is_nonframework(c) for c in candidates)

    reason = _selection_reason(primary, len(candidates))
    if framework_only:
        reason = ("Only framework/library evidence exists for this finding — no "
                  "application-owned proof was detected. Shown for completeness.")

    return {
        "version": C.SELECTION_VERSION,
        "bug_bounty_mode": bug_bounty,
        "candidate_count": len(candidates),
        "primary": _entry(primary),
        "supporting": [_entry(c) for c in supporting],
        "rejected": [_entry(c) for c in rejected],
        "framework_only": framework_only,
        "reason": reason,
    }


# Owner types whose primary is safe to promote into the finding's display location
# (the analyst's own code / the authoritative manifest). We never promote a
# library/framework/generated file over whatever was already there.
_PROMOTABLE_OWNERS = {OwnerType.APPLICATION, OwnerType.UNKNOWN}


def _promote_primary(f: dict, sel: dict) -> bool:
    """Promote the selected primary into the finding's legacy location fields.

    Returns True if a correction was applied. Conservative: only when the primary
    is application/manifest-owned and points at a DIFFERENT file than the current
    ``file_path`` — so we only ever replace a worse (library/framework) location
    with a better one, never the reverse. The original detection site is preserved.
    """
    prim = (sel or {}).get("primary") or {}
    new_path = prim.get("file_path")
    if not new_path:
        return False
    cur_path = f.get("file_path") or f.get("file") or ""
    if new_path == cur_path:
        return False
    owner = prim.get("owner_type")
    is_manifest = new_path.replace("\\", "/").lower().rsplit("/", 1)[-1] in C.MANIFEST_FILENAMES
    if owner not in _PROMOTABLE_OWNERS and not is_manifest:
        return False
    # Preserve the detection site once (idempotent across re-runs).
    f.setdefault("detected_location", {
        "file_path": cur_path,
        "line": f.get("line") or f.get("line_number") or 0,
        "snippet": f.get("snippet") or "",
    })
    f["legacy_file_path"] = cur_path
    f["file_path"] = new_path
    f["line"] = prim.get("line") or 0
    f["line_number"] = prim.get("line") or 0
    if prim.get("snippet"):
        f["snippet"] = prim["snippet"]
    return True


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
    # Content-detected binary-format files (Mach-O / bplist) recorded during the iOS scan.
    # Their "line" is a strings index or a parse artifact, never a source line.
    _binary_files = {str(p).replace("\\", "/").lower()
                     for p in (results.get("binary_evidence_files") or [])}
    already: set = set()
    # Resource-ID constant classes (recorded during the secret walk) are never a
    # valid proof location — exclude them so no secret/chain evidence points at an
    # R-constant class.
    exclude_paths = {p.replace("\\", "/").lower() for p in (results.get("resource_id_classes") or [])}

    # Skip bridged secret→finding mirrors: they are removed at reconcile and must
    # not claim a shared proof file in the cross-finding de-noise pass.
    ordered = sorted(
        [f for f in findings if isinstance(f, dict) and not f.get("secret_bridge")],
        key=lambda f: (severity_rank(f.get("severity", "info")),
                       -_int(f.get("overall_confidence"))))
    annotated = multi = corrected = 0
    for f in ordered:
        sel = select(f, ctx, bug_bounty=bb, already_selected=already, exclude_paths=exclude_paths)
        f["evidence_selection"] = sel
        if sel.get("primary"):
            f["primary_evidence"] = sel["primary"]
        # Report-accuracy keystone: stamp the precomputed render view and promote the
        # selected primary into the legacy location fields so EVERY consumer (incl.
        # un-migrated ones and the frontend reading file_path) shows the correct
        # proof. Conservative + reversible: only when the primary is application /
        # manifest owned and differs from the current file_path; the detection site
        # is preserved under f["detected_location"].
        if _promote_primary(f, sel):
            corrected += 1
        f["evidence_view"] = build_evidence_view(f, platform=ctx.platform,
                                                 binary_files=_binary_files)
        annotated += 1
        if sel.get("candidate_count", 0) > 1:
            multi += 1

    summary = {
        "version": C.SELECTION_VERSION,
        "bug_bounty_mode": bb,
        "findings_annotated": annotated,
        "multi_candidate_findings": multi,
        "primary_location_corrected": corrected,
    }
    results["evidence_selection_summary"] = summary
    log.info("[evidence_selection] %s | %s", ctx.platform, summary)
    return results
