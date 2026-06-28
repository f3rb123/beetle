"""
Finding Fusion Engine — conflict resolution (Beetle 2.0, Phase 1.95).

When two engines describe the same issue they often disagree on the details:
different severity, category, ownership verdict or code location. Fusion must
produce ONE finding, so those disagreements are resolved by DETERMINISTIC rules
and — critically — every resolution is recorded so the decision is explainable.

Resolution rules
----------------
* **Severity** — the most severe wins (lowest ``severity_rank``). Security tools
  under-rate as often as they over-rate; the engine that saw the worse case is
  trusted, and the disagreement is documented.
* **Category** — ties/disagreements break by ``config.CATEGORY_PRECEDENCE`` so the
  most security-meaningful label is adopted deterministically.
* **Ownership** — the verdict with the highest ``owner_confidence`` wins (the
  Ownership Engine's own confidence is the arbiter); ``Unknown`` never beats a
  concrete owner.
* **Location** — the primary location is taken from the finding with the strongest
  evidence (validated > has-snippet > most file-evidence); the others are retained
  as merged locations, never dropped.

This module only DECIDES and DOCUMENTS; the engine applies the decisions and keeps
all evidence. Pure and deterministic.
"""
from __future__ import annotations

from ..canonical_finding import CanonicalFinding, severity_rank
from . import config as C

_UNKNOWN_OWNERS = {"", "unknown", "owner_unknown"}


def _line_bucket(line: int) -> int:
    if not line or line <= 0 or C.LINE_BUCKET <= 0:
        return line or 0
    return (line - 1) // C.LINE_BUCKET


def _evidence_strength(cf: CanonicalFinding) -> tuple:
    """Sort key (higher = stronger) for choosing the primary location."""
    validated = cf.validation_status == "valid" or cf.raw.get("validated") is True
    has_snippet = bool(cf.snippet or cf.raw.get("snippet") or cf.raw.get("code_context"))
    return (1 if validated else 0, 1 if has_snippet else 0, len(cf.file_evidence),
            cf.overall_confidence or cf.confidence or 0)


def _category_rank(cat: str) -> int:
    c = (cat or "").strip().lower()
    for i, name in enumerate(C.CATEGORY_PRECEDENCE):
        if name in c:
            return i
    return len(C.CATEGORY_PRECEDENCE)  # unknown categories sort last


def analyze(group: list[CanonicalFinding]) -> dict:
    """Resolve metadata conflicts across a group. Returns resolutions + conflicts.

    ``resolutions`` holds the chosen values the engine applies; ``conflicts`` is a
    list of human-readable disagreement records (empty when the engines agreed).
    """
    conflicts: list[dict] = []
    resolutions: dict = {}

    # ── Severity ──────────────────────────────────────────────────────────────
    sevs = [cf.severity for cf in group if cf.severity]
    chosen_sev = min(sevs, key=severity_rank) if sevs else "info"
    resolutions["severity"] = chosen_sev
    if len(set(sevs)) > 1:
        conflicts.append({
            "field": "severity",
            "values": sorted(set(sevs), key=severity_rank),
            "chosen": chosen_sev,
            "rule": "most-severe-wins",
        })

    # ── Category ──────────────────────────────────────────────────────────────
    cats = [cf.category for cf in group if cf.category]
    if cats:
        chosen_cat = min(cats, key=_category_rank)
        resolutions["category"] = chosen_cat
        if len({c.strip().lower() for c in cats}) > 1:
            conflicts.append({
                "field": "category",
                "values": sorted(set(cats)),
                "chosen": chosen_cat,
                "rule": "category-precedence",
            })

    # ── Ownership ─────────────────────────────────────────────────────────────
    owned = [cf for cf in group if (cf.owner_type or "").strip().lower() not in _UNKNOWN_OWNERS]
    if owned:
        best = max(owned, key=lambda cf: cf.owner_confidence or 0)
        resolutions["owner_type"] = best.owner_type
        resolutions["owner_name"] = best.owner_name
        resolutions["owner_confidence"] = best.owner_confidence
        distinct = {(cf.owner_type or "").strip().lower() for cf in owned}
        if len(distinct) > 1:
            conflicts.append({
                "field": "ownership",
                "values": sorted({cf.owner_type for cf in owned}),
                "chosen": best.owner_type,
                "rule": "highest-owner-confidence",
            })

    # ── Location ──────────────────────────────────────────────────────────────
    primary = max(group, key=_evidence_strength)
    resolutions["primary_location"] = {
        "file_path": primary.file_path,
        "line": primary.line,
    }
    distinct_locs = {(cf.file_path or "", cf.line or 0) for cf in group}
    # A genuine location conflict means DIFFERENT files, or lines drifting beyond
    # the merge bucket. Trivial line drift inside the bucket (which we deliberately
    # tolerate to merge) is NOT a conflict and must not penalize corroboration.
    files = {fp for fp, _ in distinct_locs}
    buckets = {(fp, _line_bucket(ln)) for fp, ln in distinct_locs}
    if len(files) > 1 or len(buckets) > 1:
        conflicts.append({
            "field": "location",
            "values": [{"file_path": fp, "line": ln} for fp, ln in sorted(distinct_locs)],
            "chosen": resolutions["primary_location"],
            "rule": "strongest-evidence-wins",
        })

    # ── Confidence spread (documented, not resolved here) ─────────────────────
    confs = [cf.overall_confidence or cf.confidence or 0 for cf in group]
    if confs and (max(confs) - min(confs)) >= 25:
        conflicts.append({
            "field": "confidence",
            "values": sorted(set(confs)),
            "chosen": max(confs),
            "rule": "agreement-weighted (see fusion_score)",
        })

    return {"resolutions": resolutions, "conflicts": conflicts}
