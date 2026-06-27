"""
Finding Pipeline — canonical/legacy boundary adapters (Beetle 2.0, Phase 1.15).

This module is the SINGLE authoritative place where Beetle converts between the
legacy finding ``dict`` and the typed :class:`CanonicalFinding`. It exists so the
rest of the backend can move toward operating on canonical objects with legacy
dictionaries confined to compatibility edges — the target shape being::

    Analyzer ─▶ CanonicalFinding ─▶ … ─▶ CanonicalFinding ─▶ legacy dict (API)

rather than the anti-pattern of bouncing dict→canonical→dict→canonical at every
stage. When the upcoming Ownership Engine and Confidence Engine are inserted as
canonical-native stages, they take ``list[CanonicalFinding]`` in and hand it on,
calling :func:`to_canonical` once at their entry and :func:`to_legacy` once at
their exit — never in between.

Why the live finalize pipeline is NOT fully converted in this phase
-------------------------------------------------------------------
Beetle's finalize stage today is ~15 ordered passes (in ``android_analyzer`` /
``ios_analyzer`` and the modules they call: ``finding_model``,
``posture_analyzer``, ``reachability_engine``, ``trust_engine``,
``chain_analyzer``, ``scoring``, ``analyst_intel``, ``masvs_intel``,
``workspaces`` …) that mutate plain dicts in place and depend on each other's
ordering. Re-typing all of them at once is exactly the "massive rewrite" this
phase forbids, and every pass is a place a regression could hide. So this phase
lays the *spine* (these adapters + one authoritative normalizer + tests) and
migrates stages incrementally in later phases. The remaining migration points are
catalogued in ``MIGRATION_MAP`` below and in ``internal/PHASE_1_15_MIGRATION_MAP.md``.

Compatibility contract
-----------------------
* :func:`to_canonical` is lossless — the full original dict survives in
  ``CanonicalFinding.raw``.
* :func:`to_legacy` is non-destructive — it only ADDS canonical field names that
  were absent, so its output is always a superset of the input dict. Existing
  scan output, reports and the frontend are therefore unaffected.
* :func:`enrich_canonical_fields` is the incremental-migration tool: it rewrites a
  findings list in place to carry canonical names *additively*. It is provided
  for future stage migrations and is deliberately NOT wired into the live scan
  output path in this phase (doing so would add keys to serialized output).
"""
from __future__ import annotations

import logging
from typing import Iterable

from .canonical_finding import CanonicalFinding

log = logging.getLogger("cortex.finding_pipeline")


# ── Edge adapters ────────────────────────────────────────────────────────────
def to_canonical(findings: Iterable[dict], *, platform: str | None = None) -> list[CanonicalFinding]:
    """Legacy finding dicts → ``list[CanonicalFinding]`` (lossless).

    Call this ONCE at the entry of a canonical-native stage. Non-dict entries
    are skipped (defensive: the legacy lists occasionally contain stray values).
    ``CanonicalFinding`` already carries another canonical object through
    unchanged, so this is idempotent on canonical input.
    """
    out: list[CanonicalFinding] = []
    for f in findings or []:
        if isinstance(f, CanonicalFinding):
            out.append(f)
        elif isinstance(f, dict):
            out.append(CanonicalFinding.from_legacy(f, platform=platform))
    return out


def to_legacy(items: Iterable[CanonicalFinding | dict]) -> list[dict]:
    """``list[CanonicalFinding]`` → legacy finding dicts (non-destructive superset).

    Call this ONCE at the exit of a canonical-native stage, at the boundary back
    to the dict-based pipeline / API / reports. Dicts pass through untouched so a
    partially-migrated list is safe.
    """
    out: list[dict] = []
    for f in items or []:
        if isinstance(f, CanonicalFinding):
            out.append(f.to_legacy())
        elif isinstance(f, dict):
            out.append(f)
    return out


def enrich_canonical_fields(findings: list[dict], *, platform: str | None = None) -> list[dict]:
    """Add canonical field names to each finding dict, in place, additively.

    The incremental-migration helper: a stage can call this to guarantee every
    finding carries canonical names (``rule_id``, ``source_module``, normalized
    ``confidence``, …) without dropping any legacy key. Returns the same list.

    NOT wired into the serialized scan-output path in Phase 1.15 — it changes the
    *shape* of emitted dicts (adds keys), which a later phase will adopt
    deliberately once the consuming stages expect canonical names.
    """
    for i, f in enumerate(findings or []):
        if isinstance(f, dict):
            findings[i] = CanonicalFinding.from_legacy(f, platform=platform).to_legacy()
    return findings


# ── Live diagnostics (read-only; safe to run on every scan) ──────────────────
def canonical_diagnostics(findings: Iterable[dict], *, platform: str | None = None) -> dict:
    """Run findings through the canonical model and summarize representability.

    Read-only and side-effect-free with respect to the findings: it proves, on
    every real scan, that the canonical model can represent the live finding set
    and surfaces any data-quality warnings (missing rule_id/title/evidence). The
    returned dict is intended for logging only in this phase — callers must not
    splice it into serialized scan output (that would change the JSON shape).
    """
    total = 0
    representable = 0
    warning_counts: dict[str, int] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        total += 1
        try:
            cf = CanonicalFinding.from_legacy(f, platform=platform)
        except Exception:
            warning_counts["from_legacy_error"] = warning_counts.get("from_legacy_error", 0) + 1
            continue
        representable += 1
        for w in cf.validate():
            warning_counts[w] = warning_counts.get(w, 0) + 1
    return {
        "total": total,
        "representable": representable,
        "warnings": warning_counts,
    }


def log_canonical_diagnostics(findings: Iterable[dict], *, platform: str = "android") -> dict:
    """Compute and log canonical-representability diagnostics. Returns the dict.

    Used as the first *live* exercise of ``CanonicalFinding`` in the scan
    pipeline: it touches every finding of every scan but changes no value and
    emits no serialized output — only a log line — so it cannot regress behavior.
    """
    diag = canonical_diagnostics(findings, platform=platform)
    log.info(
        "[canonical] %s | findings=%d representable=%d warnings=%s",
        platform, diag["total"], diag["representable"], diag["warnings"] or "{}",
    )
    return diag


# ── Remaining migration map (documentation, not executed) ────────────────────
# Ordered by safety/leverage. Each entry: the stage, what it operates on today,
# and the canonical-native target. Later phases tick these off one at a time,
# each behind to_canonical()/to_legacy() edges and its own compatibility test.
MIGRATION_MAP = (
    {
        "stage": "Analyzer finding production (~25 analyzers)",
        "today": "dict literals appended to results['findings']",
        "target": "emit via a canonical builder; to_legacy() at the append edge",
        "risk": "medium — many call sites; do per-analyzer with golden output tests",
        "status": "pending",
    },
    {
        "stage": "finding_model finalize passes (ownership/confidence/suppression/dedup)",
        "today": "dict mutation across Phase 0–6 passes, order-dependent",
        "target": "operate on list[CanonicalFinding]; one to_canonical at entry, "
                  "one to_legacy at exit of the finalize block",
        "risk": "high — the core noise engine; migrate after analyzers + tests",
        "status": "pending",
    },
    {
        "stage": "Storage findings-table write (database.save_scan)",
        "today": "f.get(...) → columns; confidence stored as-is (str or int)",
        "target": "CanonicalFinding → row mapper (numeric confidence, normalized line)",
        "risk": "low-but-not-zero — changes some internal column values "
                "(e.g. confidence 'high'→90); internal table, low-read",
        "status": "pending — deferred to preserve exact stored values this phase",
    },
    {
        "stage": "Report engines (pdf/sarif/sbom) + API serializer",
        "today": "read result dict / results.json",
        "target": "consume CanonicalFinding.to_legacy() at the API edge",
        "risk": "low — additive keys; adopt once consumers expect canonical names",
        "status": "pending",
    },
)
