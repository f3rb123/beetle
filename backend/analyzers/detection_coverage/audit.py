"""
Detection Coverage Audit (Beetle 2.0, Phase 1.98 — consolidate-first).

Automated guardrails for the "consolidate first, expand second" philosophy. Instead
of trusting that we never created a duplicate or an orphaned capability, this module
cross-references the registry against the REAL detectors and flags:

* ``duplicate_rule_patterns`` — two SAST rules with the identical regex (copy-paste).
* ``duplicate_rule_ids``      — two SAST rules sharing an id.
* ``orphan_crypto_refs``      — a crypto coverage entry whose ``detector_ref`` does
  not resolve to an actual ``code_rules`` rule (documentation drift).
* ``unbacked_secret_entries`` — a secret coverage entry whose pattern is not in the
  unified catalog (so it would never actually match).
* ``secret_name_overlap``     — secret names defined under more than one provenance
  (informational: native/apkleaks overlap is BY DESIGN — fusion merges them — but
  the count should not grow unexpectedly).

``report()`` aggregates; the regression test asserts the hard-failure lists are empty.
This is analysis only — no scanning, no mutation.
"""
from __future__ import annotations

from . import benchmark, registry


def _code_rules():
    from ..code_rules import CODE_RULES, IOS_CODE_RULES
    return list(CODE_RULES) + list(IOS_CODE_RULES)


def duplicate_rule_patterns() -> list[dict]:
    by_pattern: dict[str, list[str]] = {}
    for r in _code_rules():
        by_pattern.setdefault(r.get("pattern", ""), []).append(r.get("id", "?"))
    return [{"pattern": p, "rule_ids": ids} for p, ids in by_pattern.items() if p and len(ids) > 1]


def duplicate_rule_ids() -> list[str]:
    seen: dict[str, int] = {}
    for r in _code_rules():
        rid = r.get("id", "")
        seen[rid] = seen.get(rid, 0) + 1
    return sorted(rid for rid, n in seen.items() if rid and n > 1)


def orphan_crypto_refs() -> list[str]:
    """Crypto coverage entries whose detector_ref isn't a real code-rule id."""
    rule_ids = {r.get("id") for r in _code_rules()}
    orphans = []
    for e in registry.by_kind(registry.KIND_CRYPTO):
        ref = e.detector_ref
        # Only refs that look like a code-rule id are expected to resolve; refs like
        # "cert:weak_rsa" point at other analyzers and are documentation.
        if ref and ref.startswith(("android_", "ios_")) and ref not in rule_ids:
            orphans.append(e.id)
    return sorted(orphans)


def unbacked_secret_entries() -> list[str]:
    """Secret coverage entries whose pattern is absent from the unified catalog."""
    from .. import secret_catalog
    catalog_names = {p.get("name") for p in secret_catalog.combined()}
    return sorted(e.id for e in registry.by_kind(registry.KIND_SECRET)
                  if e.pattern and e.name not in catalog_names)


def secret_name_overlap() -> dict:
    """Secret pattern names defined under >1 provenance (by-design overlap)."""
    from .. import secret_catalog
    by_name: dict[str, set] = {}
    for prov in ("beetle_native", "apkleaks", "coverage"):
        for p in secret_catalog.patterns(prov):
            by_name.setdefault(p.get("name", ""), set()).add(prov)
    return {name: sorted(provs) for name, provs in by_name.items() if len(provs) > 1}


def report() -> dict:
    dup_pat = duplicate_rule_patterns()
    dup_ids = duplicate_rule_ids()
    orphans = orphan_crypto_refs()
    unbacked = unbacked_secret_entries()
    overlap = secret_name_overlap()
    return {
        "duplicate_rule_patterns": dup_pat,
        "duplicate_rule_ids": dup_ids,
        "orphan_crypto_refs": orphans,
        "unbacked_secret_entries": unbacked,
        "secret_name_overlap": overlap,
        "ok": not (dup_pat or dup_ids or orphans or unbacked),
        "overlap_count": len(overlap),
    }
