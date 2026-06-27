"""
Compatibility tests for the canonical/legacy boundary (Beetle 2.0, Phase 1.15).

Proves the migration spine is safe:
  * to_canonical / to_legacy are lossless and non-destructive,
  * the adapters are idempotent and handle partially-migrated lists,
  * canonical names are added without dropping legacy keys,
  * severity normalization is consolidated to one authority that is behaviorally
    identical to the previous local implementation for every real severity,
  * canonical_diagnostics represents every major finding type Beetle emits
    (Android, iOS, attack-chain, synthesized, dependency) with no warnings.

Runnable standalone (no third-party deps) or under pytest:
    python -m tests.test_finding_pipeline      # from backend/
    python backend/tests/test_finding_pipeline.py
"""
from __future__ import annotations

import json
import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import finding_pipeline as fp  # noqa: E402
from analyzers.canonical_finding import CanonicalFinding  # noqa: E402

# Reuse the representative corpus from the Phase 1.1 tests so both suites stay in
# sync about "what Beetle emits today".
from tests.test_canonical_finding import ALL, ANDROID_FINDINGS, IOS_FINDINGS  # noqa: E402


def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


# ── Adapter behavior ──────────────────────────────────────────────────────────
def test_to_canonical_types_and_platform():
    cans = fp.to_canonical(ANDROID_FINDINGS, platform="android")
    _check(len(cans) == len(ANDROID_FINDINGS), "lost findings in to_canonical")
    _check(all(isinstance(c, CanonicalFinding) for c in cans), "non-canonical output")
    _check(all(c.platform == "android" for c in cans), "platform not stamped")


def test_to_canonical_skips_non_dicts():
    cans = fp.to_canonical([ANDROID_FINDINGS[0], None, "x", 5], platform="android")
    _check(len(cans) == 1, f"expected 1, got {len(cans)}")


def test_round_trip_is_lossless_superset():
    """to_legacy(to_canonical(d)) preserves every original key/value."""
    for d, platform in ALL:
        out = fp.to_legacy(fp.to_canonical([d], platform=platform))[0]
        for k, v in d.items():
            _check(k in out, f"[{d.get('title')}] dropped key {k!r}")
            _check(out[k] == v, f"[{d.get('title')}] changed {k!r}: {v!r} -> {out[k]!r}")


def test_to_canonical_is_idempotent():
    """Feeding canonical objects back through to_canonical is a no-op pass-through."""
    once = fp.to_canonical(ANDROID_FINDINGS, platform="android")
    twice = fp.to_canonical(once, platform="android")
    _check(all(a is b for a, b in zip(once, twice)),
           "to_canonical should pass CanonicalFinding through unchanged")


def test_to_legacy_handles_mixed_list():
    """A partially-migrated list (mix of canonical + dict) survives to_legacy."""
    mixed = [CanonicalFinding.from_legacy(ANDROID_FINDINGS[0]), dict(ANDROID_FINDINGS[1])]
    out = fp.to_legacy(mixed)
    _check(len(out) == 2 and all(isinstance(o, dict) for o in out), "mixed list not handled")
    _check(out[1]["name"] == "AWS Access Key ID", "raw dict passed through must be untouched")


def test_enrich_adds_canonical_names_in_place():
    findings = [dict(IOS_FINDINGS[1])]  # uses `id`, `file`, `line_number`, textual confidence
    same = fp.enrich_canonical_fields(findings, platform="ios")
    _check(same is findings, "enrich should return the same list object")
    f = findings[0]
    _check(f["rule_id"] == "ios_wkwebview_js_bridge", "canonical rule_id not added")
    _check(f["file_path"] == "Payload/App.app/Sources/Bridge.m", "canonical file_path not added")
    _check(f["line"] == 12, "canonical line not added")
    # Non-destructive: the legacy textual `confidence` is preserved as-is; the
    # normalized numeric value is exposed via `confidence_score` (the key the
    # existing pipeline already uses), never by clobbering `confidence`.
    _check(f["confidence"] == "medium", "legacy textual confidence must be preserved")
    _check(f["confidence_score"] == 60, "numeric confidence_score not added")
    # legacy keys preserved
    _check(f["id"] == "ios_wkwebview_js_bridge" and f["file"].endswith("Bridge.m"),
           "legacy keys must be preserved")


# ── Live diagnostics ──────────────────────────────────────────────────────────
def test_canonical_diagnostics_represents_all_types():
    findings = ANDROID_FINDINGS + IOS_FINDINGS
    diag = fp.canonical_diagnostics(findings, platform="android")
    _check(diag["total"] == len(findings), "diagnostics miscounted findings")
    _check(diag["representable"] == len(findings), "some findings not representable")
    # The representative corpus is clean: no missing-evidence / range warnings.
    _check("no extractable evidence" not in diag["warnings"],
           f"unexpected evidence warning: {diag['warnings']}")


def test_diagnostics_is_read_only():
    """Diagnostics must not mutate the findings it inspects."""
    before = json.dumps(ANDROID_FINDINGS, sort_keys=True, default=str)
    fp.canonical_diagnostics(ANDROID_FINDINGS, platform="android")
    after = json.dumps(ANDROID_FINDINGS, sort_keys=True, default=str)
    _check(before == after, "canonical_diagnostics mutated the findings list")


# ── Normalization consolidation ───────────────────────────────────────────────
def test_severity_normalizer_consolidated_and_equivalent():
    """finding_model.normalize_severity_label now delegates to the single
    authority (common.normalize_severity) and is identical for every real
    severity producers emit."""
    from analyzers import finding_model, common
    for sev in ("critical", "high", "medium", "low", "info",
                "CRITICAL", "High", "  Medium ", None, "", "info"):
        _check(finding_model.normalize_severity_label(sev) == common.normalize_severity(sev),
               f"severity normalizers diverge on {sev!r}")
    # And the canonical model uses the same authority.
    _check(CanonicalFinding(title="t", severity="HIGH").severity == "high",
           "canonical severity not normalized via the shared authority")


def test_migration_map_present():
    """The remaining migration points are documented for later phases."""
    _check(len(fp.MIGRATION_MAP) >= 3, "migration map should catalogue remaining stages")
    _check(all("stage" in m and "target" in m and "status" in m for m in fp.MIGRATION_MAP),
           "migration map entries malformed")


# ── Standalone runner ─────────────────────────────────────────────────────────
def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
