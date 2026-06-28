"""
Finding Fusion Engine tests (Beetle 2.0, Phase 1.95).

Covers the engine contract end to end:

* Two / three engines on the SAME issue collapse to ONE finding "Detected By" all.
* Cross-engine equivalence (different rule ids, small line drift) still merges.
* Distinct issues / distinct files / distinct secret values do NOT over-merge.
* Conflict resolution (severity / category / ownership / location / confidence) is
  deterministic AND documented.
* Evidence is merged without duplicate files/snippets; strongest location wins.
* Provenance (detected_by / detection_count / sources / fusion_score / evidence_count
  / merged_files / merged_locations / fusion) is stamped on fused AND singleton.
* Partial overlap (some merge, some not) in one pass.
* Multi-engine agreement raises Confidence Engine output (with reasoning); conflict
  damps it.
* Attack-chain findings pass through untouched.
* Regression: canonical round-trip of the new fields; fallback parity with dedupe.

Runnable standalone or under pytest:
    python -m tests.test_finding_fusion       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import fusion  # noqa: E402
from analyzers.fusion import identity, conflict  # noqa: E402
from analyzers.canonical_finding import from_legacy  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _f(**kw):
    """A finding dict with sane defaults; override per test."""
    base = {
        "rule_id": "rule", "title": "Issue", "cwe": "CWE-798",
        "severity": "high", "category": "Cloud Credentials",
        "file_path": "a/Config.java", "line": 10, "snippet": "x = AKIA...",
        "detected_by": ["Beetle Native"],
    }
    base.update(kw)
    return base


def _fuse(findings):
    results = {"findings": findings}
    stats = fusion.fuse(results, platform="android")
    return results["findings"], stats


# ── Identity ──────────────────────────────────────────────────────────────────
def test_cross_engine_cwe_unifies_class():
    """Same CWE in same file = same class even with different rule ids/titles."""
    a = _f(rule_id="aws-key", title="AWS Access Key ID", detected_by=["Beetle Native"])
    b = _f(rule_id="hardcoded-aws-credentials", title="Hardcoded AWS key",
           detected_by=["Semgrep"])
    _check(identity.fusion_key(a) == identity.fusion_key(b),
           "same-CWE same-file findings must share a fusion key")


def test_distinct_secret_values_do_not_merge():
    """Two DIFFERENT secret literals in one file are different findings."""
    a = _f(value="AKIAIOSFODNN7EXAMPLE1", masked_value="AKIA****1")
    b = _f(value="AKIAIOSFODNN7EXAMPLE2", masked_value="AKIA****2")
    _check(identity.fusion_key(a) != identity.fusion_key(b),
           "distinct secret values must not collapse together")


def test_broad_cwe_does_not_overmerge_distinct_rules():
    """Audit regression (Defect A): two DIFFERENT rules sharing a BROAD umbrella CWE
    a few lines apart in one file must stay separate — never collapse and drop one.
    e.g. AES/ECB and weak-DES both carry CWE-327."""
    out, _ = _fuse([
        _f(rule_id="android_aes_ecb_default", title="AES/ECB mode", cwe="CWE-327",
           category="Cryptography", file_path="com/app/Crypto.java", line=40,
           snippet="Cipher.getInstance('AES')", detected_by=["Beetle Native"]),
        _f(rule_id="android_weak_cipher_des", title="DES cipher", cwe="CWE-327",
           category="Cryptography", file_path="com/app/Crypto.java", line=42,
           snippet="Cipher.getInstance('DES')", detected_by=["Beetle Native"]),
    ])
    _check(len(out) == 2, "distinct rules sharing a broad CWE must not over-merge")
    _check(sorted(o["title"] for o in out) == ["AES/ECB mode", "DES cipher"],
           "both distinct findings must survive (no data loss)")


def test_broad_cwe_same_issue_still_merges_cross_engine():
    """The fix must not break cross-engine merging: the SAME issue (same title) on a
    broad CWE detected by two engines still collapses to one."""
    out, _ = _fuse([
        _f(rule_id="aes-ecb", title="AES/ECB mode", cwe="CWE-327",
           file_path="a/C.java", line=10, detected_by=["Beetle Native"]),
        _f(rule_id="semgrep-ecb", title="AES/ECB mode", cwe="CWE-327",
           file_path="a/C.java", line=11, detected_by=["Semgrep"]),
    ])
    _check(len(out) == 1, "same broad-CWE issue from two engines must still merge")
    _check(set(out[0]["detected_by"]) == {"Beetle Native", "Semgrep"}, "both engines credited")


def test_broad_cwe_with_value_fingerprint_still_merges():
    """A value-bearing finding (secret) is kept distinct by its fingerprint, so even
    on a broad CWE the same secret from two engines merges and two different secrets
    do not."""
    same = _fuse([
        _f(title="Cleartext Secret", cwe="CWE-312", file_path="a/C.java", line=10,
           value="AKIAIOSFODNN7EXAMPLE", detected_by=["Beetle Native"]),
        _f(title="Hardcoded value", cwe="CWE-312", file_path="a/C.java", line=10,
           value="AKIAIOSFODNN7EXAMPLE", detected_by=["APKLeaks"]),
    ])[0]
    _check(len(same) == 1, "same secret value on a broad CWE must merge across engines")
    diff = _fuse([
        _f(title="Secret A", cwe="CWE-312", file_path="a/C.java", line=10,
           value="AKIAIOSFODNN7EXAMPLE1", detected_by=["Beetle Native"]),
        _f(title="Secret B", cwe="CWE-312", file_path="a/C.java", line=10,
           value="AKIAIOSFODNN7EXAMPLE2", detected_by=["APKLeaks"]),
    ])[0]
    _check(len(diff) == 2, "different secret values must stay separate even on a broad CWE")


def test_android_and_ios_fusion_identical():
    """Android and iOS must produce identical fusion output for identical input."""
    inp = [
        _f(rule_id="a", title="AWS", cwe="CWE-798", severity="high",
           file_path="x/A.java", line=10, detected_by=["Beetle Native"]),
        _f(rule_id="b", title="AWS2", cwe="CWE-798", severity="critical",
           file_path="x/A.java", line=11, detected_by=["Semgrep"]),
    ]
    def _shape(plat):
        r = {"findings": [dict(x) for x in inp]}
        fusion.fuse(r, platform=plat)
        return [(o["detection_count"], o["severity"], sorted(o["detected_by"]),
                 o["fusion_score"]) for o in r["findings"]]
    _check(_shape("android") == _shape("ios"),
           "fusion output must be platform-independent (Android == iOS)")


def test_alias_registry_is_data_only_extensible():
    """A new engine's idiosyncratic rule can be declared equivalent via data."""
    identity.register_alias("CustomEngine", "weird-rule-42", "cwe-798")
    f = {"rule_id": "weird-rule-42", "detected_by": ["CustomEngine"], "title": "??"}
    _check(identity.issue_class(f) == "cwe-798", "alias registry not honored")


# ── Core merging ──────────────────────────────────────────────────────────────
def test_two_engines_same_issue_merge_to_one():
    out, stats = _fuse([
        _f(detected_by=["Beetle Native"]),
        _f(rule_id="semgrep-aws", title="AWS cred", detected_by=["Semgrep"], line=11),
    ])
    _check(len(out) == 1, "two detections of one issue must collapse to ONE finding")
    _check(set(out[0]["detected_by"]) == {"Beetle Native", "Semgrep"},
           "fused finding must be Detected By both engines")
    _check(out[0]["detection_count"] == 2, "detection_count must be 2")
    _check(stats["merged"] == 1 and stats["multi_engine"] == 1, "stats wrong")


def test_three_engines_same_issue_merge_to_one():
    out, _ = _fuse([
        _f(detected_by=["Beetle Native"]),
        _f(rule_id="r2", detected_by=["APKLeaks"], line=11),
        _f(rule_id="r3", detected_by=["Semgrep"], line=12),
    ])
    _check(len(out) == 1, "three detections must collapse to ONE")
    _check(out[0]["detection_count"] == 3, "detection_count must be 3")
    _check(set(out[0]["detected_by"]) == {"Beetle Native", "APKLeaks", "Semgrep"},
           "all three engines must be credited")
    _check(out[0]["fusion_score"] > 75, "3-engine agreement should score high")


def test_distinct_files_stay_separate():
    out, _ = _fuse([
        _f(file_path="a/A.java", detected_by=["Beetle Native"]),
        _f(file_path="b/B.java", detected_by=["Semgrep"]),
    ])
    _check(len(out) == 2, "same issue class in DIFFERENT files must not over-merge")


def test_partial_overlap_in_one_pass():
    out, stats = _fuse([
        _f(detected_by=["Beetle Native"]),                                  # merges
        _f(rule_id="r2", detected_by=["Semgrep"], line=11),                  # with ^
        _f(cwe="CWE-749", category="WebView", title="WebView JS",
           file_path="a/W.java", line=5, detected_by=["Beetle Native"]),    # distinct
    ])
    _check(len(out) == 2, "partial overlap: one merged pair + one distinct")
    counts = sorted(o["detection_count"] for o in out)
    _check(counts == [1, 2], "expected one 2-engine and one 1-engine finding")


# ── Conflict resolution ───────────────────────────────────────────────────────
def test_severity_conflict_takes_most_severe_and_documents():
    out, _ = _fuse([
        _f(severity="medium", detected_by=["Beetle Native"]),
        _f(severity="critical", rule_id="r2", detected_by=["Semgrep"], line=11),
    ])
    _check(out[0]["severity"] == "critical", "most-severe must win")
    fields = {c["field"] for c in out[0]["fusion"]["conflicts"]}
    _check("severity" in fields, "severity conflict must be documented")


def test_category_conflict_uses_precedence():
    out, _ = _fuse([
        _f(category="Secrets", detected_by=["Beetle Native"]),
        _f(category="Cloud Credentials", rule_id="r2", detected_by=["Semgrep"], line=11),
    ])
    _check(out[0]["category"] == "Cloud Credentials",
           "category precedence must pick the more security-meaningful label")


def test_ownership_conflict_highest_confidence_wins():
    out, _ = _fuse([
        _f(owner_type="ThirdPartySDK", owner_confidence=40, detected_by=["Beetle Native"]),
        _f(owner_type="Application", owner_confidence=90, rule_id="r2",
           detected_by=["Semgrep"], line=11),
    ])
    _check(out[0]["owner_type"] == "Application", "highest owner_confidence must win")
    fields = {c["field"] for c in out[0]["fusion"]["conflicts"]}
    _check("ownership" in fields, "ownership conflict must be documented")


def test_confidence_spread_is_documented():
    cfs = [from_legacy(_f(overall_confidence=30)), from_legacy(_f(overall_confidence=90))]
    decision = conflict.analyze(cfs)
    fields = {c["field"] for c in decision["conflicts"]}
    _check("confidence" in fields, "a large confidence spread must be documented")


# ── Evidence merging ──────────────────────────────────────────────────────────
def test_evidence_dedup_and_merged_locations():
    out, _ = _fuse([
        _f(detected_by=["Beetle Native"],
           file_evidence=[{"path": "a/Config.java", "lines": [10], "snippet": "x"}]),
        _f(rule_id="r2", detected_by=["Semgrep"], line=11,
           file_evidence=[{"path": "a/Config.java", "lines": [10], "snippet": "x"}]),
    ])
    fe = out[0].get("file_evidence", [])
    _check(len(fe) == 1, "duplicate evidence entries must be de-duplicated")
    _check(out[0]["merged_files"] == ["a/Config.java"], "merged_files wrong")


def test_location_conflict_prefers_strongest_evidence():
    out, _ = _fuse([
        _f(detected_by=["Beetle Native"], snippet="", validation_status="detected", line=10),
        _f(rule_id="r2", detected_by=["Semgrep"], line=11,
           snippet="strong", validation_status="valid"),
    ])
    _check(out[0]["line"] == 11, "validated/snippet-bearing location should be primary")


# ── Provenance ────────────────────────────────────────────────────────────────
def test_singleton_gets_full_provenance():
    out, _ = _fuse([_f(detected_by=["Beetle Native"])])
    o = out[0]
    for k in ("detected_by", "detection_count", "sources", "fusion_score",
              "evidence_count", "merged_files", "merged_locations", "fusion"):
        _check(k in o, f"singleton missing provenance field {k}")
    _check(o["detection_count"] == 1, "singleton detection_count must be 1")
    _check(o["fusion"]["reason"].startswith("Detected by a single engine"),
           "singleton reason wrong")


def test_unattributed_finding_gets_beetle_native():
    out, _ = _fuse([{"rule_id": "x", "title": "X", "file_path": "a", "line": 1}])
    _check(out[0]["detected_by"] == ["Beetle Native"],
           "a finding with no attribution must default to Beetle Native")


# ── Confidence integration ────────────────────────────────────────────────────
def test_agreement_raises_confidence():
    from analyzers.confidence import engine as ce
    solo = from_legacy(_f(detected_by=["Beetle Native"], detection_count=1,
                          owner_type="Application", owner_confidence=80))
    trio = from_legacy(_f(detected_by=["Beetle Native", "APKLeaks", "Semgrep"],
                          detection_count=3, fusion={"conflicts": []},
                          owner_type="Application", owner_confidence=80))
    r_solo = ce.classify(solo)
    r_trio = ce.classify(trio)
    _check(r_trio.detection > r_solo.detection, "3-engine agreement must raise detection")
    _check(r_trio.overall >= r_solo.overall, "agreement must not lower overall")
    _check("corroborated by 3 independent engines" in r_trio.reason,
           "agreement reasoning must be explainable")


def test_agreement_damped_on_conflict():
    from analyzers.confidence import engine as ce
    clean = from_legacy(_f(detected_by=["A", "B", "C"], detection_count=3,
                           fusion={"conflicts": []}))
    confl = from_legacy(_f(detected_by=["A", "B", "C"], detection_count=3,
                           fusion={"conflicts": [{"field": "severity"}]}))
    _check(ce.classify(confl).detection < ce.classify(clean).detection,
           "metadata conflict must damp the agreement bonus")


# ── Pass-through / regression ─────────────────────────────────────────────────
def test_attack_chain_passthrough():
    chain = _f(is_attack_chain=True, title="Chain", detected_by=["Beetle Native"])
    out, _ = _fuse([chain, _f(detected_by=["Beetle Native"]),
                    _f(rule_id="r2", detected_by=["Semgrep"], line=11)])
    chains = [o for o in out if o.get("is_attack_chain")]
    _check(len(chains) == 1, "attack-chain finding must pass through untouched")
    _check("detection_count" not in chains[0] or chains[0].get("title") == "Chain",
           "attack-chain must not be merged into a member")


def test_canonical_round_trips_fusion_fields():
    d = _f(detection_count=2, fusion_score=70,
           fusion={"engines": ["Beetle Native", "Semgrep"], "conflicts": []})
    cf = from_legacy(d, platform="android")
    _check(cf.detection_count == 2 and cf.fusion_score == 70, "fusion fields lost")
    _check(cf.fusion.get("engines") == ["Beetle Native", "Semgrep"], "fusion dict lost")
    out = cf.to_legacy()
    _check(out["detection_count"] == 2 and out["fusion_score"] == 70,
           "to_legacy dropped fusion fields")


def test_exact_duplicate_collapses_like_dedupe():
    """Two identical findings (the old dedupe case) still collapse to one."""
    out, _ = _fuse([_f(detected_by=["Beetle Native"]),
                    _f(detected_by=["Beetle Native"])])
    _check(len(out) == 1, "exact duplicates must still collapse (dedupe superset)")


def test_empty_and_malformed_are_safe():
    results = {"findings": [None, {"title": "ok", "file_path": "a", "line": 1}]}
    fusion.fuse(results, platform="android")
    _check(any(isinstance(f, dict) and f.get("title") == "ok" for f in results["findings"]),
           "valid finding must survive alongside malformed input")


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
    total = len(tests)
    print(f"\n{total - failures}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
