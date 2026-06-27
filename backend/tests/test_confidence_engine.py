"""
Confidence Engine tests (Beetle 2.0, Phase 1.3).

Covers high/low-confidence findings, SDK/framework/manifest/native/secret/
generated/binary findings, missing snippet/line, partial decompilation,
multiple evidence sources, determinism, dimension independence, the direct read
of ownership confidence, and the guarantee that enrichment never changes
existing finding data.

Runnable standalone or under pytest:
    python -m tests.test_confidence_engine     # from backend/
    python backend/tests/test_confidence_engine.py
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.canonical_finding import CanonicalFinding  # noqa: E402
from analyzers import confidence as conf  # noqa: E402
from analyzers.confidence import ConfidenceEngine  # noqa: E402
from analyzers.confidence import config as C  # noqa: E402

ENGINE = ConfidenceEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _f(**d):
    d.setdefault("title", "t")
    d.setdefault("severity", "high")
    return CanonicalFinding.from_legacy(d, platform=d.get("platform", "android"))


def _score(**d):
    return ENGINE.classify(_f(**d))


# ── Detection confidence per detector class ───────────────────────────────────
def test_detection_per_detector_class():
    cases = {
        "manifest": ("structural", {"evidence_type": "manifest"}, 95),
        "semgrep":  ("semgrep", {"evidence_type": "semgrep"}, 88),
        "sast":     ("regex", {"source": "SAST"}, 72),
        "taint":    ("dataflow", {"source": "TAINT", "evidence_type": "taint_flow"}, 85),
        "cert":     ("structural", {"source": "CERT", "category": "Certificate"}, 95),
        "elf":      ("binary", {"source": "ELF", "category": "Binary Hardening"}, 90),
        "cve":      ("dep", {"source": "CVE-MAP", "category": "Vulnerable Component"}, 90),
        "secret":   ("secret", {"source": "EVIDENCE", "category": "Secrets"}, 80),
    }
    for label, (_n, d, want) in cases.items():
        r = _score(**d)
        _check(r.detection == want, f"{label} detection {r.detection} != {want}")


def test_validated_detection_is_max():
    r = _score(source="EVIDENCE", category="Secrets", validation_status="valid")
    _check(r.detection == 100, f"validated detection {r.detection}")


# ── Ownership confidence read directly from the Ownership Engine ──────────────
def test_ownership_read_directly():
    r = _score(owner_type="ThirdPartySDK", owner_confidence=100)
    _check(r.ownership == 100, f"ownership {r.ownership} should mirror owner_confidence")
    # If ownership never ran, use a neutral prior (not 0).
    r2 = _score()
    _check(r2.ownership == C.OWNERSHIP_NEUTRAL_DEFAULT, f"neutral ownership {r2.ownership}")


# ── Evidence confidence ───────────────────────────────────────────────────────
def test_evidence_more_is_higher():
    bare = _score(source="SAST").evidence
    located = _score(source="SAST", file_path="a.java", line=10).evidence
    full = _score(source="SAST", file_path="a.java", line=10, snippet="x();",
                  method_name="m", class_name="C", source_resolved=True,
                  file_evidence=[{"path": "a.java"}, {"path": "b.java"}]).evidence
    _check(bare < located < full, f"evidence not monotonic: {bare} {located} {full}")
    _check(full >= 90, f"full evidence should be high, got {full}")


def test_missing_snippet_and_line_lower_evidence():
    with_all = _score(source="SAST", file_path="a.java", line=10, snippet="x();").evidence
    no_snippet = _score(source="SAST", file_path="a.java", line=10).evidence
    no_line = _score(source="SAST", file_path="a.java", snippet="x();").evidence
    _check(no_snippet < with_all, "missing snippet should lower evidence")
    _check(no_line < with_all, "missing line should lower evidence")


def test_multiple_evidence_sources():
    one = _score(source="SAST", file_path="a.java", file_evidence=[{"path": "a.java"}]).evidence
    many = _score(source="SAST", file_path="a.java",
                  file_evidence=[{"path": "a.java"}, {"path": "b.java"}, {"path": "c.java"}]).evidence
    _check(many > one, f"multiple evidence should raise evidence: {one} -> {many}")


def test_partial_decompilation_caps_evidence_and_overall():
    r = _score(source="TAINT", evidence_type="taint_flow", file_path="Lcom/x/Y;",
               unresolved_evidence=True, owner_type="Application", owner_confidence=90)
    _check(r.evidence <= C.EVIDENCE_UNRESOLVED_CAP, f"unresolved evidence cap {r.evidence}")
    _check(r.overall <= C.OVERALL_UNRESOLVED_CAP, f"unresolved overall cap {r.overall}")
    _check(r.stage == "Unresolved-Evidence", f"stage {r.stage}")


# ── Context confidence ────────────────────────────────────────────────────────
def test_context_by_owner():
    app = _score(owner_type="Application", owner_confidence=90).context
    sdk = _score(owner_type="ThirdPartySDK", owner_confidence=100).context
    fw = _score(owner_type="AndroidFramework", owner_confidence=98).context
    gen = _score(owner_type="GeneratedCode", owner_confidence=95).context
    _check(app > sdk > fw, f"context order app>sdk>fw: {app} {sdk} {fw}")
    _check(gen <= 30, f"generated context low: {gen}")


def test_manifest_context_floor():
    r = _score(evidence_type="manifest", category="Network Security",
               owner_type="Unknown", owner_confidence=55)
    _check(r.context >= C.CONTEXT_APP_CONFIG_FLOOR, f"manifest context {r.context}")


# ── Exploitability confidence (conservative, NOT severity) ────────────────────
def test_exploitability_signals_and_caps():
    reachable = _score(owner_type="Application", owner_confidence=90,
                       category="Attack Surface", reachability="YES", exported=True)
    unreach = _score(owner_type="Application", owner_confidence=90,
                     category="Cryptography", reachability="NO")
    generated = _score(owner_type="GeneratedCode", owner_confidence=95,
                       category="Secrets", reachability="YES")
    _check(reachable.exploitability > unreach.exploitability, "reachable > unreachable")
    _check(unreach.exploitability <= C.EXPLOIT_UNREACHABLE_CAP, f"unreachable cap {unreach.exploitability}")
    _check(generated.exploitability <= C.EXPLOIT_GENERATED_CAP,
           f"generated exploitability cap {generated.exploitability}")


def test_validated_secret_high_overall():
    r = _score(source="EVIDENCE", category="Secrets", validation_status="valid",
               owner_type="Application", owner_confidence=90, file_path="C.java", line=3, snippet="k")
    _check(r.overall >= C.OVERALL_VALIDATED_FLOOR, f"validated overall {r.overall}")
    _check(r.stage == "Validated", f"stage {r.stage}")


# ── High vs low overall ───────────────────────────────────────────────────────
def test_high_confidence_app_finding():
    r = _score(source="SAST", owner_type="Application", owner_confidence=90,
               file_path="sources/com/app/Pay.java", line=20, snippet="key=...",
               method_name="pay", class_name="Pay", source_resolved=True,
               file_evidence=[{"path": "a"}, {"path": "b"}], reachability="YES",
               category="Cryptography")
    _check(r.overall >= 75, f"expected high overall, got {r.overall}")
    _check(C.band_for(r.overall) == "High", "should band High")


def test_low_confidence_framework_finding():
    r = _score(source="SAST", owner_type="AndroidFramework", owner_confidence=98,
               category="Cryptography")  # no line/snippet/method
    _check(r.overall < 60, f"framework w/o evidence should be lowish, got {r.overall}")


def test_framework_eval_high_detection_low_context():
    # "Framework eval()" — high detection, low context, dimensions independent.
    r = _score(evidence_type="semgrep", source="semgrep", category="Command Execution",
               owner_type="AndroidFramework", owner_confidence=98, snippet="eval()")
    _check(r.detection == 88, f"detection {r.detection}")
    _check(r.context == 25, f"context {r.context}")
    _check(r.overall < r.detection, "overall must be pulled below detection by context")


# ── Dimension independence + breakdown + reason ───────────────────────────────
def test_dimensions_independent_and_breakdown_retained():
    r = _score(source="SAST", owner_type="GeneratedCode", owner_confidence=95,
               file_path="x/BuildConfig.java", line=1, snippet="X")
    # High detection but low context/exploitability — not collapsed into one number.
    _check(r.detection >= 70 and r.context <= 30 and r.exploitability <= 25,
           f"dims not independent: det={r.detection} ctx={r.context} exp={r.exploitability}")
    bd = r.breakdown["dimensions"]
    _check(set(bd) == {"detection", "ownership", "evidence", "context", "exploitability"},
           "breakdown must retain all five dimensions")
    for dim in bd.values():
        _check("score" in dim and "weight" in dim and "factors" in dim, "breakdown dim malformed")


def test_reason_is_explainable():
    r = _score(source="SAST", owner_type="Application", owner_confidence=90,
               file_path="a.java", line=2, snippet="x")
    _check(r.reason and "Application" in r.reason, f"reason should mention context: {r.reason}")


def test_overall_weights_sum_to_one():
    _check(abs(sum(C.OVERALL_WEIGHTS.values()) - 1.0) < 1e-9, "weights must sum to 1.0")


# ── Determinism ───────────────────────────────────────────────────────────────
def test_deterministic():
    d = dict(source="TAINT", evidence_type="taint_flow", owner_type="Application",
             owner_confidence=90, file_path="a.java", line=5, snippet="x",
             call_chain=["a", "b"], reachability="MAYBE")
    a = ENGINE.classify(_f(**d))
    b = ENGINE.classify(_f(**d))
    _check(a.to_fields() == b.to_fields(), "engine must be deterministic")


# ── Pipeline integration + non-destructive ────────────────────────────────────
def test_annotate_non_destructive_and_complete():
    results = {
        "platform": "android",
        "findings": [
            {"title": "A", "severity": "critical", "rule_id": "r1", "source": "SAST",
             "owner_type": "Application", "owner_confidence": 90,
             "file_path": "a.java", "line": 5, "snippet": "x", "confidence": 75,
             "confidence_score": 80, "extra": "keep-me"},
            {"title": "B", "severity": "low", "source": "EVIDENCE",
             "owner_type": "ThirdPartySDK", "owner_confidence": 100},
        ],
    }
    import copy
    before = copy.deepcopy(results["findings"])

    conf.annotate(results)

    CONF_KEYS = {"detection_confidence", "ownership_confidence", "evidence_confidence",
                 "context_confidence", "exploitability_confidence", "overall_confidence",
                 "confidence_reason", "confidence_breakdown", "confidence_stage",
                 "confidence_version"}
    for orig, now in zip(before, results["findings"]):
        for k, v in orig.items():
            _check(k in now and now[k] == v, f"enrichment changed existing key {k}")
        added = set(now) - set(orig)
        _check(added <= CONF_KEYS, f"unexpected non-confidence keys added: {added - CONF_KEYS}")
        for ck in CONF_KEYS:
            _check(ck in now, f"missing {ck}")
    # The legacy confidence/confidence_score are explicitly untouched.
    _check(results["findings"][0]["confidence"] == 75, "legacy confidence changed")
    _check(results["findings"][0]["confidence_score"] == 80, "legacy confidence_score changed")
    _check("by_band" in results["confidence_summary"], "summary missing")


def test_end_to_end_with_ownership():
    """Ownership → Confidence: ownership dimension reflects the real engine output."""
    from analyzers import ownership
    results = {
        "platform": "android", "app_info": {"package": "com.acme.app"}, "app_name": "Acme",
        "findings": [
            {"title": "App secret", "severity": "critical", "source": "EVIDENCE",
             "category": "Secrets", "file_path": "sources/com/acme/app/Cfg.java",
             "line": 3, "snippet": "AKIA..."},
            {"title": "OkHttp issue", "severity": "low", "source": "SAST",
             "package": "okhttp3.OkHttpClient"},
        ],
    }
    ownership.annotate(results)
    conf.annotate(results)
    app_f, lib_f = results["findings"]
    _check(app_f["ownership_confidence"] == app_f["owner_confidence"], "ownership dim mismatch")
    _check(app_f["context_confidence"] > lib_f["context_confidence"],
           "app finding should have higher context than library finding")
    _check(app_f["overall_confidence"] > lib_f["overall_confidence"],
           "app finding should be more confident overall than library noise")


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
