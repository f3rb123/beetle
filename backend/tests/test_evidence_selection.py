"""
Evidence Selection Engine tests (Beetle 2.0, Phase 1.96).

Covers the contract end to end:

* Multiple candidate files → the application-owned proof wins; SDK/framework lose.
* Library vs application code (AndroidX / GMS / generated) is correctly demoted.
* Identical findings / single candidate → still get a primary + full reasoning.
* Third-party SDK, generated code → rejected (file-intrinsic), not "supporting".
* Attack-chain / reachability / validation raise the score but never RESCUE a
  library file from rejection (scope separation).
* Multi-engine corroborated file gets a bonus.
* Cross-finding de-noise: a file already chosen elsewhere is penalized.
* Bug Bounty Mode sharpens toward reachable, application-owned proof.
* Extensibility: a registered contributor influences the score.
* Regression: additive (does not mutate file_path), safe on empty/malformed input.

Runnable standalone or under pytest:
    python -m tests.test_evidence_selection       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import evidence_selection as es  # noqa: E402
from analyzers.evidence_selection import scoring  # noqa: E402
from analyzers.ownership import context_from_results  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


APP = "com.company.app"


def _results(*findings):
    return {"platform": "android", "app_info": {"package": APP}, "findings": list(findings)}


def _ctx(pkg=APP):
    return context_from_results({"platform": "android", "app_info": {"package": pkg}})


def _f(**kw):
    base = {"title": "Hardcoded Crypto", "severity": "high", "cwe": "CWE-327",
            "file_path": f"sources/{APP.replace('.', '/')}/Pay.java", "line": 12,
            "snippet": "Cipher.getInstance(\"AES/ECB\")"}
    base.update(kw)
    return base


def _ev(path, line=1, snippet="x"):
    return {"path": path, "lines": [line], "snippet": snippet}


# ── Core selection ────────────────────────────────────────────────────────────
def test_application_proof_beats_library():
    f = _f(file_evidence=[
        _ev("sources/androidx/appcompat/Crypto.java", 5),
        _ev("sources/com/google/android/gms/Crypto.java", 8),
        _ev(f"sources/{APP.replace('.', '/')}/PaymentCrypto.java", 12, "Cipher.getInstance(\"AES/ECB\")"),
    ])
    sel = es.select(f, _ctx())
    _check(sel["primary"]["owner_type"] == "Application",
           "application-owned proof must be selected as primary")
    _check(f"{APP.replace('.', '/')}" in sel["primary"]["file_path"], "wrong primary file")


def test_androidx_and_gms_are_rejected_not_supporting():
    f = _f(reachability="YES", in_attack_chain=True, file_evidence=[
        _ev("sources/androidx/appcompat/Crypto.java", 5),
        _ev("sources/com/google/android/gms/Crypto.java", 8),
        _ev(f"sources/{APP.replace('.', '/')}/PaymentCrypto.java", 12),
    ])
    sel = es.select(f, _ctx())
    rejected_files = {r["file_path"] for r in sel["rejected"]}
    _check(any("androidx" in p for p in rejected_files), "AndroidX must be rejected")
    _check(any("gms" in p for p in rejected_files), "GMS must be rejected")
    support_files = {s["file_path"] for s in sel["supporting"]}
    _check(not any(("androidx" in p or "gms" in p) for p in support_files),
           "library files must NOT be promoted to supporting")


def test_finding_signals_do_not_rescue_library():
    """Reachable + attack-chain must not lift a library file's file_score >= 0."""
    f = _f(file_path="sources/androidx/work/Worker.java", line=3,
           reachability="YES", in_attack_chain=True, validated=True,
           file_evidence=[_ev("sources/androidx/work/Worker.java", 3)])
    sel = es.select(f, _ctx())
    # Only candidate → it stays primary, but its file_score must be negative.
    _check(sel["primary"]["file_score"] < 0,
           "a library file's file-intrinsic score must stay negative despite corroboration")


def test_generated_code_demoted():
    # file_path points at the generated file; the real logic is in file_evidence.
    f = _f(file_path=f"sources/{APP.replace('.', '/')}/BuildConfig.java", line=1, snippet="",
           file_evidence=[
               _ev(f"sources/{APP.replace('.', '/')}/BuildConfig.java", 1, ""),
               _ev(f"sources/{APP.replace('.', '/')}/RealLogic.java", 20, "doPayment()"),
           ])
    sel = es.select(f, _ctx())
    _check("RealLogic" in sel["primary"]["file_path"],
           "generated code must lose to real application logic")
    _check(any("BuildConfig" in r["file_path"] for r in sel["rejected"]),
           "generated BuildConfig must be demoted to rejected")


def test_single_candidate_still_gets_primary_and_reason():
    f = _f(file_evidence=[])
    sel = es.select(f, _ctx())
    _check(sel["primary"]["file_path"], "single-candidate finding must still have a primary")
    _check(sel["reason"], "primary must carry a human reason")
    _check(sel["candidate_count"] == 1, "candidate_count should be 1")


def test_attack_chain_and_reachability_raise_total_score():
    common = dict(file_evidence=[_ev(f"sources/{APP.replace('.', '/')}/Pay.java", 12, "y")])
    plain = es.select(_f(**common), _ctx())["primary"]["score"]
    boosted = es.select(_f(reachability="YES", in_attack_chain=True, validated=True, **common),
                        _ctx())["primary"]["score"]
    _check(boosted > plain, "reachability/attack-chain/validation must raise the total score")


def test_multi_engine_file_bonus():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    f = _f(detected_by=["Beetle Native", "Semgrep"], detection_count=2,
           merged_files=[appfile], file_path=appfile, file_evidence=[_ev(appfile, 12, "y")])
    bullets = es.select(f, _ctx())["primary"]["selected_because"]
    _check(any("Corroborated by" in b for b in bullets),
           "a file seen by multiple engines must get the corroboration bonus")


# ── Cross-finding de-noise ────────────────────────────────────────────────────
def test_already_selected_penalty_across_findings():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    shared = _ev(appfile, 12, "y")
    other = _ev(f"sources/{APP.replace('.', '/')}/Other.java", 30, "z")
    crit = _f(severity="critical", file_path=appfile, line=12, file_evidence=[shared])
    high = _f(severity="high", file_path=appfile, line=12,
              file_evidence=[shared, other])
    res = _results(high, crit)  # deliberately out of severity order
    es.annotate(res, platform="android")
    # The critical finding (processed first) should claim the shared file; the high
    # finding should then prefer the un-claimed Other.java for its primary.
    high_primary = high["evidence_selection"]["primary"]["file_path"]
    _check("Other.java" in high_primary,
           "a file already chosen by a higher-severity finding should be de-prioritized")


# ── Bug Bounty Mode ───────────────────────────────────────────────────────────
def test_bug_bounty_mode_amplifies_nonapp_penalty():
    f = _f(file_path="sources/com/facebook/Foo.java", line=2,
           file_evidence=[_ev("sources/com/facebook/Foo.java", 2)])
    normal = es.select(f, _ctx(), bug_bounty=False)["primary"]["file_score"]
    bounty = es.select(f, _ctx(), bug_bounty=True)["primary"]["file_score"]
    _check(bounty < normal, "bug-bounty mode must amplify non-application penalties")


def test_bug_bounty_mode_rewards_reachable_app_code():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    f = _f(reachability="YES", file_path=appfile, file_evidence=[_ev(appfile, 12, "y")])
    normal = es.select(f, _ctx(), bug_bounty=False)["primary"]["score"]
    bounty = es.select(f, _ctx(), bug_bounty=True)["primary"]["score"]
    _check(bounty > normal, "bug-bounty mode must reward reachable application proof")


def test_bug_bounty_enabled_detection():
    _check(es.bug_bounty_enabled({"bug_bounty_mode": True}), "results flag not honored")
    _check(es.bug_bounty_enabled({"options": {"bug_bounty_mode": True}}), "options flag not honored")
    _check(not es.bug_bounty_enabled({}), "should default off")


# ── Extensibility ─────────────────────────────────────────────────────────────
def test_register_contributor_influences_score():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    f = _f(file_path=appfile, file_evidence=[_ev(appfile, 12, "y")])
    before = es.select(f, _ctx())["primary"]["score"]
    marker = "future AI reviewer vote"

    def _ai(cand, ctx):
        return [(50, marker)]
    scoring.register_contributor(_ai, scope=scoring.FILE_SCOPE)
    try:
        after_sel = es.select(f, _ctx())["primary"]
        _check(after_sel["score"] == before + 50, "registered contributor must add its delta")
        _check(marker in after_sel["selected_because"], "contributor reason must appear")
    finally:
        scoring._CONTRIBUTORS[:] = [(fn, sc) for fn, sc in scoring._CONTRIBUTORS if fn is not _ai]


# ── Pipeline / regression ─────────────────────────────────────────────────────
def test_annotate_is_additive_and_non_destructive():
    appfile = f"sources/{APP.replace('.', '/')}/Pay.java"
    f = _f(file_path="sources/androidx/x/A.java", line=1,
           file_evidence=[_ev("sources/androidx/x/A.java", 1), _ev(appfile, 12, "y")])
    res = _results(f)
    es.annotate(res, platform="android")
    _check(f["file_path"] == "sources/androidx/x/A.java",
           "annotate must NOT mutate the finding's original file_path (additive only)")
    _check("evidence_selection" in f and "primary_evidence" in f,
           "annotate must add evidence_selection + primary_evidence")
    _check(appfile in f["evidence_selection"]["primary"]["file_path"],
           "the app file should still be chosen as the primary proof")


def test_empty_and_malformed_safe():
    res = {"platform": "android", "findings": [None, {"title": "x"}]}
    es.annotate(res, platform="android")  # must not raise
    _check(res["findings"][1]["evidence_selection"]["candidate_count"] == 0,
           "a finding with no location yields zero candidates safely")


def test_summary_emitted():
    res = _results(_f(file_evidence=[_ev(f"sources/{APP.replace('.', '/')}/Pay.java", 12, "y")]))
    es.annotate(res, platform="android")
    s = res["evidence_selection_summary"]
    _check(s["findings_annotated"] == 1 and "bug_bounty_mode" in s, "summary malformed")


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
