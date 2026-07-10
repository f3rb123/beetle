"""
Report-consistency tests (Beetle 2.0).

Two report inconsistencies these tests lock down:

  A — exploitability score and its sentence came from different sources. The score
      was a candidate's own `exploitability` field while the sentence was generated
      from step-title factors, so a chain with a high score but no recognized
      factors printed "Limited exploitability — no externally reachable attacker
      path identified" next to a score of 82. Now the score AND the sentence derive
      from ONE factor set per candidate, and the qualitative lead is a pure function
      of the score bucket, so the number and the prose can never disagree.

  B — two different metrics both read "false positive": the Signal-Quality funnel's
      FP-only "false positives removed" (e.g. 2) and the Findings header's TOTAL
      suppressed-from-view count (e.g. 34). They are now named with explicit keys
      (fp_removed_pre_triage vs findings_suppressed_display) and labeled distinctly.

Runnable standalone or under pytest:
    python -m tests.test_report_consistency      # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import posture_analyzer as P  # noqa: E402
from report import report_summaries as RS  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ════════════════════════════════════════════════════════════════════════════
# A — exploitability number and sentence always agree.
# ════════════════════════════════════════════════════════════════════════════
def _exploit(results):
    P.compute_exploitability(results)
    return results["exploitability_score"]


def test_v2_chain_with_no_token_factors_attributes_the_path_not_a_contradiction():
    """A v2 chain carries the engine's overall_exploitability. Even when its step
    titles yield no recognized token factors, the number must NOT sit next to a
    'no externally reachable path' sentence — the path is attributed to the chain."""
    results = {
        "findings": [],
        "high_risk_components": [],
        "attack_chains_v2": [{
            "name": "Mystery chain", "overall_exploitability": 82,
            "entry_point": {"label": "do a thing"},
            "steps": [{"title": "do a thing"}, {"title": "another thing"}],
        }],
    }
    es = _exploit(results)
    _check(es["score"] == 82, f"a v2 chain keeps the engine's exploitability, got {es['score']}")
    _check("no externally reachable" not in es["reason"],
           f"number {es['score']} must not contradict the sentence: {es['reason']!r}")
    _check("Mystery chain" in es["reason"], "the path is attributed to the chain")


def test_reason_lead_matches_score_bucket_for_real_path():
    # Exploitability sources its dominant chain from the v2 engine (attack_chains_v2),
    # naming the displayed #1 chain and carrying the engine's overall_exploitability.
    results = {
        "findings": [],
        "high_risk_components": [{"type": "activity", "short_name": "Main", "browsable": True}],
        "attack_chains_v2": [{
            "name": "WebView JavaScript Bridge RCE", "overall_exploitability": 80,
            "entry_point": {"label": "Attacker delivers a crafted URL to a browsable activity"},
            "steps": [{"title": "WebView enables JavaScript"},
                      {"title": "WebView exposes a native JavaScript interface"}],
        }],
    }
    es = _exploit(results)
    rating, label = P._rating_for(es["score"])
    _check(es["rating"] == rating, f"rating must be the pure bucket of the score: {es['rating']} vs {rating}")
    _check(es["reason"].startswith(label),
           f"sentence lead must match the score bucket label {label!r}: {es['reason']!r}")
    _check("WebView JavaScript Bridge RCE" in es["reason"], "reason should name the #1 v2 chain")


def test_no_candidates_yields_zero_and_limited_sentence():
    es = _exploit({"findings": [], "high_risk_components": [], "_chain_data": {"attack_chains": []}})
    _check(es["score"] == 0, f"no candidates → score 0, got {es['score']}")
    _check(es["rating"] == "low", "score 0 → low rating")
    _check(es["reason"].startswith("Limited exploitability"),
           f"score 0 must read as Limited, got {es['reason']!r}")


def test_rating_and_reason_are_pure_functions_of_score_across_all_buckets():
    """For every score bucket, the one-word rating and the sentence lead are fixed
    by the number — with factors present or absent."""
    for score in (0, 20, 34, 35, 59, 60, 79, 80, 100):
        rating, label = P._rating_for(score)
        with_factors = P._reason_from_factors(score, ["exported", "webview"], "Ctx")
        no_factors = P._reason_from_factors(score, [], "")
        _check(with_factors.startswith(label), f"{score}: {with_factors!r} must lead with {label!r}")
        _check(no_factors.startswith(label), f"{score}: {no_factors!r} must lead with {label!r}")


def test_score_and_reason_derive_from_the_same_factor_set():
    """A candidate whose factors produce score S must produce the sentence for S —
    they are computed from one set, so they cannot diverge."""
    factors = ["exported", "user_controlled", "webview", "javascript"]
    score = P._score_from_factors(factors)
    reason = P._reason_from_factors(score, factors, "Component X")
    rating, label = P._rating_for(score)
    _check(reason.startswith(label), "sentence lead follows the score computed from the same factors")
    _check("user_controlled" not in reason, "reason uses human phrases, not raw factor keys")
    _check("an externally reachable exported component" in reason, "reason enumerates the scoring factors")


def test_reachable_finding_exploitability_still_annotated():
    """The additive per-finding exploitability field is unchanged."""
    results = {
        "findings": [{"category": "WebView", "title": "WebView JavaScript enabled",
                      "description": "setJavaScriptEnabled(true)"}],
        "high_risk_components": [], "_chain_data": {"attack_chains": []},
    }
    P.compute_exploitability(results)
    f = results["findings"][0]
    _check(f.get("exploitability", 0) > 0, "reachable finding should carry a per-finding exploitability")
    _check(f.get("exploitability_factors"), "and its factor list")


# ════════════════════════════════════════════════════════════════════════════
# B — the two FP counts are named and labeled unambiguously.
# ════════════════════════════════════════════════════════════════════════════
def _accounting(fp_removed, total_suppressed):
    return RS.build_finding_accounting({
        "executive_summary": {"false_positives_suppressed": fp_removed},
        "finding_quality_stats": {"suppressed_count": total_suppressed},
    })


def test_two_fp_metrics_have_distinct_keys_and_values():
    acct = _accounting(2, 34)
    _check(acct["fp_removed_pre_triage"] == 2, "FP-only count maps to fp_removed_pre_triage")
    _check(acct["findings_suppressed_display"] == 34, "total-suppressed maps to findings_suppressed_display")
    _check(acct["fp_removed_pre_triage"] != acct["findings_suppressed_display"],
           "the two metrics are distinct numbers with distinct keys")


def test_two_fp_metrics_have_distinct_labels():
    acct = _accounting(2, 34)
    l1 = acct["labels"]["fp_removed_pre_triage"]
    l2 = acct["labels"]["findings_suppressed_display"]
    _check(l1 != l2, "labels must differ")
    # The total-suppressed metric must NOT be labeled as bare 'false positives' —
    # that was the ambiguity (34 'false positives' vs 2 'false positives').
    _check("false positive" not in l2.lower(),
           f"the display-total label must not read as false positives: {l2!r}")
    _check("false positive" in l1.lower(), "the FP-only metric may say false positives")


def test_accounting_survives_missing_inputs():
    acct = RS.build_finding_accounting({})
    _check(acct["fp_removed_pre_triage"] == 0 and acct["findings_suppressed_display"] == 0,
           "missing stats default to 0, not a crash")


def test_annotate_populates_finding_accounting():
    results = {
        "executive_summary": {"false_positives_suppressed": 1},
        "finding_quality_stats": {"suppressed_count": 9},
        "findings": [], "severity_summary": {},
    }
    RS.annotate(results)
    acct = results.get("finding_accounting") or {}
    _check(acct.get("fp_removed_pre_triage") == 1, "annotate exposes fp_removed_pre_triage")
    _check(acct.get("findings_suppressed_display") == 9, "annotate exposes findings_suppressed_display")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
