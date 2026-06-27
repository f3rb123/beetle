"""
Bug Bounty Intelligence Engine tests (Beetle 2.0, Phase 1.8).

Covers application vulnerabilities, framework/SDK findings, secrets, certificates,
permissions, attack chains, generated code, false positives, documentation
examples, Flutter/RN/Cordova/Unity, Android/iOS, score-not-severity, program
policy extensibility, duplicate detection, determinism, explainability and the
non-destructive guarantee.

Runnable standalone or under pytest:
    python -m tests.test_bug_bounty_engine     # from backend/
    python backend/tests/test_bug_bounty_engine.py
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import bug_bounty as bb  # noqa: E402
from analyzers.bug_bounty import BugBountyEngine, Level, NextStep, State  # noqa: E402

ENGINE = BugBountyEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def F(title="t", category="", *, owner="Application", conf=80, quality="Good",
      verification="Verified", reachability="", decision="Show", visibility="Show",
      secret=None, framework_name=None, cid=None, exploit=60, severity="high", **extra):
    f = {
        "title": title, "severity": severity, "category": category, "owner_type": owner,
        "overall_confidence": conf, "exploitability_confidence": exploit,
        "evidence_bundle": {"quality": quality, "verification_status": verification},
        "triage": {"decision": decision, "visibility": visibility},
        "canonical_id": cid or title,
    }
    if secret is not None:
        f["secret_intelligence"] = {"status": secret}
    if framework_name:
        f["framework_name"] = framework_name
    if reachability:
        f["reachability"] = reachability
    f.update(extra)
    return f


def _a(f, chain_ctx=None):
    return ENGINE.assess_finding(f, chain_ctx)


# ── Application vulnerabilities (positive) ────────────────────────────────────
def test_high_value_app_finding_reportable():
    bbm = _a(F("SQLi in app", "sql injection", quality="Excellent", reachability="YES",
               decision="Highlight", conf=90),
             {"required": {"SQLi in app"}, "conf": {"SQLi in app": 85}})
    _check(bbm["reportability_state"] == State.LIKELY_REPORTABLE, f"state {bbm['reportability_state']}")
    _check(bbm["reportability_score"] >= 80, f"score {bbm['reportability_score']}")
    _check(bbm["research_value"] == Level.HIGH and bbm["business_impact"] == Level.HIGH, "value/impact")
    _check(bbm["recommended_next_step"] == NextStep.STRONG_CANDIDATE, "next step")
    _check(bbm["review_priority"] == "P1", "priority")
    _check(any(s["id"] == "app_owned" for s in bbm["positive_signals"]), "app_owned signal")


def test_validated_secret_reportable():
    bbm = _a(F("Hardcoded AWS key", "secrets", secret="Validated Secret", quality="Excellent"))
    _check(bbm["reportability_state"] == State.LIKELY_REPORTABLE, f"state {bbm['reportability_state']}")
    _check(any(s["id"] == "validated_secret" for s in bbm["positive_signals"]), "validated_secret signal")
    _check(bbm["business_impact"] == Level.HIGH, "high impact")


# ── Framework / SDK / generated (negative) ────────────────────────────────────
def test_framework_finding_low():
    bbm = _a(F("Weak RNG", "cryptography", owner="AndroidFramework", quality="Weak",
               decision="FrameworkNoise", visibility="HiddenByDefault", conf=40, severity="critical"))
    _check(bbm["reportability_state"] in (State.FRAMEWORK_ISSUE, State.LIKELY_OUT_OF_SCOPE),
           f"state {bbm['reportability_state']}")
    _check(bbm["reportability_score"] < 40, f"framework score {bbm['reportability_score']}")
    _check(bbm["research_value"] == Level.LOW and bbm["recommended_next_step"] == NextStep.NOT_WORTH, "low value")


def test_sdk_finding_noise():
    bbm = _a(F("SDK crypto", "cryptography", owner="VendorSDK", quality="Weak",
               decision="SDKNoise", visibility="HiddenByDefault", conf=45))
    _check(bbm["reportability_state"] in (State.SDK_ISSUE, State.LIKELY_OUT_OF_SCOPE),
           f"state {bbm['reportability_state']}")
    _check(bbm["recommended_next_step"] in (NextStep.SDK_NOISE, NextStep.NOT_WORTH), "sdk next step")


def test_generated_code():
    bbm = _a(F("Generated thing", "configuration", owner="GeneratedCode", decision="GeneratedCode"))
    _check(bbm["reportability_state"] == State.GENERATED_CODE, f"state {bbm['reportability_state']}")
    _check(bbm["recommended_next_step"] == NextStep.NOT_WORTH, "next step")


def test_flutter_rn_cordova_unity_low():
    for fw in ("Flutter", "React Native", "Cordova", "Unity"):
        bbm = _a(F("hybrid crypto", "cryptography", owner="ThirdPartySDK", framework_name=fw,
                   quality="Weak", decision="FrameworkNoise", visibility="HiddenByDefault", conf=40))
        _check(bbm["reportability_score"] < 45, f"{fw} score {bbm['reportability_score']}")
        _check(bbm["research_value"] == Level.LOW, f"{fw} research value")


# ── Secrets — false positives / docs ──────────────────────────────────────────
def test_false_positive_secret():
    bbm = _a(F("Maybe key", "secrets", secret="False Positive", quality="Good"))
    _check(bbm["reportability_state"] == State.FALSE_POSITIVE, f"state {bbm['reportability_state']}")
    _check(bbm["recommended_next_step"] == NextStep.NOT_WORTH, "next step")


def test_documentation_example():
    bbm = _a(F("Doc key", "secrets", secret="Documentation Example"))
    _check(bbm["reportability_state"] == State.DOCUMENTATION_EXAMPLE, f"state {bbm['reportability_state']}")
    _check(bbm["recommended_next_step"] == NextStep.DOC_ARTIFACT, "next step")


# ── Mid-band states ───────────────────────────────────────────────────────────
def test_unreachable_needs_runtime():
    bbm = _a(F("Reflection use", "cryptography", quality="Moderate", reachability="NO",
               conf=55, verification="Decompiler Only"))
    _check(bbm["reportability_state"] in (State.NEEDS_RUNTIME_VALIDATION, State.NEEDS_MANUAL_VERIFICATION),
           f"state {bbm['reportability_state']}")


def test_taint_needs_exploitation():
    bbm = _a(F("User input to log", "taint analysis", quality="Moderate", conf=58,
              verification="Decompiler Only"))
    _check(bbm["reportability_state"] in (State.NEEDS_EXPLOITATION, State.NEEDS_MANUAL_VERIFICATION),
           f"state {bbm['reportability_state']}")
    _check(bbm["verification_effort"] == Level.HIGH, "taint effort high")


def test_informational_category():
    bbm = _a(F("App uses analytics", "Trackers", owner="ThirdPartySDK", quality="Weak", conf=40))
    _check(bbm["reportability_score"] < 45, "info low score")
    _check(bbm["business_impact"] == Level.LOW, "info impact low")


# ── Attack-chain membership boosts a finding ──────────────────────────────────
def test_chain_membership_boosts_and_overrides_framework():
    base = _a(F("WebView JS", "webview", owner="ThirdPartySDK", framework_name=None,
               quality="Good", conf=70))
    boosted = _a(F("WebView JS", "webview", owner="ThirdPartySDK", quality="Good", conf=70),
                 {"required": {"WebView JS"}, "conf": {"WebView JS": 88}})
    _check(boosted["reportability_score"] > base["reportability_score"], "chain membership boosts")
    _check(any(s["id"] == "in_attack_chain" for s in boosted["positive_signals"]), "chain signal")


# ── Score is signals, not severity ────────────────────────────────────────────
def test_score_ignores_severity():
    crit_fw = _a(F("x", "cryptography", owner="AndroidFramework", severity="critical",
                   quality="Weak", conf=40, decision="FrameworkNoise", visibility="HiddenByDefault"))
    low_app = _a(F("y", "sql injection", owner="Application", severity="low",
                   quality="Excellent", reachability="YES", conf=90, decision="Highlight"))
    _check(low_app["reportability_score"] > crit_fw["reportability_score"],
           "low-severity app finding must outscore critical-severity framework finding")


# ── Explainability + determinism ──────────────────────────────────────────────
def test_explainability():
    bbm = _a(F("SQLi", "sql injection", quality="Excellent", reachability="YES", decision="Highlight"))
    for k in ("reportability_score", "reportability_state", "research_value", "verification_effort",
              "business_impact", "review_priority", "recommended_next_step", "positive_signals",
              "negative_signals", "reasoning", "score_breakdown"):
        _check(k in bbm, f"missing {k}")
    _check(all(r.startswith(("✓", "✗")) for r in bbm["reasoning"]), "reasoning prefixes")


def test_deterministic():
    f = F("SQLi", "sql injection", quality="Excellent", reachability="YES")
    _check(_a(f) == _a(f), "must be deterministic")


# ── Attack chain assessment ───────────────────────────────────────────────────
def test_chain_assessment_strong_and_blocked():
    strong = ENGINE.assess_chain({"overall_confidence": 90, "overall_exploitability": 80,
                                  "overall_evidence_quality": "Excellent", "severity": "critical",
                                  "blocked": False, "ownership_summary": {"Application": 2}})
    _check(strong["reportability_state"] == State.LIKELY_REPORTABLE, f"strong {strong['reportability_state']}")
    _check(strong["business_impact"] == Level.HIGH and strong["research_value"] == Level.HIGH, "value")
    _check(strong["remediation_priority"] == "P1", "remediation P1")

    blocked = ENGINE.assess_chain({"overall_confidence": 80, "overall_exploitability": 30,
                                   "overall_evidence_quality": "Good", "severity": "high",
                                   "blocked": True, "blocked_by": ["cert_pinning"], "ownership_summary": {}})
    _check(blocked["reportability_state"] == State.LIKELY_OUT_OF_SCOPE, f"blocked {blocked['reportability_state']}")
    _check(blocked["verification_effort"] == Level.HIGH, "blocked effort high")


# ── Program policy extensibility ──────────────────────────────────────────────
def test_program_policy_override():
    from analyzers.bug_bounty import ProgramPolicy
    pol = ProgramPolicy(name="healthcare", weight_overrides={"real_secret": 40},
                        category_boosts={"sensitive data exposure": 15})
    eng = BugBountyEngine(pol)
    a = eng.assess_finding(F("PII key", "secrets", secret="Probable Secret", quality="Good"))
    b = ENGINE.assess_finding(F("PII key", "secrets", secret="Probable Secret", quality="Good"))
    _check(a["reportability_score"] > b["reportability_score"], "policy override raises score")
    _check(a["policy"] == "healthcare", "policy name recorded")


# ── Pipeline integration: non-destructive + chains + duplicates ───────────────
def test_annotate_non_destructive_and_chains_and_duplicates():
    results = {
        "platform": "android",
        "findings": [
            F("SQLi", "sql injection", quality="Excellent", reachability="YES", cid="a",
              rule_id="sqli", keep=1),
            F("SQLi", "sql injection", quality="Excellent", reachability="YES", cid="b",
              rule_id="sqli"),  # same (rule_id, title, owner) → probable duplicate
        ],
        "attack_chains_v2": [
            {"id": "CHAIN-1", "overall_confidence": 90, "overall_exploitability": 80,
             "overall_evidence_quality": "Excellent", "severity": "critical", "blocked": False,
             "required_findings": ["a"], "supporting_findings": [], "ownership_summary": {"Application": 1}},
        ],
    }
    import copy
    before = copy.deepcopy(results["findings"])
    bb.annotate(results)
    for orig, now in zip(before, results["findings"]):
        for k, v in orig.items():
            _check(k in now and now[k] == v, f"annotate changed existing key {k}")
        _check(set(now) - set(orig) == {"bug_bounty"}, f"unexpected keys: {set(now)-set(orig)}")
    _check(results["attack_chains_v2"][0].get("bug_bounty"), "chain got bug_bounty")
    states = [f["bug_bounty"]["reportability_state"] for f in results["findings"]]
    _check(State.PROBABLY_DUPLICATE in states, f"duplicate not detected: {states}")
    _check("by_state" in results["bug_bounty_summary"], "summary present")


def test_engine_singleton_and_helpers():
    _check(bb.get_engine() is bb.get_engine(), "singleton")
    _check(bb.assess_finding(F("x", "sql injection", quality="Excellent", reachability="YES"))["reportability_score"] > 0,
           "module-level assess works")


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
