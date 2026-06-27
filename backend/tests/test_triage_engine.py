"""
Intelligent Finding Triage Engine tests (Beetle 2.0, Phase 1.6).

Covers the five worked examples from the brief plus application/framework/SDK/
generated/secret/certificate/permission/manifest/native/Flutter/RN/Cordova/
Unity/Apple-framework/mixed findings, false positives, the SAFE-BY-DESIGN
guarantees, determinism, modular rule registration, and the regression guarantee
that no findings are lost.

Runnable standalone or under pytest:
    python -m tests.test_triage_engine     # from backend/
    python backend/tests/test_triage_engine.py
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.canonical_finding import CanonicalFinding  # noqa: E402
from analyzers import triage as tr  # noqa: E402
from analyzers.triage import Decision, TriageEngine, Visibility  # noqa: E402

ENGINE = TriageEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _f(**d):
    d.setdefault("title", "t")
    d.setdefault("severity", "high")
    return CanonicalFinding.from_legacy(d, platform=d.get("platform", "android"))


def _t(quality="Moderate", verification="Decompiler Only", reproducible=False, **d):
    d["evidence_bundle"] = {"quality": quality, "verification_status": verification,
                            "reproducible": reproducible}
    return ENGINE.evaluate(_f(**d))


# ── The five worked examples ──────────────────────────────────────────────────
def test_example1_androidx_framework_noise():
    t = _t(quality="Weak", owner_type="ThirdPartySDK", owner_name="AndroidX WorkManager",
           owner_confidence=100, category="Cryptography", overall_confidence=40)
    _check(t["decision"] == Decision.FRAMEWORK_NOISE, f"decision {t['decision']}")
    _check(t["visibility"] == Visibility.HIDDEN_BY_DEFAULT, f"visibility {t['visibility']}")
    _check("AndroidX WorkManager" in t["reason"] and "confidence is 100%" in t["reason"], t["reason"])


def test_example2_app_buildconfig_validated_secret_highlight():
    t = _t(quality="Excellent", owner_type="Application", owner_confidence=90,
           category="Secrets", secret_intelligence={"status": "Validated Secret"},
           overall_confidence=95)
    _check(t["decision"] == Decision.HIGHLIGHT, f"decision {t['decision']}")
    _check(t["visibility"] == Visibility.HIGHLIGHT, "highlight visible")


def test_example3_firebase_api_key_review_not_suppress():
    t = _t(quality="Good", owner_type="GoogleSDK", owner_name="Firebase", owner_confidence=100,
           category="Secrets", secret_intelligence={"status": "Probable Secret"}, overall_confidence=70)
    _check(t["decision"] == Decision.REVIEW, f"decision {t['decision']}")
    _check(t["visibility"] != Visibility.HIDDEN_BY_DEFAULT, "real secret never hidden")


def test_example4_bouncycastle_constant_hidden():
    t = _t(quality="Weak", owner_type="OpenSourceLibrary", owner_name="BouncyCastle",
           category="Secrets", secret_intelligence={"status": "Generated Constant"},
           overall_confidence=25)
    _check(t["decision"] in (Decision.GENERATED_CODE, Decision.FALSE_POSITIVE), f"decision {t['decision']}")
    _check(t["visibility"] == Visibility.HIDDEN_BY_DEFAULT, "constant hidden")


def test_example5_exported_provider_reachable_review():
    t = _t(quality="Good", owner_type="ThirdPartySDK", owner_name="Some SDK",
           category="Attack Surface", reachability="YES", exported=True, overall_confidence=80)
    _check(t["decision"] == Decision.REVIEW, f"decision {t['decision']}")
    _check(t["visibility"] != Visibility.HIDDEN_BY_DEFAULT, "reachable exported never hidden")
    _check(t["rule_id"] == "SAFE-REACHABLE-EXPORTED", f"rule {t['rule_id']}")


# ── Ownership classes ─────────────────────────────────────────────────────────
def test_application_finding_visible():
    t = _t(quality="Good", owner_type="Application", owner_confidence=90,
           category="Cryptography", overall_confidence=70)
    _check(t["visibility"] in (Visibility.SHOW, Visibility.HIGHLIGHT), f"app visible {t['visibility']}")


def test_framework_and_sdk_noise():
    fw = _t(quality="Weak", owner_type="AndroidFramework", owner_confidence=98,
            category="Cryptography", overall_confidence=40)
    _check(fw["decision"] == Decision.FRAMEWORK_NOISE, f"fw {fw['decision']}")
    sdk = _t(quality="Weak", owner_type="VendorSDK", owner_name="Adjust", owner_confidence=95,
             category="Cryptography", overall_confidence=45)
    _check(sdk["decision"] == Decision.SDK_NOISE, f"sdk {sdk['decision']}")
    _check(fw["visibility"] == sdk["visibility"] == Visibility.HIDDEN_BY_DEFAULT, "both hidden")


def test_generated_code():
    t = _t(quality="Good", owner_type="GeneratedCode", owner_name="Generated BuildConfig",
           category="Configuration", overall_confidence=60)
    _check(t["decision"] == Decision.GENERATED_CODE and t["visibility"] == Visibility.HIDDEN_BY_DEFAULT,
           f"generated {t['decision']}/{t['visibility']}")


def test_apple_framework_and_hybrid_frameworks_are_noise():
    apple = _t(quality="Weak", platform="ios", owner_type="AppleFramework", owner_name="UIKit",
               owner_confidence=98, category="Cryptography", overall_confidence=40)
    _check(apple["decision"] == Decision.FRAMEWORK_NOISE, f"apple {apple['decision']}")
    for fw in ("Flutter", "React Native", "Cordova", "Unity", "Capacitor"):
        t = _t(quality="Weak", owner_type="ThirdPartySDK", owner_name=fw, framework_name=fw,
               category="Cryptography", overall_confidence=40)
        _check(t["visibility"] == Visibility.HIDDEN_BY_DEFAULT, f"{fw} should be hidden noise")
        _check(t["decision"] == Decision.FRAMEWORK_NOISE, f"{fw} -> {t['decision']}")


# ── SAFE-BY-DESIGN ────────────────────────────────────────────────────────────
def test_safe_certificate_permission_manifest_webview():
    for cat in ("Certificate", "Permissions", "Network Security", "WebView", "Deeplinks"):
        t = _t(quality="Weak", owner_type="Application", owner_confidence=90, category=cat,
               evidence_type="manifest", overall_confidence=30)
        _check(t["visibility"] != Visibility.HIDDEN_BY_DEFAULT,
               f"app security category {cat} must never be hidden ({t['visibility']})")


def test_app_code_never_hidden_even_weak():
    t = _t(quality="Weak", owner_type="Application", owner_confidence=90,
           category="Cryptography", overall_confidence=20)
    _check(t["visibility"] != Visibility.HIDDEN_BY_DEFAULT, "app code never hidden")


def test_validated_secret_in_framework_still_highlighted():
    t = _t(quality="Good", owner_type="AndroidFramework", owner_name="Android Framework",
           category="Secrets", secret_intelligence={"status": "Validated Secret"})
    _check(t["decision"] == Decision.HIGHLIGHT, "validated secret always highlighted")


def test_false_positive_secret_in_app_is_hidden():
    # The philosophy: suppress for lack of value, not for being a library. A
    # confirmed false-positive secret has no value even in application code.
    t = _t(quality="Good", owner_type="Application", owner_confidence=90, category="Secrets",
           secret_intelligence={"status": "False Positive"}, overall_confidence=10)
    _check(t["decision"] == Decision.FALSE_POSITIVE, f"decision {t['decision']}")
    _check(t["visibility"] == Visibility.HIDDEN_BY_DEFAULT, "FP hidden even in app code")


# ── Low signal / unresolved ───────────────────────────────────────────────────
def test_unresolved_needs_review():
    t = _t(quality="Weak", verification="Needs Review", owner_type="Unknown",
           unresolved_evidence=True, overall_confidence=30)
    _check(t["decision"] == Decision.NEEDS_HUMAN_REVIEW, f"decision {t['decision']}")
    _check(t["visibility"] == Visibility.REVIEW, "needs review visible")


def test_native_library_finding():
    t = _t(quality="Moderate", owner_type="ThirdPartySDK", owner_name="libnative",
           category="Binary Hardening", overall_confidence=50, file_path="lib/arm64/libx.so")
    _check(t["visibility"] in (Visibility.HIDDEN_BY_DEFAULT, Visibility.REVIEW), f"native {t['visibility']}")


# ── Determinism + explainability + every finding decided ──────────────────────
def test_deterministic():
    d = dict(quality="Weak", owner_type="ThirdPartySDK", owner_name="AndroidX Room",
             owner_confidence=100, category="Cryptography", overall_confidence=40)
    _check(_t(**d) == _t(**d), "triage must be deterministic")


def test_every_decision_explained():
    t = _t(owner_type="Application", owner_confidence=90, category="Cryptography")
    for k in ("decision", "visibility", "reason", "rule_id", "rule_name", "matched_rules", "inputs"):
        _check(k in t and t[k] != "" and t[k] is not None, f"missing {k}")
    _check(t["inputs"]["owner_type"] == "Application", "inputs captured")


# ── Modularity (future engines register rules) ───────────────────────────────
def test_custom_rule_registration():
    from analyzers.triage import Rule, register
    fired = {"hit": False}

    def cond(c):
        fired["hit"] = True
        return c.category.lower() == "zzz-test-category"

    register(Rule("TEST-OVERRIDE", "test", 5000, Decision.HIGHLIGHT, 100, "test rule",
                  cond, static_reason="custom rule fired"))
    eng = TriageEngine()  # rebuild to pick up the new rule
    t = eng.evaluate(_f(category="zzz-test-category", owner_type="ThirdPartySDK"))
    _check(t["rule_id"] == "TEST-OVERRIDE" and t["reason"] == "custom rule fired", "custom rule should win")


# ── Pipeline integration: NO findings lost + non-destructive ──────────────────
def test_annotate_no_findings_lost_and_non_destructive():
    results = {
        "platform": "android",
        "findings": [
            {"title": "App bug", "severity": "high", "owner_type": "Application",
             "owner_confidence": 90, "category": "Cryptography", "overall_confidence": 70,
             "evidence_bundle": {"quality": "Good"}, "keep": 1},
            {"title": "Framework noise", "severity": "low", "owner_type": "AndroidFramework",
             "owner_confidence": 98, "category": "Cryptography", "overall_confidence": 30,
             "evidence_bundle": {"quality": "Weak"}},
            {"title": "Validated secret", "severity": "critical", "owner_type": "AndroidFramework",
             "category": "Secrets", "secret_intelligence": {"status": "Validated Secret"},
             "evidence_bundle": {"quality": "Good"}},
        ],
    }
    import copy
    before = copy.deepcopy(results["findings"])
    n_before = len(results["findings"])

    tr.annotate(results)

    _check(len(results["findings"]) == n_before, "NO findings may be deleted")
    for orig, now in zip(before, results["findings"]):
        for k, v in orig.items():
            _check(k in now and now[k] == v, f"annotate changed existing key {k}")
        _check(set(now) - set(orig) == {"triage"}, f"unexpected keys: {set(now)-set(orig)}")
    decisions = [f["triage"]["decision"] for f in results["findings"]]
    _check(decisions[0] in (Decision.SHOW, Decision.HIGHLIGHT), "app visible")
    _check(decisions[1] == Decision.FRAMEWORK_NOISE, "framework hidden")
    _check(decisions[2] == Decision.HIGHLIGHT, "validated secret highlighted")
    s = results["triage_summary"]
    _check(s["total"] == 3 and s["hidden_by_default"] == 1 and s["visible"] == 2, f"summary {s}")
    _check("noise_reduction_pct" in s, "noise metric present")


def test_engine_singleton():
    _check(tr.get_engine() is tr.get_engine(), "singleton")


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
