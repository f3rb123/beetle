"""
Trustworthy chains + secret FP tests (five backend fixes).

FIX 1 — supporting evidence is deduped (by title+file:line and rule_id+file+line),
        capped (MAX_SUPPORTING), strongest-first; a positive control is never a step.
FIX 2 — ownership is enforced: a library/framework-owned finding is never `required`,
        and a library-owned generic code-pattern hit is demoted to INFO library-noise.
FIX 3 — WEAK_CRYPTO/INSECURE_STORAGE/BACKUP chains no longer vacuum unrelated steps;
        the backup chain needs allowBackup=true and never uses a debuggable finding.
FIX 4 — a value equal to its own field name (brieflyShowPassword == BRIEFLY_SHOW_PASSWORD)
        is a preference key, not a HIGH secret; a real high-entropy password stays one.

Runnable standalone or under pytest:
    python -m tests.test_chain_trust_and_secret_fp      # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.attack_chains.engine import (  # noqa: E402
    AttackChainEngine, ChainContext, chain_role, _is_positive_control,
)
from analyzers.attack_chains import config as C  # noqa: E402
from analyzers import finding_model, common  # noqa: E402
from analyzers.secret_intelligence.engine import assess  # noqa: E402

ENGINE = AttackChainEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _f(title, category, cid, **kw):
    f = {
        "title": title, "category": category, "severity": kw.pop("severity", "high"),
        "canonical_id": cid, "rule_id": kw.pop("rule_id", cid), "overall_confidence": 80,
        "evidence_bundle": {"quality": kw.pop("quality", "Good"), "evidence_id": "EV-" + cid,
                            "primary": {"relative_path": kw.pop("file", f"a/{cid}.java"),
                                        "line": kw.pop("line", 1), "locator": {}}},
        "triage": {"decision": "Show", "visibility": "Show"},
    }
    f.update(kw)
    return f


# ════════════════════════════════════════════════════════════════════════════
# FIX 1 — supporting() dedupe + cap + positive-control exclusion.
# ════════════════════════════════════════════════════════════════════════════
def _support(findings):
    ctx = ChainContext({"platform": "android", "findings": findings})
    return ctx.supporting(frozenset({"INSECURE_STORAGE"}), set())


def test_supporting_is_deduped_and_capped():
    # 30 copies of the same plaintext-storage weakness at libapp.so:1248.
    dups = [_f("SharedPreferences storage (plaintext)", "Data Storage", f"d{i}",
               file="libapp.so", line=1248, severity="medium",
               description="plaintext sharedpreferences") for i in range(30)]
    sup = _support(dups)
    _check(len(sup) == 1, f"identical (title, file:line) rows collapse to one, got {len(sup)}")


def test_supporting_caps_at_max_supporting():
    many = [_f(f"Insecure storage weakness {i}", "Data Storage", f"s{i}",
               file=f"libapp.so", line=1200 + i, severity="medium",
               description="plaintext sharedpreferences") for i in range(20)]
    sup = _support(many)
    _check(len(sup) <= C.MAX_SUPPORTING, f"supporting must cap at {C.MAX_SUPPORTING}, got {len(sup)}")


def test_supporting_keeps_strongest_first():
    findings = [
        _f("Low storage issue", "Data Storage", "lo", severity="low", quality="Weak",
           description="plaintext sharedpreferences"),
        _f("High storage issue", "Data Storage", "hi", severity="high", quality="Excellent",
           description="plaintext sharedpreferences"),
    ]
    sup = _support(findings)
    _check(sup[0]["f"]["title"] == "High storage issue",
           "the highest-severity/best-evidence supporting row must come first")


def test_positive_control_is_never_supporting_evidence():
    weakness = _f("SharedPreferences storage (plaintext)", "Data Storage", "w",
                  description="plaintext sharedpreferences")
    secure = _f("Flutter Secure Storage in use", "Data Storage", "sec", severity="info",
                security_control=True, description="flutter secure storage in use")
    enc = _f("EncryptedSharedPreferences configured", "Data Storage", "enc", severity="info",
             description="EncryptedSharedPreferences in use")
    sup = _support([weakness, secure, enc])
    titles = {t["f"]["title"] for t in sup}
    _check("Flutter Secure Storage in use" not in titles, "a positive control must not be a step")
    _check("EncryptedSharedPreferences configured" not in titles, "a positive control must not be a step")
    _check(_is_positive_control(secure) and _is_positive_control(enc), "these are positive controls")
    _check(not _is_positive_control(weakness), "a plaintext-storage weakness is not a positive control")


def test_aggregate_evidence_dedupes_refs_and_files():
    from analyzers.attack_chains.engine import _aggregate_evidence
    dups = [_f("SharedPreferences storage (plaintext)", "Data Storage", f"d{i}",
               file="libapp.so", line=1248) for i in range(5)]
    files, _classes, _methods, refs = _aggregate_evidence(dups)
    _check(files.count("libapp.so") == 1, "affected_files must carry no repeats")
    _check(len([r for r in refs if r["file"] == "libapp.so" and r["line"] == 1248]) == 1,
           "evidence_references must carry no repeats")


# ════════════════════════════════════════════════════════════════════════════
# FIX 2 — ownership enforcement.
# ════════════════════════════════════════════════════════════════════════════
LIB_WEBVIEW = _f("addJavascriptInterface used", "WebView", "wv",
                 owner_type="ThirdPartySDK", source="SAST", rule_id="android_webview_js_interface",
                 description="addJavascriptInterface", file="io/flutter/plugins/webviewflutter/X.java")


def test_library_owned_finding_is_not_required():
    _check(chain_role(LIB_WEBVIEW) != "required",
           "a THIRD_PARTY_SDK-owned finding must never be a required chain link")


def test_application_owned_finding_stays_required():
    app_wv = _f("addJavascriptInterface used", "WebView", "wv2", owner_type="Application")
    _check(chain_role(app_wv) == "required", "an application-owned finding keeps required eligibility")


def test_library_code_finding_demoted_to_info():
    results = {"findings": [dict(LIB_WEBVIEW, severity="high")]}
    finding_model.demote_library_code_findings(results)
    f = results["findings"][0]
    _check(f["severity"] == "info", f"library-owned code-pattern finding must be INFO, got {f['severity']}")
    _check(f.get("library_noise") is True, "and marked library_noise")
    _check(f.get("severity_original") == "high", "preserving the original severity")


def test_app_owned_finding_never_demoted():
    app = _f("addJavascriptInterface used", "WebView", "a", owner_type="Application", source="SAST")
    results = {"findings": [dict(app, severity="high")]}
    finding_model.demote_library_code_findings(results)
    _check(results["findings"][0]["severity"] == "high",
           "an application-owned finding must never be demoted (guard)")


def test_library_finding_with_reachability_evidence_kept():
    reachable = dict(LIB_WEBVIEW, severity="high",
                     taint_flow={"source_cat": "Intent", "sink_cat": "webview", "chain": ["a.b"]})
    results = {"findings": [reachable]}
    finding_model.demote_library_code_findings(results)
    _check(results["findings"][0]["severity"] == "high",
           "a library finding with app-owned reachability evidence keeps its severity")


# ════════════════════════════════════════════════════════════════════════════
# FIX 3 — template gating.
# ════════════════════════════════════════════════════════════════════════════
def _types(chains):
    return {c["type"] for c in chains}


def test_backup_chain_requires_allow_backup_true():
    backup = _f("android:allowBackup is true", "Configuration", "bk", description="allowBackup enabled")
    with_bak = ENGINE.build_chains({"platform": "android", "findings": [backup],
                                    "manifest_xml": '<application android:allowBackup="true"/>'})
    _check("Backup Abuse" in _types(with_bak), "allowBackup=true must allow the backup chain")

    no_bak = ENGINE.build_chains({"platform": "android",
                                  "findings": [_f("Some storage", "Data Storage", "st",
                                                  description="plaintext sharedpreferences")],
                                  "manifest_xml": '<application android:allowBackup="false"/>'})
    _check("Backup Abuse" not in _types(no_bak),
           "without allowBackup=true the backup chain must not emit")


def test_backup_chain_never_uses_a_debuggable_finding():
    dbg = _f("Potentially Debuggable (Flag Missing)", "Configuration", "dbg", severity="medium",
             description="the debuggable flag is missing")
    chains = ENGINE.build_chains({"platform": "android", "findings": [dbg],
                                  "manifest_xml": '<application android:debuggable="true"/>'})
    _check("Backup Abuse" not in _types(chains),
           "a debuggable finding must never produce/anchor a backup chain")


def test_weak_crypto_in_a_library_does_not_emit_a_chain():
    lib_crypto = _f("Weak cipher MD5 used", "Cryptography", "md5", description="weak md5",
                    owner_type="ThirdPartySDK", source="SAST")
    chains = ENGINE.build_chains({"platform": "android", "findings": [lib_crypto]})
    _check("Weak Cryptography" not in _types(chains),
           "a weak-crypto hit in a library must not emit an app-data-exposure chain")


def test_app_owned_weak_crypto_still_emits():
    app_crypto = _f("Weak cipher MD5 used", "Cryptography", "md5a", description="weak md5",
                    owner_type="Application")
    chains = ENGINE.build_chains({"platform": "android", "findings": [app_crypto]})
    _check("Weak Cryptography" in _types(chains),
           "an application-owned weak-crypto weakness still forms its chain")


def test_secret_is_not_appended_to_a_storage_chain():
    storage = _f("Sensitive data in SharedPreferences", "Data Storage", "st",
                 owner_type="Application", description="plaintext sharedpreferences")
    secret = _f("Hardcoded AWS Key", "Secrets", "aws",
                secret_intelligence={"status": "Probable Secret", "secret_type": "AWS Access Key"})
    chains = ENGINE.build_chains({"platform": "android", "findings": [storage, secret]})
    storage_chains = [c for c in chains if c["type"] == "Insecure Storage"]
    if storage_chains:
        members = " ".join(storage_chains[0]["required_findings"] + storage_chains[0]["supporting_findings"])
        _check("aws" not in members, "a hardcoded secret must not be a step in a storage chain")


# ════════════════════════════════════════════════════════════════════════════
# FIX 4 — brieflyShowPassword secret false positive.
# ════════════════════════════════════════════════════════════════════════════
def test_value_equal_to_field_name_is_flagged_ui_fp():
    # camelCase value and its snake_case constant name normalize to the same token.
    _check(common._value_is_its_own_field_name(
        "brieflyShowPassword", 'String BRIEFLY_SHOW_PASSWORD = "brieflyShowPassword";'),
        "value equal to its own constant name is a preference-key string")
    # snake_case value the old camelCase heuristic missed, now caught by name-match.
    _check(common._looks_like_ui_password_false_positive(
        "briefly_show_password", 'String BRIEFLY_SHOW_PASSWORD = "briefly_show_password";'),
        "a snake_case value equal to its field name is a UI/key false positive")


def test_real_password_differing_from_field_name_is_not_a_name_match_fp():
    _check(not common._value_is_its_own_field_name(
        "Xq9$mK2!pL7v", 'pwd = "Xq9$mK2!pL7v";'),
        "a high-entropy value with special chars is not a field-name match")
    _check(not common._value_is_its_own_field_name(
        "correcthorse", 'dbPassword = "correcthorse";'),
        "a value that differs from its field name is not a name match")


def test_brieflyshowpassword_secret_intelligence_not_high():
    a = assess("brieflyShowPassword",
               {"name": "BRIEFLY_SHOW_PASSWORD",
                "snippet": 'private static final String BRIEFLY_SHOW_PASSWORD = "brieflyShowPassword";'})
    _check(a.status == "False Positive",
           f"a value equal to its field name must not be a real secret, got {a.status!r}")


def test_preference_key_detector_is_precise():
    """Fix 4b's routing fires ONLY for a bare identifier equal to its field name —
    never for a value with digits/special chars, nor one that differs from its name."""
    from analyzers.secret_intelligence.engine import _is_preference_key_value as pref
    _check(pref("brieflyShowPassword", {"name": "BRIEFLY_SHOW_PASSWORD"}),
           "identifier equal to its constant name is a preference key")
    _check(not pref("Xq9mK2pL7vNt4wZr", {"name": "apiPassword",
                                         "snippet": 'apiPassword = "Xq9mK2pL7vNt4wZr"'}),
           "a value with digits/entropy is never a preference key")
    _check(not pref("correcthorse", {"snippet": 'dbPassword = "correcthorse"'}),
           "a value that differs from its field name is not a preference key")


def test_real_high_entropy_password_is_not_suppressed_by_the_ui_fp_filter():
    # The HIGH "Hardcoded Password" detection is gated by common.py's UI-FP filter;
    # a real high-entropy password (differing from its field name) must pass it.
    _check(not common._looks_like_ui_password_false_positive(
        "Xq9mK2pL7vNt4wZr", 'password = "Xq9mK2pL7vNt4wZr"'),
        "a real high-entropy password must not be filtered as a UI false positive")
    _check(not common._looks_like_ui_password_false_positive(
        "h0rse-Battery9", 'pwd = "h0rse-Battery9"'),
        "a password with digits/special chars stays a candidate")


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
