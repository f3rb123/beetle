"""
Evidence Accuracy Finalization tests (Beetle 2.0, Phase 1.997).

Locks in the precision guarantees:

* Application-owned files ALWAYS outrank framework/library files (incl. obfuscated
  framework paths caught by the path-prefix gate), so framework code never headlines
  when application evidence exists.
* A finding whose ONLY proof is framework code is flagged `framework_only` and
  honestly explained (the allowed "no application evidence" exception) — never
  silently presented as application proof.
* Manifest findings ALWAYS prefer AndroidManifest.xml, with a focused snippet.
* Certificate findings NEVER render "Unknown file" — they name the real artifact.
* Framework evidence remains available as supporting/hidden, not dropped.
* Attack chains prefer manifest evidence (manifest-first policy).

Explicitly validates the report cases: Broken Crypto, Hardcoded Key, UploadService,
Debuggable, Backup, Cleartext, Exported Components, Certificate, WebView, Secrets.

Run:  cd backend && python -m tests.test_evidence_accuracy
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import evidence_selection as es  # noqa: E402
from analyzers.evidence_selection import build_evidence_view  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


APP = "com.insecureshop"
D = APP.replace(".", "/")
ANDROIDX = "sources/androidx/appcompat/app/AppCompatDelegateImpl.java"


def _annotate(*findings):
    res = {"platform": "android", "app_info": {"package": APP}, "findings": list(findings)}
    es.annotate(res, platform="android")
    return res["findings"]


def _ev(path, line=1, snippet="x"):
    return {"path": path, "lines": [line], "snippet": snippet}


# ── App always outranks framework (the core fix) ──────────────────────────────
def test_broken_crypto_prefers_app_over_framework():
    f = {"title": "Broken Crypto", "severity": "high", "category": "Cryptography",
         "rule_id": "android_weak_cipher_ecb", "file_path": ANDROIDX, "line": 5,
         "file_evidence": [_ev(ANDROIDX, 5), _ev("sources/com/google/android/gms/X.java", 8),
                           _ev(f"sources/{D}/CryptoUtil.java", 12, "Cipher.getInstance(\"AES/ECB\")")]}
    out = _annotate(f)[0]
    _check("CryptoUtil.java" in out["file_path"], "Broken Crypto must point at the app file")
    _check("AppCompatDelegateImpl" not in out["file_path"], "must not headline AndroidX")
    # framework still available as hidden evidence, not dropped
    _check(out["evidence_view"]["hidden_library_evidence"]["count"] >= 1, "framework must remain as hidden evidence")


def test_hardcoded_key_prefers_app_over_framework():
    f = {"title": "Hardcoded Key", "severity": "high", "category": "Secrets",
         "file_path": ANDROIDX, "line": 9,
         "file_evidence": [_ev(ANDROIDX, 9), _ev(f"sources/{D}/Config.java", 3, "KEY=...")]}
    out = _annotate(f)[0]
    _check("Config.java" in out["file_path"], "Hardcoded Key must point at the app file")


def test_app_outranks_obfuscated_framework_path():
    # OkHttp/Retrofit path — caught by the framework path-prefix gate regardless of
    # how ownership classifies it; the app file must still win.
    f = {"title": "Insecure TrustManager", "severity": "high", "category": "Network Security",
         "file_path": "sources/okhttp3/internal/Platform.java", "line": 2,
         "file_evidence": [_ev("sources/okhttp3/internal/Platform.java", 2),
                           _ev(f"sources/{D}/net/ApiClient.java", 40, "trustAllCerts")]}
    out = _annotate(f)[0]
    _check("ApiClient.java" in out["file_path"], "app file must outrank an OkHttp framework file")


def test_framework_only_finding_is_flagged():
    f = {"title": "Broken Crypto", "severity": "high", "category": "Cryptography",
         "file_path": ANDROIDX, "line": 5, "file_evidence": [_ev(ANDROIDX, 5)]}
    out = _annotate(f)[0]
    v = out["evidence_view"]
    _check(v.get("framework_only") is True, "a framework-only finding must be flagged")
    _check("no application-owned proof" in v["selection_reason"].lower()
           or "only framework" in v["selection_reason"].lower(),
           "framework-only reason must be explained honestly")


# ── Manifest findings always prefer AndroidManifest.xml ───────────────────────
def _manifest_case(title, category, snippet):
    f = {"title": title, "severity": "medium", "category": category, "evidence_type": "manifest",
         "file_path": "AndroidManifest.xml", "line": 3, "snippet": snippet}
    return _annotate(f)[0]


def test_debuggable_prefers_manifest_with_focused_snippet():
    out = _manifest_case("Debuggable Enabled", "Configuration",
                         '<application android:debuggable="true" android:label="x" android:icon="y">')
    v = out["evidence_view"]
    _check(v["primary"]["file"].endswith("AndroidManifest.xml"), "must point at the manifest")
    _check('android:debuggable="true"' in v["primary"]["snippet"], "snippet must focus the attribute")
    _check("android:label" not in v["primary"]["snippet"], "snippet must drop irrelevant attributes")


def test_backup_and_cleartext_prefer_manifest():
    for title, snip in [("Backup Allowed", '<application android:allowBackup="true">'),
                        ("Cleartext Traffic", '<application android:usesCleartextTraffic="true">')]:
        out = _manifest_case(title, "Network Security", snip)
        _check(out["file_path"].endswith("AndroidManifest.xml"), f"{title} must prefer the manifest")


def test_exported_component_prefers_manifest_over_sdk_class():
    f = {"title": "Exported UploadService", "severity": "medium", "category": "Exported Components",
         "evidence_type": "manifest", "file_path": "sources/net/gotev/uploadservice/UploadService.java", "line": 1}
    out = _annotate(f)[0]
    _check(out["file_path"].endswith("AndroidManifest.xml"),
           "exported component must reference the manifest, not the SDK class")


def test_manifest_beats_even_an_app_candidate():
    # Policy: manifest findings ALWAYS prefer the manifest, even if app source exists.
    f = {"title": "Exported Activity", "severity": "medium", "category": "Exported Components",
         "evidence_type": "manifest", "file_path": "AndroidManifest.xml", "line": 4,
         "file_evidence": [_ev("AndroidManifest.xml", 4, '<activity android:exported="true"/>'),
                           _ev(f"sources/{D}/MainActivity.java", 10, "class MainActivity")]}
    out = _annotate(f)[0]
    _check(out["file_path"].endswith("AndroidManifest.xml"), "manifest must win for manifest findings")


# ── Certificate findings never show "Unknown file" ────────────────────────────
def test_certificate_finding_names_artifact():
    for title, expect in [("Weak RSA Signing Key — 1024-bit", "Signing Certificate"),
                          ("Missing v2/v3 Signature Scheme", "APK Signature Block"),
                          ("Self-Signed Signing Certificate", "Signing Certificate")]:
        f = {"title": title, "severity": "medium", "category": "Certificate"}
        v = _annotate(f)[0]["evidence_view"]
        _check(v["primary"]["file"] not in ("", "Unknown file"), f"{title}: must name an artifact")
        _check(v["primary"]["file"] == expect, f"{title}: expected artifact {expect}, got {v['primary']['file']}")
        _check(v["primary"].get("artifact") is True, "certificate evidence must be marked as an artifact")


# ── WebView / Secret app cases ────────────────────────────────────────────────
def test_webview_prefers_app_implementation():
    f = {"title": "WebView JS Enabled", "severity": "medium", "category": "WebView",
         "file_path": "sources/androidx/webkit/Internal.java", "line": 2,
         "file_evidence": [_ev("sources/androidx/webkit/Internal.java", 2),
                           _ev(f"sources/{D}/ui/WebActivity.java", 22, "setJavaScriptEnabled(true)")]}
    out = _annotate(f)[0]
    _check("WebActivity.java" in out["file_path"], "WebView finding must prefer the app implementation")


def test_secret_prefers_app_file():
    f = {"title": "Hardcoded Secret", "severity": "high", "category": "Secrets",
         "file_path": "sources/com/google/firebase/X.java", "line": 1,
         "file_evidence": [_ev("sources/com/google/firebase/X.java", 1),
                           _ev(f"sources/{D}/Api.java", 7, "TOKEN=...")]}
    out = _annotate(f)[0]
    _check("Api.java" in out["file_path"], "secret must prefer the app file over a firebase file")


# ── Attack-chain evidence policy ──────────────────────────────────────────────
def test_attack_chain_prefers_manifest_evidence():
    f = {"title": "Exported component → exfil", "severity": "high", "category": "Attack Chain",
         "is_attack_chain": True, "file_path": ANDROIDX, "line": 5,
         "file_evidence": [_ev(ANDROIDX, 5),
                           _ev(f"sources/{D}/Logic.java", 12, "doExfil()"),
                           _ev("AndroidManifest.xml", 8, '<service android:exported="true"/>')]}
    out = _annotate(f)[0]
    v = out["evidence_view"]
    _check(v["primary"]["file"].endswith("AndroidManifest.xml"),
           "attack-chain evidence should prefer the manifest declaration")


# ── Standalone runner ─────────────────────────────────────────────────────────
def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t(); print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failures += 1; print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
