"""
Unified Evidence Intelligence Engine tests (Beetle 2.0, Phase 1.5).

Covers Android/iOS/native/manifest/secret/certificate/permission/deeplink/
exported-component/WebView/JNI/Flutter/RN/Cordova/Capacitor/generated/obfuscated/
binary-only/missing/multi-source findings, plus correlation, reproduction,
verification, determinism and the non-destructive guarantee.

Runnable standalone or under pytest:
    python -m tests.test_evidence_engine     # from backend/
    python backend/tests/test_evidence_engine.py
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.canonical_finding import CanonicalFinding  # noqa: E402
from analyzers import evidence as ev  # noqa: E402
from analyzers.evidence import EvidenceEngine, EvidenceType, Quality, Verification  # noqa: E402

ENGINE = EvidenceEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _f(**d):
    d.setdefault("title", "t")
    d.setdefault("severity", "high")
    return CanonicalFinding.from_legacy(d, platform=d.get("platform", "android"))


def _b(**d):
    return ENGINE.build(_f(**d))


# ── Quality bands ─────────────────────────────────────────────────────────────
def test_excellent_quality_full_code_evidence():
    e = _b(source="SAST", owner_type="Application", class_name="Pay", method_name="pay",
           file_evidence=[{"path": "sources/com/app/Pay.java", "lines": [20], "snippet": "key=k"}])
    _check(e.quality == Quality.EXCELLENT, f"quality {e.quality}")
    _check(e.verification_status == Verification.VERIFIED, f"verify {e.verification_status}")
    _check(e.reproducible is True, "should be reproducible")
    _check(e.primary["type"] == EvidenceType.DECOMPILED_JAVA, f"type {e.primary['type']}")
    _check(e.primary["relative_path"] == "com/app/Pay.java", f"relpath {e.primary['relative_path']}")
    _check("Decompile" in e.reproduction["steps"][0], "repro steps")


def test_good_quality_no_symbol():
    e = _b(source="SAST", file_path="sources/com/app/A.java", line=5, snippet="x();")
    _check(e.quality in (Quality.GOOD, Quality.EXCELLENT), f"quality {e.quality}")
    _check(e.primary["line"] == 5 and e.primary["snippet"] == "x();", "line/snippet")


def test_weak_quality_reference_only():
    e = _b(source="SAST", file_path="Lcom/app/Foo;")  # class ref, no line/snippet
    _check(e.quality in (Quality.WEAK, Quality.MODERATE), f"quality {e.quality}")


def test_missing_evidence():
    e = _b(title="No evidence", category="Meta")
    _check(e.quality == Quality.MISSING, f"quality {e.quality}")
    _check(e.item_count == 0 and e.evidence_id == "EV-empty", "empty bundle")
    _check(e.verification_status == Verification.UNKNOWN, "verify unknown")


# ── Manifest / permissions / deep links / exported components ──────────────────
def test_manifest_evidence():
    e = _b(evidence_type="manifest", category="Configuration",
           title="allowBackup", line=12, snippet='android:allowBackup="true"')
    _check(e.primary["type"] == EvidenceType.MANIFEST, f"type {e.primary['type']}")
    _check(e.primary["file_path"] == "AndroidManifest.xml", f"path {e.primary['file_path']}")
    _check(e.verification_status == Verification.MANIFEST_ONLY, f"verify {e.verification_status}")
    _check("manifest" in e.reproduction["steps"][0].lower(), "manifest repro")


def test_exported_component_and_deeplink():
    e = _b(category="Attack Surface", title="Exported activity",
           component="com.app.ExternalActivity", uri="myapp://open")
    _check(e.primary["type"] == EvidenceType.MANIFEST, "exported -> manifest")
    _check(e.primary["locator"].get("component") == "com.app.ExternalActivity", "component locator")
    _check(e.primary["locator"].get("uri") == "myapp://open", "uri locator")


def test_permission_evidence():
    e = _b(category="Permissions", evidence_type="manifest", permission="android.permission.SEND_SMS",
           line=8, snippet="<uses-permission .../>")
    _check(e.primary["locator"].get("permission") == "android.permission.SEND_SMS", "permission locator")


# ── Taint / data flow ─────────────────────────────────────────────────────────
def test_taint_flow_evidence_and_dataflow():
    e = _b(category="Taint Analysis", source="TAINT",
           taint_flow={"source": "getIntent", "sink": "rawQuery",
                       "source_cat": "User Input", "sink_cat": "sqlite",
                       "chain": ["Search.onQuery", "Dao.raw"]},
           call_chain=["Search.onQuery", "Dao.raw"])
    types = e.evidence_types
    _check(EvidenceType.TAINT_FLOW in types, f"taint type missing: {types}")
    _check(e.data_flow.get("source") == "getIntent" and e.data_flow.get("sink") == "rawQuery", "data flow")
    _check(e.data_flow["path"] == ["Search.onQuery", "Dao.raw"], "flow path")
    _check(any("source" in s.lower() or "path" in s.lower() for s in e.reproduction["steps"]), "taint repro")


# ── Certificate / binary / native / JNI ───────────────────────────────────────
def test_certificate_evidence():
    e = _b(category="Certificate", title="Debug cert", evidence="Subject: CN=Android Debug")
    _check(e.primary["type"] == EvidenceType.CERTIFICATE, f"type {e.primary['type']}")
    _check(e.primary["source"] == "cert_parser", "cert source")


def test_binary_only_evidence():
    e = _b(category="Binary Hardening", title="No canary",
           file_path="lib/arm64-v8a/libnative.so")
    _check(e.primary["type"] == EvidenceType.NATIVE_LIBRARY, f"type {e.primary['type']}")
    _check(e.verification_status == Verification.BINARY_ONLY, f"verify {e.verification_status}")
    _check(e.source_availability == "binary-only", "availability")


# ── iOS ───────────────────────────────────────────────────────────────────────
def test_ios_swift_and_objc():
    sw = _b(platform="ios", file_path="Payload/App.app/Login.swift", line=3, snippet="UserDefaults", source="SAST")
    _check(sw.primary["type"] == EvidenceType.SWIFT, f"swift {sw.primary['type']}")
    oc = _b(platform="ios", file_path="Payload/App.app/Bridge.m", line=1, snippet="WKWebView", source="IOS")
    _check(oc.primary["type"] == EvidenceType.OBJC, f"objc {oc.primary['type']}")


def test_ios_manifest_is_plist():
    e = _b(platform="ios", evidence_type="manifest", category="Configuration", line=1, snippet="<key>")
    _check(e.primary["file_path"] == "Info.plist", f"plist {e.primary['file_path']}")


# ── Frameworks ────────────────────────────────────────────────────────────────
def test_framework_evidence_types():
    cases = {
        "lib/arm64-v8a/libflutter.so": EvidenceType.FLUTTER,
        "assets/index.android.bundle": EvidenceType.REACT_NATIVE,
        "assets/www/cordova.js": EvidenceType.CORDOVA,
        "capacitor.config.json": EvidenceType.CAPACITOR,
        "lib/armeabi-v7a/libunity.so": EvidenceType.UNITY,
    }
    for path, want in cases.items():
        _check(ev.classify_type(path, _f()) == want, f"{path} -> {ev.classify_type(path, _f())} (want {want})")


def test_webview_and_smali():
    wv = _b(category="WebView", title="JS enabled", file_path="sources/com/app/Web.java", line=4, snippet="setJavaScriptEnabled(true)")
    _check(EvidenceType.DECOMPILED_JAVA in wv.evidence_types, "webview java item")
    sm = _b(source="SAST", file_path="smali/com/app/A.smali", line=2, snippet="invoke")
    _check(sm.primary["type"] == EvidenceType.SMALI and sm.primary["decompiler_status"] == "smali", "smali")


# ── Secrets ───────────────────────────────────────────────────────────────────
def test_secret_metadata_linked():
    e = _b(category="Secrets", source="EVIDENCE", file_path="sources/com/app/Cfg.java", line=3, snippet="AKIA...",
           secret_intelligence={"status": "Probable Secret", "secret_type": "AWS Access Key", "provider": "AWS"})
    _check(any(t == EvidenceType.SECRET for t in e.evidence_types), "secret item")
    _check(e.secret.get("status") == "Probable Secret" and e.secret.get("provider") == "AWS", "secret link")


# ── Generated / obfuscated / unresolved ───────────────────────────────────────
def test_generated_code_verification():
    e = _b(source="SAST", owner_type="GeneratedCode", file_path="sources/com/app/BuildConfig.java",
           line=1, snippet="VERSION")
    _check(e.verification_status == Verification.GENERATED, f"verify {e.verification_status}")
    _check(e.generated_code is True, "generated flag")


def test_unresolved_evidence_needs_review():
    e = _b(source="TAINT", file_path="Lcom/x/Y;", unresolved_evidence=True,
           taint_flow={"sink": "exec"}, call_chain=["A.b"])
    _check(e.verification_status == Verification.NEEDS_REVIEW, f"verify {e.verification_status}")


def test_obfuscated_still_builds():
    e = _b(source="SAST", file_path="sources/a/b/c.java", line=1, snippet="x", owner_type="Unknown")
    _check(e.item_count >= 1 and e.quality != Quality.MISSING, "obfuscated builds evidence")


# ── Multi-source aggregation + correlation + cross-refs ───────────────────────
def test_multi_source_aggregation_not_overwritten():
    e = _b(source="SAST", class_name="Pay",
           file_evidence=[
               {"path": "sources/com/app/Pay.java", "lines": [10], "snippet": "a"},
               {"path": "sources/com/app/Pay2.java", "lines": [20], "snippet": "b"},
               {"path": "sources/com/app/Pay3.java", "lines": [30], "snippet": "c"}])
    _check(e.item_count == 3, f"expected 3 items, got {e.item_count}")
    _check(e.location_count == 3, "3 locations")
    _check(len(e.cross_references) == 2, f"2 cross-refs, got {len(e.cross_references)}")


def test_correlation_manifest_to_source():
    e = _b(category="Attack Surface", component="com.app.Pay", class_name="Pay",
           file_evidence=[{"path": "sources/com/app/Pay.java", "lines": [10], "snippet": "class Pay"}])
    # A manifest item (exported component) + a source item for the same class.
    rels = {c["relation"] for c in e.correlation}
    _check(e.correlation, "expected correlation edges")
    _check(rels & {"same_class", "manifest_declares_source"}, f"relations {rels}")


# ── Determinism + content hash ────────────────────────────────────────────────
def test_deterministic_and_hashed():
    d = dict(source="SAST", file_path="sources/com/app/A.java", line=5, snippet="x();", class_name="A")
    a = ENGINE.build(_f(**d))
    b = ENGINE.build(_f(**d))
    _check(a.to_dict() == b.to_dict(), "engine must be deterministic")
    _check(a.content_hash and a.evidence_id.startswith("EV-"), "hash/id present")


# ── Pipeline integration + non-destructive ────────────────────────────────────
def test_annotate_non_destructive():
    results = {
        "platform": "android", "scan_time": "2026-06-27T00:00:00Z",
        "findings": [
            {"title": "A", "severity": "high", "rule_id": "r1", "source": "SAST",
             "file_path": "sources/com/app/A.java", "line": 5, "snippet": "x",
             "file_evidence": [{"path": "sources/com/app/A.java", "lines": [5], "snippet": "x"}],
             "confidence": 75, "owner_type": "Application", "extra": "keep"},
            {"title": "B", "severity": "low", "category": "Certificate", "evidence": "CN=x"},
        ],
    }
    import copy
    before = copy.deepcopy(results["findings"])
    ev.annotate(results)
    for orig, now in zip(before, results["findings"]):
        for k, v in orig.items():
            _check(k in now and now[k] == v, f"annotate changed existing key {k}")
        _check(set(now) - set(orig) == {"evidence_bundle"}, f"unexpected keys: {set(now)-set(orig)}")
    f0 = results["findings"][0]
    _check(f0["evidence_bundle"]["quality"] in (Quality.GOOD, Quality.EXCELLENT), "f0 quality")
    _check(f0["evidence_bundle"]["timestamp"] == "2026-06-27T00:00:00Z", "timestamp injected")
    # Loose legacy evidence preserved.
    _check(f0["file_evidence"] and f0["snippet"] == "x", "legacy evidence preserved")
    _check("by_quality" in results["evidence_summary"], "summary present")


def test_engine_singleton():
    _check(ev.get_engine() is ev.get_engine(), "singleton")


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
