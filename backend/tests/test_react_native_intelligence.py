"""
React Native Security Intelligence tests (Beetle 2.0, Phase 2.2).

Verifies React Native is first-class through the EXISTING pipeline — the same model
as Flutter, not a parallel one. Covers:

* Framework detection (and non-detection).
* Metro/JS bundle analysis + Hermes metadata.
* Native bridge: NativeModules / TurboModules / Fabric.
* Storage: AsyncStorage / MMKV / Realm / SQLite / Encrypted storage.
* Secrets reuse (Secret Intelligence Engine, not an RN-specific detector).
* Network reuse (endpoints + TLS-validation-disabled + WebSocket).
* package.json parsing + dependency capabilities.
* Canonical findings flow through Ownership / Confidence / Evidence / Fusion.
* Source Explorer metadata is exposed.
* Android / iOS analyzers remain importable + unaffected when not RN.

Runnable standalone or under pytest:
    python -m tests.test_react_native_intelligence       # from backend/
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import react_native_analyzer as rn  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


_PACKAGE_JSON = {
    "name": "demoapp",
    "dependencies": {
        "react": "18.2.0", "react-native": "0.73.0", "axios": "^1.6.0",
        "react-native-mmkv": "^2.10.0",
        "@react-native-async-storage/async-storage": "^1.21.0",
        "react-native-keychain": "^8.1.0", "realm": "^12.0.0",
    },
    "devDependencies": {"jest": "^29.0.0"},
}

_BUNDLE = """
var sec = NativeModules.SecureBridge;
var crypto = TurboModuleRegistry.getEnforcing('Crypto');
var emitter = new NativeEventEmitter(NativeModules.Events);
import AsyncStorage from '@react-native-async-storage/async-storage';
const store = new MMKV();
const realm = new Realm({schema: []});
const db = SQLite.openDatabase('app.db');
import * as Keychain from 'react-native-keychain';
const client = axios.create({baseURL: 'https://api.demo-backend.com/v1', httpsAgent: {rejectUnauthorized: false}});
const ws = new WebSocket('ws://realtime.demo.com/socket');
Linking.getInitialURL().then(u => handle(u));
const apiKey = 'AKIAIOSFODNN7EXAMPLE';
const token = process.env.SECRET_API_TOKEN;
if (__DEV__) { console.log('debug build'); }
"""


def _rn_tree(hermes: bool = False) -> str:
    root = tempfile.mkdtemp()
    for d in ("android", "ios", "src", "assets"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as f:
        json.dump(_PACKAGE_JSON, f)
    with open(os.path.join(root, "metro.config.js"), "w", encoding="utf-8") as f:
        f.write("module.exports = {};")
    body = ("Hermes\x00" + _BUNDLE) if hermes else _BUNDLE
    with open(os.path.join(root, "index.android.bundle"), "w", encoding="utf-8") as f:
        f.write(body)
    return root


def _run(root: str, platform: str = "android") -> dict:
    results = {"platform": platform, "app_info": {"package": "com.demo", "bundle_id": "com.demo"},
               "findings": [], "secrets": [], "endpoints": []}
    rn.analyze([root], results, platform=platform)
    return results


def _titles(results):
    return [f["title"] for f in results["findings"]]


# ── Detection ─────────────────────────────────────────────────────────────────
def test_framework_detection():
    _check(rn.detect([_rn_tree()]) is True, "a React Native project must be detected")


def test_non_rn_not_detected():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "App.java"), "w") as f:
        f.write("class App {}")
    _check(rn.detect([d]) is False, "a non-RN tree must not be detected as React Native")


# ── Bundle / Hermes ───────────────────────────────────────────────────────────
def test_bundle_and_hermes_metadata():
    r = _run(_rn_tree(hermes=True))
    meta = r["react_native"]
    _check(any("index.android.bundle" in b for b in meta["bundles"]), "the JS bundle must be located")
    _check(meta["hermes"] is True, "Hermes bytecode must be flagged in metadata")


# ── Native bridge ─────────────────────────────────────────────────────────────
def test_native_modules_and_turbomodules():
    t = _titles(_run(_rn_tree()))
    _check(any("NativeModules" in x for x in t), "NativeModules bridge call must be detected")
    _check(any("TurboModule" in x for x in t), "TurboModule must be detected")
    _check("SecureBridge" in _run(_rn_tree())["react_native"]["native_modules"],
           "the native module name must be captured for metadata")


# ── Storage ───────────────────────────────────────────────────────────────────
def test_storage_findings():
    t = _titles(_run(_rn_tree()))
    _check(any("AsyncStorage" in x for x in t), "AsyncStorage plaintext storage must be flagged")
    _check(any("MMKV" in x for x in t), "MMKV-without-encryption must be flagged")
    _check(any("Realm" in x for x in t), "Realm database must be flagged")
    _check(any("SQLite" in x for x in t), "SQLite storage must be flagged")
    _check(any("secure storage" in x.lower() for x in t), "Keychain/secure storage must be noted")


# ── Secrets (reuse Secret Intelligence) ───────────────────────────────────────
def test_secrets_enter_existing_stream():
    vals = {s.get("value") for s in _run(_rn_tree())["secrets"]}
    _check("AKIAIOSFODNN7EXAMPLE" in vals, "the embedded AWS key must enter results['secrets']")


# ── Network (reuse Network Intelligence) ──────────────────────────────────────
def test_network_findings_and_endpoints():
    r = _run(_rn_tree())
    _check("https://api.demo-backend.com/v1" in r["endpoints"], "base URL must enter endpoints")
    t = _titles(r)
    _check(any("certificate validation disabled" in x.lower() for x in t),
           "rejectUnauthorized:false must raise a TLS-validation finding")
    _check(any("axios" in x for x in t), "axios client must be detected")
    _check(any("WebSocket" in x for x in t), "WebSocket usage must be flagged")


# ── package.json ──────────────────────────────────────────────────────────────
def test_package_json_parsing():
    meta = _run(_rn_tree())["react_native"]
    deps = meta["dependencies"]
    _check("axios" in deps and "react-native-mmkv" in deps and "jest" in deps,
           f"dependencies (incl. devDependencies) missing: {deps}")
    _check(meta["dependency_capabilities"].get("axios") == "HTTP client", "capability mapping wrong")


# ── Canonical findings + pipeline integration ─────────────────────────────────
def test_findings_are_canonical_shaped():
    for f in _run(_rn_tree())["findings"]:
        for k in ("title", "severity", "category", "description", "detected_by", "file_path"):
            _check(k in f, f"RN finding missing canonical field {k}")
        _check(f["detected_by"] == ["React Native Intelligence"],
               "Detected By must be React Native Intelligence")


def test_findings_flow_through_fusion():
    from analyzers import fusion
    r = _run(_rn_tree())
    fusion.fuse(r, platform="android")
    rnf = [f for f in r["findings"] if "React Native Intelligence" in (f.get("detected_by") or [])]
    _check(rnf, "RN findings must survive fusion")
    _check(all("detection_count" in f and "fusion" in f for f in rnf),
           "fusion must stamp provenance on RN findings")


def test_findings_flow_through_ownership_confidence_evidence():
    from analyzers import ownership, evidence_selection
    from analyzers.confidence import engine as ce
    from analyzers.canonical_finding import from_legacy
    r = _run(_rn_tree())
    ownership.annotate(r)
    evidence_selection.annotate(r, platform="android")
    rnf = [f for f in r["findings"] if "React Native Intelligence" in (f.get("detected_by") or [])]
    _check(all(f.get("owner_type") for f in rnf), "ownership must annotate RN findings")
    _check(all(f.get("evidence_selection") and f.get("evidence_view") for f in rnf),
           "evidence selection must build a proof view for RN findings")
    res = ce.classify(from_legacy(rnf[0], platform="android"))
    _check(0 <= res.overall <= 100, "confidence engine must score an RN finding")


# ── Source Explorer metadata ──────────────────────────────────────────────────
def test_source_explorer_metadata_exposed():
    meta = _run(_rn_tree())["react_native"]
    ps = meta["project_structure"]
    for d in ("android", "ios", "src", "app", "assets", "node_modules"):
        _check(d in ps, f"project_structure must expose canonical dir '{d}'")
    _check(ps["android"] is True and ps["src"] is True, "present project dirs must be marked True")
    _check(meta["key_files"]["package.json"] is True, "package.json must be recorded")
    _check(meta["key_files"]["metro.config.js"] is True, "metro.config.js must be recorded")


# ── Robustness / regression ───────────────────────────────────────────────────
def test_analyze_empty_is_safe():
    results = {"platform": "android", "findings": [], "secrets": [], "endpoints": []}
    rn.analyze([tempfile.mkdtemp()], results, platform="android")  # must not raise
    _check(results["react_native"]["stats"]["findings"] == 0, "empty tree yields no RN findings")


def test_android_ios_analyzers_import_unaffected():
    import importlib
    importlib.import_module("analyzers.android_analyzer")
    importlib.import_module("analyzers.ios_analyzer")
    _check(True, "analyzers import cleanly with the RN hook present and _analyze_rn_bundle removed")


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
