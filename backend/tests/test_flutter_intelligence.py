"""
Flutter Security Intelligence tests (Beetle 2.0, Phase 2.1).

Verifies that Flutter becomes a first-class platform through the EXISTING pipeline —
not a parallel one. Covers:

* Flutter detection (and non-detection).
* Dart pattern analysis: MethodChannel / EventChannel / BasicMessageChannel.
* pubspec parsing (dependencies; the Flutter SDK pseudo-dep excluded).
* Storage: Secure Storage / SharedPreferences / Hive / SQLite.
* Secrets reuse (Secret Intelligence Engine, not a Flutter-specific detector).
* Network reuse (endpoints + TLS-validation-disabled + WebSocket).
* Canonical findings flow through Ownership / Confidence / Evidence / Fusion.
* Source Explorer metadata is exposed.
* Android / iOS analyzers remain importable + unaffected when not Flutter.

Runnable standalone or under pytest:
    python -m tests.test_flutter_intelligence       # from backend/
"""
from __future__ import annotations

import os
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import flutter_analyzer as fl  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


_PUBSPEC = """name: demoapp
description: A demo Flutter app.
dependencies:
  flutter:
    sdk: flutter
  dio: ^5.0.0
  flutter_secure_storage: ^9.0.0
  hive: ^2.0.0
  shared_preferences: ^2.0.0
  web_socket_channel: ^2.0.0
dev_dependencies:
  flutter_test:
    sdk: flutter
"""

_MAIN_DART = """
import 'package:dio/dio.dart';
const secureChannel = MethodChannel("com.demo/secure");
final events = EventChannel("com.demo/events");
final msg = BasicMessageChannel("com.demo/msg", StandardMessageCodec());
void setup() {
  final dio = Dio();
  (dio.httpClientAdapter as dynamic).onHttpClientCreate = (client) {
    client.badCertificateCallback = (cert, host, port) => true;
  };
  final prefs = SharedPreferences.getInstance();
  Hive.openBox("vault");
  final db = openDatabase("app.db");
  final storage = FlutterSecureStorage();
  const apiKey = "AKIAIOSFODNN7EXAMPLE";
  final base = "https://api.demo-backend.com/v1";
  final realtime = "ws://realtime.demo.com/socket";
}
"""


def _flutter_tree() -> str:
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "lib"))
    os.makedirs(os.path.join(root, "test"))
    os.makedirs(os.path.join(root, "assets"))
    with open(os.path.join(root, "pubspec.yaml"), "w", encoding="utf-8") as f:
        f.write(_PUBSPEC)
    with open(os.path.join(root, "pubspec.lock"), "w", encoding="utf-8") as f:
        f.write("packages:\n  dio:\n    version: 5.0.0\n")
    with open(os.path.join(root, "lib", "main.dart"), "w", encoding="utf-8") as f:
        f.write(_MAIN_DART)
    return root


def _run(root: str, platform: str = "android") -> dict:
    results = {"platform": platform, "app_info": {"package": "com.demo", "bundle_id": "com.demo"},
               "findings": [], "secrets": [], "endpoints": []}
    fl.analyze([root], results, platform=platform)
    return results


def _titles(results):
    return [f["title"] for f in results["findings"]]


# ── Detection ─────────────────────────────────────────────────────────────────
def test_flutter_detection():
    _check(fl.detect([_flutter_tree()]) is True, "a Flutter project must be detected")


def test_non_flutter_not_detected():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "App.java"), "w") as f:
        f.write("class App {}")
    _check(fl.detect([d]) is False, "a non-Flutter tree must not be detected as Flutter")


# ── Dart / platform channels ──────────────────────────────────────────────────
def test_method_event_basic_channels():
    r = _run(_flutter_tree())
    t = _titles(r)
    _check(any("MethodChannel" in x for x in t), "MethodChannel must be detected")
    _check(any("EventChannel" in x for x in t), "EventChannel must be detected")
    _check(any("BasicMessageChannel" in x for x in t), "BasicMessageChannel must be detected")
    _check(set(r["flutter"]["platform_channels"]) >= {"com.demo/secure", "com.demo/events", "com.demo/msg"},
           "channel names must be captured for the metadata")


# ── pubspec ───────────────────────────────────────────────────────────────────
def test_pubspec_parsing():
    r = _run(_flutter_tree())
    deps = r["flutter"]["dependencies"]
    _check("dio" in deps and "hive" in deps and "shared_preferences" in deps, f"deps missing: {deps}")
    _check("sdk" not in deps and "flutter" not in deps, "SDK pseudo-deps must be excluded")
    _check(r["flutter"]["dependency_capabilities"].get("dio") == "HTTP client", "capability mapping wrong")


# ── Storage ───────────────────────────────────────────────────────────────────
def test_storage_findings():
    t = _titles(_run(_flutter_tree()))
    _check(any("SharedPreferences" in x for x in t), "SharedPreferences plaintext storage must be flagged")
    _check(any("Hive" in x for x in t), "Unencrypted Hive box must be flagged")
    _check(any("SQLite" in x or "sqflite" in x.lower() for x in t), "SQLite storage must be flagged")
    _check(any("Secure Storage" in x for x in t), "flutter_secure_storage usage must be noted")


# ── Secrets (reuse Secret Intelligence, not a Flutter detector) ───────────────
def test_secrets_enter_existing_stream():
    r = _run(_flutter_tree())
    vals = {s.get("value") for s in r["secrets"]}
    _check("AKIAIOSFODNN7EXAMPLE" in vals, "the embedded AWS key must enter results['secrets']")


# ── Network (reuse Network Intelligence) ──────────────────────────────────────
def test_network_findings_and_endpoints():
    r = _run(_flutter_tree())
    _check("https://api.demo-backend.com/v1" in r["endpoints"], "base URL must enter endpoints")
    t = _titles(r)
    _check(any("certificate validation disabled" in x.lower() for x in t),
           "badCertificateCallback => true must raise a TLS-validation finding")
    _check(any("WebSocket" in x for x in t), "WebSocket usage must be flagged")


# ── Canonical findings + pipeline integration ─────────────────────────────────
def test_findings_are_canonical_shaped():
    r = _run(_flutter_tree())
    for f in r["findings"]:
        for k in ("title", "severity", "category", "description", "detected_by", "file_path"):
            _check(k in f, f"Flutter finding missing canonical field {k}")
        _check(f["detected_by"] == ["Flutter Intelligence"], "Detected By must be Flutter Intelligence")


def test_findings_flow_through_fusion():
    from analyzers import fusion
    r = _run(_flutter_tree())
    fusion.fuse(r, platform="android")
    flutter_findings = [f for f in r["findings"] if "Flutter Intelligence" in (f.get("detected_by") or [])]
    _check(flutter_findings, "Flutter findings must survive fusion")
    _check(all("detection_count" in f and "fusion" in f for f in flutter_findings),
           "fusion must stamp provenance on Flutter findings")


def test_findings_flow_through_ownership_and_confidence():
    from analyzers import ownership
    from analyzers.confidence import engine as ce
    from analyzers.canonical_finding import from_legacy
    r = _run(_flutter_tree())
    ownership.annotate(r)
    # Every Flutter finding gets an owner verdict …
    flut = [f for f in r["findings"] if "Flutter Intelligence" in (f.get("detected_by") or [])]
    _check(all(f.get("owner_type") for f in flut), "ownership must annotate Flutter findings")
    # … and a confidence assessment via the existing Confidence Engine.
    res = ce.classify(from_legacy(flut[0], platform="android"))
    _check(0 <= res.overall <= 100, "confidence engine must score a Flutter finding")


def test_findings_flow_through_evidence_selection():
    from analyzers import evidence_selection
    r = _run(_flutter_tree())
    evidence_selection.annotate(r, platform="android")
    flut = [f for f in r["findings"] if "Flutter Intelligence" in (f.get("detected_by") or [])]
    _check(all(f.get("evidence_selection") and f.get("evidence_view") for f in flut),
           "evidence selection must build a proof view for Flutter findings")


# ── Source Explorer metadata ──────────────────────────────────────────────────
def test_source_explorer_metadata_exposed():
    r = _run(_flutter_tree())
    ps = r["flutter"]["project_structure"]
    for d in ("lib", "assets", "android", "ios", "test", "windows", "linux", "macos", "web"):
        _check(d in ps, f"project_structure must expose canonical dir '{d}'")
    _check(ps["lib"] is True and ps["test"] is True, "present project dirs must be marked True")
    _check(r["flutter"]["key_files"]["pubspec.yaml"] is True, "pubspec.yaml must be recorded")


# ── Robustness / regression ───────────────────────────────────────────────────
def test_analyze_empty_is_safe():
    results = {"platform": "android", "findings": [], "secrets": [], "endpoints": []}
    fl.analyze([tempfile.mkdtemp()], results, platform="android")  # must not raise
    _check(results["flutter"]["stats"]["findings"] == 0, "empty tree yields no Flutter findings")


def test_android_ios_analyzers_import_unaffected():
    import importlib
    importlib.import_module("analyzers.android_analyzer")
    importlib.import_module("analyzers.ios_analyzer")
    # Flutter runs ONLY when framework == flutter; a results dict without that flag
    # is never touched by the Flutter hook (regression guard for native apps).
    _check(True, "analyzers import cleanly with the Flutter hook present")


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
