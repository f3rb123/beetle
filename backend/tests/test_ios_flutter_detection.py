"""
Regression: _detect_framework (ios_analyzer) misdetected Flutter iOS apps as "native"
because it did a shallow top-level os.listdir for flutter_assets — but flutter_assets
is nested under Frameworks/App.framework/. Detection is now RECURSIVE over the bundle
(flutter_assets dir / App.framework / Flutter.framework / libapp|libflutter.dylib /
a Flutter plugin pod). React Native detection (already recursive via `files`) is kept.
"""
from __future__ import annotations

import os
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import ios_analyzer as ios  # noqa: E402


def _detect(build):
    root = tempfile.mkdtemp()
    app = os.path.join(root, "Payload", "Runner.app")
    os.makedirs(app)
    build(app)
    results = {"findings": []}
    ios._detect_framework(app, results)
    return results


def _mkdir(app, *parts):
    d = os.path.join(app, *parts)
    os.makedirs(d, exist_ok=True)
    return d


def _touch(path):
    open(path, "w").close()


# ── Flutter (recursive) ──────────────────────────────────────────────────────

def test_flutter_nested_app_framework_flutter_assets():
    def b(app):
        d = _mkdir(app, "Frameworks", "App.framework", "flutter_assets")
        _touch(os.path.join(d, "AssetManifest.json"))
    r = _detect(b)
    assert r["framework"]["type"] == "flutter", "nested flutter_assets must be detected"
    assert any(f["rule_id"] == "framework_flutter_detected" for f in r["findings"])


def test_flutter_via_flutter_framework_and_dylib():
    def b(app):
        _mkdir(app, "Frameworks", "Flutter.framework")
        _touch(os.path.join(app, "libflutter.dylib"))
    assert _detect(b)["framework"]["type"] == "flutter"


def test_flutter_via_libapp_dylib():
    def b(app):
        _mkdir(app, "Frameworks", "App.framework")
        _touch(os.path.join(app, "Frameworks", "App.framework", "libapp.dylib"))
    assert _detect(b)["framework"]["type"] == "flutter"


def test_flutter_via_plugin_pod():
    def b(app):
        d = _mkdir(app, "Frameworks", "flutter_secure_storage.framework")
        _touch(os.path.join(d, "flutter_secure_storage"))
    r = _detect(b)
    assert r["framework"]["type"] == "flutter"
    assert "flutter_secure_storage" in r["framework"]["details"][0]


# ── Native stays native ──────────────────────────────────────────────────────

def test_truly_native_stays_native():
    def b(app):
        _mkdir(app, "Frameworks", "Alamofire.framework")
        _touch(os.path.join(app, "Runner"))
    r = _detect(b)
    assert r["framework"]["type"] == "native"
    assert not any(f["rule_id"] == "framework_flutter_detected" for f in r["findings"])


def test_native_with_generic_app_dir_not_flutter():
    # A non-framework directory literally named "app" must NOT trigger Flutter
    # (we match "app.framework", not "app").
    def b(app):
        _mkdir(app, "app")
        _touch(os.path.join(app, "Runner"))
    assert _detect(b)["framework"]["type"] == "native"


# ── React Native branch still works ──────────────────────────────────────────

def test_react_native_still_detected():
    def b(app):
        _touch(os.path.join(app, "main.jsbundle"))
    assert _detect(b)["framework"]["type"] == "react_native"


def test_flutter_gate_condition_matches():
    # The Flutter-analyzer gate (line ~235) reads results["framework"]["type"]; confirm
    # the value it checks is exactly what detection writes.
    def b(app):
        _mkdir(app, "Frameworks", "App.framework", "flutter_assets")
    r = _detect(b)
    assert r.get("framework", {}).get("type") == "flutter"  # gate fires


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
