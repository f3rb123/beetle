"""
Regression: a behavior finding sourced entirely from framework/library files (e.g.
Flutter's io.flutter.* engine) still emitted HIGH — "Dynamic Code Loading" and "OS
Command Execution Primitive" on a Flutter app are the engine's own primitives, not the
app's. Fix: partition attributed files by ownership; 100% framework/library → INFO;
OS command execution without a tainted flow into an app-owned exec sink → INFO
(capability, not vuln); surface the app-owned file list.

These fail on the old behavior (framework-only behaviors HIGH) and pass on the new.
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import android_analyzer as aa  # noqa: E402

_FLUTTER = "sources/io/flutter/embedding/engine/FlutterJNI.java"
_APP = "sources/com/checkin/app/Worker.java"


def _run(api, evidence, *, perms=(), taint=()):
    results = {
        "platform": "android", "app_info": {"package": "com.checkin.app"}, "findings": [],
        "permissions": {"all": list(perms)},
        "attack_surface": {"activities": [], "services": [], "receivers": [], "providers": []},
        "taint_flows": list(taint),
        "android_api": api, "android_api_evidence": evidence,
    }
    aa._build_behavior_findings(results)
    entries = {e["category"]: e for e in results["behavior_analysis"]}
    findings = {f["title"]: f for f in results["findings"]}
    return results, entries, findings


# ── framework-only behavior → INFO with its file list ────────────────────────

def test_flutter_only_dynamic_loading_is_info():
    _r, entries, findings = _run(
        {"Dynamic Class and Dexloading": [_FLUTTER,
                                          "sources/io/flutter/plugin/common/X.java"]},
        {"Dynamic Class and Dexloading": [{"path": _FLUTTER, "line": 4, "snippet": "loadLibrary"}]},
    )
    e = entries["Dynamic Class and Dexloading"]
    assert e["severity"] == "info", f"framework-only must be INFO, got {e['severity']}"
    assert e["framework_owned"] is True
    assert e["owner_scope"] == "framework"
    assert e["app_owned_files"] == []
    # The emitted finding agrees.
    assert findings["Dynamic Code Loading Detected"]["severity"] == "info"


def test_flutter_only_os_command_is_info():
    _r, entries, _f = _run(
        {"Execute OS Command": [_FLUTTER]},
        {"Execute OS Command": [{"path": _FLUTTER, "line": 9, "snippet": "exec"}]},
    )
    assert entries["Execute OS Command"]["severity"] == "info"
    assert entries["Execute OS Command"]["framework_owned"] is True


# ── app-owned file keeps severity + shows the file list ──────────────────────

def test_app_owned_behavior_keeps_severity_and_lists_files():
    _r, entries, findings = _run(
        {"GPS Location": [_APP, _FLUTTER]},  # mixed: one app file, one framework file
        {"GPS Location": [{"path": _APP, "line": 7, "snippet": "getLastKnownLocation"}]},
        perms=["android.permission.ACCESS_FINE_LOCATION"],
    )
    e = entries["GPS Location"]
    assert e["severity"] == "medium", "a mixed behavior with a granted permission keeps severity"
    assert e["framework_owned"] is False
    assert e["owner_scope"] == "mixed"
    assert _APP in e["app_owned_files"] and _FLUTTER not in e["app_owned_files"]
    assert findings["Location Collection Behavior Detected"]["app_owned_files"] == [_APP]


# ── OS command: taint-gated ──────────────────────────────────────────────────

def test_os_command_without_app_taint_is_info():
    # App-owned exec file, but no tainted source reaches an exec sink in app code.
    _r, entries, _f = _run(
        {"Execute OS Command": ["sources/com/checkin/app/Cmd.java"]},
        {"Execute OS Command": [{"path": "sources/com/checkin/app/Cmd.java", "line": 5, "snippet": "Runtime.exec"}]},
    )
    assert entries["Execute OS Command"]["severity"] == "info", "capability, not a proven vuln"


def test_os_command_with_app_taint_keeps_high():
    _r, entries, _f = _run(
        {"Execute OS Command": ["sources/com/checkin/app/Cmd.java"]},
        {"Execute OS Command": [{"path": "sources/com/checkin/app/Cmd.java", "line": 5, "snippet": "Runtime.exec"}]},
        taint=[{"sink_cat": "Execution", "owner_type": "Application"}],
    )
    assert entries["Execute OS Command"]["severity"] == "high", "a real app-owned exec taint flow keeps HIGH"


def test_os_command_taint_in_library_class_stays_info():
    # An exec taint flow whose class is library-owned does NOT prove an app vuln.
    _r, entries, _f = _run(
        {"Execute OS Command": ["sources/com/checkin/app/Cmd.java"]},
        {"Execute OS Command": [{"path": "sources/com/checkin/app/Cmd.java", "line": 5, "snippet": "Runtime.exec"}]},
        taint=[{"sink_cat": "Execution", "owner_type": "ThirdPartySDK"}],
    )
    assert entries["Execute OS Command"]["severity"] == "info"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
