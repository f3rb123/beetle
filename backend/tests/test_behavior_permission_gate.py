"""
Regression: behavior-capability findings must be gated on the app's declared
permissions / bound services, not emitted at a hardcoded HIGH severity from a
code-only API match.

A Flutter app that declares no RECORD_AUDIO cannot record audio, and Flutter's
built-in semantics APIs are not an accessibility-abuse capability without a bound
<service>. Presenting those as HIGH is a false positive.

FAILS on old behavior (always HIGH), PASSES on new (INFO unless the prerequisite
permission/service is actually declared).
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import android_analyzer as aa  # noqa: E402


def _results(category, *, permissions=(), services=()):
    ev = [{"path": "sources/com/app/Cap.java", "line": 42, "snippet": "doThing();"}]
    return {
        "findings": [],
        "android_api": {category: ["sources/com/app/Cap.java"]},
        "android_api_evidence": {category: ev},
        "permissions": {"all": list(permissions)},
        "attack_surface": {"activities": [], "services": list(services),
                           "receivers": [], "providers": []},
    }


def _finding(results, title):
    return next((f for f in results["findings"] if f.get("title") == title), None)


# ── Audio recording ──────────────────────────────────────────────────────────

def test_audio_without_permission_not_high():
    r = _results("Audio Record")  # no RECORD_AUDIO
    aa._build_behavior_findings(r)
    f = _finding(r, "Audio Recording Capability Detected")
    assert f is not None
    assert f["severity"] == "info", f"expected INFO, got {f['severity']}"
    assert f["prerequisite_met"] is False
    assert "RECORD_AUDIO" in f["description"]


def test_audio_with_permission_stays_high():
    r = _results("Audio Record", permissions=["android.permission.RECORD_AUDIO"])
    aa._build_behavior_findings(r)
    f = _finding(r, "Audio Recording Capability Detected")
    assert f is not None
    assert f["severity"] == "high"
    assert f["prerequisite_met"] is True


# ── Accessibility ────────────────────────────────────────────────────────────

def test_accessibility_without_bound_service_not_high():
    # Even WITH the BIND permission somewhere, no bound <service> → not exercisable.
    r = _results("Accessibility Service",
                 permissions=["android.permission.BIND_ACCESSIBILITY_SERVICE"])
    aa._build_behavior_findings(r)
    f = _finding(r, "Accessibility Automation Capability Detected")
    assert f is not None
    assert f["severity"] == "info"
    assert f["prerequisite_met"] is False


def test_accessibility_with_bound_service_stays_high():
    r = _results(
        "Accessibility Service",
        services=[{"name": "com.app.A11yService",
                   "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE"}],
    )
    aa._build_behavior_findings(r)
    f = _finding(r, "Accessibility Automation Capability Detected")
    assert f is not None
    assert f["severity"] == "high"
    assert f["prerequisite_met"] is True


# ── Location (either fine or coarse satisfies) ───────────────────────────────

def test_location_with_coarse_permission_kept():
    r = _results("GPS Location", permissions=["android.permission.ACCESS_COARSE_LOCATION"])
    aa._build_behavior_findings(r)
    f = _finding(r, "Location Collection Behavior Detected")
    assert f["severity"] == "medium"  # rule's real severity
    assert f["prerequisite_met"] is True


def test_location_without_permission_info():
    r = _results("GPS Location")
    aa._build_behavior_findings(r)
    f = _finding(r, "Location Collection Behavior Detected")
    assert f["severity"] == "info"


# ── Non-gated category is unaffected ─────────────────────────────────────────

def test_ungated_category_keeps_severity():
    # "Execute OS Command" has no permission prerequisite — must keep its severity.
    r = _results("Execute OS Command")
    aa._build_behavior_findings(r)
    f = _finding(r, "OS Command Execution Primitive Detected")
    assert f["severity"] == "high"
    assert f["prerequisite_met"] is True


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
