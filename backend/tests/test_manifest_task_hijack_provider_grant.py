"""
Two new manifest detectors a lead reviewer does by hand:

A — Task hijacking / StrandHogg: an EXPORTED activity with a non-default taskAffinity
    (incl. empty "") or a singleTask/singleInstance launchMode. MEDIUM, escalated to
    HIGH for a security-sensitive (login/auth/payment/pin) or LAUNCHER/main activity.
B — Exported ContentProvider grant-uri-permission wildcard ("/" or pathPattern ".*"),
    and a <path-permission> weaker than the provider's own android:permission.

Both route through _process_component (ownership/reachability/confidence pipeline) and
carry a manifest_evidence_spec that resolves to the real manifest line.
"""
from __future__ import annotations

import os
import sys
from xml.etree import ElementTree as ET

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import android_analyzer as aa  # noqa: E402
from analyzers import finding_model as fm  # noqa: E402

PKG = "com.app"


def _results(manifest_permissions=None):
    return {
        "findings": [], "manifest_permissions": manifest_permissions or [],
        "app_info": {"package": PKG},
        "attack_surface": {"activities": [], "services": [], "receivers": [], "providers": []},
    }


def _process(xml, comp_type, results=None):
    results = results if results is not None else _results()
    aa._process_component(ET.fromstring(xml), comp_type, PKG, results)
    return results["findings"]


def _by_rule(findings, rule_id):
    return [f for f in findings if f.get("rule_id") == rule_id]


_XMLNS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


# ── A: task hijacking ────────────────────────────────────────────────────────

def test_exported_singletask_activity_medium():
    xml = (f'<activity {_XMLNS} android:name=".SettingsActivity" android:exported="true" '
           'android:launchMode="singleTask">'
           '<intent-filter><action android:name="com.app.OPEN"/></intent-filter></activity>')
    hits = _by_rule(_process(xml, "activity"), "manifest_task_hijacking")
    assert hits, "an exported singleTask activity must be flagged"
    assert hits[0]["severity"] == "medium"
    assert hits[0]["manifest_evidence_spec"] == {"attr": "launchMode", "value": "singleTask"}
    assert "strandhogg" in hits[0]["description"].lower()


def test_launcher_empty_affinity_high():
    xml = (f'<activity {_XMLNS} android:name=".MainActivity" android:taskAffinity="">'
           '<intent-filter><action android:name="android.intent.action.MAIN"/>'
           '<category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>')
    hits = _by_rule(_process(xml, "activity"), "manifest_task_hijacking")
    assert hits and hits[0]["severity"] == "high", "launcher + empty taskAffinity is HIGH"
    assert hits[0]["manifest_evidence_spec"] == {"attr": "taskAffinity"}


def test_sensitive_login_singleinstance_high():
    xml = (f'<activity {_XMLNS} android:name=".LoginActivity" android:exported="true" '
           'android:launchMode="singleInstance"/>')
    hits = _by_rule(_process(xml, "activity"), "manifest_task_hijacking")
    assert hits and hits[0]["severity"] == "high"


def test_default_activity_not_flagged():
    # Exported, standard launchMode, default (absent) taskAffinity → NOT task-hijack.
    xml = (f'<activity {_XMLNS} android:name=".AboutActivity" android:exported="true">'
           '<intent-filter><action android:name="com.app.ABOUT"/></intent-filter></activity>')
    assert _by_rule(_process(xml, "activity"), "manifest_task_hijacking") == []


def test_affinity_equal_to_package_not_flagged():
    xml = (f'<activity {_XMLNS} android:name=".X" android:exported="true" '
           f'android:taskAffinity="{PKG}"/>')
    assert _by_rule(_process(xml, "activity"), "manifest_task_hijacking") == []


def test_non_exported_activity_not_flagged():
    xml = (f'<activity {_XMLNS} android:name=".Internal" android:exported="false" '
           'android:launchMode="singleTask"/>')
    assert _by_rule(_process(xml, "activity"), "manifest_task_hijacking") == []


# ── B: provider grant-uri / path-permission ──────────────────────────────────

def test_wildcard_grant_uri_high_when_unprotected():
    xml = (f'<provider {_XMLNS} android:name=".DataProvider" android:authorities="com.app.data" '
           'android:exported="true"><grant-uri-permission android:pathPattern=".*"/></provider>')
    hits = _by_rule(_process(xml, "provider"), "manifest_provider_wildcard_grant_uri")
    assert hits and hits[0]["severity"] == "high"
    assert hits[0]["manifest_evidence_spec"] == {"attr": "pathPattern", "value": ".*"}


def test_wildcard_grant_slash_path():
    xml = (f'<provider {_XMLNS} android:name=".P" android:authorities="com.app.p" '
           'android:exported="true"><grant-uri-permission android:path="/"/></provider>')
    hits = _by_rule(_process(xml, "provider"), "manifest_provider_wildcard_grant_uri")
    assert hits and hits[0]["manifest_evidence_spec"] == {"attr": "path", "value": "/"}


def test_wildcard_grant_medium_when_signature_protected():
    r = _results([{"name": "com.app.SIG", "protection_level": "signature"}])
    xml = (f'<provider {_XMLNS} android:name=".P" android:authorities="com.app.p" '
           'android:exported="true" android:permission="com.app.SIG">'
           '<grant-uri-permission android:pathPattern=".*"/></provider>')
    hits = _by_rule(_process(xml, "provider", r), "manifest_provider_wildcard_grant_uri")
    assert hits and hits[0]["severity"] == "medium"


def test_specific_grant_not_flagged():
    xml = (f'<provider {_XMLNS} android:name=".P" android:authorities="com.app.p" '
           'android:exported="true"><grant-uri-permission android:pathPrefix="/shared"/></provider>')
    assert _by_rule(_process(xml, "provider"), "manifest_provider_wildcard_grant_uri") == []


def test_weaker_path_permission_flagged():
    r = _results([{"name": "com.app.SIG", "protection_level": "signature"},
                  {"name": "com.app.NORM", "protection_level": "normal"}])
    xml = (f'<provider {_XMLNS} android:name=".SecureProvider" android:authorities="com.app.secure" '
           'android:exported="true" android:permission="com.app.SIG">'
           '<path-permission android:path="/public" android:readPermission="com.app.NORM"/></provider>')
    hits = _by_rule(_process(xml, "provider", r), "manifest_path_permission_weaker")
    assert hits and hits[0]["severity"] == "high"
    assert hits[0]["manifest_evidence_spec"] == {"attr": "readPermission", "value": "com.app.NORM"}


def test_stronger_or_equal_path_permission_not_flagged():
    r = _results([{"name": "com.app.SIG", "protection_level": "signature"}])
    xml = (f'<provider {_XMLNS} android:name=".P" android:authorities="com.app.p" '
           'android:exported="true" android:permission="com.app.SIG">'
           '<path-permission android:path="/x" android:readPermission="com.app.SIG"/></provider>')
    assert _by_rule(_process(xml, "provider", r), "manifest_path_permission_weaker") == []


# ── evidence spec resolves against the real manifest ─────────────────────────

def test_task_hijack_spec_resolves_to_manifest_line():
    manifest = ('<manifest package="com.app"><application>'
                '<activity android:name=".SettingsActivity" android:exported="true" '
                'android:launchMode="singleTask"/></application></manifest>')
    line, snippet = fm._find_manifest_line(manifest, {"attr": "launchMode", "value": "singleTask"})
    assert line > 0 and "singleTask" in snippet


def test_findings_carry_ownership_and_app_exposure():
    # Routed through Phase B: ownership + app_owned_exposure attached like other
    # exported-component findings (so the pipeline treats them consistently).
    xml = (f'<activity {_XMLNS} android:name=".LoginActivity" android:exported="true" '
           'android:launchMode="singleTask"/>')
    f = _by_rule(_process(xml, "activity"), "manifest_task_hijacking")[0]
    assert f.get("owner_type") and f.get("app_owned_exposure") is True
    assert f.get("file_path", "").endswith("LoginActivity") or "." in f.get("file_path", "")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
