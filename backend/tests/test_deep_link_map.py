"""
Structured deep-link map: the manifest parser now emits per-<data> scheme→host→path
entries with BROWSABLE/autoVerify badges, and posture_analyzer builds a per-activity
map that separates VERIFIED App Links (https + autoVerify + host) from UNVERIFIED
custom-scheme deep links (attacker-reachable), plus a best-effort taint consumer note.
Replaces the raw-action dump. Tests fixture manifests + the map.
"""
from __future__ import annotations

import os
import sys
from xml.etree import ElementTree as ET

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import android_analyzer as aa  # noqa: E402
from analyzers import posture_analyzer as pa  # noqa: E402

PKG = "com.app"
_XMLNS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def _results(taint=()):
    return {
        "findings": [], "manifest_permissions": [], "app_info": {"package": PKG},
        "attack_surface": {"activities": [], "services": [], "receivers": [], "providers": []},
        "taint_flows": list(taint),
    }


def _activity(results, xml):
    aa._process_component(ET.fromstring(xml), "activity", PKG, results)
    return results["attack_surface"]["activities"][-1]


# ── structured per-<data> parsing ────────────────────────────────────────────

def test_app_link_is_verified():
    r = _results()
    xml = (f'<activity {_XMLNS} android:name=".WebActivity" android:exported="true">'
           '<intent-filter android:autoVerify="true">'
           '<action android:name="android.intent.action.VIEW"/>'
           '<category android:name="android.intent.category.BROWSABLE"/>'
           '<data android:scheme="https" android:host="app.example.com" android:pathPrefix="/pay"/>'
           '</intent-filter></activity>')
    e = _activity(r, xml)["deep_links"][0]
    assert e["scheme"] == "https" and e["host"] == "app.example.com"
    assert e["path_kind"] == "pathPrefix" and e["path"] == "/pay"
    assert e["browsable"] is True and e["auto_verify"] is True
    assert e["app_link"] is True and e["verified"] is True and e["custom_scheme"] is False


def test_custom_scheme_is_unverified():
    r = _results()
    xml = (f'<activity {_XMLNS} android:name=".DeepLinkActivity" android:exported="true">'
           '<intent-filter><action android:name="android.intent.action.VIEW"/>'
           '<category android:name="android.intent.category.BROWSABLE"/>'
           '<data android:scheme="myapp" android:host="open" android:pathPattern=".*"/>'
           '</intent-filter></activity>')
    e = _activity(r, xml)["deep_links"][0]
    assert e["custom_scheme"] is True
    assert e["app_link"] is False and e["verified"] is False
    assert e["path_kind"] == "pathPattern"


def test_https_without_host_not_verified_applink():
    # autoVerify + https but NO host → cannot be a verified App Link.
    r = _results()
    xml = (f'<activity {_XMLNS} android:name=".A" android:exported="true">'
           '<intent-filter android:autoVerify="true"><action android:name="android.intent.action.VIEW"/>'
           '<data android:scheme="https"/></intent-filter></activity>')
    e = _activity(r, xml)["deep_links"][0]
    assert e["verified"] is False and e["app_link"] is False


def test_path_kinds_distinct():
    r = _results()
    xml = (f'<activity {_XMLNS} android:name=".A" android:exported="true">'
           '<intent-filter><data android:scheme="https" android:host="h" android:path="/exact"/></intent-filter>'
           '</activity>')
    assert _activity(r, xml)["deep_links"][0]["path_kind"] == "path"


# ── deep_link_map (posture) ──────────────────────────────────────────────────

def _both_activities(results):
    _activity(results, (f'<activity {_XMLNS} android:name=".WebActivity" android:exported="true">'
                        '<intent-filter android:autoVerify="true"><action android:name="android.intent.action.VIEW"/>'
                        '<category android:name="android.intent.category.BROWSABLE"/>'
                        '<data android:scheme="https" android:host="app.example.com" android:pathPrefix="/pay"/>'
                        '</intent-filter></activity>'))
    _activity(results, (f'<activity {_XMLNS} android:name=".DeepLinkActivity" android:exported="true">'
                        '<intent-filter><action android:name="android.intent.action.VIEW"/>'
                        '<category android:name="android.intent.category.BROWSABLE"/>'
                        '<data android:scheme="myapp" android:host="open"/></intent-filter></activity>'))


def test_map_separates_and_orders_custom_first():
    r = _results()
    _both_activities(r)
    pa.build_attack_surface_inventory(r)
    m = r["deep_link_map"]
    assert len(m) == 2
    # Custom-scheme (higher attack surface) first.
    assert m[0]["short_name"] == "DeepLinkActivity" and m[0]["has_custom_scheme"] is True
    assert m[1]["short_name"] == "WebActivity" and m[1]["verified_app_link"] is True


def test_map_consumer_note_from_taint():
    r = _results(taint=[{"class_name": "com.app.DeepLinkActivity", "source": "Intent.getData",
                         "source_cat": "User Input", "sink": "WebView.loadUrl", "sink_cat": "WebView"}])
    _both_activities(r)
    pa.build_attack_surface_inventory(r)
    dla = next(a for a in r["deep_link_map"] if a["short_name"] == "DeepLinkActivity")
    assert dla["consumer"] and dla["consumer"]["sink_cat"] == "WebView"
    assert "webview" in dla["consumer"]["note"].lower()
    # An activity with no taint flow to a high-value sink has no consumer note.
    wa = next(a for a in r["deep_link_map"] if a["short_name"] == "WebActivity")
    assert wa["consumer"] is None


def test_map_ignores_non_highvalue_taint_sink():
    # A taint flow to a Logging sink is not a deep-link "consumer" of concern.
    r = _results(taint=[{"class_name": "com.app.DeepLinkActivity", "sink": "Log.d", "sink_cat": "Logging"}])
    _both_activities(r)
    pa.build_attack_surface_inventory(r)
    dla = next(a for a in r["deep_link_map"] if a["short_name"] == "DeepLinkActivity")
    assert dla["consumer"] is None


def test_activity_without_deeplinks_absent_from_map():
    r = _results()
    _activity(r, f'<activity {_XMLNS} android:name=".Plain" android:exported="true"/>')
    pa.build_attack_surface_inventory(r)
    assert r["deep_link_map"] == []


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
