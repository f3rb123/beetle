"""
iOS report fixes (batch A–D). Backend-testable portions of four fixes:

A. Attack-chain overview count mismatch — the overview must read the SAME chain set
   the chains section renders. Backend invariant: quick_summary.chain_count ==
   len(attack_chains_v2), i.e. to_quick_summary is the single source. (The frontend
   Overview metric was pointed at the combined chain set to match ChainsPanel.)
B. Firebase GoogleService-Info.plist config (API_KEY / CLIENT_ID) now surfaced as INFO,
   dedup-safe against the generic AIza scanner. iOS-only.
C. App icon carved from a compiled Assets.car when no loose PNG exists (Flutter/Xcode
   asset-catalog builds).
D. iOS Info.plist / entitlements / URL-schemes data contract the "Application
   Configuration" panel renders.

All additions are iOS-path or platform-guarded; Android is untouched.
"""
from __future__ import annotations

import os
import struct
import sys
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import plistlib  # noqa: E402

from analyzers import ios_analyzer as ios  # noqa: E402


def _bundle():
    root = tempfile.mkdtemp()
    app = os.path.join(root, "Payload", "Runner.app")
    os.makedirs(app)
    return root, app


# ── A: chain-count source invariant ──────────────────────────────────────────

def test_quick_summary_chain_count_matches_v2():
    from analyzers.attack_chains import to_quick_summary
    results = {"platform": "ios", "attack_chains_v2": [
        {"id": "c1", "name": "Chain 1", "severity": "high", "overall_confidence": 80},
        {"id": "c2", "name": "Chain 2", "severity": "medium", "overall_confidence": 60},
    ]}
    cs = to_quick_summary(results)
    # Both the overview counter and the chains section derive from this list.
    assert len(cs) == len(results["attack_chains_v2"]) == 2


# ── B: Firebase plist config surfaces (dedup-safe, INFO) ─────────────────────

def _write_google_plist(app, binary=True):
    data = {"API_KEY": "AIzaSyA1234567890abcdefghijklmnopqrstuvw",
            "CLIENT_ID": "123-abc.apps.googleusercontent.com",
            "GOOGLE_APP_ID": "1:123:ios:abcdef", "PROJECT_ID": "checkin"}
    fmt = plistlib.FMT_BINARY if binary else plistlib.FMT_XML
    with open(os.path.join(app, "GoogleService-Info.plist"), "wb") as f:
        plistlib.dump(data, f, fmt=fmt)


def test_firebase_plist_surfaces_client_id_not_duplicating_api_key():
    _, app = _bundle()
    _write_google_plist(app, binary=True)
    # Generic scanner already found the AIza API_KEY:
    results = {"platform": "ios", "findings": [], "secrets": [
        {"name": "Google API Key", "value": "AIzaSyA1234567890abcdefghijklmnopqrstuvw",
         "file_path": "Payload/Runner.app/GoogleService-Info.plist", "line": 1}]}
    ios._extract_firebase_plist_config(app, results)
    names = [s["name"] for s in results["secrets"]]
    values = [s["value"] for s in results["secrets"]]
    # API_KEY not duplicated; CLIENT_ID + App ID added.
    assert values.count("AIzaSyA1234567890abcdefghijklmnopqrstuvw") == 1
    assert "Google OAuth Client ID" in names
    assert "123-abc.apps.googleusercontent.com" in values


def test_firebase_plist_config_renders_info():
    from analyzers import secret_intel
    _, app = _bundle()
    _write_google_plist(app, binary=False)
    results = {"platform": "ios", "findings": [], "secrets": []}
    ios._extract_firebase_plist_config(app, results)
    secret_intel.process_secrets(results, "io.checkin")
    visible = {s.get("name"): s.get("display_severity") for s in results.get("secrets", [])}
    assert "Google OAuth Client ID" in visible
    assert visible["Google OAuth Client ID"] == "info"
    # None suppressed to the "gone" state — they are inventory INFO, not dropped.
    assert all(s.get("display_severity") == "info" for s in results.get("secrets", []))


def test_firebase_plist_absent_is_noop():
    _, app = _bundle()
    results = {"platform": "ios", "secrets": []}
    ios._extract_firebase_plist_config(app, results)
    assert results["secrets"] == []


# ── C: Assets.car PNG carve ──────────────────────────────────────────────────

def _png(w, h):
    return (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + struct.pack(">II", w, h)
            + b"\x08\x06\x00\x00\x00" + b"\x00" * 80 + b"IEND\xaeB\x60\x82")


def test_icon_carved_from_assets_car_prefers_square():
    _, app = _bundle()
    blob = b"BOMStore" + b"\x11" * 40 + _png(200, 100) + b"xx" + _png(120, 120) + b"yy" + _png(60, 60)
    with open(os.path.join(app, "Assets.car"), "wb") as f:
        f.write(blob)
    plist_path = os.path.join(app, "Info.plist")
    with open(plist_path, "wb") as f:
        plistlib.dump({"CFBundleName": "Runner"}, f)
    results = {"app_info": {}}
    ios._extract_ios_app_icon(app, plist_path, results)
    ai = results["app_info"]
    assert ai.get("icon_source") == "assets_car"
    assert ai.get("icon_data", "").startswith("data:image/png;base64,")
    import base64
    raw = base64.b64decode(ai["icon_data"].split(",", 1)[1])
    assert ios.png_dimensions(raw) == (120, 120)  # largest SQUARE, not the 200x100 launch image


def test_assets_car_without_png_records_reason():
    _, app = _bundle()
    with open(os.path.join(app, "Assets.car"), "wb") as f:
        f.write(b"BOMStore" + b"\x00" * 200)  # no carve-able PNG
    plist_path = os.path.join(app, "Info.plist")
    with open(plist_path, "wb") as f:
        plistlib.dump({}, f)
    results = {"app_info": {}}
    ios._extract_ios_app_icon(app, plist_path, results)
    assert results["app_info"].get("icon_source") == "assets_car_unsupported"
    assert results["app_info"].get("icon_note")


def test_loose_appicon_png_still_preferred():
    # Regression guard: the loose-PNG path (steps 2-4) must still win when present.
    _, app = _bundle()
    with open(os.path.join(app, "AppIcon60x60@2x.png"), "wb") as f:
        f.write(_png(120, 120))
    plist_path = os.path.join(app, "Info.plist")
    with open(plist_path, "wb") as f:
        plistlib.dump({"CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}}}, f)
    results = {"app_info": {}}
    ios._extract_ios_app_icon(app, plist_path, results)
    assert results["app_info"].get("icon_source") == "ipa"


# ── D: iOS Application Configuration data contract ───────────────────────────

def test_info_plist_populates_config_data():
    _, app = _bundle()
    plist = {
        "CFBundleIdentifier": "io.checkin.app",
        "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "42",
        "MinimumOSVersion": "13.0",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["checkin", "fb123"]}],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    plist_path = os.path.join(app, "Info.plist")
    with open(plist_path, "wb") as f:
        plistlib.dump(plist, f)
    results = {"app_info": {}, "permissions": {}, "findings": [], "attack_surface":
               {"url_schemes": [], "universal_links": [], "exported_handlers": []}}
    ios._analyze_info_plist(plist_path, results)
    ai = results["app_info"]
    assert ai["bundle_id"] == "io.checkin.app"
    assert ai["version"] == "1.2.3" and ai["build"] == "42"
    assert ai["min_ios"] == "13.0"
    assert ai["ats"]["NSAllowsArbitraryLoads"] is True
    assert "checkin" in results["attack_surface"]["url_schemes"]


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
