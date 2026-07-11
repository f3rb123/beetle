"""
Regression: manifest-component findings must carry the OWNERSHIP of the class
that implements the component, not silently default to "Application".

Findings created directly in android_analyzer for exported components used to be
blanket-flagged app_owned_exposure=True, which forces APPLICATION ownership in
both ownership systems. A component backed by a library (androidx / io.flutter /
com.google) therefore never got a library label, the library-noise demotion had
nothing to act on, and Signal Quality showed "Library findings hidden 0".

These tests FAIL on the old behavior and PASS on the new:
  - a library-owned exported component finding is labeled owner_type != Application
    and a library ownership_label at creation, is counted in
    executive_summary.library_findings_hidden, and is demoted to library noise
  - unless it carries app-owned reachability (taint_flow / call_chain)
  - an app-owned component keeps app_owned_exposure and resolves to APPLICATION
"""
from __future__ import annotations

import os
import sys
from xml.etree import ElementTree as ET

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import android_analyzer as aa  # noqa: E402
from analyzers import finding_model  # noqa: E402
from analyzers import ownership  # noqa: E402
from analyzers.common import ns  # noqa: E402

APP_PKG = "com.checkin.app"


def _receiver(name, permission=None):
    e = ET.Element("receiver")
    e.set(ns("name"), name)
    e.set(ns("exported"), "true")
    if permission:
        e.set(ns("permission"), permission)
    return e


def _base():
    return {
        "findings": [], "manifest_permissions": [],
        "app_info": {"package": APP_PKG}, "platform": "android", "app_name": "checkin",
        "attack_surface": {"activities": [], "services": [], "receivers": [], "providers": []},
    }


def _component_finding(results, cls, permission=None):
    aa._process_component(_receiver(cls, permission), "receiver", APP_PKG, results)
    return results["findings"][-1]


# ── ownership attached at creation ───────────────────────────────────────────

def test_library_component_labeled_not_application():
    for cls in (
        "androidx.work.impl.background.systemalarm.RescheduleReceiver",
        "io.flutter.plugins.firebase.messaging.FlutterFirebaseMessagingReceiver",
        "com.google.firebase.iid.FirebaseInstanceIdReceiver",
    ):
        f = _component_finding(_base(), cls)
        assert f.get("owner_type") and f["owner_type"] != "Application", \
            f"{cls} should not be Application, got {f.get('owner_type')}"
        assert f.get("ownership_label") not in ("APPLICATION", None, ""), \
            f"{cls} label should be library, got {f.get('ownership_label')}"
        assert not f.get("app_owned_exposure"), \
            f"{cls} is library code — must not be flagged app_owned_exposure"


def test_app_component_keeps_app_owned_exposure():
    f = _component_finding(_base(), "com.checkin.app.MyReceiver")
    assert f.get("app_owned_exposure") is True
    # And resolves to APPLICATION through the app-namespace path.
    coarse, label, _ = finding_model.resolve_finding_ownership(f, APP_PKG)
    assert label == "APPLICATION"


# ── Signal Quality: "Library findings hidden" becomes non-zero ───────────────

def test_library_findings_hidden_nonzero():
    r = _base()
    _component_finding(r, "androidx.work.impl.background.systemalarm.RescheduleReceiver")
    _component_finding(r, "com.checkin.app.MyReceiver")
    kept, suppressed, stats = finding_model.refine_findings(
        r["findings"], app_package=APP_PKG, platform="android")
    es = finding_model.build_executive_summary(stats, suppressed)
    assert es["library_findings_hidden"] >= 1, \
        f"expected >=1 library finding hidden, got {es['library_findings_hidden']}"


# ── demotion consumes the labels ─────────────────────────────────────────────

def test_library_component_demoted_to_noise():
    r = _base()
    _component_finding(r, "androidx.work.impl.background.systemalarm.RescheduleReceiver")
    ownership.annotate(r)
    finding_model.demote_library_code_findings(r)
    f = r["findings"][0]
    assert f.get("library_noise") is True
    assert f.get("severity") == "info"
    assert r["library_noise_stats"]["demoted"] == 1


def test_library_component_with_reachability_kept():
    # A library-owned component that DOES carry app-owned reachability evidence
    # (a taint flow / call chain into app code) is a real weakness — never demoted.
    f = {
        "rule_id": "manifest_exported_receiver",
        "title": "Exported Broadcast Receiver Without Permission — X",
        "severity": "medium", "category": "Attack Surface",
        "owner_type": "ThirdPartySDK",
        "taint_flow": {"source": "Intent", "sink": "SQLiteDatabase.execSQL"},
    }
    r = {"findings": [f]}
    finding_model.demote_library_code_findings(r)
    assert not f.get("library_noise")
    assert f["severity"] == "medium"
    assert r["library_noise_stats"]["demoted"] == 0


def test_app_component_never_demoted():
    r = _base()
    _component_finding(r, "com.checkin.app.MyReceiver")
    ownership.annotate(r)
    finding_model.demote_library_code_findings(r)
    f = r["findings"][0]
    assert not f.get("library_noise")
    assert f["severity"] != "info"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
