"""
Regression: posture_analyzer._component_risk rated any exported component "high"
purely on a name-token match ("profile" → androidx.profileinstaller.
ProfileInstallReceiver = HIGH), ignoring class ownership and the signature/
privileged permission boundary. That library-owned, signature-gated receiver then
headlined the CISO "high-risk exported component" line and the Exploitability
narrative, contradicting the rest of the report (it generates no finding).

FAILS on old behavior (library signature receiver = HIGH, in high_risk_components),
PASSES on new (capped low, excluded). Genuine app-owned high-risk is preserved.
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import posture_analyzer as pa  # noqa: E402


def _comp(name, short, comp_type, **kw):
    d = {"name": name, "short_name": short, "exported": True}
    d.update(kw)
    return d


# ── library-owned + signature-protected → NOT high-risk ──────────────────────

def test_library_signature_receiver_capped_low():
    c = _comp("androidx.profileinstaller.ProfileInstallReceiver", "ProfileInstallReceiver",
              "receivers", permission="android.permission.DUMP", permission_protection="signature")
    assert pa._component_risk(c, "receivers") in ("low", "info"), \
        "a library-owned signature-protected receiver must not be high-risk"


def test_library_receiver_excluded_from_high_risk_components():
    results = {"attack_surface": {
        "activities": [], "services": [],
        "receivers": [_comp("androidx.profileinstaller.ProfileInstallReceiver",
                            "ProfileInstallReceiver", "receivers",
                            permission="android.permission.DUMP",
                            permission_protection="signature")],
        "providers": [],
    }}
    pa.build_attack_surface_inventory(results)
    names = [c.get("short_name") for c in results["high_risk_components"]]
    assert "ProfileInstallReceiver" not in names
    assert results["high_risk_components"] == []


def test_library_ownership_caps_even_sensitive_name():
    # androidx.* class, no permission at all — still library-owned, still not the
    # app's attack surface.
    c = _comp("androidx.work.impl.background.systemalarm.RescheduleReceiver",
              "RescheduleReceiver", "receivers", actions=["android.intent.action.BOOT_COMPLETED"])
    assert pa._component_risk(c, "receivers") == "low"


# ── signature-permission gate (app-owned too) ────────────────────────────────

def test_app_signature_protected_component_capped_low():
    # An app-owned but signature-gated, sensitively-named receiver is still not
    # third-party-reachable → low.
    c = _comp("com.checkin.app.ProfileSyncReceiver", "ProfileSyncReceiver", "receivers",
              permission="android.permission.BIND_DEVICE_ADMIN", permission_protection="signature")
    assert pa._component_risk(c, "receivers") == "low"


# ── genuine app-owned high-risk preserved ────────────────────────────────────

def test_app_browsable_activity_still_high():
    c = _comp("com.checkin.app.DeepLinkActivity", "DeepLinkActivity", "activities",
              browsable=True, schemes=["https"], deeplinks=["https://checkin.app/pay"])
    assert pa._component_risk(c, "activities") == "high"


def test_app_provider_no_permission_still_high():
    c = _comp("com.checkin.app.DataProvider", "DataProvider", "providers",
              authorities="com.checkin.app.provider")
    assert pa._component_risk(c, "providers") == "high"


def test_end_to_end_mixed_inventory():
    results = {"attack_surface": {
        "activities": [_comp("com.checkin.app.DeepLinkActivity", "DeepLinkActivity",
                            "activities", browsable=True, schemes=["https"],
                            deeplinks=["https://checkin.app/pay"])],
        "services": [],
        "receivers": [_comp("androidx.profileinstaller.ProfileInstallReceiver",
                            "ProfileInstallReceiver", "receivers",
                            permission="android.permission.DUMP",
                            permission_protection="signature")],
        "providers": [_comp("com.checkin.app.DataProvider", "DataProvider",
                           "providers", authorities="com.checkin.app.provider")],
    }}
    pa.build_attack_surface_inventory(results)
    hr_names = {c.get("short_name") for c in results["high_risk_components"]}
    assert "ProfileInstallReceiver" not in hr_names
    assert {"DeepLinkActivity", "DataProvider"} <= hr_names


def test_app_owned_reachability_keeps_library_component():
    # A library-owned component that DOES carry app-owned reachability evidence is
    # a real, reachable weakness → not capped by the ownership gate.
    c = _comp("androidx.core.app.CoreReceiver", "CoreReceiver", "receivers",
              browsable=True, schemes=["https"], deeplinks=["https://x/pay"],
              call_chain=["com.checkin.app.Handler.onReceive"])
    assert pa._component_risk(c, "activities") == "high"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
