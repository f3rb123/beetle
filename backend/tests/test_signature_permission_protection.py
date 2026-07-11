"""
Regression: signature/privileged/system permissions are NOT "normal".

`_permission_protection_level` used to return "normal" for any android.permission.*
not in DANGEROUS_PERMISSIONS — including signature|privileged permissions like
android.permission.DUMP that a third-party app cannot hold. That mis-classification
made androidx's ProfileInstallReceiver (permission=DUMP) look like a weak exported
component and inflated the "high-risk exported component" count.

FAILS on old behavior (DUMP → "normal" → finding), PASSES on new (DUMP → "signature",
no finding). A genuinely weak `normal`-level custom permission still produces it.
"""
from __future__ import annotations

import os
import sys
from xml.etree import ElementTree as ET

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import android_analyzer as aa  # noqa: E402
from analyzers.common import (  # noqa: E402
    ns, is_signature_or_system_permission, SIGNATURE_OR_SYSTEM_PERMISSIONS,
)

_REQUIRED = {
    "DUMP", "READ_LOGS", "WRITE_SECURE_SETTINGS", "INSTALL_PACKAGES", "DELETE_PACKAGES",
    "MOUNT_UNMOUNT_FILESYSTEMS", "MANAGE_USB", "CAPTURE_AUDIO_OUTPUT", "READ_FRAME_BUFFER",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN", "BIND_NOTIFICATION_LISTENER_SERVICE",
    "INTERACT_ACROSS_USERS", "MODIFY_PHONE_STATE", "WRITE_APN_SETTINGS",
    "CONTROL_LOCATION_UPDATES", "DEVICE_POWER", "FACTORY_TEST", "INSTALL_LOCATION_PROVIDER",
    "MANAGE_DEVICE_ADMINS", "MASTER_CLEAR", "REBOOT", "SET_TIME", "STATUS_BAR",
}


def _receiver(pkg, name, permission=None, exported="true"):
    elem = ET.Element("receiver")
    elem.set(ns("name"), name)
    if exported is not None:
        elem.set(ns("exported"), exported)
    if permission is not None:
        elem.set(ns("permission"), permission)
    return elem


def _weak_findings(results):
    return [f for f in results["findings"]
            if f.get("rule_id") == "manifest_weak_exported_permission"]


# ── table coverage ───────────────────────────────────────────────────────────

def test_required_permissions_present_in_table():
    missing = _REQUIRED - set(SIGNATURE_OR_SYSTEM_PERMISSIONS)
    assert not missing, f"table missing required signature perms: {sorted(missing)}"


def test_suffix_matching_both_forms():
    assert is_signature_or_system_permission("android.permission.DUMP")
    assert is_signature_or_system_permission("DUMP")
    assert not is_signature_or_system_permission("android.permission.INTERNET")
    assert not is_signature_or_system_permission("")


# ── protection-level resolution ──────────────────────────────────────────────

def test_dump_resolves_to_signature():
    lvl = aa._permission_protection_level("android.permission.DUMP", {"manifest_permissions": []})
    assert lvl == "signature", f"DUMP must be signature, got {lvl!r}"


def test_normal_android_permission_still_normal():
    # VIBRATE is a genuine normal-level AOSP permission (not dangerous, not signature).
    lvl = aa._permission_protection_level("android.permission.VIBRATE", {"manifest_permissions": []})
    assert lvl == "normal"


def test_self_declared_custom_permission_wins():
    # A self-declared custom permission's real protectionLevel is authoritative.
    results = {"manifest_permissions": [{"name": "com.app.C", "protection_level": "signature"}]}
    assert aa._permission_protection_level("com.app.C", results) == "signature"


# ── finding path ─────────────────────────────────────────────────────────────

def _base_results():
    return {"findings": [], "manifest_permissions": [],
            "attack_surface": {"activities": [], "services": [], "receivers": [], "providers": []}}


def test_dump_protected_receiver_no_weak_finding():
    results = _base_results()
    elem = _receiver("com.app", ".ProfileInstallReceiver", permission="android.permission.DUMP")
    aa._process_component(elem, "receiver", "com.app", results)

    recv = results["attack_surface"]["receivers"][0]
    assert recv["permission_protection"] == "signature"
    assert not _weak_findings(results), "DUMP-protected component must not be flagged weak"


def test_normal_custom_permission_still_flagged():
    results = _base_results()
    results["manifest_permissions"] = [
        {"name": "com.app.permission.CUSTOM", "protection_level": "normal"}
    ]
    elem = _receiver("com.app", ".ExportedReceiver", permission="com.app.permission.CUSTOM")
    aa._process_component(elem, "receiver", "com.app", results)

    recv = results["attack_surface"]["receivers"][0]
    assert recv["permission_protection"] == "normal"
    weak = _weak_findings(results)
    assert weak, "a normal-level custom permission must still produce the weak finding"
    # And the copy must NOT falsely claim third-party reach for a signature perm.
    assert "third-party app can request and hold" in weak[0]["description"].lower()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
