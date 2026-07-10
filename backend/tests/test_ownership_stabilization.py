"""
Ownership Engine stabilization tests (v1.3) — regression coverage for the
production issues found on the washingtonpost.apk scan (80/129 Unknown,
Application: 0):

1. Bare filenames ("AndroidManifest.xml") were parsed as dotted packages,
   blocking the application-config stage for every manifest finding.
2. app_owned_exposure (set by the manifest component analyzer) was ignored.
3. First-party code outside the applicationId namespace (com.wapo.* for
   applicationId com.washingtonpost.android) had no path to Application.
4. Signing-certificate findings fell to Unknown.
5. Well-known vendor SDKs (Amazon APS/IAP/identity, OneTrust, Radaee, IAB OM)
   had no fingerprints.
6. jadx `defpackage` (fully obfuscated) fell to the generic fallback reason.

Runnable standalone or under pytest:
    python -m tests.test_ownership_stabilization       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import ownership  # noqa: E402
from analyzers.canonical_finding import CanonicalFinding  # noqa: E402
from analyzers.ownership.engine import (  # noqa: E402
    _class_ref_package, context_from_results)
from analyzers.ownership.types import OwnershipContext, OwnerType  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


_CTX = OwnershipContext(platform="android",
                        app_packages=("com.washingtonpost.android",),
                        app_name="Washington Post")


def _classify(finding: dict, ctx=_CTX):
    cf = CanonicalFinding.from_legacy(finding, platform="android")
    return ownership.get_engine().classify(cf, ctx)


# ── 1. filename-vs-package parsing ───────────────────────────────────────────

def test_bare_filenames_are_not_packages():
    for fname in ("AndroidManifest.xml", "librdpdf.so", "strings.xml",
                  "omsdk-v1.js", "Info.plist"):
        _check(_class_ref_package(fname) == "",
               f"{fname!r} must not derive a package")
    _check(_class_ref_package("com.wapo.flagship.MainActivity")
           == "com.wapo.flagship",
           "real dotted class refs must still derive their package")


def test_manifest_finding_classifies_as_application():
    r = _classify({"title": "Cleartext HTTP Traffic Permitted",
                   "file_path": "AndroidManifest.xml",
                   "category": "Network Security",
                   "evidence_type": "manifest"})
    _check(r.owner_type == OwnerType.APPLICATION,
           f"manifest finding must be Application, got {r.owner_type}")


# ── 2. app_owned_exposure ────────────────────────────────────────────────────

def test_app_owned_exposure_outranks_fingerprints():
    r = _classify({"title": "Exported Activity Without Protection",
                   "file_path": "sources/com/amazon/aps/ads/activity/ApsInterstitialActivity.java",
                   "category": "Attack Surface",
                   "app_owned_exposure": True})
    _check(r.owner_type == OwnerType.APPLICATION,
           f"app_owned_exposure must win even over SDK code, got {r.owner_type}")
    _check(r.matched_rule == "app_exposure", r.matched_rule)


# ── 3. derived first-party namespaces ────────────────────────────────────────

def _wapo_results():
    return {
        "platform": "android",
        "app_info": {"package": "com.washingtonpost.android",
                     "main_activity": "com.wapo.flagship.wapomain.MainActivity"},
        "attack_surface": {
            "activities": [{"name": f"com.wapo.flagship.features.f{i}.SomeActivity"}
                           for i in range(9)],
            "services": [{"name": "com.amazon.device.ads.DTBInterstitialActivity"}],
            "receivers": [], "providers": [],
        },
    }


def test_namespaces_derived_from_launcher_and_components():
    ctx = context_from_results(_wapo_results())
    ns = ctx.application_namespaces()
    _check("com.washingtonpost.android" in ns, "declared package kept")
    _check("com.wapo.flagship.wapomain" in ns, "launcher package derived")
    _check("com.wapo.flagship" in ns, "dominant component namespace derived")
    _check("com.amazon.device" not in ns,
           "minority / fingerprinted namespaces must never qualify")


def test_derived_namespace_never_claims_sdk_prefix():
    results = _wapo_results()
    # Even a dominant share must be rejected when a fingerprint owns the prefix.
    results["attack_surface"]["activities"] = [
        {"name": f"com.google.firebase.f{i}.Activity"} for i in range(9)]
    results["app_info"]["main_activity"] = "com.google.firebase.Main"
    ctx = context_from_results(results)
    ns = ctx.application_namespaces()
    _check(not any(n.startswith("com.google") for n in ns),
           f"fingerprinted prefixes must be rejected, got {ns}")


def test_app_code_in_derived_namespace_is_application():
    ctx = context_from_results(_wapo_results())
    cf = CanonicalFinding.from_legacy(
        {"title": "WebView addJavascriptInterface",
         "file_path": "sources/com/wapo/flagship/features/articles2/views/Web.java"},
        platform="android")
    r = ownership.get_engine().classify(cf, ctx)
    _check(r.owner_type == OwnerType.APPLICATION, r.owner_type)


# ── 4. signing certificate findings ──────────────────────────────────────────

def test_certificate_findings_are_application():
    r = _classify({"title": "Self-Signed Signing Certificate",
                   "category": "Certificate",
                   "evidence": "Subject: CN=x"})
    _check(r.owner_type == OwnerType.APPLICATION,
           f"the signing cert is the app's own artifact, got {r.owner_type}")


# ── 5. vendor fingerprints observed in production ────────────────────────────

def test_new_vendor_fingerprints():
    cases = {
        "sources/com/amazon/aps/shared/ApsMetrics.java": "Amazon Publisher Services (APS/TAM)",
        "sources/com/amazon/device/ads/DtbDeviceData.java": "Amazon Publisher Services (APS/TAM)",
        "sources/com/amazon/device/iap/PurchasingService.java": "Amazon In-App Purchasing",
        "sources/com/amazon/identity/auth/device/x.java": "Login with Amazon",
        "sources/com/onetrust/otpublishers/headless/cmp/h.java": "OneTrust CMP",
        "sources/com/radaee/pdf/Global.java": "Radaee PDF",
        "sources/com/iab/omid/library/x.java": "IAB Open Measurement SDK",
    }
    for path, owner in cases.items():
        r = _classify({"title": "x", "file_path": path})
        _check(r.owner_type == OwnerType.VENDOR_SDK and r.owner_name == owner,
               f"{path} -> {r.owner_type}/{r.owner_name}, expected VendorSDK/{owner}")
    # path-token matches for non-package artifacts
    r = _classify({"title": "x", "file_path": "assets/omsdk-v1.js"})
    _check(r.owner_name == "IAB Open Measurement SDK", r.owner_name)
    r = _classify({"title": "x", "file_path": "librdpdf.so"})
    _check(r.owner_name == "Radaee PDF", r.owner_name)


# ── 6. defpackage = obfuscated ───────────────────────────────────────────────

def test_defpackage_is_reported_as_obfuscated():
    r = _classify({"title": "Weak Cipher Mode", "file_path": "sources/defpackage/kq3.java"})
    _check(r.owner_type == OwnerType.UNKNOWN, "defpackage stays Unknown (honest)")
    _check("obfuscated" in r.owner_reason.lower(),
           f"reason should say obfuscated, got {r.owner_reason!r}")


# ── AWS SDK prefix must not shadow the new Amazon SDKs ───────────────────────

def test_aws_sdk_fingerprint_unaffected():
    r = _classify({"title": "x", "file_path": "sources/com/amazonaws/auth/AWSCredentials.java"})
    _check(r.owner_name == "AWS SDK", f"got {r.owner_name}")


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all ownership stabilization tests passed")
