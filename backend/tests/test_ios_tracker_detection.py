"""iOS tracker detection (RUN 11).

This was billed as a "one-line wire-up" of Android's detect_trackers(). It is not: all 73
TRACKER_SIGNATURES key on an ANDROID PACKAGE PREFIX ("com.google.firebase.crashlytics") matched
with startswith(). An iOS app has no Java packages, so feeding it pod names matches NOTHING.

iOS needs its own identifier path, proven by one of three evidence signals: a pod in the bundle,
an endpoint the app contains, or a marker string statically linked into a Mach-O. The third
signal is not optional: Firebase Analytics ships NO framework in this app — it is linked
straight into Runner — so a framework-only check reports it as absent.
"""
from analyzers.tracker_db import (
    detect_trackers, detect_trackers_ios, ios_tracker_markers,
)


def test_android_detector_cannot_see_ios_pods():
    # The premise check: this is WHY iOS needs its own path.
    assert detect_trackers({"FirebaseCrashlytics", "GoogleDataTransport"}) == []


def test_pod_evidence_detects_crashlytics():
    found = detect_trackers_ios(sdk_names=["FirebaseCrashlytics"])
    names = [t["name"] for t in found]
    assert "Google Firebase Crashlytics" in names
    ev = found[0]["evidence"][0]
    assert ev["type"] == "framework" and "FirebaseCrashlytics" in ev["value"]


def test_statically_linked_sdk_is_found_by_binary_marker_alone():
    # Firebase Analytics ships no framework here. Pod list is EMPTY on purpose.
    found = detect_trackers_ios(sdk_names=[], endpoints=[],
                                binary_markers=["FirebaseAnalytics", "FIRAnalytics"])
    ga = next(t for t in found if t["name"] == "Google Firebase Analytics")
    assert ga["statically_linked"] is True
    assert any(e["type"] == "binary_symbol" for e in ga["evidence"])


def test_endpoint_evidence_alone_detects_a_tracker():
    found = detect_trackers_ios(endpoints=["https://api-adservices.apple.com/api/v1/"])
    apple = next(t for t in found if t["name"] == "Apple AdServices (Attribution)")
    assert apple["evidence"][0]["type"] == "endpoint"


def test_multiple_evidence_signals_are_all_recorded():
    found = detect_trackers_ios(
        sdk_names=["FirebaseCrashlytics"],
        endpoints=["https://reports.crashlytics.com"],
        binary_markers=["FIRCrashlytics"])
    c = next(t for t in found if "Crashlytics" in t["name"])
    kinds = {e["type"] for e in c["evidence"]}
    assert kinds == {"framework", "endpoint", "binary_symbol"}


# ── THE GUARD: no evidence -> not reported ───────────────────────────────────
def test_tracker_with_no_evidence_is_not_reported():
    assert detect_trackers_ios(sdk_names=["fluttertoast", "battery_plus"],
                               endpoints=["https://httpbin.org/post"],
                               binary_markers=["_strcpy"]) == []


def test_admob_is_not_claimed_without_the_ads_sdk():
    # MobSF reports "AdMob" for this app, but it ships NO GoogleMobileAds framework and no
    # GADMobileAds symbol -- the only "admob" string is an admob_app_id key inside App
    # Measurement (attribution plumbing, not the ad-serving SDK). Beetle must not claim AdMob
    # from Firebase evidence alone.
    found = detect_trackers_ios(
        sdk_names=["FirebaseCrashlytics", "FirebasePerformance", "GoogleDataTransport"],
        endpoints=["https://firebaselogging.googleapis.com"],
        binary_markers=["FirebaseAnalytics"])
    assert "Google AdMob" not in [t["name"] for t in found]


def test_admob_is_reported_when_the_real_ads_sdk_is_present():
    found = detect_trackers_ios(sdk_names=["GoogleMobileAds"])
    assert "Google AdMob" in [t["name"] for t in found]


def test_markers_are_exported_for_the_binary_scan():
    m = ios_tracker_markers()
    assert "FirebaseAnalytics" in m and "GADMobileAds" in m


def test_a_framework_backed_tracker_is_not_mislabelled_statically_linked():
    # Ordering regression guard: tracker detection must run AFTER the frameworks are detected.
    # When results["sdks"] was still empty, EVERY tracker fell back to marker evidence and
    # FirebaseCrashlytics -- which plainly ships FirebaseCrashlytics.framework -- was reported as
    # "statically linked, no framework". Present the pod, and it must be framework-backed.
    found = detect_trackers_ios(sdk_names=["FirebaseCrashlytics"],
                                binary_markers=["FIRCrashlytics"])
    c = next(t for t in found if "Crashlytics" in t["name"])
    assert c["statically_linked"] is False
    assert any(e["type"] == "framework" for e in c["evidence"])
