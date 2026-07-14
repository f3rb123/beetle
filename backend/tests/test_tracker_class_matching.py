"""RUN 33 — tracker detection: class-inventory matching surface + confidence tiers.

The manifest-derived package hints miss statically-linked SDKs (Google Analytics, Tag
Manager ship classes that are never declared in the manifest), so Beetle found 1 tracker
where MobSF found 3. detect_trackers now matches signature packages against the FULL DEX
class inventory and tiers confidence by network corroboration. These tests lock BOTH
directions: real classes surface the tracker; absent classes never do (no FP).
"""
import pytest

from analyzers.tracker_db import detect_trackers, _endpoint_hosts, _domain_seen


# Realistic InsecureBankv2-shaped class inventory: GA + Tag Manager + AdMob classes are
# present in the DEX but NOT in the manifest package hints.
IB2_CLASSES = {
    "com.google.android.gms.analytics.Tracker",
    "com.google.android.gms.analytics.GoogleAnalytics",
    "com.google.android.gms.tagmanager.Container",
    "com.google.android.gms.tagmanager.TagManager",
    "com.google.android.gms.ads.AdView",
    "com.android.insecurebankv2.LoginActivity",
}
# The manifest only declared the ads component (AdActivity) — analytics/tagmanager absent.
IB2_MANIFEST_HINTS = {"com.google.android.gms.ads", "com.android.insecurebankv2"}


def _named(trackers):
    return {t["name"]: t for t in trackers}


# ── the core fix: class inventory surfaces statically-linked SDKs ────────────
def test_class_inventory_surfaces_ga_and_tagmanager():
    got = _named(detect_trackers(IB2_MANIFEST_HINTS, class_names=IB2_CLASSES))
    assert "Google Analytics" in got
    assert "Google Tag Manager" in got
    assert "Google AdMob" in got
    assert got["Google Analytics"]["matched_class"].startswith("com.google.android.gms.analytics")


def test_manifest_only_misses_ga_and_tagmanager():
    """Regression proof: without the class inventory (old behavior), GA/TagManager are invisible
    because they are not in the manifest — AdMob still shows via its declared component."""
    got = _named(detect_trackers(IB2_MANIFEST_HINTS))
    assert "Google AdMob" in got                 # manifest-declared -> still found
    assert "Google Analytics" not in got         # this is exactly the gap the fix closes
    assert "Google Tag Manager" not in got


# ── confidence tiering ───────────────────────────────────────────────────────
def test_confirmed_requires_class_plus_domain():
    eps = ["https://www.google-analytics.com/collect?v=1", "https://bank.example.com/api"]
    got = _named(detect_trackers(IB2_MANIFEST_HINTS, class_names=IB2_CLASSES, endpoints=eps))
    # GA class present AND its domain observed in endpoints -> confirmed
    assert got["Google Analytics"]["confidence"] == "confirmed"
    assert got["Google Analytics"]["domain_observed"] is True
    # Tag Manager class present but googletagmanager.com not in endpoints -> likely
    assert got["Google Tag Manager"]["confidence"] == "likely"
    assert got["Google Tag Manager"]["domain_observed"] is False


def test_class_only_is_likely():
    got = _named(detect_trackers(IB2_MANIFEST_HINTS, class_names=IB2_CLASSES, endpoints=[]))
    assert got["Google Analytics"]["confidence"] == "likely"


def test_evidence_lists_matched_class_and_domain():
    eps = ["https://www.google-analytics.com/g/collect"]
    got = _named(detect_trackers(set(), class_names=IB2_CLASSES, endpoints=eps))
    ga = got["Google Analytics"]
    types = {e["type"] for e in ga["evidence"]}
    assert "code class" in types
    assert "network endpoint" in types


# ── no false positives ───────────────────────────────────────────────────────
def test_absent_tracker_never_matches():
    clean = {"com.android.insecurebankv2.LoginActivity", "androidx.appcompat.app.AppCompatActivity"}
    got = _named(detect_trackers(set(), class_names=clean))
    assert got == {}


def test_no_inputs_returns_empty():
    assert detect_trackers(set()) == []
    assert detect_trackers(set(), class_names=set(), endpoints=[]) == []


def test_ios_pod_names_still_empty():
    """Locks the pre-existing iOS guard: Android detect_trackers must not match iOS pod names
    (they lack the com.* package prefix and there is no class inventory)."""
    assert detect_trackers({"FirebaseCrashlytics", "GoogleDataTransport"}) == []


# ── endpoint host parsing helpers ────────────────────────────────────────────
def test_endpoint_host_extraction():
    hosts = _endpoint_hosts([
        "https://www.google-analytics.com/collect?v=1",
        "http://graph.facebook.com:443/v2",
        {"url": "https://app-measurement.com/a"},
        {"host": "googletagmanager.com"},
    ])
    assert "www.google-analytics.com" in hosts
    assert "graph.facebook.com" in hosts
    assert "app-measurement.com" in hosts
    assert "googletagmanager.com" in hosts


def test_domain_seen_matches_subdomains():
    hosts = {"www.google-analytics.com"}
    assert _domain_seen("google-analytics.com", hosts) is True   # subdomain of observed
    assert _domain_seen("evil.com", hosts) is False


def test_matched_class_is_deterministic():
    """A set has no stable iteration order, so the matched class must be chosen deterministically
    (min) — otherwise the Android tracker output drifts run-to-run and breaks byte-stability."""
    classes = {
        "com.google.android.gms.analytics.internal.zzw",
        "com.google.android.gms.analytics.Tracker",
        "com.google.android.gms.analytics.AnalyticsReceiver",
        "com.google.android.gms.analytics.GoogleAnalytics",
    }
    picks = {detect_trackers(set(), class_names=classes)[0]["matched_class"] for _ in range(8)}
    assert len(picks) == 1, f"matched_class not deterministic: {picks}"
    assert picks == {min(classes)}
