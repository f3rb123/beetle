"""
SDK normalization (Phase 2.5.10 #8) — regression.

The same SDK is reported under vendor-prefixed aliases by different detectors
(e.g. "Firebase" vs "Google Firebase"). normalize_sdks must merge them into one
canonical entry, enrich missing fields, and keep the highest severity.

Run: ``python -m pytest tests/test_sdk_normalization.py`` from the backend directory.
"""
from __future__ import annotations

from analyzers.tracker_db import normalize_sdks, canonical_sdk_name


def test_firebase_aliases_merge():
    assert canonical_sdk_name("Google Firebase") == "Firebase"
    assert canonical_sdk_name("firebase") == "Firebase"

    out = normalize_sdks([
        {"name": "Google Firebase", "category": "Analytics/Backend", "severity": "info"},
        {"name": "Firebase", "severity": "medium", "url": "https://firebase.google.com"},
    ])
    assert len(out) == 1, f"expected one merged Firebase entry, got {[s['name'] for s in out]}"
    s = out[0]
    assert s["name"] == "Firebase"
    assert s["category"] == "Analytics/Backend"            # enriched from the first
    assert s["url"] == "https://firebase.google.com"       # enriched from the second
    assert s["severity"] == "medium"                       # highest severity kept


def test_distinct_sdks_preserved_in_order():
    out = normalize_sdks([
        {"name": "Google Firebase", "severity": "info"},
        {"name": "Facebook", "severity": "info"},
        {"name": "Google AdMob", "severity": "info"},
        {"name": "admob", "severity": "low"},   # alias of Google AdMob → merges
    ])
    names = [s["name"] for s in out]
    assert names == ["Firebase", "Facebook SDK", "Google AdMob"]


def test_unknown_sdk_passes_through():
    out = normalize_sdks([{"name": "AcmeProprietarySDK", "severity": "info"}])
    assert out[0]["name"] == "AcmeProprietarySDK"


def test_empty_and_malformed_safe():
    assert normalize_sdks([]) == []
    assert normalize_sdks([{"severity": "info"}, "junk", None]) == []
