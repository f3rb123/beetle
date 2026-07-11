"""
Regression: the "Library findings hidden" Signal-Quality counter read a misleading
0 while the Findings header showed N findings hidden from view. Root cause: library
findings were SUPPRESSED (removed from `kept`) or labeled UNKNOWN (io.flutter was
not in finding_model's library prefixes), so `f in kept AND label in _LIB_LABELS`
missed them.

Fix: count "Library findings hidden" across BOTH kept-but-hidden and suppressed via
resolved ownership / library-noise / library suppression reasons, recognize
io.flutter as library, add a low-confidence funnel line, and make the buckets
disjoint so the funnel reconciles.

These fail on the old behavior (0 for suppressed-only library) and pass on the new.
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import finding_model as fm  # noqa: E402


# ── #3 io.flutter is a library label (finding_model caught up to the engine) ──

def test_flutter_classifies_as_library():
    assert fm.classify_ownership_label("io.flutter.embedding.engine.FlutterJNI") == fm.THIRD_PARTY_LIBRARY
    assert fm.classify_ownership_label("androidx.work.Worker") == fm.JETPACK
    assert fm.classify_ownership_label("com.google.firebase.messaging.X") == fm.FIREBASE


# ── #1 library findings counted even when SUPPRESSED ─────────────────────────

def test_suppressed_library_counted():
    # ALL library findings suppressed → old code (kept-only) read 0; new reads >0.
    kept = [
        {"ownership_label": "APPLICATION", "is_app_code": True, "confidence_score": 85},
    ]
    suppressed = [
        {"ownership_label": "JETPACK", "is_app_code": False, "suppressed_reason": "no_extractable_evidence"},
        {"ownership_label": "FIREBASE", "is_app_code": False, "suppressed_reason": "framework_library_taint"},
    ]
    stats = fm._build_quality_stats(3, kept, suppressed, 0, 0)
    assert stats["library_findings_hidden"] == 2
    assert stats["library_hidden_suppressed"] == 2
    assert stats["library_hidden_kept"] == 0


def test_library_noise_flag_counts():
    # A 6.3-demoted component finding carries library_noise even if its label
    # didn't resolve to a _LIB label.
    kept = [{"ownership_label": "UNKNOWN", "is_app_code": False,
             "confidence_score": 50, "library_noise": True}]
    stats = fm._build_quality_stats(1, kept, [], 0, 0)
    assert stats["library_findings_hidden"] == 1


# ── #2 disjoint funnel + low-confidence line ─────────────────────────────────

def test_funnel_disjoint_and_low_conf_line():
    kept = [
        {"ownership_label": "APPLICATION", "is_app_code": True, "confidence_score": 90},  # default
        {"ownership_label": "APPLICATION", "is_app_code": True, "confidence_score": 30},  # low-conf
        {"ownership_label": "JETPACK", "is_app_code": False, "confidence_score": 60},     # lib kept
    ]
    suppressed = [
        {"ownership_label": "THIRD_PARTY_LIBRARY", "is_app_code": False, "suppressed_reason": "framework_library_taint"},
        {"ownership_label": "UNKNOWN", "is_app_code": False, "suppressed_reason": "hashcode_not_crypto"},
        {"ownership_label": "UNKNOWN", "is_app_code": False, "suppressed_reason": "low_value_taint_sink"},
    ]
    stats = fm._build_quality_stats(6, kept, suppressed, 0, 0)
    es = fm.build_executive_summary(stats, suppressed)

    assert es["library_findings_hidden"] == 2      # 1 kept JETPACK + 1 suppressed framework_library_taint
    assert es["low_confidence_hidden"] == 1        # app conf<70
    assert es["false_positives_suppressed"] == 1   # hashcode_not_crypto (non-library)
    assert es["low_value_flows_pruned"] == 1       # low_value_taint_sink (non-library)
    # framework_library_taint is attributed to LIBRARY, never double-counted as low-value.
    assert "low-confidence findings hidden" in "\n".join(es["lines"]).lower()


# ── consistency: header vs Signal-Quality never contradict ───────────────────

def test_header_and_signal_quality_consistent():
    # A Flutter+Firebase+androidx app: several library findings, some kept-hidden,
    # some suppressed. The "hidden from view" header (suppressed_count) and the
    # Signal-Quality library line must not contradict (0 vs N).
    kept = [
        {"ownership_label": "APPLICATION", "is_app_code": True, "confidence_score": 88},
        {"ownership_label": "JETPACK", "is_app_code": False, "confidence_score": 55},
        {"ownership_label": "FIREBASE", "is_app_code": False, "confidence_score": 55},
    ]
    suppressed = [
        {"ownership_label": "THIRD_PARTY_LIBRARY", "is_app_code": False, "suppressed_reason": "no_extractable_evidence"},
        {"ownership_label": "APPLICATION", "is_app_code": True, "suppressed_reason": "no_extractable_evidence"},
    ]
    stats = fm._build_quality_stats(5, kept, suppressed, 0, 0)
    es = fm.build_executive_summary(stats, suppressed)

    header_hidden = stats["suppressed_count"]      # "N finding(s) hidden from this view"
    assert header_hidden > 0
    assert es["library_findings_hidden"] > 0, "must not report 0 library findings hidden"
    # library hidden cannot exceed everything that is hidden (suppressed + kept-hidden).
    assert es["library_findings_hidden"] <= stats["suppressed_count"] + stats["hidden_from_view"]
    # exact partition of the kept-but-hidden set.
    assert stats["hidden_from_view"] == (
        stats["library_hidden_kept"] + stats["low_confidence_hidden"] + stats["hidden_other"])


def test_all_app_no_library_is_zero():
    # No library findings → library line legitimately 0 (not a regression).
    kept = [{"ownership_label": "APPLICATION", "is_app_code": True, "confidence_score": 90}]
    suppressed = [{"ownership_label": "APPLICATION", "is_app_code": True, "suppressed_reason": "no_extractable_evidence"}]
    stats = fm._build_quality_stats(2, kept, suppressed, 0, 0)
    assert stats["library_findings_hidden"] == 0


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
