"""
Regression: a taint flow's severity was computed/stored inconsistently, so three
surfaces disagreed for the SAME flow:
  - the promoted finding used the calibrated severity (correct),
  - the PDF taint table rendered the RAW sink_sev (Log.e = HIGH),
  - the Data Flow panel (workspaces.build_taint_graph) defaulted raw flows to INFO.

Fix: calibrate ONCE at flow construction (flow["risk"]) and make every consumer read
it. FAILS on old behavior (panel INFO / PDF HIGH), PASSES on new (all MEDIUM/LOW).
"""
from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import taint_analyzer as ta  # noqa: E402
from analyzers import workspaces  # noqa: E402


def _raw_flow(source, source_cat, sink, sink_cat, sink_sev, cls="com.ibsplc.app.X"):
    """A raw taint flow shaped exactly as _analyze builds it (risk calibrated once)."""
    flow = {
        "source": source, "source_cat": source_cat,
        "sink": sink, "sink_cat": sink_cat,
        "sink_sev": sink_sev, "raw_sink_sev": sink_sev,
        "call_chain": [f"{cls}.log", "android.util.Log.e"],
        "class_name": cls, "method_name": "log", "owner_type": "Application",
    }
    flow["risk"] = ta.calibrate_flow_severity(flow)
    return flow


# ── #1 calibrated severity lives on the flow ─────────────────────────────────

def test_location_log_flow_risk_is_medium():
    f = _raw_flow("Location.getLatitude", "Location", "Log.e", "Logging", "high")
    assert f["risk"] == "medium", "sensitive source + logging sink → MEDIUM (not raw HIGH)"


def test_nonsensitive_log_flow_risk_is_low():
    f = _raw_flow("Bundle.get", "User Input", "Log.d", "Logging", "medium")
    assert f["risk"] == "low", "non-sensitive source + logging sink → LOW"


def test_finding_severity_matches_flow_risk():
    f = _raw_flow("Location.getLatitude", "Location", "Log.e", "Logging", "high")
    finding = ta._flow_to_finding(f)
    assert finding["severity"] == f["risk"] == "medium"
    # The sub-dict carries the same calibrated value.
    assert finding["taint_flow"]["risk"] == "medium"


# ── #2 the Data Flow panel reads the calibrated risk, never INFO ─────────────

def test_taint_graph_uses_calibrated_risk_not_info():
    loc = _raw_flow("Location.getLatitude", "Location", "Log.e", "Logging", "high")
    low = _raw_flow("Bundle.get", "User Input", "Log.d", "Logging", "medium",
                    cls="com.ibsplc.app.Y")
    results = {"findings": [], "taint_flows": [loc, low]}
    workspaces.build_taint_graph(results)
    by_sink = {g["sink"]: g["risk"] for g in results["taint_graph"]}
    assert by_sink["Log.e"] == "medium", f"panel must show MEDIUM, got {by_sink}"
    assert by_sink["Log.d"] == "low"
    assert "info" not in by_sink.values(), "no flow may default to INFO"


def test_taint_graph_promoted_finding_branch_agrees():
    # Branch 1 (promoted finding) must agree with branch 2 (raw flow) for the same flow.
    loc = _raw_flow("Location.getLatitude", "Location", "Log.e", "Logging", "high")
    finding = ta._flow_to_finding(loc)
    finding["canonical_id"] = "t1"
    results = {"findings": [finding], "taint_flows": []}
    workspaces.build_taint_graph(results)
    assert results["taint_graph"][0]["risk"] == "medium"


def test_calibrate_flow_severity_backfills_missing_risk():
    # An older flow with no "risk" is calibrated, never left to a raw/info default.
    old = {"source_cat": "Location", "sink_cat": "Logging", "sink_sev": "high"}
    assert ta.calibrate_flow_severity(old) == "medium"


# ── #3 the PDF taint table reads flow["risk"] (needs reportlab) ──────────────

def test_pdf_taint_severity_source_is_flow_risk():
    pg = pytest.importorskip("report.pdf_generator")
    loc = _raw_flow("Location.getLatitude", "Location", "Log.e", "Logging", "high")
    tf = {"source": loc["source"], "sink": loc["sink"], "sink_cat": "Logging", "risk": "medium"}
    # The value the PDF puts in the Severity column == the calibrated flow risk,
    # NOT the raw sink_sev ("high").
    assert pg._taint_flow_severity(loc, {}) == loc["risk"] == "medium"
    assert pg._taint_flow_severity({}, tf) == "medium"
    assert pg._taint_flow_severity(loc, {}) != loc["sink_sev"]  # not raw HIGH


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
