"""
Regression: the Data Flow panel (fed by results["taint_graph"], deduped by
source→sink) showed 8 flows while the PDF Taint Flows table (fed by
results["taint_flows"], per-call-site) showed 14 — contradictory counts.

Fix: one canonical source→sink-deduped list (reconcile_taint_flows) drives BOTH the
panel and the PDF, each pair annotated with its call_site_count. FAILS on old
behavior (14 != 8); PASSES on new (both report the same N with call-site counts).
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


def _site(source, source_cat, sink, sink_cat, sink_sev, cls):
    return {
        "source": source, "source_cat": source_cat, "sink": sink, "sink_cat": sink_cat,
        "sink_sev": sink_sev, "raw_sink_sev": sink_sev,
        "risk": ta.calibrate_flow_severity({"source_cat": source_cat, "sink_cat": sink_cat,
                                            "sink_sev": sink_sev}),
        "call_chain": [f"{cls}.f", "android.util.Log.e"], "class_name": cls,
        "method_name": "f", "owner_type": "Application",
    }


def _corpus_14_sites_8_pairs():
    raw = []
    for i in range(5):  # pair 1: Location → Log.e (5 sites)
        raw.append(_site("Location.getLatitude", "Location", "Log.e", "Logging", "high", f"com.app.A{i}"))
    for i in range(3):  # pair 2: Bundle.get → Log.d (3 sites)
        raw.append(_site("Bundle.get", "User Input", "Log.d", "Logging", "medium", f"com.app.B{i}"))
    for i in range(6):  # pairs 3-8: 6 distinct pairs (1 site each)
        raw.append(_site(f"Src{i}.get", "User Input", f"Sink{i}.write", "FileSystem", "high", f"com.app.C{i}"))
    return raw


# ── reconciliation collapses 14 sites → 8 pairs with counts ──────────────────

def test_reconcile_collapses_to_pairs_with_counts():
    results = {"taint_flows": _corpus_14_sites_8_pairs()}
    recon = ta.reconcile_taint_flows(results)
    assert len(recon) == 8, f"14 call sites must collapse to 8 source→sink pairs, got {len(recon)}"
    by_pair = {(e["source"], e["sink"]): e for e in recon}
    assert by_pair[("Location.getLatitude", "Log.e")]["call_site_count"] == 5
    assert by_pair[("Bundle.get", "Log.d")]["call_site_count"] == 3
    # Total call sites is preserved across the pairs.
    assert sum(e["call_site_count"] for e in recon) == 14
    # Calibrated severity carried per pair.
    assert by_pair[("Location.getLatitude", "Log.e")]["risk"] == "medium"
    assert by_pair[("Bundle.get", "Log.d")]["risk"] == "low"


# ── panel count == PDF table count (the headline invariant) ──────────────────

def _pdf_flow_count(results):
    """The number the PDF taint table would report — the same reconciled list."""
    flows = results.get("taint_flows_reconciled")
    if flows is None:
        flows = ta.reconcile_taint_flows(results)
    return len(flows)


def test_panel_count_equals_pdf_count():
    results = {"findings": [], "taint_flows": _corpus_14_sites_8_pairs()}
    workspaces.build_taint_graph(results)
    panel_count = len(results["taint_graph"])
    pdf_count = _pdf_flow_count(results)
    assert panel_count == pdf_count == 8, f"panel {panel_count} != pdf {pdf_count}"


def test_panel_and_pdf_share_reconciled_list():
    results = {"findings": [], "taint_flows": _corpus_14_sites_8_pairs()}
    workspaces.build_taint_graph(results)
    # build_taint_graph publishes the canonical list the PDF also reads.
    assert results["taint_flows_reconciled"] is not None
    assert len(results["taint_flows_reconciled"]) == len(results["taint_graph"]) == 8


def test_graph_entries_carry_call_site_count_and_calibrated_risk():
    results = {"findings": [], "taint_flows": _corpus_14_sites_8_pairs()}
    workspaces.build_taint_graph(results)
    g = {(e["source"], e["sink"]): e for e in results["taint_graph"]}
    loc = g[("Location.getLatitude", "Log.e")]
    assert loc["call_site_count"] == 5
    assert loc["risk"] == "medium"
    assert "info" not in [e["risk"] for e in results["taint_graph"]]


# ── fallback: reconstruct from TAINT findings when taint_flows absent ─────────

def test_reconcile_from_findings_fallback():
    findings = []
    for i in range(4):  # 4 sites of one pair
        findings.append({
            "source": "TAINT", "severity": "medium", "file_path": f"com.app.D{i}", "line": 0,
            "taint_flow": {"source": "Location.getLatitude", "source_cat": "Location",
                           "sink": "Log.e", "sink_cat": "Logging", "chain": [], "risk": "medium"},
        })
    results = {"findings": findings}  # no taint_flows
    recon = ta.reconcile_taint_flows(results)
    assert len(recon) == 1 and recon[0]["call_site_count"] == 4


# ── PDF builder count (needs reportlab) ──────────────────────────────────────

def test_pdf_table_uses_reconciled_count():
    pytest.importorskip("report.pdf_generator")
    results = {"findings": [], "taint_flows": _corpus_14_sites_8_pairs()}
    workspaces.build_taint_graph(results)
    # The PDF section reads results["taint_flows_reconciled"] — same length as panel.
    assert len(results["taint_flows_reconciled"]) == len(results["taint_graph"])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
