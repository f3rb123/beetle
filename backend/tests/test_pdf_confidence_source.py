"""
Regression: the PDF displayed the LEGACY confidence_score (so findings clustered at
detector defaults like regex_sast == 72) instead of the Confidence Engine's computed
overall_confidence. The report must now render overall_confidence, with confidence_score
as a fallback for un-annotated/legacy scans — the same source the chain surface uses.

These fail on the old behavior (72 shown) and pass on the new (overall_confidence shown).
"""
from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

pg = pytest.importorskip("report.pdf_generator")  # reportlab-gated


# ── the confidence line (_format_signal_quality) ─────────────────────────────

def test_signal_line_renders_overall_confidence_not_legacy():
    f = {"ownership_label": "APPLICATION", "overall_confidence": 91,
         "confidence_score": 72, "confidence_band": "HIGH"}
    line = pg._format_signal_quality(f)
    assert "Confidence: 91%" in line, line
    assert "72%" not in line, "must not render the legacy confidence_score"


def test_signal_line_falls_back_to_legacy_confidence_score():
    f = {"ownership_label": "APPLICATION", "confidence_score": 72, "confidence_band": "MEDIUM"}
    line = pg._format_signal_quality(f)
    assert "Confidence: 72%" in line, line


def test_signal_line_pre_phase3_finding_is_blank():
    assert pg._format_signal_quality({"title": "legacy"}) == ""


def test_signal_line_overall_confidence_zero_is_rendered():
    # 0 is a valid computed confidence — must not be treated as "missing".
    f = {"ownership_label": "APPLICATION", "overall_confidence": 0, "confidence_band": "LOW"}
    assert "Confidence: 0%" in pg._format_signal_quality(f)


# ── the visibility gate (_visible_findings) uses the same source ─────────────

def _results(findings):
    return {"findings": findings, "_report_findings_scope": "application"}


def test_visibility_gate_uses_overall_confidence():
    # overall_confidence 85 (>=70) is shown even though the legacy score is 60 (<70).
    hi = {"title": "a", "ownership_label": "APPLICATION", "is_app_code": True,
          "overall_confidence": 85, "confidence_score": 60}
    vis = pg._visible_findings(_results([hi]))
    assert hi in vis, "a high overall_confidence app finding must be visible"


def test_visibility_gate_hides_low_overall_confidence():
    lo = {"title": "b", "ownership_label": "APPLICATION", "is_app_code": True,
          "overall_confidence": 40, "confidence_score": 90}
    vis = pg._visible_findings(_results([lo]))
    assert lo not in vis, "a low overall_confidence finding is hidden (not rescued by legacy 90)"


def test_visibility_gate_legacy_fallback():
    # No overall_confidence → fall back to confidence_score for the gate.
    legacy = {"title": "c", "ownership_label": "APPLICATION", "is_app_code": True,
              "confidence_score": 85}
    assert legacy in pg._visible_findings(_results([legacy]))


def test_pre_phase3_finding_always_shown():
    legacy = {"title": "old"}  # no ownership_label, no confidence at all
    assert legacy in pg._visible_findings(_results([legacy]))


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
