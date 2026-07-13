"""
Five v2.6 report-quality fixes:
  1. Score-table capped rows carry an honest capped flag + raw_total.
  2. Non-Latin/symbol glyphs are transliterated so the PDF shows no black box.
  3. Root-detection evidence anchors to the code site, not a localized UI string.
  4. Certificate Key Type reads "RSA", not "RSAPublicKey".
  5. Every taint-flow card carries a snippet OR an explicit "obfuscated, no source"
     marker.
"""
from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


# ── #1 score-table cap honesty ───────────────────────────────────────────────

def test_discounted_row_carries_flag_and_raw_total():
    # RUN 15.1 replaced the flat 3x cliff with a harmonic diminishing-marginal curve. 10 mediums
    # no longer flatten to exactly 9: each still deducts weight/i (3 + 1.5 + 1 + 0.75 + …).
    from analyzers import scoring
    r = {"findings": [{"severity": "medium"}] * 10, "secrets": [], "platform": "android"}
    s = scoring.calculate_score(r)
    row = s["deductions"]["medium"]
    assert row["count"] == 10 and row["per_item"] == 3
    assert row["raw_total"] == 30                       # count x per_item, for reference
    expected = scoring.graduated_deduction(3, 10)
    assert row["total"] == round(expected, 2)
    assert row["capped"] is True                        # discounted below raw
    assert row["total"] < 30                            # discounted below the flat product
    # Every one of the 10 still contributes (unlike the old cliff, where 4..10 gave nothing):
    assert row["total"] > scoring.graduated_deduction(3, 3)   # 10 mediums > 3 mediums


def test_row_at_full_weight_is_not_flagged_as_discounted():
    # A single finding pays full weight, so nothing is discounted.
    from analyzers import scoring
    r = {"findings": [{"severity": "high"}], "secrets": [], "platform": "android"}
    s = scoring.calculate_score(r)
    row = s["deductions"]["high"]
    assert row["capped"] is False
    assert row["total"] == row["raw_total"] == 8

    # Two highs: the 2nd is discounted (8 + 4 = 12, not 16).
    r2 = {"findings": [{"severity": "high"}] * 2, "secrets": [], "platform": "android"}
    row2 = scoring.calculate_score(r2)["deductions"]["high"]
    assert row2["total"] == 12 and row2["raw_total"] == 16 and row2["capped"] is True


def test_pdf_labels_capped_rows():
    pg = pytest.importorskip("report.pdf_generator")
    # The renderer must label a discounted row so count x per_item never invites wrong
    # arithmetic. RUN 15.1 replaced the flat cap with a diminishing-returns curve.
    src = open(pg.__file__, encoding="utf-8").read()
    assert "diminishing returns" in src


# ── #2 glyph coverage (no black boxes) ───────────────────────────────────────

def test_glyph_sanitizer_transliterates():
    pg = pytest.importorskip("report.pdf_generator")
    assert pg._pdf_glyph_safe("na uređaju") == "na uredjaju".replace("dj", "d") or \
        pg._pdf_glyph_safe("na uređaju") == "na uredaju"           # đ -> d
    assert "đ" not in pg._pdf_glyph_safe("uređaju")           # no d-with-stroke
    assert pg._pdf_glyph_safe("Yes ⚠") == "Yes (!)"          # warning sign -> (!)
    assert pg._pdf_glyph_safe("čšž") == "csz"      # č š ž -> c s z


def test_glyph_sanitizer_keeps_winansi():
    pg = pytest.importorskip("report.pdf_generator")
    assert pg._pdf_glyph_safe("café über") == "café über"  # é, ü kept
    assert pg._pdf_glyph_safe("a — b") == "a — b"       # em-dash kept (WinAnsi)


# ── #3 root-detection evidence anchor ────────────────────────────────────────

def test_root_finding_anchors_to_code_not_localized_string():
    from analyzers.evidence_selection import select
    from analyzers.ownership.types import OwnershipContext
    f = {
        "title": "Root Detection", "category": "Root Detection", "rule_id": "str_root_detection",
        "file_path": "res/values-b+sr+Latn/strings.xml", "line": 5, "snippet": "na uredjaju",
        "file_evidence": [
            {"path": "res/values-b+sr+Latn/strings.xml", "lines": [5], "snippet": "na uredjaju su"},
            {"path": "sources/com/app/RootCheck.java", "lines": [12],
             "snippet": 'boolean isRooted(){ return new File("/system/bin/su").exists(); }'},
        ],
    }
    sel = select(f, OwnershipContext(platform="android"))
    primary = sel["primary"].get("file_path") or sel["primary"].get("relative_path")
    assert primary == "sources/com/app/RootCheck.java", primary


def test_base_resource_not_penalized_over_localized():
    from analyzers.evidence_selection import scoring as es
    # Base res/values/ has no locale qualifier → no localized penalty.
    from analyzers.evidence_selection.scoring import _localized_resource_signal, Candidate, SelectionContext
    base = Candidate(file_path="res/values/strings.xml")
    loc = Candidate(file_path="res/values-b+sr+Latn/strings.xml")
    assert _localized_resource_signal(base, SelectionContext()) == []
    assert _localized_resource_signal(loc, SelectionContext())[0][0] < 0


# ── #4 cert key type ─────────────────────────────────────────────────────────

def test_key_type_strips_publickey_suffix():
    from analyzers.cert_analyzer import _format_key_type
    assert _format_key_type("_RSAPublicKey") == "RSA"
    assert _format_key_type("RSAPublicKey") == "RSA"
    assert _format_key_type("_DSAPublicKey") == "DSA"
    assert _format_key_type("_EllipticCurvePublicKey") == "EC"
    assert "PublicKey" not in _format_key_type("_RSAPublicKey")


# ── #5 taint-flow card: snippet OR obfuscation marker ────────────────────────

def _taint_results():
    return {
        "platform": "android", "app_info": {"package": "com.ibsplc.app"},
        "taint_flows": [
            {"source": "Location.getLatitude", "source_cat": "Location", "sink": "Log.e",
             "sink_cat": "Logging", "sink_sev": "high", "raw_sink_sev": "high", "risk": "medium",
             "call_chain": ["Z.S.A0.log", "android.util.Log.e"], "class_name": "Z.S.A0",
             "method_name": "log", "owner_type": "Unknown"},
            {"source": "Bundle.get", "source_cat": "User Input", "sink": "Log.d",
             "sink_cat": "Logging", "sink_sev": "medium", "raw_sink_sev": "medium", "risk": "low",
             "call_chain": ["com.ibsplc.app.Handler.f", "android.util.Log.d"],
             "class_name": "com.ibsplc.app.Handler", "method_name": "f", "owner_type": "Application"},
        ],
        "findings": [
            {"title": "Taint Flow: Bundle.get -> Log.d", "source": "TAINT", "severity": "low",
             "file_path": "com.ibsplc.app.Handler", "line": 0, "snippet": "Bundle.get -> Log.d",
             "taint_flow": {"source": "Bundle.get", "sink": "Log.d", "source_cat": "User Input",
                            "sink_cat": "Logging", "chain": ["a", "b"]}},
        ],
    }


def test_every_taint_card_has_snippet_or_obfuscation_marker():
    from analyzers import workspaces as w
    r = _taint_results()
    w.build_taint_graph(r)
    for g in r["taint_graph"]:
        assert g.get("snippet") or g.get("obfuscation_note"), g
    g = {x["source"]: x for x in r["taint_graph"]}
    # Obfuscated source class → explicit honest marker, not verifiable.
    obf = g["Location.getLatitude"]
    assert obf["verifiable"] is False
    assert "obfuscated" in obf["obfuscation_note"].lower()
    assert "Z.S.A0" in obf["obfuscation_note"]
    assert "mapping.txt" in obf["obfuscation_note"]
    # Resolvable app flow → carries a snippet, verifiable.
    app = g["Bundle.get"]
    assert app["verifiable"] is True
    assert app["snippet"]


def test_obfuscation_source_detector():
    from analyzers.workspaces import _is_unresolvable_taint_source as u
    assert u("Z.S.A0") and u("M0.a.h0") and u("")
    assert not u("com.ibsplc.mobile.LocationLogger")
    assert not u("sources/com/app/X.java")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
