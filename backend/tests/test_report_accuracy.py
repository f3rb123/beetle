"""
Report Accuracy & Evidence Rendering tests (Beetle 2.0, Phase 1.97).

Verifies that EVERY report surface renders the application-owned proof selected by
the Evidence Selection Engine instead of legacy library file references:

* The unified evidence_view model (primary/supporting/hidden/detection sources).
* Fallback view for findings that never went through selection.
* The keystone location correction (file_path promoted to the app primary).
* SARIF location + related locations.
* Developer-guide rows.
* Attack-chain evidence aggregation.
* JSON / REST serialization carries the view + corrected location.
* The previously observed regressions:
    - Broken Crypto / Hardcoded Key no longer point to AppCompatDelegateImpl.java
    - Exported UploadService prefers AndroidManifest.xml over the SDK class.

Runnable standalone or under pytest:
    python -m tests.test_report_accuracy       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import evidence_selection as es  # noqa: E402
from analyzers.evidence_selection import build_evidence_view, primary_location  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


APP = "com.insecureshop"
APPDIR = APP.replace(".", "/")
ANDROIDX = "sources/androidx/appcompat/app/AppCompatDelegateImpl.java"


def _results(*findings):
    return {"platform": "android", "app_info": {"package": APP}, "findings": list(findings)}


def _crypto_finding():
    return {
        "title": "Broken Crypto", "severity": "high", "cwe": "CWE-327",
        "category": "Cryptography", "file_path": ANDROIDX, "line": 5, "snippet": "Cipher c",
        "detected_by": ["Beetle Native"],
        "file_evidence": [
            {"path": ANDROIDX, "lines": [5], "snippet": "Cipher.getInstance(x)"},
            {"path": "sources/com/google/android/gms/X.java", "lines": [8], "snippet": "c"},
            {"path": f"sources/{APPDIR}/CryptoUtil.java", "lines": [12],
             "snippet": "Cipher.getInstance(\"AES/ECB\")"},
        ],
    }


def _annotated_crypto():
    res = _results(_crypto_finding())
    es.annotate(res, platform="android")
    return res["findings"][0]


# ── View builder ──────────────────────────────────────────────────────────────
def test_view_primary_is_application():
    v = build_evidence_view(_annotated_crypto())
    _check("CryptoUtil.java" in v["primary"]["file"], "primary must be the application file")
    _check(v["evidence_ownership"] == "Application", "evidence_ownership must be Application")
    _check(v["primary"]["reasons"], "primary must carry selection reasons")


def test_view_hides_library_evidence():
    v = build_evidence_view(_annotated_crypto())
    hidden = v["hidden_library_evidence"]
    _check(hidden["count"] >= 2, "AndroidX + GMS must be hidden library evidence")
    _check(any("AndroidX" in o for o in hidden["owners"]), "AndroidX must be listed as hidden")
    _check(not any("CryptoUtil" in i["file"] for i in hidden["items"]),
           "the app file must never be hidden")


def test_view_exposes_detection_sources_and_provenance():
    f = _annotated_crypto()
    v = build_evidence_view(f)
    _check(v["detection_sources"] == ["Beetle Native"], "detection sources must surface")
    _check("provenance" in v and "evidence_score" in v and "selection_reason" in v,
           "view must expose provenance/score/reason")


def test_view_fallback_when_no_selection():
    f = {"title": "X", "file_path": "sources/com/x/Y.java", "line": 3, "snippet": "z",
         "detected_by": ["Beetle Native"]}
    v = build_evidence_view(f)
    _check(v["fallback"] is True, "must flag fallback when selection absent")
    _check(v["primary"]["file"] == "sources/com/x/Y.java", "fallback must use legacy file_path")


def test_primary_location_helper():
    f = _annotated_crypto()
    path, line, _snip = primary_location(f)
    _check("CryptoUtil.java" in path and line == 12, "primary_location must return the app proof")


# ── Keystone correction / regressions ─────────────────────────────────────────
def test_broken_crypto_no_longer_points_to_androidx():
    f = _annotated_crypto()
    _check("AppCompatDelegateImpl" not in f["file_path"],
           "Broken Crypto must no longer point at AppCompatDelegateImpl.java")
    _check("CryptoUtil.java" in f["file_path"], "Broken Crypto must point at the app crypto file")
    _check(f["detected_location"]["file_path"] == ANDROIDX,
           "the original detection site must be preserved")


def test_hardcoded_key_no_longer_points_to_androidx():
    f = {
        "title": "Hardcoded Key", "severity": "high", "cwe": "CWE-798",
        "category": "Secrets", "file_path": ANDROIDX, "line": 9, "snippet": "key",
        "detected_by": ["Beetle Native"],
        "file_evidence": [
            {"path": ANDROIDX, "lines": [9], "snippet": "k"},
            {"path": f"sources/{APPDIR}/Secrets.java", "lines": [3], "snippet": "KEY=..."},
        ],
    }
    res = _results(f)
    es.annotate(res, platform="android")
    _check("Secrets.java" in res["findings"][0]["file_path"],
           "Hardcoded Key must point at the application file, never AndroidX")


def test_exported_component_prefers_manifest():
    f = {
        "title": "Exported UploadService", "severity": "medium",
        "category": "Exported Components", "evidence_type": "manifest",
        "file_path": "sources/net/gotev/uploadservice/UploadService.java", "line": 1,
        "detected_by": ["Manifest Analysis"],
    }
    res = _results(f)
    es.annotate(res, platform="android")
    fp = res["findings"][0]["file_path"]
    _check(fp.endswith("AndroidManifest.xml"),
           "an exported component must reference the manifest, not the SDK class")


def test_secret_prefers_application_file():
    f = {
        "title": "Hardcoded Secret", "severity": "high", "category": "Secrets",
        "file_path": "sources/okhttp3/internal/Util.java", "line": 2, "snippet": "s",
        "detected_by": ["Secrets"],
        "file_evidence": [
            {"path": "sources/okhttp3/internal/Util.java", "lines": [2], "snippet": "s"},
            {"path": f"sources/{APPDIR}/Api.java", "lines": [7], "snippet": "TOKEN=..."},
        ],
    }
    res = _results(f)
    es.annotate(res, platform="android")
    _check("Api.java" in res["findings"][0]["file_path"], "secret must point at the app file")


# ── SARIF ─────────────────────────────────────────────────────────────────────
def test_sarif_location_uses_selected_primary():
    import sarif_exporter as sx
    f = _annotated_crypto()
    loc = sx._make_location(f)
    uri = loc["physicalLocation"]["artifactLocation"]["uri"]
    _check("CryptoUtil.java" in uri, "SARIF primary location must be the app file")
    _check("AppCompatDelegateImpl" not in uri, "SARIF must not lead with the AndroidX file")


def test_sarif_full_document_builds():
    import sarif_exporter as sx
    res = _results(_crypto_finding())
    es.annotate(res, platform="android")
    doc = sx.results_to_sarif(res)
    _check(isinstance(doc, dict) and doc.get("version"), "SARIF document must build")
    # The crypto result's primary location must be the app file across the doc.
    runs = doc.get("runs") or [{}]
    blob = str(runs)
    _check("CryptoUtil.java" in blob, "SARIF document must contain the app proof")


# ── Developer guide ───────────────────────────────────────────────────────────
def test_developer_guide_row_uses_primary():
    from report import report_summaries as rs
    f = _annotated_crypto()
    row = rs._what_found_entry(f)
    _check("CryptoUtil.java" in row["file"], "developer guide must reference the app file")
    _check(row["line"] == 12, "developer guide must use the primary line")


# ── Attack chains ─────────────────────────────────────────────────────────────
def test_attack_chain_evidence_uses_selected_primary():
    from analyzers.attack_chains import engine as ace
    f = _annotated_crypto()
    files, _classes, _methods, _refs = ace._aggregate_evidence([f])
    _check(any("CryptoUtil.java" in p for p in files),
           "attack-chain evidence must reference the selected app proof")
    _check(not any("AppCompatDelegateImpl" in p for p in files),
           "attack-chain evidence must not present the AndroidX file")


# ── JSON / API serialization ──────────────────────────────────────────────────
def test_json_serialization_carries_view_and_correction():
    from json_utils import make_json_safe
    res = _results(_crypto_finding())
    es.annotate(res, platform="android")
    safe = make_json_safe(res)
    sf = safe["findings"][0]
    _check("CryptoUtil.java" in sf["file_path"], "API/JSON must serve the corrected file_path")
    _check("evidence_view" in sf and sf["evidence_view"]["primary"]["file"].endswith("CryptoUtil.java"),
           "API/JSON must carry the evidence_view with the app primary")


# ── PDF (guarded — reportlab is a Docker-only dependency) ──────────────────────
def test_pdf_evidence_block_leads_with_primary():
    try:
        from report import pdf_generator as pg
    except Exception:  # reportlab not installed in this environment
        print("    (skipped: reportlab not available)")
        return
    f = _annotated_crypto()
    block = pg._format_finding_evidence(f)
    _check("Primary Evidence" in block, "PDF must label the Primary Evidence")
    _check("CryptoUtil.java" in block, "PDF primary must be the app file")
    _check(block.index("CryptoUtil.java") < (block.find("AppCompat") if "AppCompat" in block else len(block)),
           "PDF must lead with the app file, not the AndroidX file")


# ── Standalone runner ─────────────────────────────────────────────────────────
def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {t.__name__}: {e}")
    total = len(tests)
    print(f"\n{total - failures}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
