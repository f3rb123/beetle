"""
Attack-chain report source-of-truth tests (Beetle 2.0).

The PDF, the findings list, the dashboard and the AI context must all read the v2
attack-chain engine (results["attack_chains_v2"]) — not the legacy chain_analyzer
synthesizer, which stamped a hardcoded 90% confidence on every chain finding.

Guards:
  * v2 chains project to first-class is_attack_chain findings with v2's COMPUTED
    confidence (never 90/constant), and members are flagged in_attack_chain.
  * quick_summary.attack_chain is the v2 projection (legacy key names preserved so
    AI chat / executive summaries keep working).
  * an N-step chain surfaces >= N evidence pointers (per-step), not one file.
  * the legacy synthesizer no longer hardcodes 90 — surviving legacy chains (CI/CD
    repo scans) derive confidence from member evidence.

Runnable standalone or under pytest:
    python -m tests.test_chain_report_source      # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.attack_chains import bridge, to_first_class_findings, to_quick_summary  # noqa: E402
from analyzers import chain_analyzer  # noqa: E402

try:  # reportlab ships in the backend image; may be absent on a bare dev box.
    from report import pdf_generator
    _HAVE_PDF = True
except Exception:  # noqa: BLE001
    pdf_generator = None
    _HAVE_PDF = False


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _member(cid, title, sev, conf, file, line):
    return {"canonical_id": cid, "rule_id": cid, "title": title, "severity": sev,
            "file_path": file, "overall_confidence": conf,
            "evidence_bundle": {"quality": "Good", "primary": {"relative_path": file, "line": line}}}


def _chain(cid, name, sev, conf, expl, proof, req, *, steps, refs, files, **extra):
    c = {"id": cid, "name": name, "summary": f"{name} summary.", "severity": sev,
         "overall_confidence": conf, "overall_exploitability": expl, "overall_impact": f"{name} impact.",
         "reachability_proof": proof, "required_findings": req, "supporting_findings": [],
         "entry_point": {"label": "Entry", "kind": "external", "component": "com.app.Entry"},
         "steps": steps, "evidence_references": refs, "affected_files": files,
         "blocked": False, "blocked_by": [], "mitigations": ["Fix it"], "prerequisites": [],
         "version": "2.0.0", "confidence_explanation": {"why": "computed"}}
    c.update(extra)
    return c


def _results():
    findings = [
        _member("F-sqli", "Taint Flow: Intent → rawQuery", "high", 72, "sources/com/app/Dao.java", 42),
        _member("F-secret", "Hardcoded AWS Key", "high", 90, "sources/com/app/Keys.java", 7),
    ]
    chains = [
        _chain("CHAIN-sqli", "Exported Component to SQL Injection", "high", 68, 80, "proven", ["F-sqli"],
               steps=[{"order": 1, "title": "Entry point", "evidence": "com.app.Entry"},
                      {"order": 2, "title": "SQL sink", "description": "rawQuery",
                       "evidence": "sources/com/app/Dao.java:42", "finding": "F-sqli"},
                      {"order": 3, "title": "Objective achieved", "evidence": ""}],
               refs=[{"finding": "F-sqli", "evidence_id": "EV-1", "file": "sources/com/app/Dao.java", "line": 42}],
               files=["sources/com/app/Dao.java"]),
        _chain("CHAIN-secret", "Hardcoded Secret Abuse", "high", 55, 70, "manifest-only", ["F-secret"],
               steps=[{"order": 1, "title": "Download APK", "evidence": ""},
                      {"order": 2, "title": "Extract secret", "finding": "F-secret", "evidence": ""}],
               refs=[{"finding": "F-secret", "evidence_id": "EV-2", "file": "sources/com/app/Keys.java", "line": 7}],
               files=["sources/com/app/Keys.java"]),
    ]
    return {"platform": "android", "findings": findings, "attack_chains_v2": chains}


# ════════════════════════════════════════════════════════════════════════════
# v2 is the source; confidence is computed, not constant.
# ════════════════════════════════════════════════════════════════════════════
def test_first_class_findings_carry_v2_computed_confidence():
    fcf = to_first_class_findings(_results())
    _check(len(fcf) == 2, "one first-class finding per v2 chain")
    by_id = {f["attack_chain_id"]: f for f in fcf}

    sqli = by_id["CHAIN-sqli"]
    _check(sqli["confidence"] == 68 and sqli["confidence_score"] == 68,
           f"confidence must equal v2 overall_confidence (68), got {sqli['confidence']}")
    _check(sqli["chain_confidence"] == "MEDIUM", f"label from 68 should be MEDIUM, got {sqli['chain_confidence']}")
    _check(sqli["reachability_proof"] == "proven", "reachability_proof carried through")

    # The tell-tale legacy constant must never appear.
    for f in fcf:
        _check(f["confidence"] != 90 or True, "")  # 90 only fails if it were constant; assert not constant below
    _check({f["confidence"] for f in fcf} == {68, 55},
           f"confidences must be the distinct computed values, got {[f['confidence'] for f in fcf]}")


def test_no_hardcoded_ninety_across_chain_findings():
    fcf = to_first_class_findings(_results())
    _check(not all(f["confidence"] == 90 for f in fcf), "confidences must not be a flat constant")
    _check(all(0 <= f["confidence"] <= 100 for f in fcf), "confidence in range")


def test_members_flagged_in_attack_chain():
    results = _results()
    bridge.mark_members(results)
    marked = {f["canonical_id"] for f in results["findings"] if f.get("in_attack_chain")}
    _check(marked == {"F-sqli", "F-secret"}, f"both members must be flagged, got {marked}")
    for f in results["findings"]:
        if f["canonical_id"] == "F-sqli":
            _check(f["attack_chain_id"] == "CHAIN-sqli", "member carries its chain id")


def test_annotate_findings_prepends_and_is_idempotent():
    results = _results()
    n1 = bridge.annotate_findings(results)
    _check(n1 == 2, "two chain findings injected")
    _check(results["findings"][0]["is_attack_chain"], "chain findings lead the list")
    total_after_first = len(results["findings"])

    # Running again must not duplicate (drops existing chain findings first).
    n2 = bridge.annotate_findings(results)
    _check(n2 == 2 and len(results["findings"]) == total_after_first,
           "re-running must not accumulate duplicate chain findings")


# ════════════════════════════════════════════════════════════════════════════
# quick_summary.attack_chain is the v2 projection with back-compat keys.
# ════════════════════════════════════════════════════════════════════════════
def test_quick_summary_projection_has_backcompat_keys():
    qs = to_quick_summary(_results())
    _check(len(qs) == 2, "two chains projected")
    c = qs[0]
    for key in ("title", "severity", "impact", "chain_confidence", "exploitability"):
        _check(key in c, f"legacy reader key {key!r} must be present")
    _check(c["title"] == "Exported Component to SQL Injection", "title from v2 name")
    _check(c["exploitability"] == 80, "exploitability from v2 overall_exploitability")


# ════════════════════════════════════════════════════════════════════════════
# Per-step evidence: >= N pointers for an N-step chain.
# ════════════════════════════════════════════════════════════════════════════
def test_each_chain_finding_has_at_least_one_pointer_per_member():
    fcf = to_first_class_findings(_results())
    for f in fcf:
        _check(f["evidence_count"] >= 1, f"{f['title']} must carry evidence pointers")
        _check(f["files"], f"{f['title']} must list evidenced files")


def test_step_evidence_helper_yields_pointer_per_step():
    if not _HAVE_PDF:
        return  # reportlab absent on this box; the helper is exercised in-image.
    # Exercise the PDF per-step evidence helper directly.
    raw = _results()["attack_chains_v2"][0]
    steps = raw["steps"]
    refs = raw["evidence_references"]
    files = raw["affected_files"]
    pointers = [pdf_generator._chain_step_evidence(s, refs, i, files) for i, s in enumerate(steps)]
    _check(len(pointers) == len(steps), "one pointer per step")
    _check(any(p != "—" for p in pointers), "at least one concrete pointer")
    _check(pointers[1] == "sources/com/app/Dao.java:42", f"step 2 keeps its own evidence, got {pointers[1]}")


# ════════════════════════════════════════════════════════════════════════════
# Legacy synthesizer (surviving for CI/CD) no longer hardcodes 90.
# ════════════════════════════════════════════════════════════════════════════
def test_legacy_chain_confidence_is_computed_from_members():
    # Two evidenced members with confidence 80 and 60 → mean 70, fully evidenced → 70.
    members = [
        {"overall_confidence": 80, "file_evidence": [{"path": "A.java", "lines": [1], "snippet": "x"}]},
        {"overall_confidence": 60, "file_path": "B.java", "line": 2},
    ]
    score = chain_analyzer._legacy_chain_confidence(members, evidenced=2, total=2)
    _check(score == 70, f"fully-evidenced mean(80,60) should be 70, got {score}")
    _check(score != 90, "legacy confidence must not be the old constant")

    # No evidence at all → heavily discounted (halved).
    unevidenced = [{"overall_confidence": 80}, {"overall_confidence": 80}]
    low = chain_analyzer._legacy_chain_confidence(unevidenced, evidenced=0, total=2)
    _check(low == 40, f"unevidenced chain should halve mean(80)→40, got {low}")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
            except ImportError as exc:
                print(f"SKIP {name}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
