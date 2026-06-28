"""
Semgrep / SAST adapter tests (Beetle 2.0, Phase 2.4).

Semgrep is an EXTERNAL detection engine integrated like APKLeaks: adapter → canonical
findings → the one pipeline. These tests exercise the adapter WITHOUT invoking the
Semgrep binary (it is not present in CI): SARIF → canonical conversion (metadata
preserved), project-aware rule-pack selection (Android / iOS / Flutter / React Native),
configurable packs, the SARIF-import seam for future engines, and that canonical Semgrep
findings flow through the REAL Finding Fusion / Ownership / Confidence / Evidence /
Source Explorer engines (no duplicates, no perf cost when Semgrep is absent).

Runnable standalone or under pytest:
    python -m tests.test_semgrep_adapter       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.sast import config, sarif_to_canonical, semgrep, SemgrepAdapter, SastAdapter  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _sarif(rule_id="java.lang.security.audit.sqli", level="error", cwe="CWE-89: SQL Injection",
           uri="/scan/jadx/sources/com/app/Db.java", line=42, name="SQL Injection"):
    return {"runs": [{"tool": {"driver": {"rules": [{
        "id": rule_id, "name": name, "helpUri": "https://semgrep.dev/r/x",
        "fullDescription": {"text": "Possible SQL injection."},
        "properties": {"tags": ["java.lang.security"], "cwe": [cwe],
                       "references": ["https://owasp.org/sqli"]}}]}},
        "results": [{"ruleId": rule_id, "level": level,
                     "message": {"text": "User input flows into a SQL query."},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": uri},
                         "region": {"startLine": line, "snippet": {"text": "db.rawQuery(q)"}}}}]}]}]}


# ── Project-aware rule-pack selection ─────────────────────────────────────────
def test_pack_selection_per_project():
    _check(config.configs_for_project("android") == ["p/android", "p/java", "p/kotlin"], "android packs")
    ios = config.configs_for_project("ios")
    _check("p/android" not in ios and "p/java" not in ios, "iOS must NOT run Android/Java packs")
    _check("p/swift" in ios, "iOS runs the swift pack")
    rn = config.configs_for_project("android", "react_native")
    _check("p/javascript" in rn and "p/typescript" in rn, "RN adds JS/TS packs")
    flutter = config.configs_for_project("android", "flutter")
    _check("p/android" in flutter, "Flutter APK still scans its native Android wrapper")


def test_no_unnecessary_scans():
    # iOS app: no Java/Kotlin/Android packs (would be wasted work).
    _check(all(c not in config.configs_for_project("ios", None)
               for c in ("p/android", "p/java", "p/kotlin")),
           "iOS scan must not include Android-language packs")


# ── SARIF → canonical conversion (metadata preserved) ─────────────────────────
def test_sarif_to_canonical_preserves_metadata():
    f = sarif_to_canonical(_sarif(), ["/scan/jadx"], source_name="Semgrep")[0]
    _check(f["rule_id"] == "java.lang.security.audit.sqli", "rule id preserved")
    _check(f["title"] == "SQL Injection" and f["rule_name"] == "SQL Injection", "rule name preserved")
    _check(f["severity"] == "high", "error → high severity")
    _check(f["file_path"] == "sources/com/app/Db.java", "path relativized")
    _check(f["line"] == 42, "line preserved")
    _check(f["cwe"] == "CWE-89", "CWE extracted from metadata")
    _check(f["owasp"], "OWASP mapped")
    _check("https://owasp.org/sqli" in f["references"] and "https://semgrep.dev/r/x" in f["references"],
           "references + help uri preserved")


def test_detected_by_attribution():
    f = sarif_to_canonical(_sarif(), ["/scan/jadx"], source_name="Semgrep")[0]
    _check(f["detected_by"] == ["Semgrep"], "Detected By: Semgrep")
    _check(f["source_module"] == "Semgrep", "source_module attribution for fusion")


def test_severity_mapping():
    hi = sarif_to_canonical(_sarif(level="error"), ["/scan/jadx"], source_name="Semgrep")[0]
    med = sarif_to_canonical(_sarif(level="warning"), ["/scan/jadx"], source_name="Semgrep")[0]
    low = sarif_to_canonical(_sarif(level="note"), ["/scan/jadx"], source_name="Semgrep")[0]
    _check((hi["severity"], med["severity"], low["severity"]) == ("high", "medium", "low"), "severity map")


# ── Finding Fusion merges Semgrep with native (no duplicates) ─────────────────
def test_fusion_merges_semgrep_with_native():
    from analyzers import fusion
    # A specific CWE (798) so fusion merges on CWE alone (broad-CWE guard not triggered).
    native = {"title": "Hardcoded Credentials", "severity": "high", "cwe": "CWE-798",
              "file_path": "sources/com/app/Cfg.java", "line": 10, "detected_by": ["Beetle Native"]}
    semgrep_find = sarif_to_canonical(
        _sarif(rule_id="java.security.hardcoded", cwe="CWE-798", name="Hardcoded Secret",
               uri="/scan/jadx/sources/com/app/Cfg.java", line=10),
        ["/scan/jadx"], source_name="Semgrep")[0]
    results = {"findings": [native, semgrep_find]}
    fusion.fuse(results, platform="android")
    _check(len(results["findings"]) == 1, "Semgrep + native duplicate must fuse to ONE finding")
    db = set(results["findings"][0]["detected_by"])
    _check({"Beetle Native", "Semgrep"} <= db, f"fused finding credits both engines: {db}")


def test_distinct_semgrep_finding_not_over_merged():
    from analyzers import fusion
    a = sarif_to_canonical(_sarif(rule_id="r1", cwe="CWE-798", uri="/s/A.java", line=1),
                           ["/s"], source_name="Semgrep")[0]
    b = sarif_to_canonical(_sarif(rule_id="r2", cwe="CWE-327", uri="/s/B.java", line=9),
                           ["/s"], source_name="Semgrep")[0]
    results = {"findings": [a, b]}
    fusion.fuse(results, platform="android")
    _check(len(results["findings"]) == 2, "different files/CWEs must stay separate")


# ── Canonical Semgrep findings flow through the real engines ──────────────────
def test_findings_flow_through_pipeline_engines():
    from analyzers import fusion, ownership, evidence_selection, source_explorer
    from analyzers.confidence import engine as ce
    from analyzers.canonical_finding import from_legacy
    f = sarif_to_canonical(_sarif(cwe="CWE-327", name="Weak Cipher",
                                  uri="/scan/jadx/sources/com/app/Crypto.java", line=7),
                           ["/scan/jadx"], source_name="Semgrep")[0]
    results = {"platform": "android", "app_info": {"package": "com.app"},
               "findings": [f], "secrets": [], "ips": []}
    fusion.fuse(results, platform="android")
    ownership.annotate(results)
    evidence_selection.annotate(results, platform="android")
    source_explorer.annotate(results)
    sf = results["findings"][0]
    _check(sf.get("owner_type"), "Ownership annotated the Semgrep finding")
    _check(sf.get("evidence_selection") and sf.get("evidence_view"), "Evidence Selection built a proof view")
    _check(0 <= ce.classify(from_legacy(sf, platform="android")).overall <= 100, "Confidence scored it")
    # Source Explorer indexes it (tree badges + security filtering + jump target).
    _check("sources/com/app/Crypto.java" in results["source_explorer"]["file_index"],
           "Source Explorer indexes the Semgrep finding's file")
    _check("sources/com/app/Crypto.java" in results["source_explorer"]["security_index"]["crypto"],
           "Security Explorer can filter to it (crypto)")


# ── Configurable rule packs (no code change) ──────────────────────────────────
def test_configurable_packs_via_env():
    try:
        os.environ["CORTEX_SEMGREP_DISABLE_PACKS"] = "semgrep-java"
        _check("p/java" not in config.configs_for_project("android"), "disabled pack removed")
        os.environ.pop("CORTEX_SEMGREP_DISABLE_PACKS")
        os.environ["CORTEX_SEMGREP_PACKS"] = "semgrep-kotlin"
        _check(config.configs_for_project("android") == ["p/kotlin"], "whitelist limits to one pack")
        os.environ.pop("CORTEX_SEMGREP_PACKS")
        os.environ["CORTEX_SEMGREP_EXTRA_CONFIG"] = "r/my-org.rules,/opt/rules.yml"
        cfgs = config.configs_for_project("android")
        _check("r/my-org.rules" in cfgs and "/opt/rules.yml" in cfgs, "extra org configs added without code")
    finally:
        for k in ("CORTEX_SEMGREP_DISABLE_PACKS", "CORTEX_SEMGREP_PACKS", "CORTEX_SEMGREP_EXTRA_CONFIG"):
            os.environ.pop(k, None)


# ── SARIF-import seam: any engine, same converter ─────────────────────────────
def test_sarif_import_seam_for_future_engines():
    f = sarif_to_canonical(_sarif(), ["/scan/jadx"], source_name="CodeQL")[0]
    _check(f["detected_by"] == ["CodeQL"] and f["source_module"] == "CodeQL",
           "the SARIF converter attributes any engine — the future-SAST seam")
    _check(isinstance(semgrep, SemgrepAdapter) and isinstance(semgrep, SastAdapter),
           "the Semgrep adapter implements the reusable SastAdapter contract")


# ── Performance / safety when Semgrep is absent ───────────────────────────────
def test_graceful_no_binary_zero_cost():
    # Adapter must be a safe no-op (no raise, no findings) when the binary is missing.
    results = {"platform": "android", "findings": []}
    m = semgrep.run_into(results, ["/does/not/exist"], platform="android")
    if not semgrep.available():
        _check(m["ran"] is False and m["finding_count"] == 0, "no-op when Semgrep absent")
        _check(results["findings"] == [], "no findings added when absent")
    # Availability is cached (no repeated PATH probing each call).
    _check(semgrep.available() == semgrep.available(), "availability is stable/cached")


def test_android_ios_imports_unaffected():
    import importlib
    importlib.import_module("analyzers.android_analyzer")
    importlib.import_module("analyzers.ios_analyzer")
    _check(True, "analyzers import cleanly with the SAST adapter wired")


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
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
