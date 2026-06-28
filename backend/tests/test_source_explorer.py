"""
Source / Security Explorer overlay tests (Beetle 2.0, Phase 2.3).

The explorer backend is a pure projection of EXISTING metadata. These tests verify
the overlay (`results["source_explorer"]`) is built correctly for Android / iOS /
Flutter / React Native findings, that it reuses secrets + IPs, aggregates severity,
maps findings to security categories (for Security-Explorer filtering and the
source-jump), and exposes the framework project structure — without parsing anything.

Runnable standalone or under pytest:
    python -m tests.test_source_explorer       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import source_explorer as se  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _ex(results):
    se.annotate(results)
    return results["source_explorer"]


# ── Android tree ──────────────────────────────────────────────────────────────
def test_android_overlay():
    ex = _ex({"platform": "android", "findings": [
        {"title": "AES/ECB", "severity": "high", "category": "Cryptography", "cwe": "CWE-327",
         "file_path": "sources/com/app/Crypto.java"},
        {"title": "Exported Activity", "severity": "medium", "category": "Components", "cwe": "CWE-926",
         "file_path": "AndroidManifest.xml"},
    ]})
    fi = ex["file_index"]
    _check("sources/com/app/Crypto.java" in fi, "android source file indexed")
    _check(fi["sources/com/app/Crypto.java"]["max_severity"] == "high", "severity recorded")
    _check("crypto" in fi["sources/com/app/Crypto.java"]["categories"], "crypto category mapped")
    _check("components" in fi["AndroidManifest.xml"]["categories"], "components category mapped")
    _check("sources/com/app/Crypto.java" in ex["security_index"]["crypto"], "security_index crypto")


# ── iOS tree ──────────────────────────────────────────────────────────────────
def test_ios_overlay():
    ex = _ex({"platform": "ios", "findings": [
        {"title": "ATS disabled", "severity": "high", "category": "Network Security", "cwe": "CWE-319",
         "file_path": "Payload/App.app/Info.plist"},
    ]})
    _check("Payload/App.app/Info.plist" in ex["security_index"]["network"], "iOS network file mapped")


# ── Flutter tree ──────────────────────────────────────────────────────────────
def test_flutter_overlay_and_structure():
    ex = _ex({"platform": "android", "framework": {"type": "flutter"},
              "flutter": {"project_structure": {"lib": True, "assets": True, "android": True},
                          "key_files": {"pubspec.yaml": True}},
              "findings": [
                  {"title": "Unencrypted Hive box", "severity": "medium", "category": "Insecure Storage",
                   "cwe": "CWE-312", "file_path": "lib/main.dart", "detected_by": ["Flutter Intelligence"]},
              ]})
    _check("lib/main.dart" in ex["security_index"]["storage"], "Flutter storage finding mapped")
    _check(ex["project_structure"]["framework"] == "flutter", "Flutter project structure reused")
    _check(ex["project_structure"]["dirs"]["lib"] is True, "project dir exposed")


# ── React Native tree ─────────────────────────────────────────────────────────
def test_react_native_overlay_and_ipc():
    ex = _ex({"platform": "android", "framework": {"type": "react_native"},
              "react_native": {"project_structure": {"src": True, "android": True}},
              "findings": [
                  {"title": "React Native bridge call (NativeModules.X)", "severity": "info",
                   "category": "Native Bridge", "cwe": "CWE-749", "file_path": "index.android.bundle",
                   "detected_by": ["React Native Intelligence"]},
              ]})
    _check("index.android.bundle" in ex["security_index"]["ipc"], "RN bridge mapped to IPC")
    _check(ex["project_structure"]["framework"] == "react_native", "RN project structure reused")


# ── Secrets + IPs reuse ───────────────────────────────────────────────────────
def test_secrets_and_ips_reused():
    ex = _ex({"platform": "android", "findings": [],
              "secrets": [{"name": "AWS", "file_path": "sources/com/app/Cfg.java", "severity": "high",
                           "masked_value": "AKIA****"}],
              "ips": [{"ip": "34.1.2.3", "file_path": "sources/com/app/Net.java", "severity": "low",
                       "suppressed": False},
                      {"ip": "10.0.0.1", "file_path": "sources/com/app/Local.java", "suppressed": True}]})
    _check("sources/com/app/Cfg.java" in ex["security_index"]["secrets"], "secret file → secrets bucket")
    _check(ex["file_index"]["sources/com/app/Cfg.java"]["secret"] is True, "secret flag set")
    _check("sources/com/app/Net.java" in ex["security_index"]["network"], "IP file → network bucket")
    _check(ex["file_index"]["sources/com/app/Net.java"]["network"] is True, "network flag set")
    _check("sources/com/app/Local.java" not in ex["file_index"], "suppressed IP not indexed")


# ── Badge aggregation (max severity per file across findings) ──────────────────
def test_badge_severity_aggregation():
    ex = _ex({"platform": "android", "findings": [
        {"title": "A", "severity": "low", "category": "Crypto", "cwe": "CWE-327", "file_path": "x/F.java"},
        {"title": "B", "severity": "critical", "category": "Crypto", "cwe": "CWE-327", "file_path": "x/F.java"},
        {"title": "C", "severity": "medium", "category": "Crypto", "cwe": "CWE-327", "file_path": "x/F.java"},
    ]})
    rec = ex["file_index"]["x/F.java"]
    _check(rec["max_severity"] == "critical", "file badge takes the worst severity")
    _check(rec["findings"] == 3, "finding count aggregated")
    _check(rec["counts"].get("critical") == 1 and rec["counts"].get("low") == 1, "per-severity counts")


# ── Finding → file mapping (source jump target) ───────────────────────────────
def test_finding_paths_include_evidence_view():
    ex = _ex({"platform": "android", "findings": [
        {"title": "X", "severity": "high", "category": "Crypto", "cwe": "CWE-327",
         "file_path": "sources/com/app/Wrapper.java",
         "evidence_view": {"primary": {"file": "sources/com/app/CryptoManager.java"}},
         "file_evidence": [{"path": "sources/com/app/Other.java", "lines": [3]}]},
    ]})
    fi = ex["file_index"]
    for p in ("sources/com/app/Wrapper.java", "sources/com/app/CryptoManager.java",
              "sources/com/app/Other.java"):
        _check(p in fi, f"every finding location must be indexed for jump: {p}")


# ── Bridged secret findings excluded (no double-count) ────────────────────────
def test_bridged_findings_skipped():
    ex = _ex({"platform": "android", "findings": [
        {"title": "Secret", "severity": "high", "category": "Embedded Secret", "secret_bridge": True,
         "file_path": "x/Bridged.java"},
    ]})
    _check("x/Bridged.java" not in ex["file_index"], "secret-bridge mirror must be skipped")


# ── Stats + safety ────────────────────────────────────────────────────────────
def test_stats_and_empty_safe():
    ex = _ex({"platform": "android", "findings": []})
    _check(ex["stats"]["annotated_files"] == 0, "empty scan is safe")
    _check(set(ex["security_index"].keys()) == set(se.SECURITY_CATEGORIES),
           "all security categories present even when empty")


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
