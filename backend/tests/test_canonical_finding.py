"""
Sanity checks for the canonical finding model (Beetle 2.0, Phase 1.1).

Proves that every major finding type Beetle emits today — Android and iOS —
round-trips through `CanonicalFinding` without data loss, that field-name
variations are standardized, and that the helper methods behave.

Runnable two ways:
  * pytest:   pytest backend/tests/test_canonical_finding.py
  * stdlib:   python -m tests.test_canonical_finding     (run from backend/)
              python backend/tests/test_canonical_finding.py

It deliberately needs no third-party deps (the model is pure stdlib) so it runs
on any interpreter, matching the model's dependency-free design.
"""
from __future__ import annotations

import os
import sys

# Make `analyzers` importable whether run via pytest or as a bare script.
_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.canonical_finding import (  # noqa: E402
    CanonicalFinding,
    canonicalize_dict,
    from_legacy,
    from_legacy_list,
    normalize_confidence,
    normalize_severity,
)


# ── Representative legacy findings (one per major producer) ───────────────────
# Field shapes here mirror what the real analyzers emit (verified against
# code_analyzer / evidence_scanner / taint_analyzer / chain_analyzer / cve_mapper
# / cert_analyzer / ios_analyzer).
ANDROID_FINDINGS = [
    # 1. SAST regex (code_analyzer.py) — the canonical multi-file finding shape.
    {
        "title": "Use of Insecure Random", "severity": "high", "category": "Cryptography",
        "description": "java.util.Random is not cryptographically secure.",
        "impact": "Predictable values.", "recommendation": "Use SecureRandom.",
        "cwe": "CWE-330", "masvs": "MSTG-CRYPTO-6", "owasp": "M5",
        "rule_id": "android_insecure_random", "source": "SAST",
        "confidence": 75, "exploitability": 50, "validation_status": "detected",
        "file_path": "sources/com/app/pay/Token.java", "line": 42,
        "snippet": "Random r = new Random();", "code_context": "  41 | ...\n> 42 | Random r = new Random();",
        "files": ["sources/com/app/pay/Token.java"],
        "file_evidence": [{"path": "sources/com/app/pay/Token.java", "lines": [42], "snippet": "new Random()"}],
        "file_count": 1, "poc": "demo",
    },
    # 2. Secret (evidence_scanner → secret_intel) — uses `name`, masked `value`.
    {
        "name": "AWS Access Key ID", "title": "AWS Access Key ID", "severity": "critical",
        "category": "Secrets", "source": "EVIDENCE", "value": "AKIA****************",
        "file_path": "sources/com/app/Config.java", "line": 9, "confidence": "high",
        "provider": "AWS", "validation_status": "skipped",
    },
    # 3. Taint flow (taint_analyzer.py) — class-ref file_path, nested taint_flow.
    {
        "title": "User Input Reaches SQL Query", "severity": "high",
        "category": "Taint Analysis", "source": "TAINT", "confidence": 70,
        "file_path": "Lcom/app/db/Dao;", "call_chain": ["com.app.ui.Search.onQuery", "com.app.db.Dao.raw"],
        "taint_flow": {"source_cat": "User Input", "sink_cat": "sqlite",
                       "source": "getIntent", "sink": "rawQuery",
                       "chain": ["Search.onQuery", "Dao.raw"]},
        "method_name": "rawQuery",
    },
    # 4. Manifest config (android_analyzer) — evidence_type manifest, component.
    {
        "title": "Exported Activity Without Permission", "severity": "medium",
        "category": "Attack Surface", "evidence_type": "manifest",
        "component": "com.app.ExternalActivity", "rule_id": "exported_activity",
        "manifest_evidence_spec": {"attr": "name", "value": "com.app.ExternalActivity"},
    },
    # 5. Synthesized attack chain (chain_analyzer.py) — is_attack_chain.
    {
        "title": "WebView RCE Chain", "severity": "critical", "category": "Attack Chain",
        "is_attack_chain": True, "chain_confidence": "HIGH",
        "steps": [{"title": "Browsable entry", "severity": "high"},
                  {"title": "JS-enabled WebView", "severity": "high"}],
        "masvs": ["MSTG-PLATFORM-7"], "owasp": ["M7"],
    },
    # 6. Certificate (cert_analyzer.py) — metadata block, no source line.
    {
        "title": "Debug Certificate Used For Signing", "severity": "high",
        "category": "Certificate", "source": "CERT",
        "evidence": "Subject: CN=Android Debug, O=Android, C=US",
    },
    # 7. Binary hardening (elf_analyzer.py).
    {
        "title": "Native Library Missing Stack Canary", "severity": "low",
        "category": "Binary Hardening", "source": "ELF",
        "file_path": "lib/arm64-v8a/libnative.so",
    },
    # 8. Vulnerable dependency (cve_mapper.py) — CVE/CVSS/KEV.
    {
        "title": "okhttp 3.10.0 — CVE-2021-0341", "severity": "medium",
        "category": "Vulnerable Components", "source": "CVE-MAP",
        "cve": "CVE-2021-0341", "cvss": 7.5, "kev": 0, "file_path": "lib/arm64-v8a/libokhttp.so",
        "package": "com.squareup.okhttp3", "references": "https://nvd.nist.gov/vuln/detail/CVE-2021-0341",
    },
]

IOS_FINDINGS = [
    # 9. iOS SAST (ios code rules) — .swift path, platform stamped at scan level.
    {
        "title": "Insecure UserDefaults Storage", "severity": "medium",
        "category": "Data Storage", "rule_id": "ios_userdefaults_sensitive",
        "source": "SAST", "file_path": "Payload/App.app/Sources/Login.swift",
        "line": 88, "snippet": "UserDefaults.standard.set(token, forKey: \"jwt\")",
        "confidence": 65, "cwe": "CWE-922",
    },
    # 10. iOS entitlement / WebView with id-style key + textual confidence.
    {
        "id": "ios_wkwebview_js_bridge", "title": "JS Bridge Exposed in WKWebView",
        "severity": "high", "category": "WebView", "source": "IOS",
        "file": "Payload/App.app/Sources/Bridge.m", "line_number": 12,
        "confidence": "medium", "owasp": ["M7"],
    },
]

ALL = [(f, "android") for f in ANDROID_FINDINGS] + [(f, "ios") for f in IOS_FINDINGS]


# ── Assertion helpers ─────────────────────────────────────────────────────────
def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


# ── Tests ─────────────────────────────────────────────────────────────────────
def test_round_trip_is_lossless_superset():
    """to_legacy(from_legacy(d)) preserves every original key/value (superset)."""
    for d, platform in ALL:
        out = canonicalize_dict(d, platform=platform)
        for k, v in d.items():
            _check(k in out, f"[{d.get('title')}] lost key {k!r}")
            _check(out[k] == v, f"[{d.get('title')}] key {k!r} changed: {v!r} -> {out[k]!r}")


def test_canonical_names_present_after_adaptation():
    """Legacy aliases are standardized to canonical names additively."""
    # `id` -> rule_id, `file`/`line_number` -> file_path/line, `source` -> source_module.
    out = canonicalize_dict(IOS_FINDINGS[1], platform="ios")
    _check(out["rule_id"] == "ios_wkwebview_js_bridge", "id not mapped to rule_id")
    _check(out["file_path"] == "Payload/App.app/Sources/Bridge.m", "file not mapped to file_path")
    _check(out["line"] == 12, "line_number not mapped to line")
    _check(out["source_module"] == "IOS", "source not mapped to source_module")
    # original legacy keys still present (non-destructive)
    _check(out["file"] == "Payload/App.app/Sources/Bridge.m", "legacy `file` dropped")
    _check(out["id"] == "ios_wkwebview_js_bridge", "legacy `id` dropped")


def test_every_finding_type_represented():
    """Each major type produces a valid, evidence-backed canonical finding."""
    for d, platform in ALL:
        cf = from_legacy(d, platform=platform)
        _check(cf.title, f"empty title for {d}")
        _check(cf.severity in ("critical", "high", "medium", "low", "info"),
               f"bad severity {cf.severity}")
        _check(cf.platform == platform, f"platform not stamped: {cf.platform}")
        _check(0 <= cf.confidence <= 100, f"confidence out of range: {cf.confidence}")
        # All representative fixtures carry some evidence -> no validate() warnings
        # about missing evidence.
        _check("no extractable evidence" not in cf.validate(),
               f"unexpected no-evidence warning for {cf.title}")


def test_placeholders_default_but_carry_existing():
    """Future-phase placeholders default safely and are not computed here."""
    cf = from_legacy(ANDROID_FINDINGS[0], platform="android")
    _check(cf.owner_type == "unknown", "owner_type should default to 'unknown'")
    _check(cf.ownership_label is None, "ownership_label should default to None")
    _check(cf.sdk_name is None and cf.package_prefix is None, "sdk/prefix placeholders should be None")
    # exploitability is carried when present (50 in fixture #1), not invented.
    _check(cf.exploitability == 50, "exploitability should be carried from legacy")
    # A finding without exploitability stays None (not derived).
    _check(from_legacy(ANDROID_FINDINGS[5]).exploitability is None,
           "exploitability should not be invented")


def test_typed_coercion():
    """Severity/confidence/line are normalized into canonical types."""
    cf = from_legacy({"title": "x", "severity": "HIGH", "confidence": "medium",
                      "line": "0", "exploitability": "80"})
    _check(cf.severity == "high", "severity not lowercased")
    _check(cf.confidence == 60, "textual confidence not mapped to 60")
    _check(cf.line is None, "line 0 should normalize to None")
    _check(cf.exploitability == 80, "numeric-string exploitability not coerced")
    # alias normalization
    _check(normalize_severity("warning") == "medium", "severity alias failed")
    _check(normalize_confidence(125) == 100, "confidence not clamped")
    _check(normalize_confidence(None) == 0, "None confidence not 0")


def test_standards_scalar_or_list():
    """cwe/masvs/owasp accept scalar or list and become clean lists where typed."""
    cf_scalar = from_legacy(ANDROID_FINDINGS[0])   # masvs/owasp as scalars
    cf_list = from_legacy(ANDROID_FINDINGS[4])     # masvs/owasp as lists
    _check(cf_scalar.masvs == ["MSTG-CRYPTO-6"], f"scalar masvs not listified: {cf_scalar.masvs}")
    _check(cf_list.owasp == ["M7"], f"list owasp mangled: {cf_list.owasp}")


def test_identity_and_dedup():
    """identity() is rescan-stable; dedup_key mirrors the DB unique index."""
    a = from_legacy(ANDROID_FINDINGS[0])
    b = from_legacy(dict(ANDROID_FINDINGS[0], line=999))  # different line, same rule/pkg
    _check(a.identity() == b.identity(), "identity should ignore line number")
    _check(a.dedup_key() != b.dedup_key(), "dedup_key should include line")
    _check(a.dedup_key() == ("android_insecure_random", "sources/com/app/pay/Token.java", 42,
                             "Use of Insecure Random"), "dedup_key shape changed")


def test_merge():
    """merge() unions evidence and keeps the stronger severity/confidence."""
    a = from_legacy({"rule_id": "r", "title": "t", "severity": "low", "confidence": 30,
                     "file_path": "A.java", "tags": ["x"], "references": ["u1"]})
    b = from_legacy({"rule_id": "r", "title": "t", "severity": "high", "confidence": 80,
                     "method_name": "m", "tags": ["y"], "references": ["u2"],
                     "file_evidence": [{"path": "B.java", "lines": [1], "snippet": "s"}]})
    m = a.merge(b)
    _check(m.severity == "high", "merge should keep higher severity")
    _check(m.confidence == 80, "merge should keep higher confidence")
    _check(m.method_name == "m", "merge should fill empty scalar from other")
    _check(set(m.tags) == {"x", "y"}, "merge should union tags")
    _check(set(m.references) == {"u1", "u2"}, "merge should union references")
    _check(len(m.file_evidence) == 1, "merge should union evidence")
    _check(a.severity == "low" and b.severity == "high", "merge must not mutate inputs")


def test_json_and_dict_serialization():
    """to_dict omits raw by default; to_json is parseable."""
    import json
    cf = from_legacy(ANDROID_FINDINGS[2], platform="android")
    d = cf.to_dict()
    _check("raw" not in d, "to_dict should omit raw by default")
    _check("raw" in cf.to_dict(include_raw=True), "include_raw should add raw")
    parsed = json.loads(cf.to_json())
    _check(parsed["title"] == "User Input Reaches SQL Query", "json round-trip failed")


def test_from_legacy_list_skips_non_dicts():
    out = from_legacy_list([ANDROID_FINDINGS[0], None, "bad", {"title": "ok"}])
    _check(len(out) == 2, f"expected 2 findings, got {len(out)}")
    _check(all(isinstance(x, CanonicalFinding) for x in out), "non-CanonicalFinding in output")


# ── Standalone runner (no pytest required) ───────────────────────────────────
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
