"""RUN 35 T1–T3 — FP / mislabel sweep (InsecureBankv2-derived).

T1  "User-Controlled Data in Crypto Operation" (HIGH) is noise: reaching a crypto API with user
    data is the NORMAL use of crypto, not a weakness. Downgrade to LOW context; the real crypto
    weaknesses (hardcoded key/IV, ECB/CBC, Base64) are detected structurally.
T2  "Hardcoded Encryption Key" (CRITICAL) had the right conclusion but pointed at the SecretKeySpec
    usage line; repoint to the key string literal.
T3  A "SQL Injection" attack chain must not be built on a SQL step proven PARAMETERIZED (its own
    evidence reads "No Injection Evidence").
"""
import re
import pytest

from analyzers.taint_analyzer import _calibrate_severity, calibrate_flow_severity
from analyzers.attack_chains.engine import tag_capabilities
from analyzers.code_analyzer import _KEY_LITERAL_RE, refine_hardcoded_key_evidence


# ── T1 — crypto taint is LOW context ─────────────────────────────────────────
def test_crypto_sink_downgraded_to_low():
    assert _calibrate_severity("Crypto", "User Input", "high") == "low"
    assert _calibrate_severity("Crypto", "SharedPrefs", "high") == "low"


def test_crypto_flow_calibrates_low():
    flow = {"sink_cat": "Crypto", "source_cat": "User Input", "sink_sev": "high"}
    assert calibrate_flow_severity(flow) == "low"


def test_other_high_value_sinks_unchanged():
    """The downgrade is crypto-specific — WebView/SQL/exec injection sinks keep their severity."""
    assert _calibrate_severity("WebView", "User Input", "high") == "high"
    assert _calibrate_severity("Execution", "User Input", "critical") == "critical"
    assert _calibrate_severity("SQLite", "User Input", "high") == "high"


# ── T2 — hardcoded key evidence points at the literal ────────────────────────
def test_key_literal_regex_matches_the_declaration():
    src = 'class C {\n    String key = "This is the super secret key 123";\n}'
    m = _KEY_LITERAL_RE.search(src)
    assert m is not None
    assert m.group(1) == "This is the super secret key 123"


def test_key_literal_regex_ignores_non_key_strings():
    assert _KEY_LITERAL_RE.search('String label = "Camera access";') is None
    assert _KEY_LITERAL_RE.search('String mode = "AES/CBC/PKCS5Padding";') is None


def test_refine_repoints_to_key_literal(monkeypatch, tmp_path):
    # Mirror CryptoClass.java: key literal on line 2, SecretKeySpec usage on line 5.
    src = ('package x;\n'
           '    String key = "This is the super secret key 123";\n'
           '    byte[] ivBytes = {0,0,0,0};\n'
           '    void f(byte[] bArr2) {\n'
           '        SecretKeySpec s = new SecretKeySpec(bArr2, "AES");\n'
           '    }\n')
    p = tmp_path / "CryptoClass.java"
    p.write_text(src)

    import analyzers.scan_storage as scan_storage
    monkeypatch.setattr(scan_storage, "resolve_source_file", lambda sid, rel: p)

    finding = {
        "rule_id": "android_encryption_key_hardcoded", "severity": "critical",
        "file_path": "sources/x/CryptoClass.java", "line": 5,
        "snippet": "SecretKeySpec s = new SecretKeySpec(bArr2, \"AES\");",
        "file_evidence": [{"path": "sources/x/CryptoClass.java", "lines": [5],
                           "snippet": "SecretKeySpec s = new SecretKeySpec(bArr2, \"AES\");"}],
    }
    results = {"scan_id": "sid", "findings": [finding]}
    stats = refine_hardcoded_key_evidence(results)

    assert stats["repointed"] == 1
    assert finding["line"] == 2                     # the key literal line, not the usage line
    assert "super secret key" in finding["snippet"]
    assert finding["file_evidence"][0]["lines"] == [2]
    assert finding.get("masked_key_value")          # masked value surfaced
    assert "super secret key 123" not in finding["masked_key_value"]  # not leaked in clear


def test_refine_noop_without_key_literal(monkeypatch, tmp_path):
    p = tmp_path / "NoKey.java"
    p.write_text("class C { void f(byte[] b){ new SecretKeySpec(b,\"AES\"); } }")
    import analyzers.scan_storage as scan_storage
    monkeypatch.setattr(scan_storage, "resolve_source_file", lambda sid, rel: p)
    finding = {"rule_id": "android_encryption_key_hardcoded", "file_path": "x.java", "line": 1}
    stats = refine_hardcoded_key_evidence({"scan_id": "s", "findings": [finding]})
    assert stats["repointed"] == 0
    assert finding["line"] == 1                      # untouched


# ── T3 — parameterized SQL earns no SQL_SINK ─────────────────────────────────
def test_parameterized_sql_no_sql_sink():
    f = {"rule_id": "android_sqlite_raw_query",
         "title": "Raw SQL Query (Parameterized) — No Injection Evidence",
         "category": "Code Quality",
         "sql_injection_evidence": "parameterized (no string-building detected)",
         "severity_downgraded_reason": "parameterized raw query"}
    assert "SQL_SINK" not in tag_capabilities(f)


def test_real_sqli_still_earns_sql_sink():
    """A string-building SQL finding (real injection) keeps SQL_SINK so its chain still forms."""
    f = {"rule_id": "android_sqlite_raw_query", "title": "Raw SQL Query — SQL Injection Risk",
         "category": "Code Quality",
         "sql_injection_evidence": "string-building in SQL argument (concatenation/format/interpolation)"}
    assert "SQL_SINK" in tag_capabilities(f)


def test_taint_sqlite_sink_still_earns_sql_sink():
    f = {"rule_id": "TAINT-SQLITE", "taint_flow": {"sink_cat": "SQLite", "source_cat": "user input"}}
    assert "SQL_SINK" in tag_capabilities(f)
