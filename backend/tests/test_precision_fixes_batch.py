"""
Six independent precision fixes:
  1. String-presence crypto categories are INFO (not HIGH) + DES/3DES split.
  2. Email extractor rejects code-identifier false positives.
  3. Hardcoded-IP string category is INFO (heuristic).
  4. Header MEDIUM count == score-table MEDIUM count (one severity_summary source).
  5. Score dict exposes secret_deductions so the deduction table reconciles.
  6. Cert signature algorithm has no 'PUBLICKEY' suffix + PDF mojibake repair.
"""
from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import scoring, string_analyzer, cert_analyzer  # noqa: E402


def _cat(name):
    return next((p for p in string_analyzer.STRING_PATTERNS if p["category"] == name), None)


# ── #1 crypto string-presence severity + DES/3DES split ──────────────────────

def test_crypto_string_presence_is_info():
    for name in (
        "Crypto Algorithm String Present — MD5",
        "Crypto Algorithm String Present — SHA-1",
        "Crypto Algorithm String Present — DES",
        "Crypto Algorithm String Present — 3DES/TripleDES",
        "Crypto Algorithm String Present — ECB Mode",
    ):
        p = _cat(name)
        assert p is not None, f"missing category {name}"
        assert p["severity"] == "info", f"{name} must be INFO, got {p['severity']}"


def test_no_high_weak_crypto_category_remains():
    for p in string_analyzer.STRING_PATTERNS:
        if "MD5" in p["category"] or "SHA" in p["category"] or "DES" in p["category"] or "ECB" in p["category"]:
            assert p["severity"] != "high", f"{p['category']} should not be HIGH"


def test_des_and_3des_are_distinct():
    des = _cat("Crypto Algorithm String Present — DES")
    tdes = _cat("Crypto Algorithm String Present — 3DES/TripleDES")
    assert des and tdes and des["category"] != tdes["category"]
    import re
    # \bDES\b matches single DES, never DESede/TripleDES.
    assert re.search(des["pattern"], "uses DES cipher", re.I)
    assert not re.search(des["pattern"], "uses DESede", re.I)
    assert re.search(tdes["pattern"], "uses TripleDES", re.I)


def test_crypto_string_presence_dedupe():
    results = {
        "string_analysis": {
            "Crypto Algorithm String Present — MD5": {
                "severity": "info", "description": "",
                "matches": [{"value": "MD5", "files": ["sources/com/app/A.java"]}],
                "count": 1,
            }
        },
        "findings": [
            {"rule_id": "android_weak_hash_md5", "file_path": "sources/com/app/A.java"},
        ],
    }
    string_analyzer.suppress_crypto_string_presence_duplicates(results)
    assert "Crypto Algorithm String Present — MD5" not in results["string_analysis"], \
        "string-presence MD5 must be suppressed when a code MD5 finding covers the same file"


# ── #2 email FPs ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    "_Double@0150898.fromInteger",  # leading _, all-digit domain, camelCase pseudo-TLD
    "n@d.Ce",                       # 1-char domain label, mixed-case pseudo-TLD
    "x@1234.5678",                  # numeric
])
def test_email_false_positives_rejected(bad):
    assert not string_analyzer._is_real_email(bad)


@pytest.mark.parametrize("good", [
    "dev.team@company.io", "john.doe@sub.example.co.uk", "SUPPORT@EXAMPLE.COM",
])
def test_real_emails_accepted(good):
    assert string_analyzer._is_real_email(good)


# ── #3 hardcoded IP is INFO ──────────────────────────────────────────────────

def test_hardcoded_ip_is_info():
    p = _cat("Hardcoded IP Address")
    assert p["severity"] == "info"
    assert "heuristic" in p["description"].lower()


# ── #4 header MEDIUM == score-table MEDIUM ───────────────────────────────────

def test_header_and_score_table_medium_agree():
    # A deliberately STALE severity_summary must not win — calculate_score
    # recomputes from the current findings and writes it back.
    results = {
        "findings": [{"severity": "medium"}, {"severity": "medium"},
                     {"severity": "high"}, {"severity": "low"}],
        "secrets": [], "platform": "android",
        "severity_summary": {"critical": 0, "high": 9, "medium": 99, "low": 9, "info": 0},
    }
    score = scoring.calculate_score(results)
    header_medium = results["severity_summary"]["medium"]
    table_medium = score["deductions"].get("medium", {}).get("count", 0)
    assert header_medium == 2
    assert header_medium == table_medium, f"header {header_medium} != table {table_medium}"


# ── #5 score reconciles (secret_deductions present) ──────────────────────────

def test_score_exposes_reconciling_components():
    results = {
        "findings": [{"severity": "medium"}],
        "secrets": [{"severity": "high"}, {"severity": "medium"}],
        "platform": "android",
    }
    score = scoring.calculate_score(results)
    assert "secret_deductions" in score
    assert "chain_penalty" in score and "total_bonus" in score and "total_deducted" in score
    # The components must reconcile to the final score (pre-clamp).
    computed = max(0, min(100, 100 - score["total_deducted"] + score["total_bonus"]))
    assert computed == score["score"]


# ── #6a cert signature algorithm ─────────────────────────────────────────────

@pytest.mark.parametrize("hash_name,key_cls,expected", [
    ("sha256", "_RSAPublicKey", "SHA256withRSA"),
    ("SHA1", "_RSAPublicKey", "SHA1withRSA"),
    ("sha384", "_EllipticCurvePublicKey", "SHA384withECDSA"),
    ("sha256", "_DSAPublicKey", "SHA256withDSA"),
])
def test_signature_algorithm_no_publickey_suffix(hash_name, key_cls, expected):
    algo = cert_analyzer._format_signature_algorithm(hash_name, key_cls)
    assert algo == expected
    assert "PUBLICKEY" not in algo.upper()


# ── #6b PDF mojibake repair (needs reportlab) ────────────────────────────────

def test_pdf_mojibake_repair():
    pdfgen = pytest.importorskip("report.pdf_generator")
    moji = "—".encode("utf-8").decode("latin-1")  # em-dash → "â€""
    assert pdfgen._repair_mojibake(moji) == "—"
    assert pdfgen._repair_mojibake("risk â€” flag") == "risk — flag"
    # Plain text is untouched.
    assert pdfgen._repair_mojibake("normal text") == "normal text"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
