"""
Regression: secret display severity must be derived from the evidence-based Secret
Intelligence status so surfaces AGREE — a package-restricted client key (AIza) shows
INFO (not HIGH), a weakly-evidenced Possible is capped at MEDIUM, and a Validated
secret keeps HIGH. Plus a dictionary word ("ApeAnotherValue") must not match the
Artifactory Password FP pattern.

These fail on the old behavior (client key HIGH, word FP flagged) and pass on the new.
"""
from __future__ import annotations

import os
import re
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import secret_intel as si  # noqa: E402
from analyzers import scoring  # noqa: E402
from analyzers.detection_sources import apkleaks_patterns as ap  # noqa: E402


def _finalize(status, computed_sev, name="Google API Key"):
    """Run one secret through the canonicalization that assigns display severity."""
    secret = {
        "name": name, "value": "x", "severity": computed_sev, "secret_status": status,
        "secret_intelligence": {"status": status, "recognized_format": True},
        "file_path": "res/values/strings.xml", "line": 3, "snippet": "k",
        "provider": "GOOGLE", "type": name,
    }
    return si._build_canonical(secret, app_package="com.app")


# ── (a) CLIENT_KEY renders INFO and contributes 0 to the score ───────────────

def test_client_key_display_severity_is_info():
    c = _finalize("Client Key", "high")
    assert c["severity"] == "info"
    assert c["display_severity"] == "info"
    # The detector/evidence severity is preserved for audit, not displayed.
    assert c["severity_computed"] == "high"


def test_client_key_contributes_zero_to_score():
    c = _finalize("Client Key", "high")
    results = {"findings": [], "secrets": [c], "platform": "android"}
    score = scoring.calculate_score(results)
    assert score.get("secret_deductions", 0) == 0, "a client key must not move the score"


def test_public_value_is_info():
    assert _finalize("Public Value", "high")["display_severity"] == "info"


def test_hidden_fp_classes_contribute_zero():
    # DOC_EXAMPLE / FALSE_POSITIVE / GENERATED_CONSTANT → INFO (weight 0), so even if
    # one reaches the score list it deducts nothing.
    for status in ("Documentation Example", "False Positive", "Generated Constant"):
        assert _finalize(status, "high")["display_severity"] == "info", status
    fps = [_finalize(s, "high") for s in ("False Positive", "Generated Constant")]
    score = scoring.calculate_score({"findings": [], "secrets": fps, "platform": "android"})
    assert score.get("secret_deductions", 0) == 0


# ── (c) a VALIDATED secret still renders HIGH ────────────────────────────────

def test_validated_secret_keeps_high():
    c = _finalize("Validated Secret", "high", name="AWS Access Key")
    assert c["severity"] == "high"
    assert c["display_severity"] == "high"


def test_validated_secret_moves_the_score():
    c = _finalize("Validated Secret", "high", name="AWS Access Key")
    score = scoring.calculate_score({"findings": [], "secrets": [c], "platform": "android"})
    assert score.get("secret_deductions", 0) > 0, "a real confidential secret must deduct"


def test_possible_secret_capped_at_medium():
    assert _finalize("Possible Secret", "high")["display_severity"] == "medium"
    # A Possible whose computed severity is already lower is not raised.
    assert _finalize("Possible Secret", "low")["display_severity"] == "low"


def test_no_status_leaves_severity_unchanged():
    assert _finalize(None, "high")["display_severity"] == "high"


# ── (b) "ApeAnotherValue" is NOT flagged Artifactory Password ────────────────

def _artifactory_pw_regex():
    pat = next(p for p in ap.APKLEAKS_PATTERNS if p["name"] == "Artifactory Password")
    # Compiled exactly as the scanner does (evidence_scanner uses IGNORECASE|MULTILINE).
    return re.compile(pat["pattern"], re.IGNORECASE | re.MULTILINE)


def test_dictionary_word_not_flagged_artifactory():
    rx = _artifactory_pw_regex()
    for word in ('"ApeAnotherValue"', 'x = "ApeSomeValue"', '"Apricotdelicious"', 'ap: "Apoptosisxx"'):
        assert not rx.search(word), f"plain word must not match: {word}"


def test_real_artifactory_password_still_matches():
    rx = _artifactory_pw_regex()
    for real in (' APe1b2c3d4x5', 'pw = "APa9bXk2mQ7z"', ':AP7f3a91bce0d'):
        assert rx.search(real), f"a digit-bearing Artifactory password must still match: {real}"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
