"""RUN 34 — Janus (CVE-2017-13156) context-aware severity.

A v1-only APK is HIGH only when its minSdk reaches the Janus-vulnerable OS range (Android 5.0–8.0
/ API 21–26, fixed in 8.1/API 27); otherwise MEDIUM. Neither MobSF's blanket-HIGH nor Beetle's old
blanket-MEDIUM is right — exposure depends on whether a supported device is actually vulnerable.
"""
import pytest

from analyzers.cert_analyzer import _janus_severity


def _sev(min_sdk):
    return _janus_severity({"app_info": {"min_sdk": min_sdk}})[0]


def test_low_minsdk_is_high():
    # InsecureBankv2 minSdk=15 -> reaches the vulnerable range -> HIGH.
    assert _sev(15) == "high"
    assert _sev(21) == "high"


def test_boundary_api_26_high_api_27_medium():
    assert _sev(26) == "high"   # Android 8.0 — last vulnerable API
    assert _sev(27) == "medium" # Android 8.1 — OS-level fix


def test_modern_minsdk_is_medium():
    assert _sev(29) == "medium"
    assert _sev(34) == "medium"


def test_unknown_minsdk_is_high_conservative():
    assert _sev("?") == "high"
    assert _sev("") == "high"
    assert _janus_severity({})[0] == "high"


def test_reason_names_the_range_and_value():
    sev, reason = _janus_severity({"app_info": {"min_sdk": 15}})
    assert sev == "high"
    assert "15" in reason
    assert "21" in reason and "26" in reason   # names the concrete vulnerable API range

    sev2, reason2 = _janus_severity({"app_info": {"min_sdk": 30}})
    assert sev2 == "medium"
    assert "27" in reason2   # names the fix boundary
