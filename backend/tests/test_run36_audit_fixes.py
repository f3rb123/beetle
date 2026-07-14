"""RUN 36 — self-audit fixes: SMS-exfil taint sink + plaintext-credential logging severity."""
import pytest

from analyzers.taint_analyzer import (
    SINKS, _SINK_META, _HIGH_VALUE_SINKS, _calibrate_severity)
from analyzers.finding_model import _HIGH_VALUE_TAINT_SINKS, _taint_group_title
from analyzers.code_analyzer import refine_credential_logging_severity, _CREDENTIAL_LOG_RE


# ── SMS-exfil taint sink (missed TP: MyBroadCastReceiver intent extra → sendTextMessage) ──
def test_sms_send_is_a_registered_sink():
    labels = {label for (_c, _m, label, _cat, _sev) in SINKS}
    assert "SmsManager.sendTextMessage" in labels
    assert "SmsManager.sendMultipartTextMessage" in labels


def test_sms_send_sink_is_high_value_and_high_severity():
    sms = [t for t in SINKS if t[3] == "SmsSend"]
    assert sms and all(t[4] == "high" for t in sms)
    assert "SmsSend" in _HIGH_VALUE_SINKS
    assert "SmsSend" in _SINK_META                      # CWE/MASVS wired
    assert "smssend" in _HIGH_VALUE_TAINT_SINKS         # surfaced by the value gate
    assert _calibrate_severity("SmsSend", "User Input", "high") == "high"


def test_sms_flow_gets_friendly_group_title():
    assert _taint_group_title("SmsSend") == "User-Controlled Data Sent via SMS"


# ── plaintext-credential logging → MEDIUM ────────────────────────────────────
def _log_finding(snippet):
    return {"rule_id": "android_log_debug", "severity": "low", "snippet": snippet}


def test_credential_log_bumped_to_medium():
    # InsecureBankv2 DoLogin.java:136
    f = _log_finding('Log.d("Successful Login:", ", account=" + DoLogin.this.username + ":" + DoLogin.this.password)')
    r = {"findings": [f]}
    stats = refine_credential_logging_severity(r)
    assert stats["bumped"] == 1
    assert f["severity"] == "medium"
    assert f["credential_logging"] is True
    assert "Credentials" in f["title"]


def test_username_only_log_stays_low():
    # InsecureShop LoginActivity.java:84 — no password token → not bumped.
    f = _log_finding('Log.d("userName", valueOf);')
    stats = refine_credential_logging_severity({"findings": [f]})
    assert stats["bumped"] == 0
    assert f["severity"] == "low"


def test_string_literal_mention_not_bumped():
    """A password word inside a UI string (no credential value logged) must NOT trip it."""
    f = _log_finding('Log.d("please enter your password to continue")')
    refine_credential_logging_severity({"findings": [f]})
    assert f["severity"] == "low"


def test_regex_matches_credential_value_not_bare_string():
    assert _CREDENTIAL_LOG_RE.search('", account=" + user + ":" + this.password')  # value logged
    assert _CREDENTIAL_LOG_RE.search('Log.d(tag, sessionToken)')                   # token value
    assert not _CREDENTIAL_LOG_RE.search('Log.d("enter password here")')           # literal only


def test_non_log_findings_untouched():
    f = {"rule_id": "android_webview_js_enabled", "severity": "medium",
         "snippet": "+ this.password"}
    refine_credential_logging_severity({"findings": [f]})
    assert f["severity"] == "medium" and "credential_logging" not in f
