"""MASVS control detection (RUN 8.1).

RUN 8 proved MASVS-CODE cannot move off 0 by adding findings: the score is
    (controls_present / expected) * 60  +  (40 - penalty)
so findings are PENALTIES and only ever subtract. The score is floored until Beetle can
detect the controls an app genuinely implements.

THE DISCIPLINE (same as RUN 7's "unknown stays reachable"): a control is marked present ONLY
with real evidence that it is implemented. A control is NEVER assumed present to lift a score.
An app that ships no anti-tampering must score 0 for anti-tampering — that is the honest
answer, not a bug to be tuned away.
"""
from analyzers.masvs_intel import _detect_controls, build_coverage


def _results(**kw):
    base = {"findings": [], "sdks": [], "permissions": []}
    base.update(kw)
    return base


def _cov(results, category):
    return next(c for c in build_coverage(results) if c["category"] == category)


# ── evidence present → control present ───────────────────────────────────────
def test_ios_security_suite_evidences_tamper_detection():
    r = _results(sdks=[{"name": "IOSSecuritySuite", "category": "security"}])
    assert "Root/Tamper Detection" in _detect_controls(r)["MASVS-RESILIENCE"]


def test_flutter_jailbreak_detection_evidences_tamper_detection():
    r = _results(sdks=[{"name": "flutter_jailbreak_detection_plus", "category": "security"}])
    assert "Root/Tamper Detection" in _detect_controls(r)["MASVS-RESILIENCE"]


def test_flutter_secure_storage_evidences_encrypted_storage():
    r = _results(sdks=[{"name": "flutter_secure_storage", "category": "storage"}])
    assert "Encrypted Storage" in _detect_controls(r)["MASVS-STORAGE"]


# ── THE GUARD: no evidence → control stays ABSENT ────────────────────────────
def test_control_with_no_evidence_stays_absent():
    # An app that ships none of these frameworks must NOT be credited with the controls.
    r = _results(sdks=[{"name": "fluttertoast", "category": "platform"},
                       {"name": "battery_plus", "category": "platform"}])
    present = _detect_controls(r)
    assert "Root/Tamper Detection" not in present["MASVS-RESILIENCE"]
    assert "Encrypted Storage" not in present["MASVS-STORAGE"]


def test_empty_app_credits_no_controls_at_all():
    present = _detect_controls(_results())
    assert all(not names for names in present.values()), present


def test_detection_raises_the_score_only_when_evidence_exists():
    without = _cov(_results(sdks=[{"name": "fluttertoast"}]), "MASVS-RESILIENCE")["score"]
    with_ = _cov(_results(sdks=[{"name": "IOSSecuritySuite"}]), "MASVS-RESILIENCE")["score"]
    assert with_ > without, "detecting a real control must raise the category score"
    # And the lift comes from the CONTROL term, not from silently dropping penalties.
    assert "Root/Tamper Detection" in _cov(
        _results(sdks=[{"name": "IOSSecuritySuite"}]), "MASVS-RESILIENCE")["controls_present"]
