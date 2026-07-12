"""Semantic grade ceiling (RUN 15.2).

The grade is a MEANING label on the honest score. The number picks a band; a semantic ceiling
then caps it by what the app actually SHIPS:

  A / Excellent = a clean bill — NO real finding or secret ABOVE INFO (a LOW bars it too:
                  a LOW is a real, evidence-backed issue, so an app carrying one is "very good,
                  minor issues", not a clean bill).
  B / Good      = has LOW and/or MEDIUM findings, nothing HIGH/CRITICAL.

The ceiling only ever LOWERS a grade. It is derived from the definitions, not from a target: an
app with 4 real MEDIUMs grades B BECAUSE it has mediums, whatever its score.
"""
from analyzers.scoring import calculate_score


def _app(score_findings, secrets=None):
    return calculate_score({"findings": list(score_findings), "secrets": list(secrets or [])})


def _f(sev, n=1):
    return [{"rule_id": f"{sev}{i}", "title": f"{sev} {i}", "severity": sev} for i in range(n)]


# ── property 1: a genuinely clean app grades A ───────────────────────────────
def test_no_findings_above_info_grades_a():
    s = _app(_f("info", 5))
    assert s["grade"] == "A"
    assert s["score"] == 100
    assert "no findings above INFO" in s["grade_reason"]


def test_one_real_low_cannot_grade_a():
    # CHANGED to LOW+: a LOW is a real, evidence-backed issue, so it bars the clean-bill A.
    s = _app(_f("low", 1))
    assert s["score"] >= 90                # a single low barely dents the score
    assert s["grade"] == "B", "a real LOW must cap the grade at B, not leave it at Excellent"
    assert "LOW" in s["grade_reason"] and "capped" in s["grade_reason"]


def test_sixty_lows_do_not_grade_a():
    # The edge case that MEDIUM+ let through: 60 real lows score ~95 but are NOT a clean bill.
    # Accumulation-blindness killed on the score side (RUN 15.1) must not survive on the grade
    # side. LOW+ closes it.
    s = _app(_f("low", 60))
    assert s["grade"] != "A"


# ── property 2: one real MEDIUM forbids A (both directions) ───────────────────
def test_one_medium_cannot_grade_a_even_with_a_top_score():
    s = _app(_f("medium", 1))
    assert s["score"] >= 90          # a single medium barely dents the score
    assert s["grade"] == "B", "a real MEDIUM must cap the grade at B, whatever the score"
    assert "MEDIUM" in s["grade_reason"] and "capped" in s["grade_reason"]


def test_a_high_finding_caps_at_c():
    s = _app(_f("high", 1))
    assert s["grade"] == "C", "nothing HIGH/CRITICAL may grade above Fair"


def test_a_critical_finding_caps_at_c_or_lower():
    s = _app(_f("critical", 1))
    assert s["grade"] in ("C", "D", "F")
    assert s["grade"] != "A" and s["grade"] != "B"


# ── property 3: THIS app (4 medium, 2 low, score 92) grades B, reason cites mediums ──
def test_this_apps_profile_grades_b_and_cites_the_mediums():
    s = _app(_f("medium", 4) + _f("low", 2))
    assert s["score"] == 92, "score must be unchanged by the label remapping"
    assert s["grade"] == "B"
    assert "MEDIUM" in s["grade_reason"]
    assert "4 real MEDIUM" in s["grade_reason"]


# ── the ceiling only LOWERS, never raises ────────────────────────────────────
def test_a_high_critical_app_is_not_lifted_up_to_its_ceiling():
    # 1 critical + 11 high + 7 medium + 4 low (no attack-chain penalty in this synthetic, so it
    # scores in the D band). The C ceiling for high/critical must NOT raise a D-band app to C.
    s = _app(_f("critical", 1) + _f("high", 11) + _f("medium", 7) + _f("low", 4))
    assert s["grade"] == "D", f"the ceiling only lowers; got {s['grade']} at score {s['score']}"
    assert s["grade"] != "C"


# ── secrets gate the grade by DISPLAY severity ───────────────────────────────
def test_an_info_client_key_secret_does_not_block_a():
    s = _app(_f("info", 1), secrets=[{"display_severity": "info", "value": "AIza…"}])
    assert s["grade"] == "A", "an INFO client key must not cap the grade"


def test_a_medium_secret_caps_at_b():
    s = _app(_f("info", 1), secrets=[{"display_severity": "medium", "value": "secret"}])
    assert s["grade"] == "B"


def test_a_low_secret_also_caps_at_b():
    # Under LOW+, even a low-severity secret bars the clean bill.
    s = _app(_f("info", 1), secrets=[{"display_severity": "low", "value": "secret"}])
    assert s["grade"] == "B"


# ── the score itself is never touched by the label remapping ─────────────────
def test_score_is_identical_regardless_of_ceiling():
    findings = _f("medium", 4) + _f("low", 2)
    s = _app(findings)
    # 100 - (3 + 1.5 + 1 + 0.75) - (1 + 0.5) = 100 - 7.75 = 92.25 -> 92
    assert s["score"] == 92
