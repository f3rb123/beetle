"""Graduated (diminishing-marginal-weight) score contribution — RUN 15.1.

THE DEFECT: the old model capped each severity at 3x its weight — a CLIFF. Full weight for the
first three findings, then nothing at all. 4 MEDIUMs and 40 MEDIUMs scored IDENTICALLY, so
accumulation did not register. The same flattening bit on LOW: 36 lows deducted 3 points, which
is why removing 34 false-positive lows in RUN 15 recovered only one point.

THE FIX: the i-th finding of a severity deducts weight/i. Chosen by SHAPE, never by the number
it produces:
  * the 1st finding costs full weight (severity is never discounted away);
  * every additional finding still moves the score (the defect is fixed);
  * the sum grows like ln(n), so VOLUME CAN NEVER OVERTAKE SEVERITY at any count (the old cap's
    purpose survives).
"""
import pytest

from analyzers.scoring import SEVERITY_WEIGHTS, calculate_score, graduated_deduction

CRITICAL = SEVERITY_WEIGHTS["critical"]   # 15
LOW = SEVERITY_WEIGHTS["low"]             # 1
MEDIUM = SEVERITY_WEIGHTS["medium"]       # 3


def _app(**counts):
    findings = []
    for sev, n in counts.items():
        findings += [{"rule_id": f"r_{sev}_{i}", "title": f"{sev} {i}", "severity": sev}
                     for i in range(n)]
    results = {"findings": findings, "secrets": []}
    return calculate_score(results)


# ── property 1: volume must never outscore severity (the cap's original purpose) ──
def test_a_swarm_of_info_never_outscores_one_critical():
    assert _app(info=40)["score"] > _app(critical=1)["score"]


def test_even_a_thousand_lows_never_outscore_one_critical():
    # The strong form. Harmonic growth (~ln n) guarantees this at ANY count; a weight/sqrt(i)
    # curve would fail here (56 lows would already outweigh a CRITICAL).
    assert graduated_deduction(LOW, 1000) < CRITICAL
    assert _app(low=1000)["score"] > _app(critical=1)["score"]


def test_one_critical_still_outweighs_many_mediums_at_realistic_counts():
    assert graduated_deduction(MEDIUM, 5) < CRITICAL


# ── property 2: accumulation must REGISTER (the defect being fixed) ──────────
def test_forty_mediums_score_meaningfully_lower_than_four():
    four = _app(medium=4)["score"]
    forty = _app(medium=40)["score"]
    assert forty < four, "40 real MEDIUMs must score lower than 4 — this was the defect"
    assert four - forty >= 5, f"the gap must be meaningful, got {four - forty}"


def test_the_old_cliff_is_gone_every_extra_finding_still_deducts():
    # Under the old cap, findings 4..40 contributed EXACTLY ZERO. Now every one of them adds a
    # (shrinking) deduction. Asserted on the DEDUCTION, because the published score is an
    # integer: at small n a single extra finding can move the deduction by less than a point
    # (3 mediums -> 5.50, 4 mediums -> 6.25) and both round to the same displayed score. The
    # mechanism registers it; the integer display cannot always show it.
    deductions = [graduated_deduction(MEDIUM, n) for n in (3, 4, 10, 40)]
    assert deductions == sorted(deductions)
    assert len(set(deductions)) == 4, "each additional finding must still deduct something"
    # Across a real span the SCORE moves too.
    scores = [_app(medium=n)["score"] for n in (3, 10, 40)]
    assert scores == sorted(scores, reverse=True)
    assert len(set(scores)) == 3


def test_marginal_weight_decays_but_never_reaches_zero():
    first = graduated_deduction(MEDIUM, 1)
    assert first == MEDIUM                                   # 1st costs full weight
    for n in range(2, 50):
        marginal = graduated_deduction(MEDIUM, n) - graduated_deduction(MEDIUM, n - 1)
        prev = graduated_deduction(MEDIUM, n - 1) - graduated_deduction(MEDIUM, n - 2) \
            if n > 2 else first
        assert 0 < marginal < prev, f"the {n}th finding must matter less, but still matter"


# ── uniformity: the fix applies to every tier, not one special case ──────────
@pytest.mark.parametrize("sev", ["critical", "high", "medium", "low"])
def test_the_curve_applies_to_every_severity_tier(sev):
    w = SEVERITY_WEIGHTS[sev]
    assert graduated_deduction(w, 1) == w
    assert graduated_deduction(w, 2) == pytest.approx(w * 1.5)
    assert graduated_deduction(w, 3) == pytest.approx(w * (1 + 0.5 + 1 / 3))


# ── the FP guard is independent of the curve ────────────────────────────────
def test_zero_weight_severities_contribute_nothing_at_any_count():
    # INFO carries weight 0. The suppressed Dart-AOT / string-index classes are either not
    # emitted at all (RUN 9/15) or INFO — so they contribute ZERO whatever the curve.
    assert SEVERITY_WEIGHTS["info"] == 0
    assert graduated_deduction(SEVERITY_WEIGHTS["info"], 500) == 0.0
    assert _app(info=500)["score"] == 100
