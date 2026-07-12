# Cortex Security Scoring Engine
# Weighted score 0-100 with letter grade

from .security_controls import is_present
from .common import compute_severity_summary

SEVERITY_WEIGHTS = {
    "critical": 15,
    "high":      8,
    "medium":    3,
    "low":       1,
    "info":      0,
}

# Good-practice bonuses, awarded strictly from the resolved security-control states.
# Order is fixed so `bonuses` renders identically across runs.
CONTROL_BONUSES = (
    ("frida_detection",          "Frida detection implemented",   2),
    ("root_detection",           "Root detection implemented",    3),
    ("flag_secure",              "Screenshot prevention enabled", 2),
    ("safetynet_play_integrity", "SafetyNet/Play Integrity used", 3),
    ("sqlcipher",                "SQLCipher encryption used",     3),
    ("cert_pinning",             "Certificate pinning detected",  5),
    ("obfuscation",              "Code obfuscation enabled",      3),
)

GRADE_THRESHOLDS = [
    (90, "A", "Excellent",  "Very few issues detected. App demonstrates strong security practices."),
    (75, "B", "Good",       "Minor issues detected. Overall security posture is reasonable."),
    (60, "C", "Fair",       "Moderate security issues detected. Several items require attention."),
    (40, "D", "Poor",       "Significant security issues found. Immediate remediation recommended."),
    (0,  "F", "Critical",   "Critical security vulnerabilities detected. App poses serious risk to users."),
]


# Grade ordering, worst -> best, for composing the score-grade with the semantic ceiling.
_GRADE_ORDER = ["F", "D", "C", "B", "A"]
_GRADE_META = {
    "A": ("Excellent",  "Very few issues detected. App demonstrates strong security practices."),
    "B": ("Good",       "Minor issues detected. Overall security posture is reasonable."),
    "C": ("Fair",       "Moderate security issues detected. Several items require attention."),
    "D": ("Poor",       "Significant security issues found. Immediate remediation recommended."),
    "F": ("Critical",   "Critical security vulnerabilities detected. App poses serious risk to users."),
}


def _apply_semantic_ceiling(grade, label, desc, ss, secrets, score):
    """Cap the score-based grade by what the app actually SHIPS (RUN 15.2).

    A/Excellent is a clean bill: no real finding ABOVE INFO — i.e. no LOW, MEDIUM, HIGH or
    CRITICAL (findings OR secrets). A LOW is still a real, evidence-backed issue, so an app that
    carries one is "very good, minor issues" (B), not a clean bill. B/Good tolerates LOW and
    MEDIUM but nothing HIGH/CRITICAL. The ceiling only ever LOWERS the grade. Returns
    (grade, label, desc, reason) with a reason that names the gating findings.
    """
    crit = int(ss.get("critical", 0) or 0)
    high = int(ss.get("high", 0) or 0)
    med = int(ss.get("medium", 0) or 0)
    low = int(ss.get("low", 0) or 0)
    # Secrets are scored on their DISPLAY severity, so an INFO client key never gates the grade;
    # a real LOW-or-higher secret does.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    secret_worst = max((sev_rank.get(str(s.get("display_severity") or s.get("severity") or "info").lower(), 0)
                        for s in (secrets or [])), default=0)

    if crit or high or secret_worst >= 3:
        ceiling, why = "C", ("nothing HIGH or CRITICAL may grade above Fair — this app has "
                             f"{crit} critical and {high} high-severity finding(s)"
                             + (" plus a high-severity secret" if secret_worst >= 3 else ""))
    elif med or secret_worst >= 2:
        ceiling, why = "B", (f"a clean bill (Excellent) requires no finding above INFO — "
                             f"this app has {med} real MEDIUM finding(s)"
                             + (f" and {low} LOW" if low else "")
                             + (" and a medium-severity secret" if secret_worst >= 2 else ""))
    elif low or secret_worst >= 1:
        ceiling, why = "B", (f"a clean bill (Excellent) requires no finding above INFO — "
                             f"this app has {low} real LOW finding(s)"
                             + (" and a low-severity secret" if secret_worst >= 1 else ""))
    else:
        ceiling, why = "A", "no findings above INFO"

    # Grade = the WORSE (lower) of the score-band grade and the semantic ceiling.
    final = grade if _GRADE_ORDER.index(grade) <= _GRADE_ORDER.index(ceiling) else ceiling
    if final == grade:
        # Score-band already at/below the ceiling — the number is the binding constraint.
        reason = f"Score {score} in the {label} band; {why}."
        return grade, label, desc, reason
    # The ceiling lowered the grade: the app scored higher but its findings forbid that band.
    new_label, new_desc = _GRADE_META[final]
    reason = (f"Score {score} would place this in the {label} band, but capped at "
              f"{final}/{new_label}: {why}.")
    return final, new_label, new_desc, reason


def graduated_deduction(weight: float, count: int) -> float:
    """Diminishing MARGINAL weight: the i-th finding of a severity deducts ``weight / i``.

    REPLACES a flat cap (min(weight*count, 3*weight)), which was a CLIFF: it gave full weight
    to the first three findings and then charged nothing at all. Under it, 4 MEDIUMs and 40
    MEDIUMs scored identically — accumulation simply did not register. The same flattening bit
    on LOW: 36 lows deducted 3 points, which is why removing 34 false-positive lows in RUN 15
    recovered only a single point.

    THE CURVE IS CHOSEN BY ITS SHAPE, NEVER BY THE NUMBER IT PRODUCES:

      * The 1st finding of a severity costs full weight — severity is never discounted away.
      * Every additional finding STILL moves the score (weight/2, weight/3, …), so volume
        registers, which is the defect being fixed.
      * The sum grows like ln(n): unbounded, but slowly enough that VOLUME CAN NEVER OVERTAKE
        SEVERITY at any count. 1000 LOWs deduct ~7.5 points and still cost less than a single
        CRITICAL (15). This is the property the old cap existed to protect, and it survives.
        (A gentler curve such as weight/sqrt(i) fails exactly here: 56 LOWs would outweigh a
        CRITICAL.)

    Harmonic decay is the canonical "the Nth matters less than the 1st, but still matters" law,
    and it is the only one of the candidates that holds both properties at once.
    """
    if weight <= 0 or count <= 0:
        return 0.0
    return float(weight) * sum(1.0 / i for i in range(1, int(count) + 1))


def calculate_score(results: dict) -> dict:
    """
    Calculate a weighted security score from findings and secrets.
    Returns score dict with value (0-100), grade (A-F), and breakdown.
    """
    findings = results.get("findings", [])
    secrets  = results.get("secrets",  [])
    # Recompute the severity rollup from the CURRENT (post-triage) findings and write
    # it back, so the report header, CISO summary, and this deduction table — which
    # all read results["severity_summary"] — are derived from one identical snapshot
    # and can never disagree (e.g. header MEDIUM == score-table MEDIUM).
    ss = compute_severity_summary(findings)
    results["severity_summary"] = ss

    deductions = {}
    total_deducted = 0

    # Findings deductions
    for sev, weight in SEVERITY_WEIGHTS.items():
        count = ss.get(sev, 0)
        if count and weight > 0:
            deducted = graduated_deduction(weight, count)
            raw = weight * count
            deductions[sev] = {
                "count": count, "per_item": weight,
                "total": round(deducted, 2),
                "raw_total": raw,
                # Kept for renderers that label a discounted row. The discount is now a
                # curve, not a cliff.
                "capped": deducted < raw,
                "cap": None,
                "curve": "harmonic",
                "marginal_weights": [round(weight / i, 2) for i in range(1, min(count, 6) + 1)],
            }
            total_deducted += deducted

    # Secrets deductions — use the mapped DISPLAY severity (status-derived) so a
    # client/public key or a hidden FP contributes 0 (INFO, weight 0) and only real
    # confidential secrets move the score.
    secret_deductions = 0
    secret_sev_counts = {}
    for s in secrets:
        sev = s.get("display_severity") or s.get("severity") or "medium"
        secret_sev_counts[sev] = secret_sev_counts.get(sev, 0) + 1

    for sev, count in secret_sev_counts.items():
        weight = SEVERITY_WEIGHTS.get(sev, 3)
        # Same curve as findings — the flattening defect was uniform, so the fix is uniform.
        secret_deductions += graduated_deduction(weight, count)
    secret_deductions = round(secret_deductions, 2)

    total_deducted += secret_deductions

    # ── Phase 7 Task 7 — factor-based posture breakdown ───────────────────────
    # A descriptive per-factor view (Attack Chains, SSL, Exported Components,
    # Secrets, WebView, Certificates, Cleartext) PLUS a small extra penalty for
    # correlated/reachable risk that the per-severity deductions undercount: an
    # attack chain is worse than the sum of its individually-counted findings.
    factors, chain_penalty = _security_factors(results, findings, secrets)
    total_deducted += chain_penalty

    # Bonus points for good practices. Presence is decided once, by
    # security_controls.resolve(), from positive evidence only — a finding that says
    # a control is MISSING can no longer pay that control's bonus. `is_present`
    # excludes `partial`, so pinning that debug-overrides can switch off earns nothing.
    bonuses = []
    platform = results.get("platform", "android")

    if platform == "android":
        for control, label, points in CONTROL_BONUSES:
            if is_present(results, control):
                bonuses.append((label, points))

    total_bonus = sum(b[1] for b in bonuses)

    raw_score = max(0, min(100, 100 - total_deducted + total_bonus))
    score = round(raw_score)

    # Letter grade — the NUMBER picks a band, then a SEMANTIC CEILING can only lower it
    # (RUN 15.2). The grade is a meaning label on the honest score, and the top bands are
    # defined by what the app actually ships, not by arithmetic alone:
    #   A/Excellent = a clean bill — NO real finding at MEDIUM or above (findings or secrets).
    #   B/Good      = real but limited findings, nothing HIGH/CRITICAL.
    # So one real MEDIUM forbids A, and one HIGH/CRITICAL forbids B, no matter how high the
    # score. The ceiling never RAISES a grade, so a low score still grades low.
    grade_info = GRADE_THRESHOLDS[-1]
    for threshold, grade, label, desc in GRADE_THRESHOLDS:
        if score >= threshold:
            grade_info = (threshold, grade, label, desc)
            break

    _, grade, grade_label, grade_desc = grade_info
    grade, grade_label, grade_desc, grade_reason = _apply_semantic_ceiling(
        grade, grade_label, grade_desc, ss, secrets, score)

    # Risk level (matches findings)
    if ss.get("critical", 0) > 0:
        risk = "Critical"
    elif ss.get("high", 0) > 0:
        risk = "High"
    elif ss.get("medium", 0) > 0:
        risk = "Medium"
    elif ss.get("low", 0) > 0:
        risk = "Low"
    else:
        risk = "Minimal"

    return {
        "score":          score,
        "grade":          grade,
        "grade_label":    grade_label,
        "grade_desc":     grade_desc,
        "risk":           risk,
        "total_deducted": total_deducted,
        "deductions":     deductions,
        "secret_deductions": secret_deductions,
        "bonuses":        bonuses,
        "total_bonus":    total_bonus,
        "factors":        factors,
        "chain_penalty":  chain_penalty,
        "grade_reason":   grade_reason,
    }


def _security_factors(results: dict, findings: list, secrets: list) -> tuple[dict, int]:
    """Phase 7 Task 7 — per-factor posture breakdown + a correlated-risk penalty.

    Returns (factors, extra_deduction). `factors` is descriptive (no double
    counting with the severity deductions); the extra deduction only reflects
    reachable attack chains and overall exploitability, which the per-finding
    severity model undercounts.
    """
    def _blob(f):
        return (str(f.get("title", "")) + " " + str(f.get("category", ""))).lower()

    qs = results.get("quick_summary", {}) or {}
    chains = qs.get("attack_chain", []) or []
    chain_count = qs.get("chain_count", len(chains))
    exploit = (results.get("exploitability_score") or {}).get("score", 0) or 0
    surf = results.get("attack_surface_score") or {}
    inv = results.get("exported_component_inventory") or {}

    ssl_issues = sum(1 for f in findings if "ssl" in _blob(f) or "certificate errors" in _blob(f))
    webview_risks = sum(1 for f in findings if f.get("category") == "WebView")
    cert_issues = sum(1 for f in findings if f.get("category") == "Certificate"
                      and f.get("severity") in ("critical", "high", "medium"))
    cleartext = sum(1 for f in findings if "cleartext" in _blob(f))
    exported = inv.get("exported_total", 0)

    def _status(n, hi=1):
        return "issues" if n >= hi else "ok"

    factors = {
        "attack_chains":      {"count": chain_count, "status": "issues" if chain_count else "ok"},
        "ssl_issues":         {"count": ssl_issues, "status": _status(ssl_issues)},
        "exported_components": {"count": exported, "status": "review" if exported else "ok",
                                "score": surf.get("score", 0), "rating": surf.get("rating", "low")},
        "secrets":            {"count": len(secrets), "status": _status(len(secrets))},
        "webview_risks":      {"count": webview_risks, "status": _status(webview_risks)},
        "certificates":       {"count": cert_issues, "status": _status(cert_issues)},
        "cleartext_traffic":  {"count": cleartext, "status": _status(cleartext)},
        "exploitability":     {"score": exploit,
                               "rating": (results.get("exploitability_score") or {}).get("rating", "low")},
    }

    # Correlated-risk penalty: chains (5 each, cap 20) + a high-exploitability tax.
    penalty = min(chain_count * 5, 20)
    if exploit >= 80:
        penalty += 10
    elif exploit >= 60:
        penalty += 5
    return factors, penalty
