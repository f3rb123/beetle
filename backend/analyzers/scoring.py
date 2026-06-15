# Cortex Security Scoring Engine
# Weighted score 0-100 with letter grade

SEVERITY_WEIGHTS = {
    "critical": 15,
    "high":      8,
    "medium":    3,
    "low":       1,
    "info":      0,
}

GRADE_THRESHOLDS = [
    (90, "A", "Excellent",  "Very few issues detected. App demonstrates strong security practices."),
    (75, "B", "Good",       "Minor issues detected. Overall security posture is reasonable."),
    (60, "C", "Fair",       "Moderate security issues detected. Several items require attention."),
    (40, "D", "Poor",       "Significant security issues found. Immediate remediation recommended."),
    (0,  "F", "Critical",   "Critical security vulnerabilities detected. App poses serious risk to users."),
]


def calculate_score(results: dict) -> dict:
    """
    Calculate a weighted security score from findings and secrets.
    Returns score dict with value (0-100), grade (A-F), and breakdown.
    """
    findings = results.get("findings", [])
    secrets  = results.get("secrets",  [])
    ss       = results.get("severity_summary", {})

    deductions = {}
    total_deducted = 0

    # Findings deductions
    for sev, weight in SEVERITY_WEIGHTS.items():
        count = ss.get(sev, 0)
        if count and weight > 0:
            # Diminishing returns for many findings of same severity
            deducted = min(weight * count, weight * 3)  # cap at 3x weight per severity
            deductions[sev] = {"count": count, "per_item": weight, "total": deducted}
            total_deducted += deducted

    # Secrets deductions
    secret_deductions = 0
    secret_sev_counts = {}
    for s in secrets:
        sev = s.get("severity", "medium")
        secret_sev_counts[sev] = secret_sev_counts.get(sev, 0) + 1

    for sev, count in secret_sev_counts.items():
        weight = SEVERITY_WEIGHTS.get(sev, 3)
        deducted = min(weight * count, weight * 3)
        secret_deductions += deducted

    total_deducted += secret_deductions

    # Bonus points for good practices
    bonuses = []
    platform = results.get("platform", "android")

    if platform == "android":
        finding_titles = [f.get("title", "").lower() for f in findings]
        all_text = " ".join(finding_titles + [f.get("description", "").lower() for f in findings])

        if "frida detection" in all_text:           bonuses.append(("Frida detection implemented", 2))
        if "root detection" in all_text:            bonuses.append(("Root detection implemented", 3))
        if "flag_secure" in all_text:               bonuses.append(("Screenshot prevention enabled", 2))
        if "safetynet" in all_text or "play integrity" in all_text:
            bonuses.append(("SafetyNet/Play Integrity used", 3))
        if "sqlcipher" in all_text:                 bonuses.append(("SQLCipher encryption used", 3))
        if "certificate pinning" in all_text:       bonuses.append(("Certificate pinning detected", 5))

        # Only give obfuscation bonus if "not detected" finding is NOT present
        obf_not_detected = any("obfuscation not detected" in t for t in finding_titles)
        obf_detected = any("obfuscation detected" in t and "not" not in t for t in finding_titles)
        if obf_detected and not obf_not_detected:
            bonuses.append(("Code obfuscation enabled", 3))

    total_bonus = sum(b[1] for b in bonuses)

    raw_score = max(0, min(100, 100 - total_deducted + total_bonus))
    score = round(raw_score)

    # Letter grade
    grade_info = GRADE_THRESHOLDS[-1]
    for threshold, grade, label, desc in GRADE_THRESHOLDS:
        if score >= threshold:
            grade_info = (threshold, grade, label, desc)
            break

    _, grade, grade_label, grade_desc = grade_info

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
        "bonuses":        bonuses,
        "total_bonus":    total_bonus,
    }
