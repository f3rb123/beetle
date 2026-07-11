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
            # Diminishing returns for many findings of same severity: the per-severity
            # deduction is capped at 3x the weight. Record whether the cap bit and the
            # uncapped raw total so the renderer can label it ("capped at 3x") and the
            # shown count x per_item never invites wrong arithmetic.
            raw = weight * count
            deducted = min(raw, weight * 3)  # cap at 3x weight per severity
            deductions[sev] = {
                "count": count, "per_item": weight, "total": deducted,
                "raw_total": raw, "capped": deducted < raw, "cap": weight * 3,
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
        deducted = min(weight * count, weight * 3)
        secret_deductions += deducted

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
        "secret_deductions": secret_deductions,
        "bonuses":        bonuses,
        "total_bonus":    total_bonus,
        "factors":        factors,
        "chain_penalty":  chain_penalty,
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
