"""
Executive report summaries — Phase 11.95.

Builds two audience-targeted, deterministic rollups from data the pipeline has
ALREADY produced (score, severity_summary, masvs_summary, attack chains,
posture/exploitability/attack-surface scores, findings, secrets, certificate).

  results["ciso_summary"]      — business-level posture for executives.
  results["developer_summary"] — engineering remediation grouped by area.

Pure, deterministic, no network, no LLM. Reuse-only: it reads existing keys and
never re-runs an analyzer. Safe to call after masvs_intel + scoring.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cortex.report_summaries")

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_LABEL = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}


def _findings(results: dict) -> list:
    return [f for f in (results.get("findings") or []) if isinstance(f, dict)]


def _real_findings(results: dict) -> list:
    """App findings minus the synthesized attack-chain pseudo-findings."""
    return [f for f in _findings(results) if not f.get("is_attack_chain")]


def _sev_of(f: dict) -> str:
    s = str(f.get("severity") or "info").lower()
    return s if s in _SEV_RANK else "info"


def _worst_severity(findings: list) -> str:
    if not findings:
        return "info"
    return _SEV_LABEL[min(_SEV_RANK.get(_sev_of(f), 4) for f in findings)]


def _priority_for(severity: str) -> str:
    return {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}.get(severity, "P3")


# ─── CISO summary (Task 3) ───────────────────────────────────────────────────
def build_ciso_summary(results: dict) -> dict:
    score = results.get("score") or {}
    ss = results.get("severity_summary") or {}
    masvs = results.get("masvs_summary") or {}
    surf = results.get("attack_surface_score") or {}
    expl = results.get("exploitability_score") or {}
    trust = results.get("trust_score") or {}
    reach = results.get("reachability_summary") or {}
    qs = results.get("quick_summary") or {}
    chains = [c for c in (qs.get("attack_chain") or []) if isinstance(c, dict)]

    crit = int(ss.get("critical", 0) or 0)
    high = int(ss.get("high", 0) or 0)
    med = int(ss.get("medium", 0) or 0)

    risk_rating = score.get("risk") or (
        "Critical" if crit else "High" if high else "Medium" if med else "Low"
    )
    masvs_score = masvs.get("overall_score")
    masvs_maturity = masvs.get("overall_maturity") or "unknown"

    # Overall posture — one concrete sentence executives can repeat.
    grade = score.get("grade") or "—"
    grade_label = score.get("grade_label") or ""
    posture_bits = [
        f"Security grade {grade}" + (f" ({grade_label})" if grade_label else ""),
        f"{crit} critical and {high} high-severity findings",
    ]
    if masvs_score is not None:
        posture_bits.append(f"{masvs_maturity} MASVS maturity ({masvs_score}/100 coverage)")
    overall_posture = ". ".join(posture_bits) + "."

    # Most critical issue — prefer the top correlated attack chain, else worst finding.
    most_critical = ""
    if chains:
        top = chains[0]
        most_critical = top.get("title", "")
        if top.get("impact"):
            most_critical = f"{most_critical} — {top['impact']}"
    else:
        ranked = sorted(_real_findings(results), key=lambda f: _SEV_RANK.get(_sev_of(f), 4))
        if ranked:
            top = ranked[0]
            most_critical = top.get("title", "")
            if top.get("impact"):
                most_critical = f"{most_critical} — {top['impact']}"

    # Business risks — concrete, signal-driven (no generic filler).
    business_risks: list[dict] = []
    secrets = results.get("secrets") or []
    cloud_exp = results.get("cloud_exposures") or []
    by_cat = _bucket_findings(results)
    if secrets or cloud_exp:
        business_risks.append({
            "risk": "Data exposure",
            "detail": f"{len(secrets)} embedded secret(s) and {len(cloud_exp)} cloud exposure(s) "
                      "could leak customer data or backend access if extracted.",
        })
    if surf.get("exported_components"):
        business_risks.append({
            "risk": "Unauthorized access",
            "detail": f"{surf.get('exported_components')} exported component(s) "
                      f"({surf.get('high_risk_components', 0)} high-risk) widen the externally "
                      "reachable attack surface.",
        })
    if by_cat.get("Crypto") or by_cat.get("Storage"):
        business_risks.append({
            "risk": "Weak data protection",
            "detail": "Cryptography or local-storage weaknesses reduce confidentiality of "
                      "data held on the device.",
        })
    if by_cat.get("Network"):
        business_risks.append({
            "risk": "Traffic interception",
            "detail": "Network-security weaknesses expose in-transit data to man-in-the-middle attacks.",
        })
    cert = results.get("certificate") or {}
    if cert.get("debug_cert") or cert.get("expired"):
        business_risks.append({
            "risk": "Release-integrity / brand risk",
            "detail": "Signing weaknesses (debug or expired certificate) indicate a non-release "
                      "build and enable repackaging or impersonation.",
        })

    # Attack-surface concerns — reuse the posture factors + primary entry point.
    concerns = list(surf.get("factors") or [])
    if reach.get("primary_entry_point"):
        concerns.insert(0, f"Primary entry point: {reach['primary_entry_point']}")

    # Prioritized remediation — chains first, then worst app findings.
    prioritized = _prioritized_remediation(results, chains)

    return {
        "overall_posture": overall_posture,
        "risk_rating": risk_rating,
        "security_grade": grade,
        "security_score": score.get("score"),
        "trust_score": trust.get("score"),
        "security_maturity": {
            "label": masvs_maturity,
            "score": masvs_score,
            "weakest_area": masvs.get("weakest_category", ""),
            "strongest_controls": list(masvs.get("strong_controls") or [])[:6],
        },
        "most_critical_issue": most_critical,
        "business_risks": business_risks,
        "attack_surface_concerns": concerns[:6],
        "exploitability": {
            "score": expl.get("score"),
            "rating": expl.get("rating"),
            "reachable_findings": reach.get("reachable"),
        },
        "prioritized_remediation": prioritized,
    }


def _prioritized_remediation(results: dict, chains: list) -> list:
    out: list[dict] = []
    for c in chains[:3]:
        rem = ""
        # Chains carry remediation only via member findings; synthesize from impact.
        title = c.get("title", "Attack chain")
        out.append({
            "priority": _priority_for(str(c.get("severity") or "high")),
            "item": title,
            "action": "Break the chain by remediating its highest-severity step; "
                      "see the Attack Chains section for contributing findings.",
        })
    ranked = sorted(_real_findings(results), key=lambda f: _SEV_RANK.get(_sev_of(f), 4))
    seen = {o["item"] for o in out}
    for f in ranked:
        if _SEV_RANK.get(_sev_of(f), 4) > 1:  # only critical/high
            break
        title = f.get("title", "")
        if not title or title in seen:
            continue
        seen.add(title)
        expl = f.get("analyst_explanation") or {}
        action = (f.get("recommendation") or expl.get("developer_fix")
                  or (expl.get("remediation") or {}).get("summary") or "Review and remediate.")
        out.append({
            "priority": _priority_for(_sev_of(f)),
            "item": title,
            "action": str(action)[:240],
        })
        if len(out) >= 8:
            break
    return out


# ─── Developer summary (Task 4) ──────────────────────────────────────────────
# Map a finding to an engineering area using the analyst category template first
# (most reliable), then the detector's free-text category.
_TEMPLATE_AREA = {
    "WEBVIEW": "WebView",
    "CRYPTO": "Crypto",
    "NETWORK": "Network",
    "FIREBASE": "Network",
    "FILE_STORAGE": "Storage",
    "S3": "Storage",
    "SECRETS": "Secrets",
    "CERTIFICATE": "Certificate",
    "INTENT_INJECTION": "Components",
    "DEEP_LINKS": "Components",
}
_CATEGORY_AREA = {
    "WebView": "WebView",
    "Cryptography": "Crypto",
    "Network Security": "Network",
    "Data Storage": "Storage",
    "Permissions": "Permissions",
    "Certificate": "Certificate",
    "Attack Surface": "Components",
    "Deeplinks": "Components",
    "Platform Interaction": "Components",
}
# Stable display order for the eight requested areas.
_AREA_ORDER = ["WebView", "Crypto", "Network", "Storage", "Permissions",
               "Components", "Secrets", "Certificate"]

_AREA_BLURB = {
    "WebView": "WebView configuration and JavaScript bridges.",
    "Crypto": "Cryptographic primitives, key handling and randomness.",
    "Network": "Transport security and certificate validation.",
    "Storage": "Local and external data storage protection.",
    "Permissions": "Requested permissions and capability scope.",
    "Components": "Exported components, deep links and IPC surface.",
    "Secrets": "Embedded credentials and key material.",
    "Certificate": "App signing and release integrity.",
}


def _area_of(f: dict) -> str | None:
    tmpl = (f.get("analyst_explanation") or {}).get("category_template")
    if tmpl in _TEMPLATE_AREA:
        return _TEMPLATE_AREA[tmpl]
    cat = f.get("category")
    return _CATEGORY_AREA.get(cat)


def _bucket_findings(results: dict) -> dict:
    buckets: dict[str, list] = {a: [] for a in _AREA_ORDER}
    for f in _real_findings(results):
        area = _area_of(f)
        if area:
            buckets[area].append(f)
    return buckets


def build_developer_summary(results: dict) -> dict:
    buckets = _bucket_findings(results)
    groups: list[dict] = []

    for area in _AREA_ORDER:
        items = buckets.get(area) or []
        if not items:
            continue
        items = sorted(items, key=lambda f: _SEV_RANK.get(_sev_of(f), 4))
        worst = _worst_severity(items)
        rep = items[0]
        expl = rep.get("analyst_explanation") or {}

        why = (expl.get("why_dangerous") or expl.get("why_it_matters")
               or rep.get("impact") or "")
        fix = (expl.get("developer_fix") or rep.get("recommendation")
               or (expl.get("remediation") or {}).get("summary") or "")
        code_example = expl.get("code_example") or ""

        groups.append({
            "area": area,
            "blurb": _AREA_BLURB[area],
            "count": len(items),
            "max_severity": worst,
            "priority": _priority_for(worst),
            "what_found": [
                {
                    "title": f.get("title", ""),
                    "severity": _sev_of(f),
                    "file": f.get("file_path") or "",
                    "line": f.get("line") or f.get("line_number"),
                }
                for f in items[:5]
            ],
            "why_dangerous": str(why)[:400],
            "fix": str(fix)[:400],
            "code_example": str(code_example)[:600],
            "masvs": (expl.get("remediation") or {}).get("masvs") or rep.get("masvs") or "",
        })

    covered = sum(g["count"] for g in groups)
    return {
        "groups": groups,
        "group_count": len(groups),
        "covered_findings": covered,
        "areas_with_issues": [g["area"] for g in groups],
    }


# ─── Entry point ─────────────────────────────────────────────────────────────
def annotate(results: dict) -> None:
    """Populate results["ciso_summary"] and results["developer_summary"]."""
    try:
        results["ciso_summary"] = build_ciso_summary(results)
    except Exception:
        log.exception("[report_summaries] CISO summary failed")
        results["ciso_summary"] = {}
    try:
        results["developer_summary"] = build_developer_summary(results)
    except Exception:
        log.exception("[report_summaries] developer summary failed")
        results["developer_summary"] = {"groups": []}
    log.info("[report_summaries] ciso=%s dev_groups=%d",
             (results.get("ciso_summary") or {}).get("risk_rating"),
             len((results.get("developer_summary") or {}).get("groups") or []))
