"""
MASVS Coverage Intelligence — Phase 11.

Measures security POSTURE — how much of the OWASP MASVS is implemented — rather
than counting vulnerabilities or exploitability. For each MASVS category it
weighs the weaknesses found against the positive controls detected and produces a
0-100 coverage score + a maturity label, so Beetle can say "Cryptography maturity
is weak" instead of "5 crypto findings".

Pure, deterministic, no network (Task 8). Runs after analyst_intel (reuses the
MASVS mapping it already attached to each finding).

Emits:
  results["masvs_coverage"] — list[CanonicalMasvsCoverage]
  results["masvs_summary"]  — weakness analysis + executive rollup
"""
from __future__ import annotations

import json
import logging

log = logging.getLogger("cortex.masvs_intel")

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

# ─── The eight MASVS v2 categories + their expected controls ─────────────────
CATEGORIES = [
    "MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK",
    "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE", "MASVS-PRIVACY",
]

_EXPECTED_CONTROLS = {
    "MASVS-STORAGE":    ["Encrypted Storage", "No Sensitive Data in External Storage"],
    "MASVS-CRYPTO":     ["Strong Cryptography", "Keystore/Keychain-backed Keys", "No Hardcoded Keys"],
    "MASVS-AUTH":       ["Biometric Authentication", "Secure Credential Handling"],
    "MASVS-NETWORK":    ["Network Security Config", "Certificate Pinning", "No Cleartext Traffic"],
    "MASVS-PLATFORM":   ["Safe WebView Configuration", "Protected Components", "Validated Deep Links"],
    "MASVS-CODE":       ["Safe Input Handling", "Up-to-date Dependencies"],
    "MASVS-RESILIENCE": ["Root/Tamper Detection", "Integrity / Attestation", "Strong App Signing"],
    "MASVS-PRIVACY":    ["Minimal Permissions", "Data Minimization"],
}

# ─── Positive control signals (Task 3) — name, category, detection patterns ──
# Detected over a POSITIVE corpus (manifest/config/behavior/INFO-control findings)
# so a weakness finding that merely *names* a control does not count as present.
_SIGNALS = [
    ("Network Security Config", "MASVS-NETWORK",
     ("networksecurityconfig", "network_security_config", "android:networksecurityconfig")),
    ("Certificate Pinning", "MASVS-NETWORK",
     ("certificatepinner", "certificate pinning", "pin-set", "pinset", "public-key-pins", "trustkit")),
    ("No Cleartext Traffic", "MASVS-NETWORK",
     ("cleartexttrafficpermitted=\"false\"", "usescleartexttraffic=\"false\"", "cleartext disabled")),
    ("Biometric Authentication", "MASVS-AUTH",
     ("biometricprompt", "biometricmanager", "fingerprintmanager", "use_biometric",
      "use_fingerprint", "localauthentication", "lacontext", "setuserauthenticationrequired")),
    ("Encrypted Storage", "MASVS-STORAGE",
     ("encryptedsharedpreferences", "encryptedfile", "androidx.security.crypto", "masterkey",
      "kSecAttrAccessible".lower())),
    ("Keystore/Keychain-backed Keys", "MASVS-CRYPTO",
     ("androidkeystore", "android keystore", "keychain", "seckey", "keygenparameterspec")),
    ("Root/Tamper Detection", "MASVS-RESILIENCE",
     ("root detection", "rootbeer", "tamper", "jailbreak detection")),
    ("Integrity / Attestation", "MASVS-RESILIENCE",
     ("playintegrity", "play integrity", "safetynet", "attestation", "dcdevice")),
    ("Strong App Signing", "MASVS-RESILIENCE",
     ("signature scheme v2", "signature scheme v3", "apk signature scheme v2", "v2/v3 signed")),
]

_NEGATION = ("no ", "not ", "without", "missing", "disabled", "absent", "lack",
             "insecure", "weak", "vulnerab")

# Severity → weakness penalty weight.
_SEV_PEN = {"critical": 22, "high": 14, "medium": 7, "low": 3, "info": 0}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _base_category(masvs: str) -> str:
    """'MASVS-CRYPTO-1' -> 'MASVS-CRYPTO'; validated against the 8 categories."""
    if not masvs:
        return ""
    parts = str(masvs).upper().split("-")
    if len(parts) >= 2:
        base = f"{parts[0]}-{parts[1]}"
        if base in _EXPECTED_CONTROLS:
            return base
    return ""


def _finding_category(finding: dict) -> str:
    """Resolve a finding to a MASVS base category (Task 2)."""
    cat = _base_category(finding.get("masvs"))
    if cat:
        return cat
    expl = finding.get("analyst_explanation") or {}
    cat = _base_category((expl.get("remediation") or {}).get("masvs"))
    if cat:
        return cat
    # Fall back to the analyst category template's implied area.
    tmpl = expl.get("category_template", "")
    fallback = {
        "WEBVIEW": "MASVS-PLATFORM", "DEEP_LINKS": "MASVS-PLATFORM",
        "INTENT_INJECTION": "MASVS-PLATFORM", "CRYPTO": "MASVS-CRYPTO",
        "SECRETS": "MASVS-CRYPTO", "NETWORK": "MASVS-NETWORK",
        "FIREBASE": "MASVS-NETWORK", "S3": "MASVS-STORAGE",
        "FILE_STORAGE": "MASVS-STORAGE", "CERTIFICATE": "MASVS-RESILIENCE",
        "ROOT_DETECTION": "MASVS-RESILIENCE", "SQL_INJECTION": "MASVS-CODE",
    }.get(tmpl, "")
    return fallback or "MASVS-CODE"


def _positive_corpus(results: dict) -> str:
    """Build a lowercase corpus biased toward POSITIVE controls so weakness
    findings that merely name a control do not count as 'present'."""
    parts: list[str] = []
    mx = results.get("manifest_xml")
    if isinstance(mx, str):
        parts.append(mx)
    nc = results.get("network_config")
    if nc:
        parts.append(json.dumps(nc, default=str))
    for b in results.get("behavior_analysis") or []:
        if isinstance(b, dict):
            parts.append(str(b.get("title", "")) + " " + str(b.get("description", "")))
    for p in results.get("manifest_permissions") or results.get("permissions") or []:
        parts.append(str(p if isinstance(p, str) else (p.get("name", "") if isinstance(p, dict) else "")))
    # INFO / security-control findings indicate a control is PRESENT.
    for f in results.get("findings") or []:
        if not isinstance(f, dict):
            continue
        if f.get("security_control") or str(f.get("severity")) == "info":
            parts.append(" ".join(str(f.get(k, "")) for k in ("title", "description", "snippet", "code_context")))
    return " ".join(parts).lower()


def _detect_controls(results: dict) -> dict[str, list[str]]:
    """Detect present positive controls per category (Task 3)."""
    corpus = _positive_corpus(results)
    present: dict[str, list[str]] = {c: [] for c in CATEGORIES}
    for name, category, patterns in _SIGNALS:
        for pat in patterns:
            idx = corpus.find(pat)
            if idx == -1:
                continue
            window = corpus[max(0, idx - 24):idx]
            if any(neg in window for neg in _NEGATION):
                continue  # "no certificate pinning" must not count as present
            if name not in present[category]:
                present[category].append(name)
            break
    return present


def _maturity(score: int) -> str:
    return "strong" if score >= 75 else ("moderate" if score >= 45 else "weak")


def build_coverage(results: dict) -> list[dict]:
    """Build the per-category CanonicalMasvsCoverage list (Task 1/4)."""
    findings = [f for f in (results.get("findings") or []) if isinstance(f, dict)
                and not f.get("is_attack_chain")]
    by_cat: dict[str, list[dict]] = {c: [] for c in CATEGORIES}
    for f in findings:
        by_cat[_finding_category(f)].append(f)

    present = _detect_controls(results)
    coverage: list[dict] = []
    for cat in CATEGORIES:
        expected = _EXPECTED_CONTROLS[cat]
        controls_present = present[cat]
        controls_missing = [c for c in expected if c not in controls_present]

        cat_findings = by_cat[cat]
        penalty = min(40, sum(_SEV_PEN.get(f.get("severity", "info"), 0) for f in cat_findings))
        present_ratio = (len(controls_present) / len(expected)) if expected else 0.0
        control_score = present_ratio * 60.0
        hygiene = 40.0 - penalty
        score = int(round(max(0.0, min(100.0, control_score + hygiene))))

        signals = len(cat_findings) + len(controls_present)
        confidence = HIGH if signals >= 3 else (MEDIUM if signals >= 1 else LOW)

        worst = sorted(cat_findings, key=lambda f: _SEV_RANK.get(f.get("severity", "info"), 4))
        coverage.append({
            "category": cat,
            "controls_present": controls_present,
            "controls_missing": controls_missing,
            "score": score,
            "maturity": _maturity(score),
            "confidence": confidence,
            "evidence": {
                "controls": controls_present,
                "finding_count": len(cat_findings),
                "weaknesses": [{"title": f.get("title"), "severity": f.get("severity")}
                               for f in worst[:5]],
            },
        })
    return coverage


def _risk_weight(f: dict) -> int:
    return {"critical": 3, "high": 2, "medium": 1}.get(f.get("severity"), 0)


def build_summary(results: dict, coverage: list[dict]) -> dict:
    """Weakness analysis (Task 5) + executive rollup (Task 6)."""
    findings = [f for f in (results.get("findings") or []) if isinstance(f, dict)
                and not f.get("is_attack_chain")]
    risk_by_cat: dict[str, int] = {c: 0 for c in CATEGORIES}
    count_by_cat: dict[str, int] = {c: 0 for c in CATEGORIES}
    for f in findings:
        cat = _finding_category(f)
        risk_by_cat[cat] += _risk_weight(f)
        count_by_cat[cat] += 1

    by_score = sorted(coverage, key=lambda c: (c["score"], c["category"]))
    weakest = by_score[0]["category"] if by_score else ""
    highest_risk = max(CATEGORIES, key=lambda c: (risk_by_cat[c], -CATEGORIES.index(c)))
    most_findings = max(CATEGORIES, key=lambda c: (count_by_cat[c], -CATEGORIES.index(c)))

    overall = int(round(sum(c["score"] for c in coverage) / len(coverage))) if coverage else 0
    strong_controls = sorted({ctrl for c in coverage for ctrl in c["controls_present"]})

    return {
        "overall_score": overall,
        "overall_maturity": _maturity(overall),
        "weakest_category": weakest,
        "weakest_maturity": _maturity(by_score[0]["score"]) if by_score else "",
        "highest_risk_category": highest_risk if risk_by_cat[highest_risk] else "",
        "most_findings_category": most_findings if count_by_cat[most_findings] else "",
        "top_weaknesses": [
            {"category": c["category"], "score": c["score"], "maturity": c["maturity"]}
            for c in by_score[:3]
        ],
        "strong_controls": strong_controls,
        "coverage_radar": [{"category": c["category"], "score": c["score"]} for c in coverage],
    }


def annotate(results: dict) -> dict:
    """Build results["masvs_coverage"] + results["masvs_summary"]. Deterministic."""
    coverage = build_coverage(results)
    summary = build_summary(results, coverage)
    results["masvs_coverage"] = coverage
    results["masvs_summary"] = summary
    log.info("[masvs_intel] overall=%d (%s) weakest=%s controls=%d",
             summary["overall_score"], summary["overall_maturity"],
             summary["weakest_category"], len(summary["strong_controls"]))
    return summary
