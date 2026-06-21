"""
Cloud Attack-Path Correlation — Phase 9.5.

Correlates the canonical secrets (9.1/9.2), their validation state (9.3) and the
cloud exposures (9.4) into CanonicalAttackPath chains — "attack chains for cloud
assets". Adds NO new providers, NO privilege enumeration, NO network calls, NO
mutations. It is a pure, deterministic transform over data already on `results`.

  HIGH   chain = validated credential + confirmed exposure
  MEDIUM chain = unvalidated credential + confirmed exposure
  LOW    chain = credential only (no confirmed exposure) — suppressed by default

Components and evidence reference only MASKED values / exposure metadata already
produced by earlier phases, so no secret is ever exposed here.
"""
from __future__ import annotations

import hashlib
import logging
import os

log = logging.getLogger("cortex.cloud_correlation")

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
_CONF_RISK = {HIGH: 95, MEDIUM: 78, LOW: 40}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─── Correlation rules (Task 2) ──────────────────────────────────────────────
# credential_types  → canonical secret `type`s that can start the chain
# exposure_types    → cloud exposure `exposure_type`s that complete it
_CHAIN_RULES = [
    {
        "id": "CLOUD_DATA_EXPOSURE_CHAIN",
        "title": "Cloud Data Exposure — AWS credential + public S3 bucket",
        "provider": "AWS",
        "credential_types": {"AWS_CREDENTIAL_PAIR"},
        "exposure_types": {"S3_PUBLIC_LISTING"},
        "severity": "critical",
        "exposure_desc": "public S3 bucket",
    },
    {
        "id": "FIREBASE_EXPOSURE_CHAIN",
        "title": "Firebase Exposure — config + public database",
        "provider": "FIREBASE",
        "credential_types": {"FIREBASE_PAIR", "FIREBASE_URL"},
        "exposure_types": {"FIREBASE_PUBLIC_READ", "FIREBASE_PUBLIC_WRITE"},
        "severity": "critical",
        "exposure_desc": "public Firebase database",
    },
    {
        "id": "GOOGLE_API_EXPOSURE_CHAIN",
        "title": "Google API Exposure — unrestricted key",
        "provider": "GOOGLE",
        "credential_types": {"GOOGLE_API_KEY", "GCP_API_KEY", "FIREBASE_PAIR"},
        "exposure_types": {"GOOGLE_KEY_UNRESTRICTED"},
        "severity": "high",
        "exposure_desc": "unrestricted Google API key",
    },
]


def correlation_enabled() -> bool:
    """Correlation is opt-in and never runs in benchmark/offline mode."""
    for var in ("CORTEX_BENCHMARK", "CORTEX_DISABLE_LIVE_CHECKS"):
        if os.environ.get(var, "").strip().lower() in ("1", "true", "yes"):
            return False
    return os.environ.get("CORTEX_ENABLE_CLOUD_CORRELATION", "0").strip().lower() in ("1", "true", "yes")


def _exposure_label(exposure: dict) -> str:
    return {
        "S3_PUBLIC_LISTING": "Public S3 Listing",
        "FIREBASE_PUBLIC_READ": "Firebase Publicly Readable",
        "FIREBASE_PUBLIC_WRITE": "Firebase Publicly Writable",
        "GOOGLE_KEY_UNRESTRICTED": "Unrestricted Google API Key",
    }.get(exposure.get("exposure_type"), exposure.get("exposure_type", "Exposure"))


def _make_chain(rule: dict, cred: dict, exposures: list[dict], confidence: str) -> dict:
    provider = rule["provider"]
    validated = cred.get("validation_result") == "valid"

    components = [
        {
            "step": 1, "kind": "credential",
            "label": f"Hardcoded {provider} Credential" + ("s" if cred.get("is_pair") else ""),
            "ref": cred.get("id"), "type": cred.get("type"),
            "masked_value": cred.get("masked_value"),
            "evidence": cred.get("evidence"),
        },
        {
            "step": 2, "kind": "validation",
            "label": "Credential Valid" if validated else "Credential Not Validated",
            "state": cred.get("validation_result"),
        },
    ]
    for i, e in enumerate(exposures, start=3):
        components.append({
            "step": i, "kind": "exposure",
            "label": _exposure_label(e), "ref": e.get("id"),
            "exposure_type": e.get("exposure_type"),
            "evidence": e.get("evidence"),
        })

    if confidence == LOW:
        severity = "low"
        summary = (f"{provider} credential present in the app, but no public cloud "
                   f"exposure was confirmed.")
    else:
        severity = rule["severity"]
        lead = "Valid" if confidence == HIGH else "Unvalidated"
        summary = (f"{lead} {provider} credential + {rule['exposure_desc']} → "
                   f"{severity} cloud exposure chain")

    exposure_ids = sorted(e.get("id", "") for e in exposures)
    cid = "BEETLE-CHAIN-" + hashlib.sha1(
        f"{rule['id']}|{cred.get('id')}|{'|'.join(exposure_ids)}".encode("utf-8", "replace")
    ).hexdigest()[:10]

    return {
        "id": cid,
        "is_cloud_chain": True,
        "rule_id": rule["id"],
        "title": rule["title"],
        "provider": provider,
        "confidence": confidence,
        "severity": severity,
        "risk_score": _CONF_RISK[confidence],
        "components": components,
        "credential_ref": cred.get("id"),
        "exposure_refs": exposure_ids,
        "summary": summary,
        "suppressed_reason": "",
    }


def correlate(secrets: list[dict], exposures: list[dict]) -> tuple[list[dict], list[dict], dict]:
    """Build attack-path chains. Returns (visible, suppressed_low, summary)."""
    visible: list[dict] = []
    suppressed: list[dict] = []
    seen: set = set()

    for rule in _CHAIN_RULES:
        creds = [s for s in secrets if s.get("type") in rule["credential_types"]]
        if not creds:
            continue
        rule_exposures = [e for e in exposures if e.get("exposure_type") in rule["exposure_types"]]
        for cred in creds:
            # Prefer exposures tied to THIS credential; fall back to untied
            # exposures of the right type (e.g. S3 listing has no source secret).
            linked = [e for e in rule_exposures
                      if (e.get("evidence") or {}).get("source_secret_id") == cred.get("id")]
            if not linked:
                linked = [e for e in rule_exposures
                          if not (e.get("evidence") or {}).get("source_secret_id")]
            if linked:
                confidence = HIGH if cred.get("validation_result") == "valid" else MEDIUM
                chain = _make_chain(rule, cred, linked, confidence)
            else:
                chain = _make_chain(rule, cred, [], LOW)
                chain["suppressed_reason"] = "low_confidence"
            if chain["id"] in seen:
                continue
            seen.add(chain["id"])
            (suppressed if chain["confidence"] == LOW else visible).append(chain)

    visible.sort(key=lambda c: (_SEV_RANK.get(c["severity"], 4), c["rule_id"], c["id"]))
    suppressed.sort(key=lambda c: (c["rule_id"], c["id"]))
    return visible, suppressed, summarize(visible)


def summarize(visible: list[dict]) -> dict:
    """Executive rollup (Task 4)."""
    critical = [c for c in visible if c["severity"] == "critical"]
    confidence = HIGH if any(c["confidence"] == HIGH for c in visible) else (
        MEDIUM if visible else "")
    return {
        "cloud_attack_chains": len(visible),
        "critical_chains": len(critical),
        "chain_confidence": confidence,
        "affected_providers": sorted({c["provider"] for c in visible}),
    }
