"""
Secret Intelligence — Phase 9.1 (safety foundation).

Normalizes every detected secret into a single CanonicalSecret shape and — most
importantly — MASKS the raw value before anything is serialized, logged, sent
over SSE, exported to PDF, or rendered in the UI. This module adds NO network
calls and NO new detections; it is purely a safety + normalization layer that
runs once in finalize after all secret producers have populated
`results["secrets"]`.

Responsibilities (Phase 9.1):
  * Canonical model        — one object shape for every secret (Task 1).
  * Masking                — raw values never reach a sink (Task 2).
  * Provider/type tagging  — route loose detector dicts to a stable provider/type
                             using the existing detector names (Task 3).
  * Evidence gate          — file + line + snippet required, else drop (Task 4).
  * Ownership suppression  — APPLICATION (and UNKNOWN) shown; THIRD_PARTY_LIBRARY
                             and FRAMEWORK suppressed but counted (Task 5).
  * Confidence suppression — LOW confidence kept in data, hidden by default,
                             counted (Task 6).
  * Executive summary      — results["secrets_summary"] (Task 7).

Validation is NOT performed here. `validation_result` is mapped from any legacy
result already on the secret (the live-probe feature), otherwise "skipped".
Provider validation / privilege enumeration arrives in later phases.

Contract: the raw secret value is read once to build the masked form + hash,
then OVERWRITTEN in place. After process_secrets() runs, no dict in
results["secrets"] / results["suppressed_secrets"] carries a raw value.
"""
from __future__ import annotations

import hashlib
import logging

from .finding_model import classify_ownership, classify_ownership_label

log = logging.getLogger("cortex.secret_intel")

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

APPLICATION = "APPLICATION"
THIRD_PARTY_LIBRARY = "THIRD_PARTY_LIBRARY"
FRAMEWORK = "FRAMEWORK"
UNKNOWN = "UNKNOWN"


# ─── Provider / type tagging (Task 3) ────────────────────────────────────────
# Keyed on the detector's `name` (the string the existing patterns already emit).
# This reuses the existing detections — it does NOT add new ones.
_PROVIDER_MAP: dict[str, tuple[str, str]] = {
    "AWS Access Key ID":            ("AWS", "AWS_ACCESS_KEY"),
    "AWS Secret Access Key":        ("AWS", "AWS_SECRET_KEY"),
    "Google API Key":               ("GOOGLE", "GOOGLE_API_KEY"),
    "Firebase Realtime Database URL": ("FIREBASE", "FIREBASE_URL"),
    "FCM Server Key":               ("FIREBASE", "FCM_SERVER_KEY"),
    "Stripe Live Secret Key":       ("STRIPE", "STRIPE_SECRET"),
    "Stripe Test Key":              ("STRIPE", "STRIPE_SECRET"),
    "Stripe Publishable Key":       ("STRIPE", "STRIPE_PUBLISHABLE"),
    "GitHub Personal Access Token": ("GITHUB", "GITHUB_PAT"),
    "Slack OAuth Token":            ("SLACK", "SLACK_OAUTH_TOKEN"),
    "Slack Webhook URL":            ("SLACK", "SLACK_WEBHOOK"),
    "SendGrid API Key":             ("SENDGRID", "SENDGRID_API_KEY"),
    "Twilio Account SID":           ("TWILIO", "TWILIO_ACCOUNT_SID"),
    "Twilio Auth Token":            ("TWILIO", "TWILIO_AUTH_TOKEN"),
    "OpenAI API Key":               ("OPENAI", "OPENAI_API_KEY"),
    "Anthropic API Key":            ("ANTHROPIC", "ANTHROPIC_API_KEY"),
    "HuggingFace API Token":        ("HUGGINGFACE", "HUGGINGFACE_TOKEN"),
    "Mailgun API Key":              ("MAILGUN", "MAILGUN_API_KEY"),
    "Mailchimp API Key":            ("MAILCHIMP", "MAILCHIMP_API_KEY"),
    "Shopify Access Token":         ("SHOPIFY", "SHOPIFY_ACCESS_TOKEN"),
    "Shopify Storefront Token":     ("SHOPIFY", "SHOPIFY_STOREFRONT_TOKEN"),
    "Azure Storage Account Key":    ("AZURE", "AZURE_STORAGE_KEY"),
    "Azure Connection String":      ("AZURE", "AZURE_CONNECTION_STRING"),
    "GCP Service Account Key":      ("GCP", "GCP_SERVICE_ACCOUNT_KEY"),
    "PEM Private Key":              ("PRIVATE_KEY", "PEM_PRIVATE_KEY"),
    "Apple Push Notification Key":  ("APPLE", "APNS_AUTH_KEY"),
    "Cloudflare API Token":         ("CLOUDFLARE", "CLOUDFLARE_API_TOKEN"),
    "Cloudflare Global API Key":    ("CLOUDFLARE", "CLOUDFLARE_GLOBAL_KEY"),
    "Facebook App Secret":          ("FACEBOOK", "FACEBOOK_APP_SECRET"),
    "npm Publish Token":            ("NPM", "NPM_TOKEN"),
    "Docker Hub Token":             ("DOCKER", "DOCKER_TOKEN"),
    "Mapbox Access Token":          ("MAPBOX", "MAPBOX_TOKEN"),
    "Supabase Service Role Key":    ("SUPABASE", "SUPABASE_SERVICE_KEY"),
    "Algolia Admin API Key":        ("ALGOLIA", "ALGOLIA_ADMIN_KEY"),
    "Sentry Auth Token":            ("SENTRY", "SENTRY_AUTH_TOKEN"),
    "Square Access Token":          ("SQUARE", "SQUARE_ACCESS_TOKEN"),
    "Okta API Token":               ("OKTA", "OKTA_API_TOKEN"),
    "Databricks Token":             ("DATABRICKS", "DATABRICKS_TOKEN"),
    "GCP API Key":                  ("GCP", "GCP_API_KEY"),
    "Basic Auth in URL":            ("GENERIC", "BASIC_AUTH_URL"),
    "Hardcoded Password":           ("GENERIC", "HARDCODED_PASSWORD"),
    "Hardcoded Username":           ("GENERIC", "HARDCODED_USERNAME"),
    "Generic API Key":              ("GENERIC", "GENERIC_API_KEY"),
}

# Detector names whose pattern is inherently weak/generic — always LOW unless
# a future phase validates them live.
_WEAK_DETECTORS = {
    "Generic API Key", "Hardcoded Password", "Hardcoded Username",
}


def tag_provider(name: str, value: str) -> tuple[str, str]:
    """Map a detector name to (provider, type). Falls back to a GENERIC type
    derived from the detector name so nothing is ever left untagged."""
    if name in _PROVIDER_MAP:
        return _PROVIDER_MAP[name]
    slug = "".join(c if c.isalnum() else "_" for c in (name or "secret")).upper().strip("_")
    return "GENERIC", slug or "GENERIC_SECRET"


# ─── Masking (Task 2) ────────────────────────────────────────────────────────
_PEM_REDACTED = "<REDACTED PRIVATE KEY>"
_CONN_REDACTED = "<REDACTED CONNECTION STRING>"


def _looks_like_pem(v: str) -> bool:
    u = v.upper()
    return "PRIVATE KEY" in u or "BEGIN RSA" in u or "BEGIN EC PRIVATE" in u or (
        "-----BEGIN" in u and "KEY-----" in u
    )


def _looks_like_connection_string(v: str) -> bool:
    low = v.lower()
    if "accountkey=" in low or "sharedaccesskey=" in low:
        return True
    if "endpoint=" in low and ("accountname=" in low or "accountkey=" in low):
        return True
    if low.startswith(("postgres://", "postgresql://", "mysql://", "mongodb://",
                       "mongodb+srv://", "amqp://", "redis://", "rediss://")):
        return True
    return False


def mask_value(value, provider: str = "") -> str:
    """Mask a secret value so a recognizable shape survives but the secret does not.

    Examples:
      AKIAIOSFODNN7EXAMPLE -> AKIA************MPLE
      ghp_aBc...xyz        -> ghp_****************...****
      sk_live_4eC39H...    -> sk_l****************...XaBc
      <short token>        -> prefix preserved, rest masked
      PEM / private key    -> <REDACTED PRIVATE KEY>
      connection string    -> <REDACTED CONNECTION STRING>
    """
    if value is None:
        return ""
    v = str(value)
    if not v:
        return ""

    if _looks_like_pem(v):
        return _PEM_REDACTED
    if _looks_like_connection_string(v):
        return _CONN_REDACTED

    n = len(v)
    # Short tokens: preserve a short prefix only (no suffix to avoid leaking).
    if n <= 8:
        keep = 4 if n > 6 else 2
        keep = min(keep, n - 1) if n > 1 else n
        return v[:keep] + "*" * (n - keep)

    prefix = v[:4]
    suffix = v[-4:]
    stars = "*" * max(4, n - 8)
    return f"{prefix}{stars}{suffix}"


def _scrub_text(text, raw_value: str, masked: str) -> str:
    """Replace every occurrence of the raw secret in a snippet/context with its
    masked form so evidence snippets never carry the live value."""
    if not text:
        return text or ""
    t = str(text)
    if raw_value and raw_value in t:
        t = t.replace(raw_value, masked)
    return t


# ─── Ownership collapse (Task 5) ─────────────────────────────────────────────
def _collapse_ownership(label: str) -> str:
    """Collapse the fine-grained finding_model label into the Phase 9 vocabulary.

    APPLICATION stays APPLICATION; UNKNOWN stays visible (could be obfuscated app
    code). Google/Firebase SDKs and generic libraries are THIRD_PARTY_LIBRARY;
    Jetpack / platform runtime are FRAMEWORK.
    """
    if label == APPLICATION:
        return APPLICATION
    if label in ("THIRD_PARTY_LIBRARY", "GOOGLE_SDK", "FIREBASE"):
        return THIRD_PARTY_LIBRARY
    if label in ("ANDROID_FRAMEWORK", "JETPACK"):
        return FRAMEWORK
    return UNKNOWN


# ─── Confidence (Task 6 / Task 13) ───────────────────────────────────────────
def _confidence_label(secret: dict, validated: bool) -> str:
    """HIGH = pattern + validation; MEDIUM = strong pattern; LOW = weak/generic."""
    if validated:
        return HIGH
    name = secret.get("name") or secret.get("title") or ""
    if name in _WEAK_DETECTORS:
        return LOW
    conf = secret.get("confidence")
    try:
        conf = float(conf)
    except (TypeError, ValueError):
        conf = 0.0
    if conf >= 80:
        return MEDIUM
    if conf and conf < 60:
        return LOW
    # No numeric confidence from the detector (e.g. common-scanner secrets): a
    # named provider pattern is still MEDIUM, an unnamed generic match is LOW.
    return MEDIUM if name and name not in _WEAK_DETECTORS else LOW


# ─── Static risk scores (placeholders until validation phases) ───────────────
_SEV_EXPLOIT = {"critical": 90, "high": 70, "medium": 45, "low": 25, "info": 10}
_OWN_EXPOSURE = {APPLICATION: 70, UNKNOWN: 50, THIRD_PARTY_LIBRARY: 20, FRAMEWORK: 10}


def _exploitability(secret: dict, severity: str) -> int:
    base = secret.get("exploitability")
    if isinstance(base, (int, float)) and base:
        return int(base)
    return _SEV_EXPLOIT.get(severity, 25)


def _exposure(ownership: str) -> int:
    return _OWN_EXPOSURE.get(ownership, 40)


# ─── Evidence gate (Task 4) ──────────────────────────────────────────────────
def _evidence(secret: dict) -> tuple[str, int, str]:
    """Return (file_path, line, snippet). Empty/zero where missing."""
    path = secret.get("full_path") or secret.get("file_path") or secret.get("source") or ""
    line = secret.get("line") or 0
    snippet = secret.get("snippet") or ""
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 0
    return str(path), line, str(snippet)


def _stable_id(provider: str, stype: str, value_sha: str, path: str, line: int) -> str:
    basis = f"{provider}|{stype}|{value_sha[:12]}|{path}:{line}".encode("utf-8", "replace")
    return "BEETLE-SECRET-" + hashlib.sha1(basis).hexdigest()[:10]


def _build_canonical(secret: dict, app_package: str) -> dict | None:
    """Normalize + mask one secret in place. Returns the same dict, or None when
    it fails the evidence gate (no file/line/snippet)."""
    if not isinstance(secret, dict):
        return None
    # Idempotency: never re-mask an already-processed secret.
    if secret.get("masked_value"):
        return secret

    path, line, snippet = _evidence(secret)
    if not (path and line and snippet):
        return None  # Task 4 — no evidence, no finding.

    raw_value = secret.get("value") or ""
    name = secret.get("name") or secret.get("title") or ""
    provider, stype = tag_provider(name, raw_value)

    masked = mask_value(raw_value, provider)
    value_sha = (
        hashlib.sha256(raw_value.encode("utf-8", "replace")).hexdigest()
        if raw_value else ""
    )

    label = classify_ownership_label(path, app_package)
    ownership = _collapse_ownership(label)
    _, owner_pkg = classify_ownership(path, app_package)

    legacy_vr = secret.get("validation_result")
    validated = secret.get("validated") is True or legacy_vr == "live"
    if validated:
        validation_result = "valid"
    elif legacy_vr == "invalid":
        validation_result = "invalid"
    else:
        validation_result = "skipped"

    confidence = _confidence_label(secret, validated)
    severity = secret.get("severity") or "info"
    masked_snippet = _scrub_text(snippet, raw_value, masked)
    masked_context = _scrub_text(secret.get("code_context", ""), raw_value, masked)

    exploit = _exploitability(secret, severity)
    exposure = _exposure(ownership)
    sid = _stable_id(provider, stype, value_sha, path, line)

    # Preserve the detector's numeric confidence before overwriting the field
    # with the canonical HIGH/MEDIUM/LOW label.
    detector_conf = secret.get("confidence")

    secret.update({
        "id":                   sid,
        "provider":             provider,
        "type":                 stype,
        "ownership":            ownership,
        "ownership_label":      label,
        "owner_package":        owner_pkg or "",
        "masked_value":         masked,
        "value":                masked,          # raw value OVERWRITTEN — never serialized
        "value_sha256":         value_sha,
        "confidence":           confidence,
        "detector_confidence":  detector_conf,
        "validation_result":    validation_result,
        "validated":            validated,
        "privileges":           secret.get("privileges") or [],
        "exposure_score":       exposure,
        "exploitability_score": exploit,
        "severity":             severity,
        "paired_with":          secret.get("paired_with") or [],
        "suppressed_reason":    "",
        "snippet":              masked_snippet,
        "code_context":         masked_context,
        "evidence": {
            "file_path": path,
            "line":      line,
            "snippet":   masked_snippet,
        },
    })
    secret.pop("_raw", None)
    return secret


# ─── Public entry point ──────────────────────────────────────────────────────
def process_secrets(results: dict, app_package: str = "") -> dict:
    """Canonicalize + mask + partition results["secrets"] (runs once in finalize).

    Mutates results:
      results["secrets"]            -> visible: APPLICATION / UNKNOWN, non-LOW.
      results["suppressed_secrets"] -> SDK/framework + LOW-confidence (kept, hidden).
      results["secrets_summary"]    -> executive rollup (Task 7).

    Returns the secrets_summary dict.
    """
    raw = results.get("secrets") or []
    visible: list[dict] = []
    suppressed: list[dict] = []
    dropped_no_evidence = 0
    suppressed_sdk = 0
    low_conf = 0
    providers: set[str] = set()

    for secret in raw:
        canonical = _build_canonical(secret, app_package)
        if canonical is None:
            dropped_no_evidence += 1
            continue
        providers.add(canonical["provider"])

        if canonical["ownership"] in (THIRD_PARTY_LIBRARY, FRAMEWORK):
            canonical["suppressed_reason"] = "third_party_sdk"
            suppressed_sdk += 1
            suppressed.append(canonical)
        elif canonical["confidence"] == LOW:
            canonical["suppressed_reason"] = "low_confidence"
            low_conf += 1
            suppressed.append(canonical)
        else:
            visible.append(canonical)

    validated = sum(1 for s in visible if s["validation_result"] == "valid")
    invalid = sum(1 for s in visible if s["validation_result"] == "invalid")
    high_risk = sum(1 for s in visible if s["severity"] in ("critical", "high"))

    results["secrets"] = visible
    results["suppressed_secrets"] = suppressed
    summary = {
        "validated_secrets":         validated,
        "invalid_secrets":           invalid,
        "high_risk_credentials":     high_risk,
        "suppressed_sdk_secrets":    suppressed_sdk,
        "low_confidence_suppressed": low_conf,
        "dropped_no_evidence":       dropped_no_evidence,
        "total_application_secrets": len(visible),
        "providers":                 sorted(providers),
    }
    results["secrets_summary"] = summary
    log.info(
        "[secret_intel] app_pkg=%s | visible=%d suppressed_sdk=%d low_conf=%d "
        "dropped_no_evidence=%d validated=%d providers=%s",
        app_package or "?", len(visible), suppressed_sdk, low_conf,
        dropped_no_evidence, validated, ",".join(sorted(providers)) or "-",
    )
    return summary
