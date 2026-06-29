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
from collections import Counter

from . import cloud_correlation as _cloud_correlation
from . import cloud_intel as _cloud_intel
from . import secret_validators as _secret_validators
from .finding_model import classify_ownership, classify_ownership_label

log = logging.getLogger("cortex.secret_intel")

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

APPLICATION = "APPLICATION"
THIRD_PARTY_LIBRARY = "THIRD_PARTY_LIBRARY"
FRAMEWORK = "FRAMEWORK"
UNKNOWN = "UNKNOWN"


# ─── Canonical primary categories (Phase 2.5.1) ──────────────────────────────
# Every VISIBLE secret maps to EXACTLY ONE primary category, so the per-category
# counts always sum to the visible total (len(results["secrets"])). A secret may
# still carry secondary classifications (provider, type, detected_by, cloud-exposure
# cross-refs) — those are facets and never affect the primary partition. The tuple
# order is the canonical display order.
PRIMARY_CATEGORIES = (
    "Credential Pairs",
    "Cloud Credentials",
    "Private Keys",
    "API Keys & Tokens",
    "Passwords & Logins",
    "Other Secrets",
)

_CLOUD_PROVIDERS = {"AWS", "GCP", "GOOGLE", "AZURE", "FIREBASE", "CLOUDFLARE", "SUPABASE"}
_PRIVATE_KEY_TYPES = {"PEM_PRIVATE_KEY", "GCP_SERVICE_ACCOUNT_KEY", "APNS_AUTH_KEY"}
_PASSWORD_TYPES = {"HARDCODED_PASSWORD", "HARDCODED_USERNAME", "BASIC_AUTH_URL"}


def primary_category(secret: dict) -> str:
    """Resolve a secret's ONE canonical primary category (Phase 2.5.1).

    Mutually exclusive + exhaustive: the return value is always one of
    PRIMARY_CATEGORIES, so summing per-category counts over the visible secrets
    always reproduces the total. Precedence is deliberate — a composite pair is a
    pair first; a private key is a private key before its provider's cloud bucket.
    """
    if secret.get("is_pair"):
        return "Credential Pairs"
    provider = str(secret.get("provider") or "").upper()
    stype = str(secret.get("type") or "").upper()
    if provider == "PRIVATE_KEY" or stype in _PRIVATE_KEY_TYPES:
        return "Private Keys"
    if provider in _CLOUD_PROVIDERS:
        return "Cloud Credentials"
    if stype in _PASSWORD_TYPES:
        return "Passwords & Logins"
    if (provider and provider != "GENERIC") or any(
        tok in stype for tok in ("KEY", "TOKEN", "SECRET", "API", "WEBHOOK", "PAT")
    ):
        return "API Keys & Tokens"
    return "Other Secrets"


def categorize_secrets(visible: list[dict]) -> list[dict]:
    """Tag each visible secret with its primary_category and return an ordered,
    partition-complete breakdown [{category, count}] whose counts sum to
    len(visible). Mutates each secret in place (adds `primary_category`)."""
    counter: Counter = Counter()
    for s in visible:
        pc = primary_category(s)
        s["primary_category"] = pc
        counter[pc] += 1
    return [{"category": c, "count": counter[c]} for c in PRIMARY_CATEGORIES if counter[c]]


# ─── Secret Intelligence verdict gate (Phase 1.91) ───────────────────────────
# The Secret Intelligence Engine (secret_intelligence.annotate, run BEFORE this
# module) classifies every value and writes `secret_status` /
# `secret_overall_confidence` / `secret_intelligence`. Until Phase 1.91 those were
# advisory only — process_secrets partitioned visible vs suppressed using legacy
# ownership + detector confidence ALONE, so a value the engine had already judged a
# False Positive / Public Value / Generated Constant (a UUID, hash, crypto
# parameter, library constant, or a long random string with no credential context)
# still showed in the analyst's default view. We now consume that verdict here:
# rejected or below-floor values are moved to the suppressed partition — kept and
# counted, never dropped — so the FP no longer surfaces while staying auditable.
try:
    from .secret_intelligence import config as _si_config
    _SUPPRESS_FLOOR = _si_config.SUPPRESS_OVERALL_FLOOR
    _CONTEXT_STRONG_MIN = _si_config.CONTEXT_STRONG_MIN
    _PROBABLE_STATUS = _si_config.Status.PROBABLE
    _VALIDATED_STATUS = _si_config.Status.VALIDATED
    _POSSIBLE_STATUS = _si_config.Status.POSSIBLE
    _PUBLIC_STATUS = _si_config.Status.PUBLIC_VALUE
    _DOC_EXAMPLE_STATUS = _si_config.Status.DOC_EXAMPLE
    _FALSE_POSITIVE_STATUS = _si_config.Status.FALSE_POSITIVE
    _GENERATED_CONSTANT_STATUS = _si_config.Status.GENERATED_CONSTANT
except Exception:  # pragma: no cover — engine import must never break secret processing
    _SUPPRESS_FLOOR = 45
    _CONTEXT_STRONG_MIN = 75
    _PROBABLE_STATUS, _VALIDATED_STATUS = "Probable Secret", "Validated Secret"
    _POSSIBLE_STATUS = "Possible Secret"
    _PUBLIC_STATUS, _DOC_EXAMPLE_STATUS = "Public Value", "Documentation Example"
    _FALSE_POSITIVE_STATUS, _GENERATED_CONSTANT_STATUS = "False Positive", "Generated Constant"

# Reject classes split by certainty:
#  * DEFINITIVE — a public cert IS public; a documentation example is matched by an
#    exact value hash. Safe to suppress even a recognized provider/structured format.
#  * HEURISTIC  — placeholder substring / crypto-constant / unreferenced-generic
#    signals. These must NEVER hide a value that ALSO carries a recognized provider/
#    structured format (item 13): the recognized format outweighs a heuristic FP, so
#    a real key that merely happens to contain a placeholder substring stays visible.
_REJECT_DEFINITIVE = {_PUBLIC_STATUS, _DOC_EXAMPLE_STATUS}
_REJECT_HEURISTIC = {_FALSE_POSITIVE_STATUS, _GENERATED_CONSTANT_STATUS}


def _intelligence_supports(secret: dict) -> bool:
    """True when the Secret Intelligence verdict vouches for this value strongly
    enough to RESCUE it from legacy detector-centric low-confidence suppression.

    This is the coverage half of Phase 1.91: an application-specific / custom
    enterprise secret detected only by a generic ("weak") detector would otherwise
    be hidden as low-confidence — but when the engine has corroborated it (Probable/
    Validated, or Possible with strong credential context: a credential variable
    name + nearby security-API usage) it is a real secret and must stay visible.
    Conservative on purpose: a weakly-evidenced Possible without strong context is
    NOT rescued.
    """
    status = secret.get("secret_status")
    if status in (_PROBABLE_STATUS, _VALIDATED_STATUS):
        return True
    si = secret.get("secret_intelligence") or {}
    if status == si.get("status") == _POSSIBLE_STATUS:
        ctx = secret.get("secret_context_score")
        if isinstance(ctx, (int, float)) and ctx >= _CONTEXT_STRONG_MIN:
            return True
    return False


def _intelligence_rejected(secret: dict) -> bool:
    """True when the Secret Intelligence verdict says hide this by default.

    Hidden = a DEFINITIVE non-secret class (Public Value / Documentation Example),
    a HEURISTIC reject class (False Positive / Generated Constant) ONLY when the
    value carries no recognized provider/structured format, OR an overall confidence
    below the floor for a value with no recognized format. Recognized-format secrets
    (item 13) and Probable/Validated secrets are NEVER hidden by a heuristic signal
    or the floor — a recognized key with weak corroboration is still worth showing.
    When the engine has not annotated the secret (no status present), this returns
    False — behavior is unchanged.
    """
    status = secret.get("secret_status")
    if not status:
        return False  # not assessed → preserve legacy behavior
    if status in (_PROBABLE_STATUS, _VALIDATED_STATUS):
        return False
    si = secret.get("secret_intelligence") or {}
    # An UNAMBIGUOUS provider/structured format (not a bare-UUID "provider" the engine
    # already judged needs-context). Falls back to format_valid for pre-1.91 data.
    recognized = si.get("recognized_format")
    if recognized is None:
        recognized = si.get("format_valid") is True
    if status in _REJECT_DEFINITIVE:
        return True   # public cert / known doc example — suppress even if recognized
    if status in _REJECT_HEURISTIC:
        # Item 13: a recognized provider/structured format outweighs a heuristic FP.
        return not recognized
    if recognized:
        return False  # Possible/Unknown with a recognized format — keep visible
    conf = secret.get("secret_overall_confidence")
    return isinstance(conf, (int, float)) and conf < _SUPPRESS_FLOOR


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

    Examples (placeholders — not real credentials):
      EXAMPLE_AWS_ACCESS_KEY -> EXAM***************_KEY
      EXAMPLE_GITHUB_TOKEN   -> EXAM***************KEN
      EXAMPLE_STRIPE_SECRET  -> EXAM***************RET
      <short token>          -> prefix preserved, rest masked
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


# Text fields on a secret that can carry a raw value (snippet/context windows in
# particular can include a *neighbouring* secret's value — e.g. several pattern
# hits on adjacent lines of an ASN.1/cert hex dump). The cross-scrub pass below
# masks every detected raw value out of every one of these fields.
_SCRUBBABLE_FIELDS = ("snippet", "code_context", "description", "recommendation")


def _cross_scrub(secret: dict, pairs: list[tuple[str, str]]) -> None:
    """Replace EVERY detected raw value (not just this secret's own) with its
    masked form across all text fields. `pairs` must be sorted longest-raw-first
    so a longer secret that contains a shorter one is masked before it."""
    if not pairs:
        return
    for field in _SCRUBBABLE_FIELDS:
        val = secret.get(field)
        if not val:
            continue
        t = str(val)
        for raw, masked in pairs:
            if raw and raw in t:
                t = t.replace(raw, masked)
        secret[field] = t
    ev = secret.get("evidence")
    if isinstance(ev, dict) and ev.get("snippet"):
        t = str(ev["snippet"])
        for raw, masked in pairs:
            if raw and raw in t:
                t = t.replace(raw, masked)
        ev["snippet"] = t


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


# ═════════════════════════════════════════════════════════════════════════════
# Phase 9.2 — Pairing, validation gating, eligibility, risk
# ═════════════════════════════════════════════════════════════════════════════

# ─── Validation states (Task 3) ──────────────────────────────────────────────
ST_SKIPPED = "skipped"      # not eligible, or live checks disabled → no probe
ST_ELIGIBLE = "eligible"    # could be validated, but no probe was made (default)
ST_VALID = "valid"          # confirmed live by a probe (live mode only)
ST_INVALID = "invalid"      # rejected by a probe (live mode only)
ST_ERROR = "error"          # a probe was attempted and errored


# ─── Provider eligibility (Task 4) ───────────────────────────────────────────
# Types a single secret can be validated on its own (a future phase performs the
# actual probe — here we only declare the capability).
_LONE_ELIGIBLE_TYPES = {
    "GOOGLE_API_KEY", "GCP_API_KEY", "FIREBASE_URL", "STRIPE_SECRET",
    "GITHUB_PAT", "GITHUB_FINE_GRAINED_PAT", "SENDGRID_API_KEY",
    "SLACK_OAUTH_TOKEN", "SLACK_WEBHOOK", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "HUGGINGFACE_TOKEN", "NPM_TOKEN", "MAILCHIMP_API_KEY", "SHOPIFY_ACCESS_TOKEN",
    "AZURE_CONNECTION_STRING",
}
# Composite pair types are validatable (they carry the full credential material).
_PAIR_ELIGIBLE_TYPES = {
    "AWS_CREDENTIAL_PAIR", "TWILIO_ACCOUNT_PAIR", "STRIPE_KEY_PAIR",
    "FIREBASE_PAIR", "AZURE_STORAGE_PAIR",
}
# Types that are explicitly NOT eligible: harmless public keys, or half of a pair
# that cannot be validated alone (no signing material without its partner).
_NOT_ELIGIBLE_TYPES = {
    "STRIPE_PUBLISHABLE", "MAPBOX_TOKEN", "SHOPIFY_STOREFRONT_TOKEN",
    "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN", "AZURE_STORAGE_KEY",
}


def can_validate(secret: dict) -> bool:
    """Declare whether a secret COULD be validated — without doing so (Task 4)."""
    if secret.get("paired_into"):
        return False  # validation happens at the composite-pair level, not the member
    stype = secret.get("type", "")
    if secret.get("is_pair"):
        return stype in _PAIR_ELIGIBLE_TYPES
    if stype in _NOT_ELIGIBLE_TYPES:
        return False
    return stype in _LONE_ELIGIBLE_TYPES


def validation_state(secret: dict, eligible: bool) -> str:
    """Resolve the validation state machine (Task 3). Default skipped; eligible
    when a probe COULD run but did not (no network by default). valid/invalid/
    error only ever come from an actual probe in a later/live phase."""
    vr = secret.get("validation_result")
    if vr in (ST_VALID, ST_INVALID, ST_ERROR):
        return vr
    return ST_ELIGIBLE if eligible else ST_SKIPPED


# ─── Pairing (Task 1 / Task 2) ───────────────────────────────────────────────
# (relationship_type, primary_type, secondary_type, pair_type, title, provider)
_PAIR_RULES = [
    ("aws_credential_pair", "AWS_ACCESS_KEY",  "AWS_SECRET_KEY",
     "AWS_CREDENTIAL_PAIR", "AWS Credential Pair", "AWS"),
    ("twilio_account_pair", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN",
     "TWILIO_ACCOUNT_PAIR", "Twilio Account Pair", "TWILIO"),
    ("stripe_key_pair", "STRIPE_PUBLISHABLE", "STRIPE_SECRET",
     "STRIPE_KEY_PAIR", "Stripe Key Pair", "STRIPE"),
    ("firebase_pair", "GOOGLE_API_KEY", "FIREBASE_URL",
     "FIREBASE_PAIR", "Firebase Configuration Pair", "FIREBASE"),
    ("azure_storage_pair", "AZURE_CONNECTION_STRING", "AZURE_STORAGE_KEY",
     "AZURE_STORAGE_PAIR", "Azure Storage Pair", "AZURE"),
]

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _loc(secret: dict) -> tuple[str, int]:
    ev = secret.get("evidence") or {}
    return (str(ev.get("file_path", "")), int(ev.get("line", 0) or 0))


def _higher_severity(a: dict, b: dict) -> str:
    return min((a.get("severity") or "info", b.get("severity") or "info"),
               key=lambda s: _SEV_RANK.get(s, 4))


def _stronger_ownership(a: dict, b: dict) -> tuple[str, str, str]:
    """Return (ownership, ownership_label, owner_package) — APPLICATION wins."""
    for c in (a, b):
        if c.get("ownership") == APPLICATION:
            return APPLICATION, c.get("ownership_label", APPLICATION), c.get("owner_package", "")
    for c in (a, b):
        if c.get("ownership") == UNKNOWN:
            return UNKNOWN, c.get("ownership_label", UNKNOWN), c.get("owner_package", "")
    return a.get("ownership", UNKNOWN), a.get("ownership_label", UNKNOWN), a.get("owner_package", "")


def _pick_secondary(primary: dict, secondaries: list[dict], used: set) -> tuple[dict | None, str]:
    """Greedy co-location match: same file (HIGH) > same package (MEDIUM) > any (LOW)."""
    pf, _ = _loc(primary)
    pp = primary.get("owner_package", "")
    avail = [s for s in secondaries if s["id"] not in used]
    for s in avail:
        if _loc(s)[0] == pf and pf:
            return s, HIGH
    for s in avail:
        if pp and s.get("owner_package", "") == pp:
            return s, MEDIUM
    if avail:
        return avail[0], LOW
    return None, ""


def _member_summary(s: dict) -> dict:
    ev = s.get("evidence") or {}
    return {
        "id": s.get("id"), "type": s.get("type"), "provider": s.get("provider"),
        "masked_value": s.get("masked_value"), "value_sha256": s.get("value_sha256", ""),
        "file_path": ev.get("file_path", ""), "line": ev.get("line", 0),
    }


def _make_pair(rule, a: dict, b: dict, rel_conf: str, keep_raw: bool = False) -> dict:
    relationship_type, _pt, _st, pair_type, title, provider = rule
    severity = _higher_severity(a, b)
    ownership, own_label, owner_pkg = _stronger_ownership(a, b)
    pid = "BEETLE-PAIR-" + hashlib.sha1(
        f"{pair_type}|{'|'.join(sorted([a.get('value_sha256',''), b.get('value_sha256','')]))}"
        .encode("utf-8", "replace")
    ).hexdigest()[:10]

    file_evidence = []
    for m in (a, b):
        ev = m.get("evidence") or {}
        file_evidence.append({
            "path": ev.get("file_path", ""),
            "lines": [ev.get("line", 0)] if ev.get("line") else [],
            "snippet": ev.get("snippet", ""),
            "type": m.get("type"),
        })

    masked_value = "; ".join(f"{m.get('type')}={m.get('masked_value')}" for m in (a, b))
    pair = {
        "id": pid,
        "is_pair": True,
        "provider": provider,
        "type": pair_type,
        "relationship_type": relationship_type,
        "relationship_confidence": rel_conf,
        "name": title,
        "title": title,
        "category": "Cloud Credentials",
        "severity": severity,
        "ownership": ownership,
        "ownership_label": own_label,
        "owner_package": owner_pkg,
        "confidence": rel_conf,            # the pair's confidence is its linkage strength
        "masked_value": masked_value,
        "value": masked_value,
        "value_sha256": "",
        "members": [a.get("id"), b.get("id")],
        "components": [_member_summary(a), _member_summary(b)],
        "paired_with": [a.get("id"), b.get("id")],
        "evidence": dict(a.get("evidence") or {}),
        "file_evidence": file_evidence,
        "exposure_score": _exposure(ownership),
        "exploitability_score": min(100, _SEV_EXPLOIT.get(severity, 25) + 15),
        "validation_result": ST_SKIPPED,
        "validated": False,
        "privileges": [],
        "description": (
            f"A {provider} {relationship_type.replace('_', ' ')} was found: both halves of "
            f"the credential are present in the app ({a.get('type')} + {b.get('type')}), which "
            f"together grant usable access. Linkage confidence: {rel_conf} "
            f"({'same file' if rel_conf == HIGH else 'same package' if rel_conf == MEDIUM else 'co-present'})."
        ),
        "recommendation": (
            f"Rotate both credentials immediately and remove them from the app. "
            f"A complete {provider} credential pair is directly usable by an attacker."
        ),
    }
    if keep_raw:
        # Transient material for the optional validator — stripped before return.
        pair["_raw_members"] = {
            a.get("type"): a.get("_raw"),
            b.get("type"): b.get("_raw"),
        }
    return pair


def _build_pairs(candidates: list[dict], keep_raw: bool = False) -> tuple[list[dict], set]:
    """Build composite pair findings from co-occurring secrets. Returns
    (pairs, used_member_ids). Deterministic: rules + members are sorted."""
    pairs: list[dict] = []
    used: set = set()
    by_type: dict[str, list[dict]] = {}
    for c in candidates:
        by_type.setdefault(c.get("type", ""), []).append(c)
    for lst in by_type.values():
        lst.sort(key=_loc)

    for rule in _PAIR_RULES:
        _rt, prim_t, sec_t, _pt, _title, _prov = rule
        prims = [c for c in by_type.get(prim_t, []) if c["id"] not in used]
        secs = by_type.get(sec_t, [])
        for p in prims:
            match, rel_conf = _pick_secondary(p, secs, used)
            if match is None:
                continue
            used.add(p["id"])
            used.add(match["id"])
            pairs.append(_make_pair(rule, p, match, rel_conf, keep_raw=keep_raw))
    pairs.sort(key=lambda x: (_SEV_RANK.get(x.get("severity"), 4), x.get("type", "")))
    return pairs, used


# ─── Risk model (Task 5) ─────────────────────────────────────────────────────
_RISK_SEV_BASE = {"critical": 90, "high": 70, "medium": 45, "low": 25, "info": 10}
_RISK_OWN = {APPLICATION: 10, UNKNOWN: 0, THIRD_PARTY_LIBRARY: -20, FRAMEWORK: -25}
_RISK_CONF = {HIGH: 10, MEDIUM: 0, LOW: -15}


def _compute_risk(secret: dict) -> tuple[int, str]:
    """Risk from severity + paired + ownership + confidence (NOT privileges)."""
    base = _RISK_SEV_BASE.get(secret.get("severity", "info"), 10)
    if secret.get("is_pair") or secret.get("paired_into"):
        base += 15
    base += _RISK_OWN.get(secret.get("ownership"), 0)
    base += _RISK_CONF.get(secret.get("confidence"), 0)
    score = max(0, min(100, base))
    level = HIGH if score >= 70 else (MEDIUM if score >= 40 else LOW)
    return score, level


def _apply_gating(secret: dict) -> None:
    """Attach can_validate / validation_result / risk to a secret in place.

    Idempotent: pairing's exploitability bump is applied at pair-construction
    time (and in _build_canonical for members), never here — so calling this
    repeatedly (e.g. after live validation flips a state) does not drift scores.
    """
    eligible = can_validate(secret)
    secret["can_validate"] = eligible
    secret["validation_result"] = validation_state(secret, eligible)
    secret["validated"] = secret["validation_result"] == ST_VALID
    risk_score, risk_level = _compute_risk(secret)
    secret["risk_score"] = risk_score
    secret["risk_level"] = risk_level


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


def _build_canonical(secret: dict, app_package: str, keep_raw: bool = False) -> dict | None:
    """Normalize + mask one secret in place. Returns the same dict, or None when
    it fails the evidence gate (no file/line/snippet).

    When keep_raw is True (live validation opted-in) the raw value is stashed in a
    transient `_raw` field for the validator; process_secrets strips it before
    returning, so it never serializes."""
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
        "is_pair":              False,
        "paired_into":          "",
        "relationship_type":    secret.get("relationship_type") or "",
        "suppressed_reason":    "",
        "snippet":              masked_snippet,
        "code_context":         masked_context,
        "evidence": {
            "file_path": path,
            "line":      line,
            "snippet":   masked_snippet,
        },
    })
    if keep_raw:
        secret["_raw"] = raw_value      # transient — stripped before serialization
    else:
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
    canon: list[dict] = []
    dropped_no_evidence = 0
    providers: set[str] = set()
    scrub_pairs: list[tuple[str, str]] = []  # (raw_value, masked_value) for cross-scrub

    # Live validation (9.3) and cloud exposure (9.4) are opt-in only. When either
    # is on, raw values are kept transiently and stripped before this returns.
    do_val = _secret_validators.validation_enabled()
    do_cloud = _cloud_intel.cloud_intel_enabled()
    keep_raw = do_val or do_cloud

    for secret in raw:
        # Capture the raw value BEFORE _build_canonical overwrites it, so the
        # cross-scrub pass can purge it from EVERY secret's snippet/context.
        raw_value = str(secret.get("value") or "")
        canonical = _build_canonical(secret, app_package, keep_raw=keep_raw)
        if canonical is None:
            dropped_no_evidence += 1
            continue
        if raw_value and len(raw_value) >= 6:
            scrub_pairs.append((raw_value, canonical["masked_value"]))
        providers.add(canonical["provider"])
        # Provisional bucket (pairing may move a visible member to "paired").
        # Intelligence verdict is checked FIRST: a value the Secret Intelligence
        # Engine judged a non-secret (FP / public / constant / below-floor generic)
        # is suppressed regardless of ownership/detector confidence — this is the
        # Phase 1.91 fix that stops UUIDs / hashes / crypto constants / long random
        # strings from surfacing in the analyst's default view.
        if _intelligence_rejected(canonical):
            canonical["_bucket"] = "intel_fp"
            canonical["suppressed_reason"] = "intelligence_fp"
        elif canonical["ownership"] in (THIRD_PARTY_LIBRARY, FRAMEWORK):
            canonical["_bucket"] = "sdk"
            canonical["suppressed_reason"] = "third_party_sdk"
        elif canonical["confidence"] == LOW and not _intelligence_supports(canonical):
            # Legacy detector-centric low-confidence suppression — unless the Secret
            # Intelligence verdict rescues it as a corroborated application-specific
            # secret (Phase 1.91 coverage half).
            canonical["_bucket"] = "low"
            canonical["suppressed_reason"] = "low_confidence"
        else:
            canonical["_bucket"] = "visible"
        canon.append(canonical)

    # Cross-scrub: purge every detected raw value from every secret's text fields
    # (a neighbouring secret's value can land in this one's context window).
    # Longest raw first so a longer secret containing a shorter one is masked first.
    scrub_pairs.sort(key=lambda p: len(p[0]), reverse=True)
    for secret in canon:
        _cross_scrub(secret, scrub_pairs)

    # ── Pairing (Task 1/2): build composites from co-occurring application secrets.
    pair_candidates = [c for c in canon if c["_bucket"] == "visible"]
    pairs, used_member_ids = _build_pairs(pair_candidates, keep_raw=keep_raw)
    for c in canon:
        if c["id"] in used_member_ids:
            c["_bucket"] = "paired"
            c["suppressed_reason"] = "paired"
            c["paired_into"] = next(
                (p["id"] for p in pairs if c["id"] in p.get("members", [])), ""
            )
            other = [m for p in pairs if c["id"] in p.get("members", [])
                     for m in p.get("members", []) if m != c["id"]]
            if other:
                c["paired_with"] = other
                c["relationship_type"] = next(
                    (p["relationship_type"] for p in pairs if c["id"] in p.get("members", [])), ""
                )

    # ── Validation gating + risk (Task 3/4/5) on every secret AND every pair. ──
    for secret in canon + pairs:
        _apply_gating(secret)

    # ── Assemble final partitions. ──────────────────────────────────────────
    visible = pairs + [c for c in canon if c["_bucket"] == "visible"]
    suppressed = [c for c in canon if c["_bucket"] in ("sdk", "low", "paired", "intel_fp")]
    for c in canon + pairs:
        c.pop("_bucket", None)

    # ── Optional live validation (Phase 9.3) — opt-in only, never in benchmark. ──
    # Probes eligible visible items, flips validation_result to valid/invalid/error.
    if do_val:
        try:
            _secret_validators.run_validation(visible)
            for s in visible:
                if s.get("validation_result") == ST_VALID:
                    s["confidence"] = HIGH           # validated → highest confidence
                    s["risk_score"], s["risk_level"] = _compute_risk(s)
        except Exception:
            log.exception("[secret_intel] live validation failed; leaving states as-is")

    # ── Optional cloud exposure intelligence (Phase 9.4) — opt-in, read-only. ──
    cloud_summary = {"cloud_exposures": 0, "public_cloud_exposures": 0,
                     "critical_exposures": 0, "exposure_confidence": "", "exposure_types": []}
    results.setdefault("cloud_exposures", [])
    if do_cloud:
        try:
            exposures = _cloud_intel.detect_exposures(results, visible)
            cloud_summary = _cloud_intel.summarize(exposures)
        except Exception:
            log.exception("[secret_intel] cloud intelligence failed; no exposures emitted")

    # ── Strip transient raw material — nothing raw may serialize. ────────────
    for s in canon + pairs:
        s.pop("_raw", None)
        s.pop("_raw_members", None)

    # ── Optional cloud attack-path correlation (Phase 9.5) — opt-in, no network. ──
    # Correlates masked secrets + exposures into chains. Uses no raw material.
    corr_summary = {"cloud_attack_chains": 0, "critical_chains": 0,
                    "chain_confidence": "", "affected_providers": []}
    results.setdefault("cloud_attack_paths", [])
    results.setdefault("suppressed_cloud_attack_paths", [])
    if _cloud_correlation.correlation_enabled():
        try:
            _chains, _supp_chains, corr_summary = _cloud_correlation.correlate(
                visible, results.get("cloud_exposures", []),
            )
            results["cloud_attack_paths"] = _chains
            results["suppressed_cloud_attack_paths"] = _supp_chains
        except Exception:
            log.exception("[secret_intel] cloud correlation failed; no chains emitted")

    suppressed_sdk = sum(1 for c in suppressed if c.get("suppressed_reason") == "third_party_sdk")
    low_conf = sum(1 for c in suppressed if c.get("suppressed_reason") == "low_confidence")
    paired_members = sum(1 for c in suppressed if c.get("suppressed_reason") == "paired")
    intel_fp = sum(1 for c in suppressed if c.get("suppressed_reason") == "intelligence_fp")
    unpaired = sum(1 for c in visible if not c.get("is_pair"))
    candidates = sum(1 for c in visible if c.get("can_validate"))
    validated = sum(1 for s in visible if s["validation_result"] == ST_VALID)
    invalid = sum(1 for s in visible if s["validation_result"] == ST_INVALID)
    high_risk = sum(1 for s in visible if s["severity"] in ("critical", "high"))

    # ── Canonical primary-category partition (Phase 2.5.1). ──────────────────
    # Tag every visible secret with its single primary category and emit a
    # breakdown whose counts ALWAYS sum to total_application_secrets, so the UI
    # category counters can never disagree with the total again.
    secrets_by_category = categorize_secrets(visible)

    results["secrets"] = visible
    results["suppressed_secrets"] = suppressed
    summary = {
        "validated_secrets":         validated,
        "invalid_secrets":           invalid,
        "high_risk_credentials":     high_risk,
        "paired_credentials":        len(pairs),
        "unpaired_credentials":      unpaired,
        "secrets_by_category":       secrets_by_category,
        "validation_candidates":     candidates,
        "paired_members_hidden":     paired_members,
        "suppressed_sdk_secrets":    suppressed_sdk,
        "low_confidence_suppressed": low_conf,
        "intelligence_fp_suppressed": intel_fp,
        "dropped_no_evidence":       dropped_no_evidence,
        "total_application_secrets": len(visible),
        "providers":                 sorted(providers),
        "relationship_types":        sorted({p["relationship_type"] for p in pairs}),
        # Phase 9.4 — cloud exposure rollup (zeros when disabled).
        "cloud_exposures":           cloud_summary["cloud_exposures"],
        "public_cloud_exposures":    cloud_summary["public_cloud_exposures"],
        "critical_exposures":        cloud_summary["critical_exposures"],
        "exposure_confidence":       cloud_summary["exposure_confidence"],
        "exposure_types":            cloud_summary["exposure_types"],
        # Phase 9.5 — cloud attack-path correlation rollup (zeros when disabled).
        "cloud_attack_chains":       corr_summary["cloud_attack_chains"],
        "critical_chains":           corr_summary["critical_chains"],
        "chain_confidence":          corr_summary["chain_confidence"],
        "affected_providers":        corr_summary["affected_providers"],
    }
    results["secrets_summary"] = summary
    log.info(
        "[secret_intel] app_pkg=%s | visible=%d pairs=%d unpaired=%d candidates=%d "
        "suppressed_sdk=%d low_conf=%d intel_fp=%d paired_hidden=%d dropped=%d providers=%s",
        app_package or "?", len(visible), len(pairs), unpaired, candidates,
        suppressed_sdk, low_conf, intel_fp, paired_members, dropped_no_evidence,
        ",".join(sorted(providers)) or "-",
    )
    return summary
