"""
Optional live secret-validation framework — Phase 9.3.

Orchestrates the per-provider validators behind a strict safety envelope:

  * OFF by default. Enabled ONLY when CORTEX_ENABLE_SECRET_VALIDATION is truthy
    AND it is not a benchmark run AND live checks are not disabled (Task 2).
  * 5s per-validator timeout; any failure → validation_result="error" and the
    scan is never affected (Task 3).
  * Results cached for 1h keyed on value_sha256 (never raw values) (Task 5).
  * Low concurrency, single attempt, no retry storms (Task 6).
  * No privilege/scope enumeration, no writes, no mutations (Task 4).

The caller (secret_intel) provides each secret with a transient `_raw` (single)
or `_raw_members` (pair) holding the value(s) to probe. secret_intel strips
those before serialization, so raw values never leave memory.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import base
from .aws import AWSValidator
from .azure import AzureValidator
from .firebase import FirebaseValidator
from .github import GitHubValidator
from .google import GoogleValidator
from .stripe import StripeValidator
from .twilio import TwilioValidator

log = logging.getLogger("cortex.secret_validators")

VALID, INVALID, ERROR = base.VALID, base.INVALID, base.ERROR

# Map canonical secret `type` → validator instance (stateless, reusable).
_VALIDATORS = {
    "AWS_CREDENTIAL_PAIR":       AWSValidator(),
    "GOOGLE_API_KEY":            GoogleValidator(),
    "GCP_API_KEY":               GoogleValidator(),
    "FIREBASE_URL":              FirebaseValidator(),
    "FIREBASE_PAIR":             FirebaseValidator(),
    "STRIPE_SECRET":             StripeValidator(),
    "STRIPE_KEY_PAIR":           StripeValidator(),
    "TWILIO_ACCOUNT_PAIR":       TwilioValidator(),
    "GITHUB_PAT":                GitHubValidator(),
    "GITHUB_FINE_GRAINED_PAT":   GitHubValidator(),
    "AZURE_CONNECTION_STRING":   AzureValidator(),
    "AZURE_STORAGE_PAIR":        AzureValidator(),
}

_MAX_WORKERS = 4          # low concurrency (Task 6)
_CACHE_TTL = 3600         # 1 hour (Task 5)
_cache: dict[str, tuple[str, float]] = {}   # sha → (result, expiry_epoch)


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def validation_enabled() -> bool:
    """Live validation is opt-in only and never runs in benchmark/offline mode."""
    if _truthy("CORTEX_BENCHMARK") or _truthy("CORTEX_DISABLE_LIVE_CHECKS"):
        return False
    return _truthy("CORTEX_ENABLE_SECRET_VALIDATION")


def supported_type(stype: str) -> bool:
    return stype in _VALIDATORS


# ─── Cache (Task 5) — keyed on non-reversible hash, never raw values ──────────
def _cache_key(secret: dict) -> str:
    if secret.get("is_pair"):
        shas = sorted(
            c.get("value_sha256", "") for c in (secret.get("components") or [])
        )
        return hashlib.sha256(("pair|" + "|".join(shas)).encode()).hexdigest()
    return secret.get("value_sha256", "")


def _cache_get(key: str) -> str | None:
    entry = _cache.get(key)
    if not entry:
        return None
    result, expiry = entry
    if time.time() >= expiry:
        _cache.pop(key, None)
        return None
    return result


def _cache_put(key: str, result: str) -> None:
    if key:
        _cache[key] = (result, time.time() + _CACHE_TTL)


def clear_cache() -> None:
    """Test/maintenance hook."""
    _cache.clear()


# ─── Single validation (cache + timeout + error containment) ─────────────────
def _validate_one(secret: dict) -> str:
    validator = _VALIDATORS.get(secret.get("type", ""))
    if validator is None:
        return ERROR
    key = _cache_key(secret)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    try:
        result = validator.validate(secret)
    except Exception:
        result = ERROR
    if result not in (VALID, INVALID, ERROR):
        result = ERROR
    _cache_put(key, result)
    return result


def run_validation(items: list[dict]) -> int:
    """Validate eligible items in place. Sets validation_result/validated on each.

    `items` are visible secrets + pairs. Only those with can_validate==True and a
    supported type are probed. No-ops (returns 0) when validation is disabled.
    Returns the number of items probed.
    """
    if not validation_enabled():
        return 0
    targets = [
        s for s in items
        if s.get("can_validate") and supported_type(s.get("type", ""))
    ]
    if not targets:
        return 0

    probed = 0
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {executor.submit(_validate_one, s): s for s in targets}
        for fut in as_completed(futures):
            secret = futures[fut]
            try:
                result = fut.result()
            except Exception:
                result = ERROR
            secret["validation_result"] = result
            secret["validated"] = (result == VALID)
            probed += 1
    log.info("[secret_validators] probed=%d (live validation enabled)", probed)
    return probed
