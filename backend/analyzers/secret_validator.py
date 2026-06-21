"""
Cortex Secret Validator
=======================
Probes detected secrets against their issuer APIs to confirm whether
credentials are still active (live). Only reads — never writes.

Each validator returns one of:
  "live"     — confirmed active by the API (bump to critical)
  "invalid"  — API rejected the credential (keep as detected)
  "unknown"  — network error, timeout, or inconclusive response
"""

from __future__ import annotations

import os
import re
import json
import urllib.request
import urllib.error
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── Probe timeout (seconds) ─────────────────────────────────────────────────
PROBE_TIMEOUT = 6


def _live_checks_disabled() -> bool:
    """Live validation is OFF whenever live checks are disabled or a benchmark is
    running. This keeps offline/benchmark scans network-free and deterministic
    (Phase 9 safety model). No probe is issued; every secret is marked skipped."""
    for var in ("CORTEX_DISABLE_LIVE_CHECKS", "CORTEX_BENCHMARK"):
        if os.environ.get(var, "").strip().lower() in ("1", "true", "yes"):
            return True
    return False


def _get(url: str, headers: dict = None, timeout: int = PROBE_TIMEOUT) -> tuple[int, str]:
    """HTTP GET — returns (status_code, body). Raises on network error."""
    req = urllib.request.Request(url, headers={"User-Agent": "Cortex-Scanner/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read(4096).decode("utf-8", errors="replace")


def _post(url: str, data: bytes, headers: dict = None, timeout: int = PROBE_TIMEOUT) -> tuple[int, str]:
    """HTTP POST — returns (status_code, body)."""
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": "Cortex-Scanner/1.0", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read(4096).decode("utf-8", errors="replace")


# ─── Individual probe functions ───────────────────────────────────────────────

def _probe_aws(secret: dict) -> str:
    """
    AWS Access Key ID validation via STS GetCallerIdentity.
    Requires both AKIA key and secret key — skip if only AKIA present.
    """
    value = secret.get("value", "")
    if not re.match(r"AKIA[0-9A-Z]{16}$", value):
        return "unknown"
    # We only have the access key ID — can't sign a request without the secret.
    # Mark as unknown (can't validate without the secret key).
    return "unknown"


def _probe_github(secret: dict) -> str:
    """GitHub PAT — probe /user endpoint."""
    value = secret.get("value", "")
    try:
        status, body = _get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {value}"},
        )
        if status == 200:
            return "live"
        if status in (401, 403):
            return "invalid"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_stripe(secret: dict) -> str:
    """Stripe secret key — probe /v1/balance."""
    value = secret.get("value", "")
    try:
        b64 = base64.b64encode(f"{value}:".encode()).decode()
        status, _ = _get(
            "https://api.stripe.com/v1/balance",
            headers={"Authorization": f"Basic {b64}"},
        )
        if status == 200:
            return "live"
        if status in (401, 403):
            return "invalid"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_sendgrid(secret: dict) -> str:
    """SendGrid — probe /v3/user/profile."""
    value = secret.get("value", "")
    try:
        status, _ = _get(
            "https://api.sendgrid.com/v3/user/profile",
            headers={"Authorization": f"Bearer {value}"},
        )
        if status == 200:
            return "live"
        if status in (401, 403):
            return "invalid"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_slack_token(secret: dict) -> str:
    """Slack OAuth token — probe auth.test."""
    value = secret.get("value", "")
    try:
        status, body = _get(
            f"https://slack.com/api/auth.test?token={value}",
        )
        if status == 200:
            data = json.loads(body)
            return "live" if data.get("ok") else "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_slack_webhook(secret: dict) -> str:
    """Slack Incoming Webhook — send a benign test POST with no text to confirm active."""
    value = secret.get("value", "")
    try:
        # Send empty JSON — Slack returns 400 "no_text" if webhook is active
        # and 404/410 if revoked
        payload = json.dumps({"text": ""}).encode()
        status, body = _post(value, data=payload, headers={"Content-Type": "application/json"})
        if status == 400 and "no_text" in body:
            return "live"
        if status == 200:
            return "live"
    except urllib.error.HTTPError as e:
        if e.code == 400:
            return "live"    # still active, just rejected empty payload
        if e.code in (403, 404, 410):
            return "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_openai(secret: dict) -> str:
    """OpenAI — probe /v1/models."""
    value = secret.get("value", "")
    try:
        status, _ = _get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {value}"},
        )
        if status == 200:
            return "live"
        if status in (401, 403):
            return "invalid"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_huggingface(secret: dict) -> str:
    """HuggingFace — probe /api/whoami-v2."""
    value = secret.get("value", "")
    try:
        status, _ = _get(
            "https://huggingface.co/api/whoami-v2",
            headers={"Authorization": f"Bearer {value}"},
        )
        if status == 200:
            return "live"
        if status in (401, 403):
            return "invalid"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_npm(secret: dict) -> str:
    """npm token — probe registry whoami."""
    value = secret.get("value", "")
    try:
        status, body = _get(
            "https://registry.npmjs.org/-/whoami",
            headers={"Authorization": f"Bearer {value}"},
        )
        if status == 200 and "username" in body:
            return "live"
        if status in (401, 403):
            return "invalid"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_shopify(secret: dict) -> str:
    """Shopify access token — we can't validate without the shop domain, mark unknown."""
    return "unknown"


def _probe_mailchimp(secret: dict) -> str:
    """Mailchimp — use datacenter suffix to probe /3.0/ping."""
    value = secret.get("value", "")
    match = re.search(r"-(us\d+)$", value)
    if not match:
        return "unknown"
    dc = match.group(1)
    try:
        b64 = base64.b64encode(f"anystring:{value}".encode()).decode()
        status, body = _get(
            f"https://{dc}.api.mailchimp.com/3.0/ping",
            headers={"Authorization": f"Basic {b64}"},
        )
        if status == 200 and "Everything's Chimpy!" in body:
            return "live"
        if status in (401, 403):
            return "invalid"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "invalid"
    except Exception:
        pass
    return "unknown"


def _probe_databricks(secret: dict) -> str:
    """Databricks token — can't validate without workspace URL."""
    return "unknown"


# ─── Dispatch table ───────────────────────────────────────────────────────────
_VALIDATORS: dict[str, callable] = {
    "AWS Access Key ID":          _probe_aws,
    "GitHub Personal Access Token": _probe_github,
    "Stripe Live Secret Key":     _probe_stripe,
    "Stripe Test Key":            _probe_stripe,
    "SendGrid API Key":           _probe_sendgrid,
    "Slack OAuth Token":          _probe_slack_token,
    "Slack Webhook URL":          _probe_slack_webhook,
    "OpenAI API Key":             _probe_openai,
    "HuggingFace API Token":      _probe_huggingface,
    "npm Publish Token":          _probe_npm,
    "Shopify Access Token":       _probe_shopify,
    "Mailchimp API Key":          _probe_mailchimp,
    "Databricks Token":           _probe_databricks,
}


# ─── Public entry point ───────────────────────────────────────────────────────

def validate_secrets(secrets: list) -> list:
    """
    Probe each secret against its issuer API.
    Returns the same list with added fields:
      - validated: bool
      - validation_result: "live" | "invalid" | "unknown" | "skipped"
      - severity: bumped to "critical" if live
    Runs probes concurrently (max 8 threads).
    """
    if not secrets:
        return secrets

    # Benchmark / offline safety: never touch the network. Mark all skipped so
    # downstream (secret_intel) sees a deterministic, network-free result.
    if _live_checks_disabled():
        for secret in secrets:
            secret["validated"] = False
            secret["validation_result"] = "skipped"
        return secrets

    # Only probe secrets that have a known validator
    probeable = [s for s in secrets if s.get("name") in _VALIDATORS or s.get("title") in _VALIDATORS]

    def _probe_one(secret: dict) -> tuple[dict, str]:
        name = secret.get("name") or secret.get("title", "")
        fn = _VALIDATORS.get(name)
        if fn is None:
            return secret, "skipped"
        try:
            result = fn(secret)
        except Exception:
            result = "unknown"
        return secret, result

    results_map: dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_probe_one, s): i for i, s in enumerate(secrets)}
        for future in as_completed(futures):
            idx = futures[future]
            try:
                _, result = future.result()
                results_map[idx] = result
            except Exception:
                results_map[idx] = "unknown"

    # Apply results
    for i, secret in enumerate(secrets):
        result = results_map.get(i, "skipped")
        secret["validated"] = (result == "live")
        secret["validation_result"] = result
        if result == "live" and secret.get("severity") != "critical":
            secret["severity"] = "critical"
            secret["severity_bumped"] = True

    return secrets
