"""
Cloud Exposure Intelligence — Phase 9.4 (safe, read-only).

Moves from "credential accepted" to "what exposure exists?" — WITHOUT privilege
enumeration, writes, mutations, or object/collection discovery.

Every probe is a single read-only HTTP GET behind a strict safety envelope:
  * OFF by default. Enabled ONLY when CORTEX_ENABLE_CLOUD_INTELLIGENCE is truthy
    AND it is not a benchmark run AND live checks are not disabled (Task 8).
  * 5s timeout (shared base.http_send), single attempt, no retries.
  * Errors are contained — a failed probe yields no exposure, never an exception.
  * Sensitive data is NEVER stored: evidence keeps a masked target + HTTP status
    + method only. Firebase data read back, S3 object keys, etc. are discarded.

Produces results["cloud_exposures"] — a list of CanonicalExposure objects — and
a small rollup the executive summary consumes.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from .secret_validators import base

log = logging.getLogger("cortex.cloud_intel")

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
_MAX_WORKERS = 4

# ─── Exposure types ──────────────────────────────────────────────────────────
FIREBASE_PUBLIC_READ = "FIREBASE_PUBLIC_READ"
FIREBASE_PUBLIC_WRITE = "FIREBASE_PUBLIC_WRITE"
FIREBASE_REACHABLE = "FIREBASE_REACHABLE"
FIREBASE_AUTH_REQUIRED = "FIREBASE_AUTH_REQUIRED"
GOOGLE_KEY_UNRESTRICTED = "GOOGLE_KEY_UNRESTRICTED"
GOOGLE_KEY_RESTRICTED = "GOOGLE_KEY_RESTRICTED"
GOOGLE_KEY_INVALID = "GOOGLE_KEY_INVALID"
S3_PUBLIC_LISTING = "S3_PUBLIC_LISTING"
S3_ACCESS_DENIED = "S3_ACCESS_DENIED"

# Exposures that represent an ACTUAL public exposure (drive the summary counts).
_PUBLIC_EXPOSURES = {
    FIREBASE_PUBLIC_READ, FIREBASE_PUBLIC_WRITE,
    GOOGLE_KEY_UNRESTRICTED, S3_PUBLIC_LISTING,
}
_SEVERITY = {
    FIREBASE_PUBLIC_READ: "critical",
    FIREBASE_PUBLIC_WRITE: "critical",
    FIREBASE_REACHABLE: "medium",
    FIREBASE_AUTH_REQUIRED: "info",
    GOOGLE_KEY_UNRESTRICTED: "high",
    GOOGLE_KEY_RESTRICTED: "info",
    GOOGLE_KEY_INVALID: "info",
    S3_PUBLIC_LISTING: "high",
    S3_ACCESS_DENIED: "info",
}
_RISK = {"critical": 95, "high": 80, "medium": 55, "low": 30, "info": 15}


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def cloud_intel_enabled() -> bool:
    """Cloud exposure probing is opt-in and never runs in benchmark/offline mode."""
    if _truthy("CORTEX_BENCHMARK") or _truthy("CORTEX_DISABLE_LIVE_CHECKS"):
        return False
    return _truthy("CORTEX_ENABLE_CLOUD_INTELLIGENCE")


def _mask(value: str) -> str:
    from .secret_intel import mask_value  # lazy: avoid import cycle
    return mask_value(value)


# ─── CanonicalExposure (Task 1) ──────────────────────────────────────────────
def _exposure(provider: str, etype: str, *, validated: bool, summary: str,
              target: str, method: str, status, source_secret_id: str = "") -> dict:
    severity = _SEVERITY.get(etype, "info")
    eid = "BEETLE-EXPOSURE-" + hashlib.sha1(
        f"{provider}|{etype}|{target}".encode("utf-8", "replace")
    ).hexdigest()[:10]
    return {
        "id": eid,
        "provider": provider,
        "exposure_type": etype,
        "severity": severity,
        "confidence": HIGH,             # probe-confirmed
        "validated": validated,
        "evidence": {                   # masked target + HTTP metadata ONLY
            "target_masked": _mask(target),
            "method": method,
            "status": status,
            "source_secret_id": source_secret_id,
        },
        "risk_score": _RISK.get(severity, 15),
        "summary": summary,
    }


# ─── Firebase (Task 2) ───────────────────────────────────────────────────────
def _firebase_url(secret: dict) -> str:
    members = secret.get("_raw_members") or {}
    if members.get("FIREBASE_URL"):
        return members["FIREBASE_URL"]
    if secret.get("type") == "FIREBASE_URL":
        return secret.get("_raw") or ""
    return ""


def _probe_firebase(url: str, sid: str) -> list[dict]:
    out: list[dict] = []
    root = url.rstrip("/")
    # ── Read: shallow GET so we never pull back the actual data tree. ──
    try:
        status, body = base.http_send(base.make_request(root + "/.json?shallow=true"))
        if status == 200:
            if body and body.strip() not in ("null", "", "{}"):
                out.append(_exposure("FIREBASE", FIREBASE_PUBLIC_READ, validated=True,
                                     summary="Firebase database publicly readable",
                                     target=url, method="GET /.json", status=200,
                                     source_secret_id=sid))
            else:
                out.append(_exposure("FIREBASE", FIREBASE_REACHABLE, validated=True,
                                     summary="Firebase database reachable (empty/null read)",
                                     target=url, method="GET /.json", status=200,
                                     source_secret_id=sid))
    except urllib.error.HTTPError as e:
        if e.code == 401:
            out.append(_exposure("FIREBASE", FIREBASE_AUTH_REQUIRED, validated=True,
                                 summary="Firebase database requires authentication (rules OK)",
                                 target=url, method="GET /.json", status=401,
                                 source_secret_id=sid))
        # 404 / other → no exposure
    except Exception:
        pass

    # ── Write: read-only rules inspection (NEVER a write — Task 8). ──
    # We only flag public write when the rules endpoint leaks a world-writable
    # rule. Confirming write by probing a PUT would mutate exactly in the
    # dangerous case, so it is deliberately not done.
    try:
        ws, wbody = base.http_send(base.make_request(root + "/.settings/rules.json"))
        low = (wbody or "").lower().replace(" ", "")
        if ws == 200 and ('".write":true' in low or '".write":"true"' in low or '"write":true' in low):
            out.append(_exposure("FIREBASE", FIREBASE_PUBLIC_WRITE, validated=True,
                                 summary="Firebase security rules allow public write",
                                 target=url, method="GET /.settings/rules.json", status=200,
                                 source_secret_id=sid))
    except Exception:
        pass
    return out


# ─── Google API keys (Task 3) ────────────────────────────────────────────────
def _google_key(secret: dict) -> str:
    members = secret.get("_raw_members") or {}
    if members.get("GOOGLE_API_KEY"):
        return members["GOOGLE_API_KEY"]
    if secret.get("type") in ("GOOGLE_API_KEY", "GCP_API_KEY"):
        return secret.get("_raw") or ""
    return ""


def _probe_google(key: str, sid: str) -> list[dict]:
    url = ("https://maps.googleapis.com/maps/api/geocode/json"
           f"?address=Mountain+View&key={key}")
    try:
        status, body = base.http_send(base.make_request(url))
    except urllib.error.HTTPError as e:
        if e.code in (400, 403):
            return [_exposure("GOOGLE", GOOGLE_KEY_INVALID, validated=True,
                              summary="Google API key rejected (invalid)",
                              target=key, method="GET geocode", status=e.code,
                              source_secret_id=sid)]
        return []
    except Exception:
        return []
    if status != 200:
        return []
    low = body.lower()
    if '"status"' not in low:
        return []
    if "request_denied" in low and "restrict" not in low and any(
            w in low for w in ("invalid", "not authorized", "unauthorized", "expired")):
        return [_exposure("GOOGLE", GOOGLE_KEY_INVALID, validated=True,
                          summary="Google API key rejected (invalid)",
                          target=key, method="GET geocode", status=200, source_secret_id=sid)]
    if "request_denied" in low and "restrict" in low:
        return [_exposure("GOOGLE", GOOGLE_KEY_RESTRICTED, validated=True,
                          summary="Google API key is application-restricted (good)",
                          target=key, method="GET geocode", status=200, source_secret_id=sid)]
    # Accepted with no restriction error → usable without restriction on this API.
    return [_exposure("GOOGLE", GOOGLE_KEY_UNRESTRICTED, validated=True,
                      summary="Google API key is unrestricted (usable without referer/IP limits)",
                      target=key, method="GET geocode", status=200, source_secret_id=sid)]


# ─── S3 buckets (Task 4) ─────────────────────────────────────────────────────
_S3_PATTERNS = (
    re.compile(r"https?://([a-z0-9.\-]+)\.s3[.\-][a-z0-9\-]*\.?amazonaws\.com", re.I),
    re.compile(r"https?://([a-z0-9.\-]+)\.s3\.amazonaws\.com", re.I),
    re.compile(r"https?://s3[.\-][a-z0-9\-]*\.?amazonaws\.com/([a-z0-9.\-]+)", re.I),
    re.compile(r"https?://s3\.amazonaws\.com/([a-z0-9.\-]+)", re.I),
)


def _s3_targets(endpoints: list) -> list[str]:
    buckets = {}
    for ep in endpoints or []:
        s = str(ep)
        for pat in _S3_PATTERNS:
            m = pat.search(s)
            if m:
                bucket = m.group(1).rstrip(".")
                if bucket and bucket.lower() not in ("s3", "www"):
                    buckets.setdefault(bucket, f"https://{bucket}.s3.amazonaws.com/")
                break
    return [buckets[b] for b in sorted(buckets)]


def _probe_s3(list_url: str) -> list[dict]:
    try:
        status, body = base.http_send(base.make_request(list_url))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return [_exposure("S3", S3_ACCESS_DENIED, validated=True,
                              summary="S3 bucket exists but listing is denied (private)",
                              target=list_url, method="GET ?list", status=403)]
        return []   # 404 NoSuchBucket / other → no exposure
    except Exception:
        return []
    # Detect that listing is ENABLED — but never parse/store the object keys.
    if status == 200 and "<ListBucketResult" in body:
        return [_exposure("S3", S3_PUBLIC_LISTING, validated=True,
                          summary="S3 bucket listing is publicly enabled",
                          target=list_url, method="GET ?list", status=200)]
    return []


# ─── Orchestration ───────────────────────────────────────────────────────────
def _run_task(kind: str, value: str, sid: str) -> list[dict]:
    try:
        if kind == "firebase":
            return _probe_firebase(value, sid)
        if kind == "google":
            return _probe_google(value, sid)
        if kind == "s3":
            return _probe_s3(value)
    except Exception:
        return []
    return []


def detect_exposures(results: dict, secrets: list[dict]) -> list[dict]:
    """Probe cloud exposure for the visible secrets + S3 endpoints. Mutates
    results["cloud_exposures"] and returns the exposure list. No-op (empty) when
    cloud intelligence is disabled."""
    results.setdefault("cloud_exposures", [])
    if not cloud_intel_enabled():
        return results["cloud_exposures"]

    tasks: list[tuple[str, str, str]] = []
    seen_targets: set = set()
    for s in secrets:
        stype = s.get("type", "")
        if stype in ("FIREBASE_URL", "FIREBASE_PAIR"):
            url = _firebase_url(s)
            if url and ("fb", url) not in seen_targets:
                seen_targets.add(("fb", url))
                tasks.append(("firebase", url, s.get("id", "")))
        if stype in ("GOOGLE_API_KEY", "GCP_API_KEY", "FIREBASE_PAIR"):
            key = _google_key(s)
            if key and ("g", key) not in seen_targets:
                seen_targets.add(("g", key))
                tasks.append(("google", key, s.get("id", "")))
    for url in _s3_targets(results.get("endpoints", [])):
        tasks.append(("s3", url, ""))

    exposures: list[dict] = []
    if tasks:
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
            futures = {ex.submit(_run_task, k, v, sid): (k, v) for (k, v, sid) in tasks}
            for fut in as_completed(futures):
                try:
                    exposures.extend(fut.result() or [])
                except Exception:
                    pass

    # Deterministic ordering, de-dup by id.
    uniq = {e["id"]: e for e in exposures}
    exposures = sorted(uniq.values(), key=lambda e: (e["exposure_type"], e["id"]))
    results["cloud_exposures"] = exposures
    log.info("[cloud_intel] probed=%d exposures=%d public=%d",
             len(tasks), len(exposures),
             sum(1 for e in exposures if e["exposure_type"] in _PUBLIC_EXPOSURES))
    return exposures


def summarize(exposures: list[dict]) -> dict:
    """Executive rollup (Task 7)."""
    public = [e for e in exposures if e["exposure_type"] in _PUBLIC_EXPOSURES]
    critical = [e for e in exposures if e["severity"] == "critical"]
    return {
        "cloud_exposures": len(exposures),
        "public_cloud_exposures": len(public),
        "critical_exposures": len(critical),
        "exposure_confidence": HIGH if exposures else "",
        "exposure_types": sorted({e["exposure_type"] for e in exposures}),
    }
