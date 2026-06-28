"""
Benchmark Engine (Beetle 2.0, Phase 1.98).

Compares what BEETLE detected against what MobSF and APKLeaks detected for the same
APK, and categorizes the differences so developers can close real gaps without
chasing noise:

    common           detected by Beetle AND another engine
    beetle_only      Beetle found it, the others did not (Beetle's edge)
    missing          another engine found it, Beetle did not (a gap to close)
    duplicate        the same logical detection appears multiple times in one engine
    better_evidence  common detections where Beetle has file+line evidence

Each engine's output is normalized to canonical *detection signatures* (e.g.
"aws_access_key", "weak_cipher_ecb") via an alias map + slugging, so superficial
naming differences between tools do not create false gaps. This complements the
existing ``benchmark.py`` quality-gate runner; this module is the pure, testable
comparison core (no scanning, no I/O).
"""
from __future__ import annotations

import re

_SLUG = re.compile(r"[^a-z0-9]+")

# Canonical-signature aliases: many surface labels → one detection signature, so
# Beetle "AWS Access Key ID" and MobSF "AWS Access Key" compare equal. KEYS MUST be
# in slugged form (lowercase, single spaces, no punctuation) — they are matched
# against signature()'s slugged input. Extend freely.
_ALIASES = {
    "aws access key": "aws_access_key", "aws access key id": "aws_access_key",
    "aws secret": "aws_secret_key", "aws secret access key": "aws_secret_key",
    "aws cognito": "aws_cognito", "cognito": "aws_cognito",
    "aws cognito identity pool": "aws_cognito", "identity pool": "aws_cognito",
    "aws cognito user pool": "aws_cognito", "user pool": "aws_cognito",
    "aws mws auth token": "aws_mws", "aws arn account exposure": "aws_arn",
    "google api key": "google_api_key", "google maps": "google_api_key",
    "google oauth client secret": "google_oauth_secret",
    "firebase database url": "firebase", "firebase realtime database url": "firebase",
    "firebase app id": "firebase",
    "stripe live secret key": "stripe_secret", "stripe restricted key": "stripe_secret",
    "stripe publishable key": "stripe_publishable",
    "twilio account sid": "twilio", "twilio api key": "twilio", "twilio auth token": "twilio",
    "slack token": "slack", "slack oauth token": "slack", "slack webhook url": "slack_webhook",
    "slack app level token": "slack_app",
    "discord bot token": "discord", "discord webhook url": "discord",
    "github token": "github", "github personal access token": "github",
    "github fine grained token": "github", "gitlab personal access token": "gitlab",
    "mailgun api key": "mailgun", "sendgrid api key": "sendgrid",
    "openai api key": "openai", "openai project api key": "openai",
    "anthropic api key": "anthropic", "telegram bot token": "telegram",
    "json web token": "jwt", "jwt": "jwt",
    "rsa private key": "private_key", "ec private key": "private_key",
    "dsa private key": "private_key", "openssh private key": "private_key",
    "pgp private key block": "private_key", "generic private key": "private_key",
    "pem private key": "private_key",
    # crypto (slugged: em-dashes/slashes collapse to spaces)
    "weak cipher mode ecb": "weak_cipher_ecb", "weak cipher ecb": "weak_cipher_ecb",
    "aes default mode ecb": "weak_cipher_ecb",
    "weak cipher des 3des": "weak_cipher_des", "weak cipher des": "weak_cipher_des",
    "weak cipher rc4": "weak_cipher_rc4",
    "weak hash md5": "weak_hash_md5", "weak hash algorithm md5": "weak_hash_md5",
    "weak hash sha 1": "weak_hash_sha1", "weak hash algorithm sha 1": "weak_hash_sha1",
    "weak prng": "weak_prng", "insecure random number generator": "weak_prng",
    "static predictable iv": "static_iv", "hardcoded or predictable iv": "static_iv",
    "hardcoded salt": "static_salt", "weak pbkdf iteration count": "weak_pbkdf",
    "cbc padding oracle": "cbc_oracle",
    "weak rsa signing key": "weak_rsa", "weak rsa key size keygen": "weak_rsa",
    # bare labels other tools emit
    "ecb": "weak_cipher_ecb", "des": "weak_cipher_des", "3des": "weak_cipher_des",
    "rc4": "weak_cipher_rc4", "md5": "weak_hash_md5", "sha1": "weak_hash_sha1",
    # manifest / platform
    "backup allowed": "allow_backup", "cleartext traffic": "cleartext",
    "exported components": "exported", "deep links": "deeplinks",
    "app transport security": "ats",
}


def signature(label: str) -> str:
    """Canonical detection signature for a surface label."""
    s = _SLUG.sub(" ", str(label or "").lower()).strip()
    if s in _ALIASES:
        return _ALIASES[s]
    # Substring alias match (e.g. "AWS Cognito Identity Pool (eu-west-1)").
    for needle, sig in _ALIASES.items():
        if needle in s:
            return sig
    return _SLUG.sub("_", s).strip("_") or "unknown"


# ── Adapters: each engine's native output → set/list of signatures ─────────────
def beetle_signatures(results: dict) -> list[str]:
    """Signatures Beetle produced: findings (category/title) + secrets (name/type)."""
    sigs: list[str] = []
    for f in results.get("findings") or []:
        if isinstance(f, dict):
            sigs.append(signature(f.get("title") or f.get("category") or f.get("rule_id") or ""))
    for bucket in ("secrets", "suppressed_secrets"):
        for s in results.get(bucket) or []:
            if isinstance(s, dict):
                sigs.append(signature(s.get("type") or s.get("name") or s.get("title") or ""))
    return sigs


def mobsf_signatures(report: dict) -> list[str]:
    """Signatures from a MobSF JSON report (best-effort across its sections)."""
    sigs: list[str] = []
    if not isinstance(report, dict):
        return sigs
    for sec in report.get("secrets", []) or []:
        sigs.append(signature(sec if isinstance(sec, str) else (sec.get("name") or sec.get("secret") or "")))
    for key in ("code_analysis", "manifest_analysis", "binary_analysis"):
        block = report.get(key) or {}
        findings = block.get("findings") if isinstance(block, dict) else block
        if isinstance(findings, dict):
            sigs.extend(signature(k) for k in findings.keys())
        elif isinstance(findings, list):
            for it in findings:
                sigs.append(signature(it.get("title") or it.get("rule") or it if isinstance(it, dict) else it))
    for c in report.get("certificate_analysis", {}).get("certificate_findings", []) or []:
        if isinstance(c, (list, tuple)) and len(c) >= 2:
            sigs.append(signature(c[1]))
    return [s for s in sigs if s and s != "unknown"]


def apkleaks_signatures(report: dict) -> list[str]:
    """Signatures from an APKLeaks JSON report ({results:[{name,matches}]})."""
    sigs: list[str] = []
    if not isinstance(report, dict):
        return sigs
    for r in report.get("results", []) or []:
        if isinstance(r, dict) and r.get("name"):
            sigs.append(signature(r["name"]))
    return sigs


def _dupes(sigs: list[str]) -> dict:
    seen: dict[str, int] = {}
    for s in sigs:
        seen[s] = seen.get(s, 0) + 1
    return {s: n for s, n in seen.items() if n > 1}


def compare(beetle: list[str], mobsf: list[str] | None = None,
            apkleaks: list[str] | None = None, *, results: dict | None = None) -> dict:
    """Categorize coverage across engines. Inputs are signature lists (use the
    adapters) or raw — strings are normalized defensively. ``results`` (optional)
    lets the report flag better_evidence for common detections."""
    b = {signature(x) for x in beetle}
    m = {signature(x) for x in (mobsf or [])}
    a = {signature(x) for x in (apkleaks or [])}
    others = m | a

    common = sorted(b & others)
    beetle_only = sorted(b - others)
    missing = sorted(others - b)

    better_evidence = []
    if results is not None:
        evidenced = {signature(f.get("title") or f.get("category") or "")
                     for f in (results.get("findings") or []) if isinstance(f, dict)
                     and (f.get("file_path") or f.get("evidence_selection"))}
        better_evidence = sorted(set(common) & evidenced)

    return {
        "common": common,
        "beetle_only": beetle_only,
        "missing": missing,
        "only_mobsf": sorted(m - b),
        "only_apkleaks": sorted(a - b),
        "duplicate": {
            "beetle": _dupes([signature(x) for x in beetle]),
            "mobsf": _dupes([signature(x) for x in (mobsf or [])]),
            "apkleaks": _dupes([signature(x) for x in (apkleaks or [])]),
        },
        "better_evidence": better_evidence,
        "counts": {"beetle": len(b), "mobsf": len(m), "apkleaks": len(a),
                   "common": len(common), "beetle_only": len(beetle_only),
                   "missing": len(missing)},
    }
