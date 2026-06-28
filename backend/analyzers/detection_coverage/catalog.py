"""
Detection Coverage Catalog (Beetle 2.0, Phase 1.98).

The DATA behind the coverage registry. It does two things:

1. Documents Beetle's EXISTING detection capabilities (secrets / crypto / manifest /
   iOS) so the registry is the single source of truth for "what Beetle detects" and
   the benchmark engine can compute gaps vs MobSF / APKLeaks.
2. Adds the genuine GAPS found in the MobSF comparison — new secret patterns and
   new crypto rules — marked ``new=True``. New SECRET patterns are contributed to
   the unified ``analyzers.secret_catalog`` (provenance ``"coverage"``) so they are
   matched by the ONE combined walk; new CRYPTO rules live in ``code_rules`` and are
   referenced here by ``detector_ref``. Nothing here re-implements matching.

``register_all()`` is idempotent and is invoked on import.
"""
from __future__ import annotations

import logging

from .registry import (
    CoverageEntry, KIND_CRYPTO, KIND_MANIFEST, KIND_PLATFORM, KIND_SECRET,
    SOURCE_BEETLE_NATIVE, SOURCE_COVERAGE, register, to_secret_patterns,
)

log = logging.getLogger("cortex.detection_coverage")

_CWE_SECRET = "CWE-798"
_CWE_INFO = "CWE-200"


def _sec(id, name, category, pattern, *, severity="high", confidence=85, exploitability=60,
         cwe=_CWE_SECRET, masvs="MASVS-CRYPTO-2", owasp="M1", platform="both",
         check_entropy=False, refs=(), desc="", rec="", new=True, source=SOURCE_COVERAGE):
    return CoverageEntry(
        id=id, category=category, name=name, kind=KIND_SECRET, source=source,
        platform=platform, pattern=pattern, severity=severity, confidence=confidence,
        exploitability=exploitability, cwe=cwe, masvs=masvs, owasp=owasp,
        references=list(refs), description=desc, recommendation=rec,
        check_entropy=check_entropy, new=new)


# ── NEW secret patterns (genuine gaps from the MobSF comparison) ───────────────
# Deliberately exclude anything already covered by beetle_native / apkleaks
# (GitLab glpat-, Discord, Square, FCM, JWT, AWS access/secret keys, …) to avoid
# duplicate detections.
_NEW_SECRETS = [
    _sec("cov_aws_cognito_identity_pool", "AWS Cognito Identity Pool", "Cloud Credentials",
         r"(?:us|eu|ap|sa|ca|me|af|cn)-(?:east|west|north|south|central|northeast|southeast)-\d:"
         r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
         severity="high", confidence=90, exploitability=70, cwe=_CWE_INFO, owasp="M1",
         refs=["https://docs.aws.amazon.com/cognito/"],
         desc="AWS Cognito Identity Pool ID (region:uuid) detected. Unauthenticated/"
              "guest identities or over-broad IAM roles can grant access to AWS resources.",
         rec="Audit the identity pool: disable unauthenticated access if unused and scope "
             "the authenticated/guest IAM roles to least privilege."),
    _sec("cov_aws_cognito_user_pool", "AWS Cognito User Pool", "Cloud Config",
         r"(?:us|eu|ap|sa|ca|me|af|cn)-(?:east|west|north|south|central|northeast|southeast)-\d_[A-Za-z0-9]{6,12}",
         severity="medium", confidence=88, exploitability=45, cwe=_CWE_INFO, owasp="M8",
         refs=["https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html"],
         desc="AWS Cognito User Pool ID (region_id) detected. Identifies the user "
              "directory; combined with self-service sign-up or a leaked app client it "
              "enables account enumeration / unauthenticated registration attacks.",
         rec="Confirm sign-up is restricted as intended and app client secrets are not "
             "shipped in the client; the pool id alone is a recon identifier, not a credential."),
    _sec("cov_aws_sts_key", "AWS STS Temporary Access Key", "Cloud Credentials",
         r"ASIA[0-9A-Z]{16}",
         severity="high", confidence=88, exploitability=80,
         refs=["https://docs.aws.amazon.com/STS/"],
         desc="AWS STS temporary access key id (ASIA prefix) detected. Beetle's base "
              "AWS rule only matched the AKIA (long-term) prefix — STS/temporary and "
              "other IAM principal credentials were a coverage gap.",
         rec="Treat as a live credential until expiry; rotate the issuing role/session."),
    _sec("cov_aws_iam_unique_id", "AWS IAM Unique ID", "Cloud Config",
         r"(?:AROA|AIDA|AGPA|AIPA|ANPA|ANVA)[0-9A-Z]{16}",
         severity="low", confidence=75, exploitability=15, cwe=_CWE_INFO, owasp="M8",
         desc="AWS IAM unique id (role/user/group principal). Not a secret by itself "
              "but confirms AWS IAM usage and aids attacker recon.",
         rec="Avoid shipping IAM principal ids in the client where avoidable."),
    _sec("cov_cloudfront_url", "AWS CloudFront Distribution", "Cloud Config",
         r"[a-z0-9]{6,}\.cloudfront\.net",
         severity="low", confidence=80, exploitability=15, cwe=_CWE_INFO, owasp="M8",
         desc="AWS CloudFront distribution domain detected. Confirms the CDN/origin "
              "and is useful for mapping the cloud footprint.",
         rec="Confirm the distribution/origin is not serving sensitive unauthenticated content."),
    _sec("cov_aws_account_arn", "AWS ARN (account exposure)", "Cloud Config",
         r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[A-Za-z0-9\-_/:.]+",
         severity="low", confidence=70, exploitability=20, cwe=_CWE_INFO, owasp="M8",
         desc="AWS ARN embedding a 12-digit account id. Useful for attacker recon of the "
              "cloud account and resource naming.",
         rec="Avoid shipping ARNs with account ids in the client where possible."),
    _sec("cov_google_oauth_client_secret", "Google OAuth Client Secret", "OAuth",
         r"GOCSPX-[A-Za-z0-9_\-]{28}",
         severity="critical", confidence=95, exploitability=85,
         desc="Google OAuth client secret (GOCSPX-) detected. Allows impersonating the "
              "OAuth client to obtain tokens.",
         rec="Rotate the client secret in Google Cloud Console; never embed it in a client app."),
    _sec("cov_openai_project_key", "OpenAI Project API Key", "AI Service",
         r"sk-proj-[A-Za-z0-9_\-]{40,}",
         severity="critical", confidence=92, exploitability=85, check_entropy=True,
         desc="OpenAI project-scoped API key (sk-proj-) detected. Grants model access at "
              "your billing cost.",
         rec="Rotate at platform.openai.com; keep API keys server-side."),
    _sec("cov_slack_app_token", "Slack App-Level Token", "API Token",
         r"xapp-\d-[A-Za-z0-9]+-\d+-[a-f0-9]+",
         severity="high", confidence=90, exploitability=65,
         desc="Slack app-level token (xapp-) detected. Enables Socket Mode / app actions.",
         rec="Revoke and rotate the app-level token in Slack app settings."),
    _sec("cov_telegram_bot_token", "Telegram Bot Token", "API Token",
         r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b",
         severity="high", confidence=85, exploitability=65, check_entropy=True,
         desc="Telegram bot token detected. Grants full control of the bot account.",
         rec="Regenerate the token via BotFather; keep it server-side."),
    _sec("cov_stripe_publishable_key", "Stripe Publishable Key", "Payment Config",
         r"pk_live_[0-9a-zA-Z]{24,}",
         severity="low", confidence=90, exploitability=15, cwe=_CWE_INFO, owasp="M8",
         desc="Stripe live publishable key detected. Public by design but confirms the "
              "live Stripe integration and is useful for recon.",
         rec="Publishable keys are client-safe; ensure no SECRET (sk_live_) key is shipped."),
    _sec("cov_firebase_cloud_messaging_v1", "Firebase App ID", "Cloud Config",
         r"1:\d{6,}:(?:android|ios|web):[a-f0-9]{8,}",
         severity="low", confidence=80, exploitability=15, cwe=_CWE_INFO, owasp="M8",
         desc="Firebase application id (mobilesdk_app_id) detected. Identifies the Firebase "
              "project; combine with open security rules for impact.",
         rec="Confirm Firebase security rules are not world-readable/writable."),
]

# ── EXISTING capabilities (documentation only — these detectors already exist) ─
def _doc(id, name, category, kind, detector_ref, *, platform="android",
         severity="medium", source=SOURCE_BEETLE_NATIVE, masvs="", owasp=""):
    return CoverageEntry(id=id, category=category, name=name, kind=kind, source=source,
                         platform=platform, detector_ref=detector_ref, severity=severity,
                         masvs=masvs, owasp=owasp, new=False)


_EXISTING_CRYPTO = [
    _doc("doc_md5", "Weak Hash — MD5", "Cryptography", KIND_CRYPTO, "android_weak_hash_md5", masvs="MASVS-CRYPTO-1"),
    _doc("doc_sha1", "Weak Hash — SHA-1", "Cryptography", KIND_CRYPTO, "android_weak_hash_sha1", masvs="MASVS-CRYPTO-1"),
    _doc("doc_des", "Weak Cipher — DES/3DES", "Cryptography", KIND_CRYPTO, "android_weak_cipher_des", masvs="MASVS-CRYPTO-1"),
    _doc("doc_ecb", "Weak Cipher Mode — ECB", "Cryptography", KIND_CRYPTO, "android_weak_cipher_ecb", masvs="MASVS-CRYPTO-1"),
    _doc("doc_cbc_oracle", "CBC Padding Oracle", "Cryptography", KIND_CRYPTO, "android_cbc_padding_oracle", masvs="MASVS-CRYPTO-1"),
    _doc("doc_insecure_random", "Weak PRNG", "Cryptography", KIND_CRYPTO, "android_insecure_random", masvs="MASVS-CRYPTO-1"),
    _doc("doc_weak_iv", "Static/Predictable IV", "Cryptography", KIND_CRYPTO, "android_weak_iv", masvs="MASVS-CRYPTO-2"),
    _doc("doc_weak_rsa_signing", "Weak RSA Signing Key", "Cryptography", KIND_CRYPTO, "cert:weak_rsa", masvs="MASVS-CRYPTO-1"),
]

# NEW crypto rules added to code_rules this phase (the rule does the matching).
_NEW_CRYPTO = [
    CoverageEntry(id="cov_rc4", category="Cryptography", name="Weak Cipher — RC4",
                  kind=KIND_CRYPTO, source=SOURCE_COVERAGE, detector_ref="android_weak_cipher_rc4",
                  severity="high", masvs="MASVS-CRYPTO-1", owasp="M10", new=True),
    CoverageEntry(id="cov_aes_ecb_default", category="Cryptography",
                  name="AES Default Mode (ECB)", kind=KIND_CRYPTO, source=SOURCE_COVERAGE,
                  detector_ref="android_aes_ecb_default", severity="high",
                  masvs="MASVS-CRYPTO-1", owasp="M10", new=True),
    CoverageEntry(id="cov_static_salt", category="Cryptography", name="Hardcoded Salt",
                  kind=KIND_CRYPTO, source=SOURCE_COVERAGE, detector_ref="android_static_salt",
                  severity="medium", masvs="MASVS-CRYPTO-2", owasp="M10", new=True),
    CoverageEntry(id="cov_weak_pbkdf", category="Cryptography",
                  name="Weak PBKDF Iteration Count", kind=KIND_CRYPTO, source=SOURCE_COVERAGE,
                  detector_ref="android_weak_pbkdf_iterations", severity="medium",
                  masvs="MASVS-CRYPTO-1", owasp="M10", new=True),
    CoverageEntry(id="cov_weak_rsa_keygen", category="Cryptography",
                  name="Weak RSA Key Size (keygen)", kind=KIND_CRYPTO, source=SOURCE_COVERAGE,
                  detector_ref="android_weak_rsa_keygen", severity="high",
                  masvs="MASVS-CRYPTO-1", owasp="M10", new=True),
]

_EXISTING_MANIFEST = [
    _doc("doc_allow_backup", "Backup Allowed", "Configuration", KIND_MANIFEST, "manifest:allowBackup", masvs="MASVS-STORAGE-1"),
    _doc("doc_cleartext", "Cleartext Traffic", "Network Security", KIND_MANIFEST, "manifest:usesCleartextTraffic", masvs="MASVS-NETWORK-1"),
    _doc("doc_nsc", "Network Security Config", "Network Security", KIND_MANIFEST, "manifest:networkSecurityConfig", masvs="MASVS-NETWORK-1"),
    _doc("doc_exported", "Exported Components", "Exported Components", KIND_MANIFEST, "manifest:exported", masvs="MASVS-PLATFORM-1"),
    _doc("doc_deeplinks", "Deep Links", "Deep Links", KIND_MANIFEST, "manifest:intent-filter", masvs="MASVS-PLATFORM-3"),
    _doc("doc_permissions", "Dangerous Permissions", "Permissions", KIND_MANIFEST, "manifest:permissions", masvs="MASVS-PLATFORM-1"),
    _doc("doc_debuggable", "Debuggable Flag", "Configuration", KIND_MANIFEST, "manifest:debuggable", masvs="MASVS-RESILIENCE-1"),
    _doc("doc_task_affinity", "Task Affinity", "Configuration", KIND_MANIFEST, "manifest:taskAffinity", masvs="MASVS-PLATFORM-1"),
    _doc("doc_legacy_storage", "RequestLegacyExternalStorage", "Storage", KIND_MANIFEST, "manifest:requestLegacyExternalStorage", masvs="MASVS-STORAGE-1"),
]

_EXISTING_IOS = [
    _doc("doc_ats", "App Transport Security", "Network Security", KIND_PLATFORM, "ios:ATS", platform="ios", masvs="MASVS-NETWORK-1"),
    _doc("doc_keychain", "Keychain Accessibility", "Storage", KIND_PLATFORM, "ios:keychain", platform="ios", masvs="MASVS-STORAGE-1"),
    _doc("doc_url_schemes", "Custom URL Schemes", "Deep Links", KIND_PLATFORM, "ios:url_schemes", platform="ios", masvs="MASVS-PLATFORM-3"),
    _doc("doc_entitlements", "Entitlements", "Configuration", KIND_PLATFORM, "ios:entitlements", platform="ios", masvs="MASVS-PLATFORM-1"),
    _doc("doc_pasteboard", "Pasteboard Usage", "Privacy", KIND_PLATFORM, "ios:pasteboard", platform="ios", masvs="MASVS-PLATFORM-2"),
    _doc("doc_file_protection", "File Protection Class", "Storage", KIND_PLATFORM, "ios:file_protection", platform="ios", masvs="MASVS-STORAGE-1"),
    _doc("doc_biometrics", "Biometric Auth", "Authentication", KIND_PLATFORM, "ios:biometrics", platform="ios", masvs="MASVS-AUTH-2"),
]

_ALL = (_NEW_SECRETS + _EXISTING_CRYPTO + _NEW_CRYPTO
        + _EXISTING_MANIFEST + _EXISTING_IOS)

_REGISTERED = False


def register_all() -> None:
    """Register every catalog entry and contribute new secret patterns to the
    unified secret_catalog. Idempotent."""
    global _REGISTERED
    if _REGISTERED:
        return
    for entry in _ALL:
        register(entry)
    # Contribute coverage secrets to the ONE unified catalog (no separate matcher).
    try:
        from .. import secret_catalog
        secret_catalog.register("coverage", to_secret_patterns(), source=SOURCE_COVERAGE)
    except Exception:
        log.exception("[detection_coverage] failed to contribute secrets to secret_catalog")
    _REGISTERED = True


register_all()
