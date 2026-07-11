"""
APKLeaks pattern catalog — ported into Beetle's native pattern shape (Phase 1.9).

APKLeaks (https://github.com/dwisiswant0/apkleaks) ships a flat ``config/regexes.json``
of ~50 rules in the form ``{"<name>": "<regex>" | ["<regex>", …]}``. Those rules
carry *only* a name + regex — no severity, category, CWE, MASVS, OWASP, confidence
or remediation. APKLeaks emits raw, ungraded regex hits grouped by rule name.

This module is the "learn from APKLeaks, don't wrap it" deliverable: every rule is
re-expressed in Beetle's existing pattern dict shape (the same shape
``evidence_scanner.SECRET_PATTERNS_EVIDENCE`` uses), so the ported rules flow
through Beetle's own ``scan_file_for_patterns`` machinery (line/snippet capture,
entropy gate, length cap, binary-dump suppression, dedup) and then through the full
intelligence pipeline. We supply the security metadata APKLeaks lacks.

Design notes
------------
* **No subprocess, no apkleaks dependency, no second report.** Only the *pattern
  intelligence* is reused; the catalog is plain data consumed by Beetle's scanner.
* **De-duplication against Beetle Native.** Beetle already detects many of these
  (AWS, Google API, Firebase, Stripe, Twilio, GitHub, Slack, JWT, PEM keys) via
  ``SECRET_PATTERNS_EVIDENCE``. We KEEP overlapping rules here on purpose: when both
  engines fire on the same value, the fusion layer merges them into ONE finding
  "Detected By" both. The value of this catalog is the rules Beetle is *missing*
  (Heroku, PayPal/Braintree, Square, Mailgun, Discord, Facebook/Twitter OAuth,
  MailChimp, Picatic, Amazon MWS, Google OAuth, generic Authorization headers,
  RSA/DSA/EC/PGP key blocks, credentials-in-URL, …).
* **kind**: ``"secret"`` rules are routed to ``results["secrets"]`` (so they inherit
  Secret Intelligence + masking); ``"finding"`` rules (key *files*, cert blocks)
  are routed straight to ``results["findings"]``. ``"endpoint"`` rules feed
  ``results["endpoints"]``.
* Each entry is intentionally conservative on confidence/severity; the downstream
  entropy gate, ownership engine, triage engine and bug-bounty engine refine and
  may suppress. Broad/noisy rules start at lower severity/confidence.

Every dict is compatible with ``evidence_scanner.scan_file_for_patterns`` (which
reads ``name``, ``pattern``, ``severity``, ``category``, ``description``,
``recommendation``, ``confidence``, ``exploitability``, ``check_entropy``,
``max_len``, plus the ``cwe``/``masvs``/``owasp`` it forwards onto the finding).
"""
from __future__ import annotations

# Display name of this detection source — written into finding/secret attribution.
SOURCE_NAME = "APKLeaks"

# CWE shorthand reused across credential rules.
_CWE_HARDCODED = "CWE-798"          # Use of Hard-coded Credentials
_CWE_INFO_EXPOSURE = "CWE-200"      # Exposure of Sensitive Information
_CWE_PRIVATE_KEY = "CWE-321"        # Use of Hard-coded Cryptographic Key


def _p(name, pattern, severity, category, desc, rec, *,
       confidence=75, exploitability=50, kind="secret",
       cwe=_CWE_HARDCODED, masvs="MASVS-CRYPTO-2", owasp="M1",
       check_entropy=False, max_len=300, redact_context=False):
    """Build one Beetle-shaped pattern dict from an APKLeaks-style rule.

    ``redact_context`` marks rules whose surrounding lines may themselves contain
    raw key/cert material (PEM blocks): for these the windowed ``code_context`` is
    dropped at routing time so no body fragment can survive masking (masking only
    scrubs the matched value, not a windowed context that excludes it).
    """
    return {
        "name": name,
        "pattern": pattern,
        "severity": severity,
        "category": category,
        "description": desc,
        "recommendation": rec,
        "confidence": confidence,
        "exploitability": exploitability,
        "cwe": cwe,
        "masvs": masvs,
        "owasp": owasp,
        "check_entropy": check_entropy,
        "max_len": max_len,
        "redact_context": redact_context,
        # Beetle-internal routing + provenance (consumed by the unified scan).
        "kind": kind,
        "provenance": "apkleaks",
        "source": SOURCE_NAME,
    }


# ── The ported catalog ───────────────────────────────────────────────────────
# Ordered roughly cloud → payment → comms → vcs → oauth → keys → generic → net.
APKLEAKS_PATTERNS: list[dict] = [
    # ── Cloud / infrastructure ────────────────────────────────────────────────
    _p("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical", "Cloud Credentials",
       "AWS Access Key ID detected (APKLeaks rule). With the secret key it grants AWS API access.",
       "Rotate immediately; use STS/IAM roles instead of embedding long-lived keys.",
       confidence=95, exploitability=90),
    _p("AWS MWS Auth Token",
       r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
       "high", "Cloud Credentials",
       "Amazon MWS (Marketplace Web Service) auth token detected.",
       "Rotate the MWS token in Seller Central; never ship it in a client.",
       confidence=90, exploitability=70),
    _p("AWS S3 Bucket URL",
       r"[a-z0-9.\-]+\.s3(?:[-.][a-z0-9\-]+)?\.amazonaws\.com",
       "medium", "Cloud Config",
       "Amazon S3 bucket URL referenced. Check for public list/read/write access.",
       "Audit the bucket ACL and policy; block public access unless required.",
       confidence=70, exploitability=55, cwe=_CWE_INFO_EXPOSURE,
       masvs="MASVS-NETWORK-1", owasp="M8", kind="endpoint"),
    _p("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high", "API Key",
       "Google API key detected (APKLeaks rule). May allow unauthorized API/quota use.",
       "Restrict the key by API, app package and SHA-1 in Google Cloud Console.",
       confidence=90, exploitability=70),
    _p("Google OAuth Client ID",
       r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
       "low", "OAuth",
       "Google OAuth client ID detected. Public by design, but useful for recon.",
       "Confirm the OAuth consent/redirect config; client IDs alone are low risk.",
       confidence=80, exploitability=20, cwe=_CWE_INFO_EXPOSURE, owasp="M1"),
    _p("Google OAuth Access Token", r"ya29\.[0-9A-Za-z\-_]+", "high", "OAuth",
       "Google OAuth access token detected. Grants the token's scopes until expiry.",
       "Treat as compromised; revoke and stop embedding user tokens in the app.",
       confidence=80, exploitability=75, owasp="M1", check_entropy=True),
    _p("Firebase Database URL",
       r"https://[a-z0-9\-]+\.firebaseio\.com",
       "medium", "Cloud Config",
       "Firebase Realtime Database URL found. Test for unauthenticated read/write.",
       "Audit Firebase security rules; verify /.json is not world-readable.",
       confidence=85, exploitability=60, cwe=_CWE_INFO_EXPOSURE,
       masvs="MASVS-NETWORK-1", owasp="M8", kind="endpoint"),
    _p("Google Cloud Service Account",
       r'"type"\s*:\s*"service_account"',
       "critical", "Cloud Credentials",
       "Embedded GCP service-account JSON detected. Often grants broad project access.",
       "Remove the key file; use Workload Identity / short-lived credentials.",
       confidence=85, exploitability=85),
    _p("Heroku API Key",
       r"(?i)heroku(?:.{0,20})?[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
       "high", "Cloud Credentials",
       "Heroku API key detected. Grants control of the associated Heroku account/apps.",
       "Rotate the Heroku key; use scoped, server-side credentials.",
       confidence=70, exploitability=70),
    _p("Azure Storage Account Key",
       r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}",
       "critical", "Cloud Credentials",
       "Azure Storage connection string with account key detected.",
       "Rotate the storage key; use SAS tokens / managed identities instead.",
       confidence=90, exploitability=85),

    # ── Payment providers ─────────────────────────────────────────────────────
    _p("Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "critical",
       "Payment Credentials",
       "Stripe live secret key detected. Full payment API access.",
       "Rotate immediately in the Stripe dashboard; never embed secret keys.",
       confidence=99, exploitability=95, check_entropy=True),
    _p("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,}", "high",
       "Payment Credentials",
       "Stripe restricted key detected. Grants the key's configured scopes.",
       "Rotate in the Stripe dashboard; keep restricted keys server-side.",
       confidence=95, exploitability=80, check_entropy=True),
    _p("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}", "critical",
       "Payment Credentials",
       "Square access token detected. Grants Square API access.",
       "Rotate the token in the Square dashboard.",
       confidence=90, exploitability=85),
    _p("Square OAuth Secret", r"sq0csp-[0-9A-Za-z\-_]{43}", "critical",
       "Payment Credentials",
       "Square OAuth application secret detected.",
       "Rotate the Square OAuth secret; keep it server-side only.",
       confidence=90, exploitability=85),
    _p("PayPal Braintree Access Token",
       r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
       "critical", "Payment Credentials",
       "PayPal/Braintree production access token detected.",
       "Rotate the Braintree token; never ship production tokens in a client.",
       confidence=90, exploitability=85),
    _p("Picatic API Key", r"sk_live_[0-9a-z]{32}", "high", "Payment Credentials",
       "Picatic live API key detected.",
       "Rotate the Picatic key in the dashboard.",
       confidence=70, exploitability=60),

    # ── Communications / messaging ────────────────────────────────────────────
    _p("Twilio Account SID", r"AC[a-z0-9]{32}", "high", "API Key",
       "Twilio Account SID detected. Combined with the auth token grants Twilio API use.",
       "Rotate the Twilio auth token; keep Twilio credentials server-side.",
       confidence=80, exploitability=60),
    _p("Twilio API Key", r"SK[a-z0-9]{32}", "high", "API Key",
       "Twilio API key (SK) detected.",
       "Rotate the Twilio API key; restrict its capabilities.",
       confidence=80, exploitability=65),
    _p("SendGrid API Key",
       r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
       "high", "API Key",
       "SendGrid API key detected. Grants email-sending on the account.",
       "Rotate the SendGrid key; restrict scopes; keep server-side.",
       confidence=90, exploitability=70),
    _p("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "high", "API Key",
       "Mailgun API key detected.",
       "Rotate the Mailgun key; keep mail credentials server-side.",
       confidence=70, exploitability=60),
    _p("MailChimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}", "high", "API Key",
       "MailChimp API key detected.",
       "Rotate the MailChimp key in account settings.",
       confidence=80, exploitability=60),
    _p("Slack Token",
       r"xox[baprs]-[0-9A-Za-z\-]{10,72}",
       "high", "API Token",
       "Slack token detected. Grants the token's Slack workspace scopes.",
       "Revoke the token in Slack; never embed workspace tokens in a client.",
       confidence=90, exploitability=70),
    _p("Slack Webhook URL",
       r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z]{24}",
       "medium", "API Token",
       "Slack incoming webhook URL detected. Allows posting to a Slack channel.",
       "Rotate the webhook; treat the URL as a credential.",
       confidence=90, exploitability=50, cwe=_CWE_INFO_EXPOSURE, owasp="M8"),
    _p("Discord Bot Token",
       r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
       "high", "API Token",
       "Discord bot token detected. Grants control of the bot account.",
       "Regenerate the Discord bot token; keep it server-side.",
       confidence=80, exploitability=70, check_entropy=True),
    _p("Discord Webhook URL",
       r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z\-_]+",
       "medium", "API Token",
       "Discord webhook URL detected.",
       "Delete/rotate the Discord webhook.",
       confidence=85, exploitability=45, cwe=_CWE_INFO_EXPOSURE, owasp="M8"),

    # ── Version control / CI ──────────────────────────────────────────────────
    _p("GitHub Token",
       r"(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}",
       "critical", "API Token",
       "GitHub token detected. Grants repository/account access per its scopes.",
       "Revoke the token on GitHub immediately; rotate any exposed repos' secrets.",
       confidence=95, exploitability=85),
    _p("GitHub Fine-grained Token",
       r"github_pat_[0-9A-Za-z_]{82}",
       "critical", "API Token",
       "GitHub fine-grained personal access token detected.",
       "Revoke the token on GitHub immediately.",
       confidence=95, exploitability=85),
    _p("GitLab Personal Access Token",
       r"glpat-[0-9A-Za-z\-_]{20}",
       "critical", "API Token",
       "GitLab personal access token detected.",
       "Revoke the token in GitLab; rotate affected project secrets.",
       confidence=90, exploitability=85),

    # ── Artifactory (JFrog) ───────────────────────────────────────────────────
    # APKLeaks upstream ships these two and Beetle's native catalog lacked them —
    # the HDFC benchmark gap. Both are JFrog Artifactory credential formats:
    # the API token is prefixed ``AKC``; the encrypted password is prefixed ``AP``
    # followed by a single hex nibble. Anchored on an assignment/quote context + a
    # length floor + the entropy gate. NB: patterns compile case-INSENSITIVE, so the
    # ``AP`` password prefix + a hex nibble (``[0-9A-Fa-f]`` — includes vowels a/e/f)
    # otherwise matches plain words like ``ApeAnotherValue``. A ``(?=[A-Za-z0-9]*[0-9])``
    # lookahead requires a DIGIT in the credential body: a real encrypted password is
    # digit-bearing, an English word is not. (``AKC`` is not an English-word prefix, so
    # the token rule keeps its all-base62 coverage unchanged — see review note below.)
    _p("Artifactory API Token",
       # Reviewed: 'AKC' is not a natural-word prefix; the context anchor + 10-char
       # floor + entropy gate already exclude words, so coverage is left intact.
       r"(?:\s|=|:|\"|')AKC[a-zA-Z0-9]{10,}",
       "high", "API Token",
       "JFrog Artifactory API token detected. Grants access to the artifact registry.",
       "Revoke the token in Artifactory; use short-lived access tokens server-side.",
       confidence=80, exploitability=70, owasp="M1", check_entropy=True),
    _p("Artifactory Password",
       r"(?:\s|=|:|\"|')AP(?=[A-Za-z0-9]*[0-9])[0-9ABCDEFabcdef][a-zA-Z0-9]{8,}",
       "high", "Credentials",
       "JFrog Artifactory encrypted password detected. Allows authenticated registry access.",
       "Rotate the Artifactory credential; never embed registry passwords in a client.",
       confidence=75, exploitability=70, owasp="M1", check_entropy=True),

    # ── Generic auth material ─────────────────────────────────────────────────
    _p("Authorization Bearer Header",
       r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*",
       "medium", "Secrets",
       "Hard-coded Authorization: Bearer token detected.",
       "Do not embed bearer tokens; obtain them at runtime over TLS.",
       confidence=55, exploitability=55, check_entropy=True),
    _p("Authorization Basic Header",
       r"(?i)basic\s+[A-Za-z0-9=:_+/\-]{16,}",
       "medium", "Secrets",
       "Hard-coded Authorization: Basic credential detected (base64 user:pass).",
       "Remove embedded basic-auth credentials; use per-user tokens over TLS.",
       confidence=55, exploitability=55, check_entropy=True),
    _p("Facebook Access Token",
       r"EAACEdEose0cBA[0-9A-Za-z]+",
       "high", "OAuth",
       "Facebook access token detected.",
       "Revoke the token; use the Facebook login SDK to obtain tokens at runtime.",
       confidence=80, exploitability=70, owasp="M1"),
    _p("Facebook OAuth Secret",
       r"(?i)facebook.{0,20}['\"][0-9a-f]{32}['\"]",
       "high", "OAuth",
       "Facebook app secret detected. Allows impersonating the app.",
       "Rotate the Facebook app secret; keep it server-side only.",
       confidence=65, exploitability=75, owasp="M1"),
    _p("Twitter OAuth Secret",
       r"(?i)twitter.{0,20}['\"][0-9a-zA-Z]{35,44}['\"]",
       "high", "OAuth",
       "Twitter OAuth secret detected.",
       "Rotate the Twitter API secret; keep it server-side.",
       confidence=60, exploitability=70, owasp="M1", check_entropy=True),

    # ── Private keys / certificates ───────────────────────────────────────────
    # SECRET-kind (not finding): private key material must travel the secret
    # pipeline so it is masked + assessed by Secret Intelligence exactly like a
    # native PEM detection. ``redact_context=True`` drops the windowed code_context
    # so a base64 key-body fragment can never reach a serialized sink.
    _p("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "critical",
       "Private Key",
       "Embedded RSA private key block detected.",
       "Remove the private key from the app; provision keys server-side / via KMS.",
       confidence=99, exploitability=90, cwe=_CWE_PRIVATE_KEY,
       masvs="MASVS-CRYPTO-1", owasp="M10", kind="secret", redact_context=True),
    _p("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "critical",
       "Private Key",
       "Embedded DSA private key block detected.",
       "Remove the private key from the app bundle.",
       confidence=99, exploitability=85, cwe=_CWE_PRIVATE_KEY,
       masvs="MASVS-CRYPTO-1", owasp="M10", kind="secret", redact_context=True),
    _p("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "critical",
       "Private Key",
       "Embedded elliptic-curve private key block detected.",
       "Remove the private key from the app bundle.",
       confidence=99, exploitability=85, cwe=_CWE_PRIVATE_KEY,
       masvs="MASVS-CRYPTO-1", owasp="M10", kind="secret", redact_context=True),
    _p("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "critical",
       "Private Key",
       "Embedded OpenSSH private key detected.",
       "Remove the SSH key; never distribute private keys in a client.",
       confidence=99, exploitability=85, cwe=_CWE_PRIVATE_KEY,
       masvs="MASVS-CRYPTO-1", owasp="M10", kind="secret", redact_context=True),
    _p("PGP Private Key Block", r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
       "critical", "Private Key",
       "Embedded PGP private key block detected.",
       "Remove the PGP private key from the app.",
       confidence=99, exploitability=80, cwe=_CWE_PRIVATE_KEY,
       masvs="MASVS-CRYPTO-1", owasp="M10", kind="secret", redact_context=True),
    _p("Generic Private Key", r"-----BEGIN PRIVATE KEY-----", "critical",
       "Private Key",
       "Embedded PKCS#8 private key block detected.",
       "Remove the private key from the app; use a server-side keystore / KMS.",
       confidence=95, exploitability=85, cwe=_CWE_PRIVATE_KEY,
       masvs="MASVS-CRYPTO-1", owasp="M10", kind="secret", redact_context=True),

    # ── JWT / generic tokens ──────────────────────────────────────────────────
    _p("JSON Web Token",
       r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
       "medium", "JWT",
       "JSON Web Token detected. May embed claims/credentials or grant API access.",
       "Decode and review claims; do not embed long-lived JWTs in the client.",
       confidence=80, exploitability=55, cwe=_CWE_INFO_EXPOSURE, owasp="M1",
       check_entropy=True),

    # ── Credentials embedded in URLs ──────────────────────────────────────────
    _p("Credentials in URL",
       r"(?i)[a-z][a-z0-9+.\-]*://[^/\s:@]{2,}:[^/\s:@]{2,}@[^\s/$.?#].[^\s]*",
       "high", "Credentials",
       "URL containing inline user:password credentials detected.",
       "Remove embedded credentials from URLs; use a credential store + TLS.",
       confidence=70, exploitability=70, cwe=_CWE_HARDCODED, owasp="M1"),
]


def secret_patterns() -> list[dict]:
    """Patterns whose hits become secret entries (results['secrets'])."""
    return [p for p in APKLEAKS_PATTERNS if p["kind"] == "secret"]


def finding_patterns() -> list[dict]:
    """Patterns whose hits become findings directly (results['findings'])."""
    return [p for p in APKLEAKS_PATTERNS if p["kind"] == "finding"]


def endpoint_patterns() -> list[dict]:
    """Patterns whose hits become endpoints (results['endpoints'])."""
    return [p for p in APKLEAKS_PATTERNS if p["kind"] == "endpoint"]
