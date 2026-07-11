"""
Secret Intelligence Engine — configuration (Beetle 2.0, Phase 1.4).

THE single tuning file. Weights, entropy thresholds, false-positive vocabularies,
known example/test values, and status thresholds — all data, all documented.
`engine.py` is logic only. Adding a placeholder word or a known example value is a
one-line edit here.

Principle: *"A value should not become a security finding simply because it
matches a regular expression."* Every constant below exists to make that true.
"""
from __future__ import annotations

SECRET_INTEL_VERSION = "1.0.0"


# ════════════════════════════════════════════════════════════════════════════
# SECRET STATUS — the final classification vocabulary
# ════════════════════════════════════════════════════════════════════════════
class Status:
    VALIDATED = "Validated Secret"       # live-verified (existing probers) — highest certainty
    PROBABLE = "Probable Secret"         # provider format + checksum/entropy hold, app context
    POSSIBLE = "Possible Secret"         # plausible but weakly evidenced
    FALSE_POSITIVE = "False Positive"    # placeholder / garbage / known non-secret
    DOC_EXAMPLE = "Documentation Example"  # a known docs/RFC/test sample
    PUBLIC_VALUE = "Public Value"        # public key / certificate — not sensitive
    CLIENT_KEY = "Client Key"            # package/referrer-restricted client key
                                         # (Firebase/GCP AIza) — visible/INFO, not confidential
    GENERATED_CONSTANT = "Generated Constant"  # crypto constant / generated code value
    UNKNOWN = "Unknown"


# ════════════════════════════════════════════════════════════════════════════
# CONFIDENCE — weights for the overall secret confidence roll-up
# ════════════════════════════════════════════════════════════════════════════
# detection (does the value match a real secret format?) and validation
# (format/checksum/entropy/not-FP) dominate; ownership/evidence modulate
# operational relevance. Sums to 1.0.
OVERALL_WEIGHTS = {
    "detection":  0.30,
    "validation": 0.35,
    "ownership":  0.15,
    "evidence":   0.20,
}

# Ownership relevance — a secret in first-party app code matters far more than a
# constant inside a crypto library or generated code. Drives ownership_confidence.
OWNERSHIP_RELEVANCE = {
    "Application":        95,
    "Unknown":           60,
    "OpenSourceLibrary": 35,   # e.g. BouncyCastle crypto constants
    "VendorSDK":         40,
    "ThirdPartySDK":     40,
    "GoogleSDK":         40,
    "GeneratedCode":     25,
    "AndroidFramework":  20,
    "AppleFramework":    20,
}
OWNERSHIP_RELEVANCE_DEFAULT = 50


# ════════════════════════════════════════════════════════════════════════════
# ENTROPY — one signal, never the only one
# ════════════════════════════════════════════════════════════════════════════
# Shannon entropy (bits/char). High-entropy random strings clear the bar; English
# words / placeholders fall below it. Used to corroborate, never to decide alone.
ENTROPY_MIN_RANDOM = 3.2          # below this, a generic token is suspect
ENTROPY_STRONG = 4.0              # at/above this, strong randomness signal
ENTROPY_MIN_LENGTH = 12          # entropy is meaningless on very short strings


# ════════════════════════════════════════════════════════════════════════════
# VALIDATION — points awarded by the validation stage (capped at 100)
# ════════════════════════════════════════════════════════════════════════════
VALIDATION_POINTS = {
    "format_valid":   40,   # matches a provider's exact format
    "checksum_valid": 30,   # deterministic checksum holds (GitHub, Luhn, …)
    "entropy_ok":     20,   # randomness corroborates
    "structure_valid": 15,  # JWT/PEM/base64/hex/uuid structurally valid
}
VALIDATION_FP_PENALTY = 60   # known FP / placeholder slashes validation


# ════════════════════════════════════════════════════════════════════════════
# DETECTION — base confidence by how the type was identified
# ════════════════════════════════════════════════════════════════════════════
DETECTION_PROVIDER_FORMAT = 90   # matched a specific provider prefix+format (AKIA…, ghp_…)
DETECTION_STRUCTURED = 80        # JWT/PEM/private-key structure
DETECTION_GENERIC_HIGH_ENTROPY = 50  # generic high-entropy token, no provider
DETECTION_WEAK = 30              # generic "password"/"apikey"-named low-signal value
DETECTION_VALIDATED = 100        # live-validated


# ════════════════════════════════════════════════════════════════════════════
# EVIDENCE — points by available evidence (capped at 100)
# ════════════════════════════════════════════════════════════════════════════
EVIDENCE_BASE = 25
EVIDENCE_POINTS = {
    "file_path": 20,
    "line":      20,
    "snippet":   20,
    "code_context": 15,
}
# Context-kind quality multiplier (some locations are stronger evidence of a real
# embedded secret than others).
CONTEXT_WEIGHT = {
    "buildconfig": 1.0, "java": 1.0, "kotlin": 1.0, "swift": 1.0, "objc": 1.0,
    "properties": 1.0, "json": 0.95, "yaml": 0.95, "xml": 0.85, "gradle": 0.9,
    "manifest": 0.9, "strings_xml": 0.85, "resources": 0.8, "assets": 0.8,
    "native": 0.7, "binary": 0.7, "config": 0.95, "database": 0.9,
    "test": 0.5, "sample": 0.4, "documentation": 0.3, "unknown": 0.8,
}


# ════════════════════════════════════════════════════════════════════════════
# STATUS THRESHOLDS — overall confidence → status band
# ════════════════════════════════════════════════════════════════════════════
STATUS_PROBABLE_MIN = 70
STATUS_POSSIBLE_MIN = 45
# below POSSIBLE_MIN (and not otherwise classified) → False Positive / Unknown


# ════════════════════════════════════════════════════════════════════════════
# FALSE-POSITIVE VOCABULARIES
# ════════════════════════════════════════════════════════════════════════════
# Placeholder substrings — if a value contains one, it is almost never a secret.
PLACEHOLDER_SUBSTRINGS = (
    "your_", "_here", "changeme", "change_me", "example", "sample", "dummy",
    "placeholder", "redacted", "insert_", "todo", "fixme", "xxxx", "yyyy",
    "foobar", "foo_bar", "lorem", "ipsum", "test_key", "testkey", "fake",
    "<your", "<insert", "<api", "<secret", "<token", "notarealkey", "donotuse",
    "replace_me", "replaceme", "my_secret", "my_api", "abcd1234", "1234567890",
    "deadbeef", "0123456789abcdef", "aaaaaaaa", "n/a", "none", "null", "undefined",
)

# Whole-value placeholders (case-insensitive exact-ish).
PLACEHOLDER_EXACT = (
    "password", "passwd", "secret", "token", "apikey", "api_key", "key",
    "username", "user", "admin", "root", "test", "demo", "example", "string",
    "value", "default", "changeit", "changeme",
)

# Path / context tokens that mark a non-production sample location.
FP_CONTEXT_TOKENS = (
    "/test/", "/tests/", "/androidtest/", "/sample", "/samples/", "/example",
    "/examples/", "/demo", "/mock", "/fixture", "/fixtures/", "/docs/", "/doc/",
    "readme", "tutorial", "/javadoc/", "changelog", "license", "/node_modules/",
)

# Known, world-famous documentation/example credentials (AWS docs keys, the
# jwt.io canonical token, the Google "AIza…Example" key, the Stripe docs test key,
# …). These are deterministic false positives.
#
# We do NOT store these literals in source — committing strings that match
# provider secret formats trips GitHub Push Protection (and is poor hygiene).
# Instead we store the SHA-256 of each (lower-cased) value. Detection is fully
# preserved: a real scanned value is hashed at runtime and matched here. The
# hashes are one-way and carry no secret material. To register a new known
# example, add `sha256(value.lower())` to this set (see tools or a REPL).
KNOWN_EXAMPLE_HASHES = frozenset((
    "2eb6c6020c2290c8d9020b570bd9d6ef7577109b2d51c2510b61674ca782ee18",  # AWS docs access key
    "9b4d1fe07ab0b901c8c549a3431f4cd95ffb0149cbbbd41a37026098e0a857c0",  # AWS docs secret key
    "5657c8f55007c901ceef82fe8c8dc05d45380cec42051c8cef9d745bf059a2f7",  # AWS short example id
    "4818806648ce94668c21c5dcf8c2b270dda9e575ced18ef5822f8ccaf00f0243",  # jwt.io canonical token
    "cd8cdd7bfefdb32d2e5d2d0d4ea78364a6eb587a7232102d7862898674329a0b",  # Google docs API key
    "414b0f60b0b31da2fe9712ff7576cbc1bf871a378c15cf7e511e1837b7267f33",  # Stripe docs test key
))

# Plain-text known examples that are themselves obvious, non-sensitive
# placeholders (safe to commit). Extend freely with clearly-fake samples.
KNOWN_EXAMPLE_LITERALS = frozenset(v.lower() for v in (
    "example_documentation_secret_placeholder",
))


def is_known_example(value: str) -> bool:
    """True when ``value`` is a registered documentation/example credential.

    Checks the safe literal placeholders first, then the SHA-256 of the
    lower-cased value against the hash registry — so real famous examples are
    detected at runtime without their literals ever living in the repo.
    """
    import hashlib
    v = (value or "").strip().lower()
    if not v:
        return False
    if v in KNOWN_EXAMPLE_LITERALS:
        return True
    return hashlib.sha256(v.encode()).hexdigest() in KNOWN_EXAMPLE_HASHES

# Known crypto test vectors / constants (NIST/FIPS/RFC) — never real secrets.
CRYPTO_TEST_VECTORS = frozenset(v.lower() for v in (
    "000102030405060708090a0b0c0d0e0f",            # common AES/IV sample
    "2b7e151628aed2a6abf7158809cf4f3c",            # FIPS-197 AES-128 test key
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",  # FIPS-197 AES-256
    "0123456789abcdef",
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
    "0000000000000000",
))

# Nil / degenerate UUIDs.
DEGENERATE_UUIDS = frozenset((
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "11111111-1111-1111-1111-111111111111",
))


# ════════════════════════════════════════════════════════════════════════════
# CONTEXT VALIDATION  (Phase 1.91 — variable name + nearby usage + dead constant)
# ════════════════════════════════════════════════════════════════════════════
# These let Beetle keep application-specific / custom enterprise secrets while
# refusing to report a long random string *simply because it is long*. They read
# only the already-captured snippet / code_context / detector name — no file
# re-read, no network. A GENERIC value with NONE of these signals is treated as an
# unreferenced constant; a GENERIC value WITH them is corroborated as a real secret.

# Identifier tokens that, when they name the assignment holding the value, signal a
# genuine credential (variable-name analysis).
CONTEXT_VAR_NAME_HINTS = (
    "apikey", "api_key", "apisecret", "api_secret", "secretkey", "secret_key",
    "clientsecret", "client_secret", "accesstoken", "access_token",
    "bearertoken", "bearer_token", "refreshtoken", "refresh_token",
    "privatekey", "private_key", "signingkey", "signing_key",
    "encryptionkey", "encryption_key", "consumerkey", "consumer_key",
    "consumersecret", "consumer_secret", "authkey", "auth_key",
    "apitoken", "api_token", "password", "passwd", "pwd", "credential",
    "secret", "token", "auth_secret",
)

# Security / credential APIs that, when used near the value, corroborate it
# (nearby-usage analysis).
CONTEXT_USAGE_HINTS = (
    "authorization", "bearer ", "basic ", "x-api-key", "x-auth-token",
    ".header(", ".addheader", "setrequestproperty", "httpurlconnection",
    "httpsurlconnection", "retrofit", "okhttp", "interceptor",
    "cipher", "keystore", "keypair", "secretkeyspec", "ivparameterspec",
    "sharedpreferences", "encryptedsharedpreferences",
    "firebase", "firebaseapp", "getinstance", "credentials", "oauth",
    "amazonaws", "cognito", "awscredentials", "signrequest",
)

# Context kinds (from _context_kind) that are themselves a strong secret surface.
CONTEXT_STRONG_KINDS = frozenset((
    "buildconfig", "properties", "config", "gradle",
))

# Declaration shapes that mark a (possibly inert) constant.
CONTEXT_CONSTANT_DECL = (
    "static final", "public static final", "private static final",
    "const ", "const val ", " val ", "@stringdef",
)

CONTEXT_BASE = 50
CONTEXT_POINTS = {
    "var_name":        30,   # the assignment identifier names a credential
    "usage":           25,   # a security/credential API is used nearby
    "strong_file":     15,   # value lives in BuildConfig / Config / Properties
    "provider_format": 20,   # value already matched a provider format (corroborates)
}
CONTEXT_DEAD_CONSTANT_PENALTY = 35   # constant decl, no credential name/usage → inert
CONTEXT_NO_SIGNAL_PENALTY = 25       # generic value, snippet present, zero positive signals

# A GENERIC/WEAK value whose context score is at/below this — AND whose snippet was
# actually inspected — is the classic "long random string" false positive (UUID,
# hash, library constant, crypto parameter). It is rejected as unreferenced.
CONTEXT_GENERIC_FP_MAX = 35
# At/above this, a GENERIC value's credential context is strong enough to
# corroborate it as a real secret (validation bonus).
CONTEXT_STRONG_MIN = 75
CONTEXT_VALIDATION_BONUS = 20

# ════════════════════════════════════════════════════════════════════════════
# VISIBILITY  (Phase 1.91 — consumed by secret_intel's suppression gate)
# ════════════════════════════════════════════════════════════════════════════
# The engine classifies; secret_intel decides what an analyst sees by DEFAULT.
# Secrets the engine rejects (these statuses) or scores below the floor are moved
# to the suppressed partition — KEPT and COUNTED, never silently dropped.
#
# The full vocabulary of statuses the engine treats as non-secrets. The consumer
# (``secret_intel``) splits these by CERTAINTY before suppressing: PUBLIC_VALUE and
# DOC_EXAMPLE are DEFINITIVE (a public cert is public; a doc example is matched by an
# exact value hash) and may suppress even a recognized format; FALSE_POSITIVE and
# GENERATED_CONSTANT are HEURISTIC and must never hide a value that also carries a
# recognized provider/structured format (so a real key is never lost to an FP guess).
REJECT_STATUSES = frozenset((
    Status.FALSE_POSITIVE, Status.DOC_EXAMPLE,
    Status.PUBLIC_VALUE, Status.GENERATED_CONSTANT,
))
# Overall-confidence floor below which a value with NO recognized provider/
# structured format is suppressed from the default view. Recognized-format
# secrets (format_valid) and Probable/Validated secrets are never floored out.
SUPPRESS_OVERALL_FLOOR = 45
