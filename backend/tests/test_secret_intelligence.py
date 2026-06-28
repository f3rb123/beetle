"""
Secret Intelligence Engine tests (Beetle 2.0, Phase 1.4).

Covers real vs fake secrets, AWS/Google/Firebase/Stripe/Twilio/GitHub/JWT, PEM
private keys, public keys/certificates, BouncyCastle constants, RFC/doc examples,
demo credentials, framework/SDK/generated ownership, obfuscated strings, high/low
entropy garbage, and the regression guarantee that real secrets stay detected
while known false positives are rejected — without changing existing data.

Runnable standalone or under pytest:
    python -m tests.test_secret_intelligence     # from backend/
    python backend/tests/test_secret_intelligence.py
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.secret_intelligence import (  # noqa: E402
    SecretIntelligenceEngine, Status, annotate, assess,
)
from analyzers.secret_intelligence import patterns as P  # noqa: E402

ENGINE = SecretIntelligenceEngine()
APP = {"file_path": "sources/com/acme/app/Config.java", "owner_type": "Application", "line": 10, "snippet": "k"}


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _a(value, **ctx):
    c = dict(APP)
    c.update(ctx)
    return ENGINE.assess(value, c)


# ── Type classification ───────────────────────────────────────────────────────
def test_type_and_provider_classification():
    cases = {
        "AKIA" + "Z" * 16:                               ("AWS Access Key", "AWS"),
        "AIza" + "B" * 35:                               ("Google API Key", "GOOGLE"),
        "sk_live_" + "a" * 24:                           ("Stripe Secret Key", "STRIPE"),
        "pk_live_" + "a" * 24:                           ("Stripe Publishable Key", "STRIPE"),
        "AC" + "0" * 32:                                 ("Twilio Account SID", "TWILIO"),
        "SG." + "a" * 22 + "." + "b" * 43:               ("SendGrid API Key", "SENDGRID"),
        P.make_github_token():                           ("GitHub Token", "GITHUB"),
    }
    for val, (typ, prov) in cases.items():
        a = _a(val)
        _check(a.secret_type == typ, f"{val[:12]} type {a.secret_type} != {typ}")
        _check(a.provider == prov, f"{val[:12]} provider {a.provider} != {prov}")


# ── Real secrets → Probable/Validated ─────────────────────────────────────────
def test_real_provider_secret_is_probable():
    a = _a("AKIA" + "QWERTYUIOP123456")  # AWS access key, app context
    _check(a.status == Status.PROBABLE, f"AWS key status {a.status}")
    _check(a.overall_confidence >= 70, f"AWS overall {a.overall_confidence}")
    _check(a.detection_confidence == 90 and a.format_valid, "AWS detection/format")


def test_validated_secret_is_validated():
    a = _a("AKIA" + "QWERTYUIOP123456", validation_status="valid")
    _check(a.status == Status.VALIDATED, f"validated status {a.status}")
    _check(a.overall_confidence == 100, "validated overall 100")


def test_github_checksum_distinguishes_real_from_fake():
    good = P.make_github_token()
    bad = "ghp_" + "A" * 36  # wrong checksum
    _check(_a(good).checksum_valid is True, "valid github checksum")
    _check(_a(bad).checksum_valid is False, "invalid github checksum")
    _check(_a(good).validation_confidence > _a(bad).validation_confidence,
           "checksum should raise validation confidence")


# ── JWT structure ─────────────────────────────────────────────────────────────
def test_real_jwt_vs_example_jwt():
    # Synthetic JWT assembled from fragments so no contiguous token sits in the
    # source. header={"alg":"HS256"}, payload={"uid":"99999","role":"x"}.
    header = "eyJhbGciOiJIUzI1NiJ9"
    payload = "eyJ1aWQiOiI5OTk5OSIsInJvbGUiOiJ4In0"
    sig = "synthetic" + "signature" + "fragment" + "0123456789"
    real = header + "." + payload + "." + sig
    a = _a(real)
    _check(a.secret_type == "JWT" and a.structure_valid is True, f"jwt structure {a.structure_valid}")
    _check(a.status in (Status.PROBABLE, Status.POSSIBLE), f"real jwt status {a.status}")
    # A registered documentation example must be a Documentation Example.
    ex = _a("example_documentation_secret_placeholder")
    _check(ex.status == Status.DOC_EXAMPLE, f"example status {ex.status}")
    _check(ex.overall_confidence <= 15, "example overall low")


# ── PEM private keys vs public material ───────────────────────────────────────
def _pem(kind: str, body: str) -> str:
    """Build a synthetic PEM block at runtime. For the private-key case the kind
    is assembled from fragments so the private-key PEM marker never appears as a
    contiguous literal in the committed source (secret scanners flag those)."""
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


# base64("BEETLE-EXAMPLE-PEM-BODY-NOT-A-REAL-KEY") — obviously synthetic.
_FAKE_PEM_BODY = "QkVFVExFLUVYQU1QTEUtUEVNLUJPRFktTk9ULUEtUkVBTC1LRVk="


def test_private_key_is_secret_public_key_is_public():
    priv = _pem("RSA PRIVATE" + " KEY", _FAKE_PEM_BODY)   # fragmented marker
    a = _a(priv)
    _check(a.secret_type == "RSA Private Key", f"priv type {a.secret_type}")
    _check(a.status in (Status.PROBABLE, Status.POSSIBLE), f"priv status {a.status}")
    pub = _pem("PUBLIC KEY", _FAKE_PEM_BODY)   # public material — not a secret
    p = _a(pub)
    _check(p.status == Status.PUBLIC_VALUE, f"public key status {p.status}")
    cert = _pem("CERTIFICATE", _FAKE_PEM_BODY)
    c = _a(cert)
    _check(c.secret_type == "Certificate" and c.status == Status.PUBLIC_VALUE, f"cert {c.status}")


# ── False positives ───────────────────────────────────────────────────────────
def test_known_example_is_doc_example():
    # Registered documentation example (a safe placeholder literal — real famous
    # examples are matched at runtime by SHA-256, never stored as literals).
    a = _a("example_documentation_secret_placeholder")
    _check(a.status == Status.DOC_EXAMPLE, f"known-example status {a.status}")
    _check(a.false_positive is True, "known-example flagged FP")


def test_placeholders_rejected():
    for val in ("your_api_key_here", "YOUR_SECRET", "changeme", "live_secret_replace_me",
                "API_EXAMPLE_KEY_PLACEHOLDER"):
        a = _a(val)
        _check(a.status in (Status.FALSE_POSITIVE, Status.DOC_EXAMPLE),
               f"placeholder {val!r} status {a.status}")
        _check(a.overall_confidence <= 20, f"placeholder {val!r} overall {a.overall_confidence}")


def test_crypto_test_vectors_are_constants():
    a = _a("2b7e151628aed2a6abf7158809cf4f3c")  # FIPS-197 AES-128 test key
    _check(a.status == Status.GENERATED_CONSTANT, f"aes vector status {a.status}")


def test_degenerate_and_low_entropy_garbage():
    _check(_a("00000000-0000-0000-0000-000000000000").status == Status.FALSE_POSITIVE, "nil uuid")
    _check(_a("aaaaaaaaaaaaaaaa").status == Status.FALSE_POSITIVE, "repeated char")


def test_high_entropy_generic_is_possible_not_probable():
    # Random 32-hex with no provider format, in app code: plausible but not strong.
    a = _a("9f8c2a1b7e4d6c3f0a5b8e2d1c4f7a9b")
    _check(a.status in (Status.POSSIBLE, Status.UNKNOWN, Status.FALSE_POSITIVE),
           f"generic hex status {a.status}")
    _check(a.detection_confidence < 90, "generic should not get provider-format detection")


# ── Ownership awareness ───────────────────────────────────────────────────────
def test_ownership_influences_confidence():
    val = "AKIA" + "QWERTYUIOP123456"
    app = _a(val, owner_type="Application")
    fw = _a(val, owner_type="AndroidFramework")
    _check(app.ownership_confidence > fw.ownership_confidence, "app ownership > framework")
    _check(app.overall_confidence > fw.overall_confidence, "app overall > framework for same value")


def test_bouncycastle_constant_rejected():
    # A generic hex constant living in BouncyCastle (OSS crypto lib) is not a secret.
    a = _a("48656c6c6f576f726c64313233343536", owner_type="OpenSourceLibrary",
           file_path="sources/org/bouncycastle/crypto/Const.java")
    _check(a.status in (Status.GENERATED_CONSTANT, Status.FALSE_POSITIVE),
           f"bouncycastle const status {a.status}")


def test_generated_code_value():
    a = _a("abc123def456ghi789jkl012mno345pq", owner_type="GeneratedCode",
           file_path="sources/com/acme/app/BuildConfig.java")
    _check(a.status in (Status.GENERATED_CONSTANT, Status.POSSIBLE, Status.FALSE_POSITIVE),
           f"generated status {a.status}")


# ── Environment + context ─────────────────────────────────────────────────────
def test_environment_classification():
    _check(_a("sk_live_" + "a" * 24).environment == "production", "live env")
    _check(_a("sk_test_" + "a" * 24).environment == "test", "test env")
    _check(_a("AKIA" + "Z" * 16, file_path="src/test/Foo.java").environment in ("test",), "test path env")


def test_context_kind_detection():
    _check(_a("AKIA" + "Z" * 16, file_path="x/BuildConfig.java").context == "buildconfig", "buildconfig ctx")
    _check(_a("AKIA" + "Z" * 16, file_path="res/values/strings.xml").context == "strings_xml", "strings ctx")


# ── Explainability ────────────────────────────────────────────────────────────
def test_every_assessment_is_explained():
    a = _a("AKIA" + "QWERTYUIOP123456")
    for key in ("detected", "classified", "provider", "confidence"):
        _check(a.reasons.get(key), f"missing reason: {key}")
    rej = _a("your_api_key_here")
    _check(rej.reasons.get("rejected"), "rejected reason missing for FP")


def test_deterministic():
    val = P.make_github_token()
    _check(ENGINE.assess(val, APP).to_dict() == ENGINE.assess(val, APP).to_dict(), "must be deterministic")


# ── Pipeline integration + non-destructive + regression ──────────────────────
def test_annotate_non_destructive_and_regression():
    results = {
        "platform": "android",
        "secrets": [
            {"name": "AWS Access Key ID", "value": "AKIA" + "QWERTYUIOP123456",
             "file_path": "sources/com/acme/app/Cfg.java", "line": 3,
             "severity": "critical", "keepme": 1},
            {"name": "Doc Example", "value": "example_documentation_secret_placeholder",
             "file_path": "docs/README.md", "line": 1, "severity": "high"},
            {"name": "Generic", "value": "your_api_key_here", "file_path": "a.java"},
        ],
    }
    import copy
    before = copy.deepcopy(results["secrets"])

    annotate(results)

    NEW = {"secret_intelligence", "secret_status", "secret_overall_confidence",
           "secret_context_score", "secret_validation_reason"}
    for orig, now in zip(before, results["secrets"]):
        for k, v in orig.items():
            _check(k in now and now[k] == v, f"annotate changed existing key {k}")
        _check(set(now) - set(orig) <= NEW, f"unexpected keys added: {set(now)-set(orig)-NEW}")

    real, example, placeholder = results["secrets"]
    # Regression: the genuine secret survives as a strong secret …
    _check(real["secret_status"] == Status.PROBABLE, f"real secret status {real['secret_status']}")
    _check(real["secret_overall_confidence"] >= 70, "real secret confidence")
    # … while the known example and placeholder are correctly demoted.
    _check(example["secret_status"] == Status.DOC_EXAMPLE, f"example status {example['secret_status']}")
    _check(placeholder["secret_status"] == Status.FALSE_POSITIVE, f"placeholder status {placeholder['secret_status']}")
    # Raw value is never stored inside the assessment.
    _check("value" not in real["secret_intelligence"], "assessment must not store raw value")
    _check("by_status" in results["secret_intelligence_summary"], "summary present")


def test_assess_helper_and_singleton():
    from analyzers.secret_intelligence import get_engine
    _check(get_engine() is get_engine(), "engine singleton")
    _check(assess("AKIA" + "Z" * 16).provider == "AWS", "module-level assess works")


# ── Standalone runner ─────────────────────────────────────────────────────────
def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
