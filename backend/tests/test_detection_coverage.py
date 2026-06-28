"""
Detection Coverage Expansion & Benchmark tests (Beetle 2.0, Phase 1.98).

* New secret patterns are matched by the ONE unified combined walk (not a second
  matcher) — incl. the named gap, AWS Cognito Identity Pool.
* New crypto rules (RC4, AES-ECB-default, static salt, weak PBKDF, weak RSA keygen).
* The coverage registry records capabilities and exposes a benchmark/gap view.
* Benchmark engine categorizes common / beetle-only / missing across engines.
* Regression corpus coverage never drops below the declared ground truth.
* No duplicate detection: coverage secrets carry the coverage provenance.

Runnable standalone or under pytest:
    python -m tests.test_detection_coverage       # from backend/
"""
from __future__ import annotations

import os
import re
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import secret_catalog  # noqa: E402
from analyzers.detection_coverage import benchmark, corpus, registry  # noqa: E402
from analyzers.detection_coverage import catalog as cov_catalog  # noqa: E402  (ensures registration)
from analyzers.evidence_scanner import scan_file_for_patterns  # noqa: E402
from analyzers.code_rules import CODE_RULES  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _scan(code: str):
    return {h["name"] for h in scan_file_for_patterns("X.java", code, secret_catalog.combined())}


def _crypto_rule(rule_id: str) -> dict:
    for r in CODE_RULES:
        if r["id"] == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not found")


# ── Registry ──────────────────────────────────────────────────────────────────
def test_registry_records_capabilities():
    s = registry.summary()
    _check(s["total"] >= 30, "registry should record a substantial capability set")
    _check(s["new_this_phase"] >= 10, "this phase should add ≥10 new detectors")
    _check("Cryptography" in s["categories"] and "Cloud Credentials" in s["categories"],
           "core categories must be present")


def test_registry_is_extensible_without_duplicates():
    before = len(registry.all_entries())
    e = registry.CoverageEntry(id="test_x", category="Test", name="Test Detector",
                               kind=registry.KIND_SECRET, pattern="ZZTOP-[0-9]{6}")
    registry.register(e)
    registry.register(e)  # idempotent on id
    _check(len(registry.all_entries()) == before + 1, "register must be idempotent on id")
    _check(registry.get("test_x") is not None, "registered entry must be retrievable")
    # Clean up the fixture entry so it does not pollute the shared registry
    # singleton for later tests (e.g. the audit's unbacked-secret-entries check).
    registry._REGISTRY.pop("test_x", None)


# ── New secret patterns via the UNIFIED walk ──────────────────────────────────
def test_aws_cognito_identity_pool_detected():
    names = _scan('String pool = "us-east-1:12345678-1234-1234-1234-123456789012";')
    _check("AWS Cognito Identity Pool" in names,
           "the named MobSF gap (AWS Cognito Identity Pool) must now be detected")


def test_aws_cognito_identity_pool_exact_mobsf_value():
    """The exact value MobSF reported in the benchmark (region:uuid)."""
    names = _scan('p = "us-east-1:7e9426f7-42af-4717-8689-00a9a4b65c1c";')
    _check("AWS Cognito Identity Pool" in names,
           "the exact MobSF benchmark Cognito Identity Pool value must be detected")


def test_aws_cognito_user_pool_detected():
    names = _scan('String up = "us-east-1_aBcD1234X";')
    _check("AWS Cognito User Pool" in names,
           "AWS Cognito User Pool ID (region_id) must be detected")


def test_cognito_identity_vs_user_pool_are_distinct_no_collision():
    """Identity Pool (region:uuid) and User Pool (region_id) use disjoint separators
    so they never double-report the same value."""
    idp = _scan('us-east-1:7e9426f7-42af-4717-8689-00a9a4b65c1c')
    usp = _scan('us-east-1_aBcD1234X')
    _check(idp == {"AWS Cognito Identity Pool"}, f"identity pool over-matched: {idp}")
    _check(usp == {"AWS Cognito User Pool"}, f"user pool over-matched: {usp}")


def test_app_client_id_not_false_positived():
    """App Client IDs are 26-char lowercase-alnum — too generic to value-regex
    without unacceptable false positives, so we deliberately do NOT match them as a
    bare value. Guard that a generic 26-char token does not produce a Cognito finding."""
    names = _scan('String s = "1h57kfei123d2lonro951ng3jh";')
    _check(not any("Cognito" in n for n in names),
           "a bare 26-char token must not be mis-detected as a Cognito identifier")


def test_existing_aws_akia_asia_coverage():
    """AKIA (long-term) and ASIA (STS/temporary) access key prefixes both covered."""
    _check("AWS Access Key ID" in _scan('k="AKIAIOSFODNN7EXAMPLE";'), "AKIA prefix regressed")
    _check("AWS STS Temporary Access Key" in _scan('k="ASIAIOSFODNN7EXAMPLE";'),
           "ASIA (STS) prefix regressed")


def test_new_secret_gaps_detected():
    cases = {
        "Google OAuth Client Secret": 'k="GOCSPX-abcdefghijklmnopqrstuvwxyz12";',  # 28 chars
        "OpenAI Project API Key": 'k="sk-proj-aB3xK9mP2qR7sT1vW5yZ8cF4gH6jL0nQ7dE2uI4oP9k";',
        "Slack App-Level Token": 'k="xapp-1-A012345-1234567890-abcdef0123456789abcdef";',
        "Telegram Bot Token": 'k="123456789:AAFvbcDeFgHiJkLmNoPqRsTuVwXyZ012345";',
        "Stripe Publishable Key": 'k="pk_live_abcdEFGH1234567890wxyz99";',
    }
    for expected, code in cases.items():
        names = _scan(code)
        _check(expected in names, f"{expected} not detected by the unified walk")


def test_coverage_secrets_use_coverage_provenance_no_duplicate_matcher():
    pats = secret_catalog.patterns("coverage")
    _check(pats, "coverage provenance must be registered in the unified catalog")
    _check(all(p.get("provenance") == "coverage" for p in pats), "wrong provenance tag")
    # combined() must include coverage so the single walk applies it.
    combined_names = {p["name"] for p in secret_catalog.combined()}
    _check("AWS Cognito Identity Pool" in combined_names,
           "combined() walk must include coverage patterns")


def test_existing_secret_still_detected_regression():
    names = _scan('String k = "AKIAIOSFODNN7EXAMPLE";')
    _check("AWS Access Key ID" in names, "existing AWS key detection must not regress")


# ── New crypto rules ──────────────────────────────────────────────────────────
def test_new_crypto_rules_match():
    cases = {
        "android_weak_cipher_rc4": 'Cipher.getInstance("RC4")',
        "android_aes_ecb_default": 'Cipher.getInstance("AES")',
        "android_static_salt": 'new PBEKeySpec(pw, "staticsalt".getBytes(), 1000, 256)',
        "android_weak_pbkdf_iterations": 'new PBEKeySpec(pw, salt, 1000, 256)',
        "android_weak_rsa_keygen": 'kpg.initialize(1024)',
    }
    for rule_id, sample in cases.items():
        rule = _crypto_rule(rule_id)
        _check(re.search(rule["pattern"], sample), f"{rule_id} must match its sample")


def test_aes_ecb_default_does_not_collide_with_mode_specified():
    rule = _crypto_rule("android_aes_ecb_default")
    _check(not re.search(rule["pattern"], 'Cipher.getInstance("AES/GCM/NoPadding")'),
           "AES-default rule must not fire on an explicitly-moded cipher")


def test_strong_rsa_not_flagged():
    rule = _crypto_rule("android_weak_rsa_keygen")
    _check(not re.search(rule["pattern"], 'kpg.initialize(2048)'),
           "2048-bit RSA must not be flagged as weak")


# ── Benchmark engine ──────────────────────────────────────────────────────────
def test_signature_aliasing():
    _check(benchmark.signature("AWS Access Key ID") == benchmark.signature("AWS Access Key"),
           "naming variants must map to one signature")
    _check(benchmark.signature("AWS Cognito Identity Pool (eu-west-1)") == "aws_cognito",
           "substring aliasing must work")


def test_benchmark_categorizes_common_beetleonly_missing():
    beetle = ["AWS Access Key ID", "Weak Cipher Mode — ECB", "Exported Components"]
    mobsf = ["AWS Access Key", "AWS Cognito Identity Pool", "ECB"]
    out = benchmark.compare(beetle, mobsf=mobsf)
    _check("aws_access_key" in out["common"], "shared detection must be common")
    _check("weak_cipher_ecb" in out["common"], "ECB reported by both must be common")
    _check("exported" in out["beetle_only"], "Beetle-only detection must be flagged")
    _check("aws_cognito" in out["missing"], "a MobSF-only detection must be flagged missing")


def test_benchmark_adapters():
    mobsf = {"secrets": ["AWS Access Key"],
             "code_analysis": {"findings": {"Weak Hash — MD5": {}}}}
    apk = {"results": [{"name": "AWS Access Key ID", "matches": ["AKIA..."]}]}
    _check("aws_access_key" in benchmark.mobsf_signatures(mobsf), "mobsf adapter failed")
    _check("weak_hash_md5" in benchmark.mobsf_signatures(mobsf), "mobsf code-analysis adapter failed")
    _check("aws_access_key" in benchmark.apkleaks_signatures(apk), "apkleaks adapter failed")


def test_benchmark_detects_duplicates_and_better_evidence():
    results = {"findings": [{"title": "Weak Cipher Mode — ECB", "file_path": "a/App.java"}],
               "secrets": []}
    beetle = benchmark.beetle_signatures(results)
    out = benchmark.compare(beetle, mobsf=["ECB", "ECB"], results=results)
    _check(out["duplicate"]["mobsf"].get("weak_cipher_ecb") == 2, "duplicate must be counted")
    _check("weak_cipher_ecb" in out["better_evidence"], "evidenced common finding must be flagged")


# ── Regression corpus ─────────────────────────────────────────────────────────
def test_corpus_coverage_complete():
    rep = corpus.coverage_report()
    gaps = {name: st["missing"] for name, st in rep.items() if not st["ok"]}
    _check(not gaps, f"regression corpus coverage gaps: {gaps}")


def test_corpus_specific_apps_present():
    names = {a.name for a in corpus.REGRESSION_CORPUS}
    for required in ("InsecureShop", "DVIA-v2", "OWASP MSTG Hacking Playground", "GoatDroid"):
        _check(required in names, f"corpus must include {required}")


# ── Consolidation audit (consolidate-first guardrails) ────────────────────────
def test_audit_no_duplicate_rules_or_orphans():
    from analyzers.detection_coverage import audit
    rep = audit.report()
    _check(not rep["duplicate_rule_ids"], f"duplicate SAST rule ids: {rep['duplicate_rule_ids']}")
    _check(not rep["duplicate_rule_patterns"], f"duplicate SAST rule patterns: {rep['duplicate_rule_patterns']}")
    _check(not rep["orphan_crypto_refs"], f"crypto coverage entries with no backing rule: {rep['orphan_crypto_refs']}")
    _check(not rep["unbacked_secret_entries"], f"secret entries not in the catalog: {rep['unbacked_secret_entries']}")
    _check(rep["ok"], "coverage audit must pass (no duplication / orphans)")


def test_no_duplicate_code_rule_ids_regression():
    """Regression for the duplicate android_runtime_exec / android_dex_class_loader
    rule ids the audit caught (one was silently shadowing the other)."""
    ids = [r["id"] for r in CODE_RULES]
    dupes = {i for i in ids if ids.count(i) > 1}
    _check(not dupes, f"CODE_RULES has duplicate ids: {dupes}")


def test_coverage_secret_reachable_on_common_scanner():
    """Reachability consolidation: catalog secrets (incl. coverage gaps) must also
    be matched by the common scanner used for JS bundles / DEX strings / fallback —
    not only the main evidence walk."""
    from analyzers.common import scan_text_for_secrets
    hits = scan_text_for_secrets(
        'var pool = "us-east-1:12345678-1234-1234-1234-123456789012";',
        "index.android.bundle")
    _check(any(h["name"] == "AWS Cognito Identity Pool" for h in hits),
           "coverage secret must be reachable on the bundle/DEX/fallback path")


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
    total = len(tests)
    print(f"\n{total - failures}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
