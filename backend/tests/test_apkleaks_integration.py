"""
APKLeaks Integration tests (Beetle 2.0, Phase 1.9).

Covers the contract of the APKLeaks detection source + cross-source fusion + the
masked secret→finding bridge:

* Beetle Native only — unchanged, gains "Beetle Native" attribution.
* APKLeaks only — its hits land in the native streams with "APKLeaks" attribution.
* Mixed detections — both sources' findings coexist.
* Duplicate findings — native + APKLeaks on the SAME value collapse to ONE entry.
* Evidence merging — a merged secret unions evidence/attribution.
* Source attribution — detected_by / sources populated and unioned.
* Bridge — masked secrets mirror into findings (never raw); unmasked refused.
* Pipeline pass-through — bridged findings flow through ownership / confidence /
  bug-bounty exactly like native findings.
* Regression — the canonical model round-trips the new fields losslessly.

Runnable standalone or under pytest:
    python -m tests.test_apkleaks_integration     # from backend/
    python backend/tests/test_apkleaks_integration.py
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.canonical_finding import CanonicalFinding, from_legacy  # noqa: E402
from analyzers.detection_sources import fusion  # noqa: E402
from analyzers.detection_sources import apkleaks_patterns as cat  # noqa: E402
from analyzers.detection_sources.apkleaks_source import ApkLeaksSource  # noqa: E402
from analyzers.detection_sources import run_detection_sources  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ── Catalog sanity ───────────────────────────────────────────────────────────
def test_catalog_shapes_are_beetle_native():
    """Every ported rule carries the metadata Beetle's scanner/pipeline needs."""
    _check(len(cat.APKLEAKS_PATTERNS) >= 30, "catalog unexpectedly small")
    for p in cat.APKLEAKS_PATTERNS:
        for k in ("name", "pattern", "severity", "category", "confidence",
                  "cwe", "masvs", "owasp", "kind", "source"):
            _check(k in p, f"rule {p.get('name')!r} missing {k}")
        _check(p["kind"] in ("secret", "finding", "endpoint"), f"bad kind on {p['name']}")
        _check(p["source"] == "APKLeaks", "source must be APKLeaks")
    # Catalog must add value beyond Beetle Native: gap rules present.
    names = {p["name"] for p in cat.APKLEAKS_PATTERNS}
    for gap in ("Heroku API Key", "PayPal Braintree Access Token", "RSA Private Key",
                "Credentials in URL", "Discord Bot Token"):
        _check(gap in names, f"expected gap-filling rule {gap!r} in catalog")


def test_catalog_routing_buckets():
    """Priority 1: private keys route to SECRETS (so they get masking + Secret
    Intelligence, exactly like a native PEM detection); URLs to endpoints; the rest
    to secrets. No private-key rule may bypass the secret pipeline as a raw finding.
    """
    snames = {p["name"] for p in cat.secret_patterns()}
    enames = {p["name"] for p in cat.endpoint_patterns()}
    for key in ("RSA Private Key", "EC Private Key", "DSA Private Key",
                "OpenSSH Private Key", "PGP Private Key Block", "Generic Private Key"):
        _check(key in snames, f"{key} must route as a SECRET (Priority 1), not a finding")
    # Private-key rules must drop their windowed context so the key body never
    # reaches a serialized sink.
    for p in cat.secret_patterns():
        if "Private Key" in p["name"]:
            _check(p.get("redact_context") is True,
                   f"{p['name']} must set redact_context to drop the key body")
    _check("Firebase Database URL" in enames, "Firebase URL should be an endpoint")
    _check(all(p["kind"] == "secret" for p in cat.secret_patterns()), "secret bucket impure")


# ── Source scanning over a real temp tree ────────────────────────────────────
def _write_tree(tmp):
    src = os.path.join(tmp, "jadx", "sources", "com", "acme")
    os.makedirs(src, exist_ok=True)
    # AWS key (also a Beetle-native rule) + a Heroku key (APKLeaks-only) + RSA key.
    with open(os.path.join(src, "Config.java"), "w") as f:
        f.write(
            'class Config {\n'
            '  String aws = "AKIAIOSFODNN7EXAMPLE";\n'
            '  String heroku = "heroku api 12345678-1234-1234-1234-1234567890ab";\n'
            '  String fb = "https://demo-app.firebaseio.com";\n'
            '}\n'
        )
    # Inline RSA key block in a scanned source file (decompiled apps embed keys as
    # string constants / config). The header-only regex matches; redact_context
    # drops the windowed body so no key material survives.
    with open(os.path.join(src, "Keys.java"), "w") as f:
        f.write(
            'class Keys {\n'
            '  String pk = "-----BEGIN RSA PRIVATE KEY-----";\n'
            '  // MIIEowIBAAK...\n'
            '}\n'
        )
    return os.path.join(tmp, "jadx")


def test_source_scans_and_attributes():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        jadx = _write_tree(tmp)
        res = ApkLeaksSource().scan([jadx], platform="android")
        # AWS + Heroku + Firebase URL + RSA key were planted.
        sec_names = {s["name"] for s in res.secrets}
        _check("AWS Access Key ID" in sec_names, "AWS not detected by source")
        _check("Heroku API Key" in sec_names, "Heroku not detected by source")
        # Priority 1: private keys travel the SECRET pipeline (masked + assessed by
        # Secret Intelligence), NOT routed straight to findings.
        _check("RSA Private Key" in sec_names,
               "RSA private key should route as a SECRET (masked pipeline), not a finding")
        _check(any("firebaseio.com" in e for e in res.endpoints),
               "Firebase URL should be an endpoint")
        for s in res.secrets:
            _check(s["detected_by"] == ["APKLeaks"], "secret missing APKLeaks attribution")
            _check(s["sources"] and s["sources"][0]["engine"] == "APKLeaks", "no source detail")


# ── Fusion: dedup + merge + attribution ──────────────────────────────────────
def _native_secret(name="AWS Access Key ID", value="AKIAIOSFODNN7EXAMPLE"):
    return {"name": name, "value": value, "file_path": "sources/com/acme/Config.java",
            "line": 2, "snippet": f'k="{value}"', "severity": "critical",
            "category": "Cloud Credentials"}


def _apkleaks_secret(name="AWS Access Key ID", value="AKIAIOSFODNN7EXAMPLE"):
    s = _native_secret(name, value)
    s.update({"source": "APKLeaks", "detected_by": ["APKLeaks"],
              "sources": [{"engine": "APKLeaks", "rule_id": name}]})
    return s


def test_native_only_gets_attribution():
    results = {"secrets": [_native_secret()]}
    fusion.merge_secret_streams(results, [])
    _check(results["secrets"][0]["detected_by"] == ["Beetle Native"],
           "native secret should be attributed to Beetle Native")


def test_apkleaks_only_lands_in_stream():
    results = {"secrets": []}
    stats = fusion.merge_secret_streams(results, [_apkleaks_secret()])
    _check(stats["added"] == 1 and stats["merged"] == 0, "APKLeaks-only should add 1")
    _check(results["secrets"][0]["detected_by"] == ["APKLeaks"], "attribution lost")


def test_duplicate_secret_merges_not_duplicates():
    results = {"secrets": [_native_secret()]}
    stats = fusion.merge_secret_streams(results, [_apkleaks_secret()])
    _check(len(results["secrets"]) == 1, "duplicate secret must collapse to ONE")
    _check(stats["merged"] == 1 and stats["added"] == 0, "should be a merge, not add")
    _check(results["secrets"][0]["detected_by"] == ["Beetle Native", "APKLeaks"],
           "merged secret must be detected by BOTH engines")


def test_evidence_filled_on_merge():
    bare = {"name": "AWS Access Key ID", "value": "AKIAIOSFODNN7EXAMPLE", "severity": "critical"}
    results = {"secrets": [bare]}
    fusion.merge_secret_streams(results, [_apkleaks_secret()])
    _check(results["secrets"][0].get("file_path"), "missing evidence should be filled from APKLeaks")


def test_mixed_distinct_secrets_coexist():
    results = {"secrets": [_native_secret()]}
    fusion.merge_secret_streams(results, [_apkleaks_secret("Heroku API Key", "heroku-xyz-123456789012")])
    _check(len(results["secrets"]) == 2, "distinct secrets should both be kept")


def test_finding_dedup_merges_attribution():
    native_f = {"title": "RSA Private Key", "rule_id": "RSA Private Key",
                "file_path": "a/key.pem", "line": 1, "severity": "critical",
                "detected_by": ["Beetle Native"]}
    apkleaks_f = {"title": "RSA Private Key", "rule_id": "RSA Private Key",
                  "file_path": "a/key.pem", "line": 1, "severity": "critical",
                  "source": "APKLeaks", "detected_by": ["APKLeaks"],
                  "sources": [{"engine": "APKLeaks", "rule_id": "RSA Private Key"}]}
    results = {"findings": [native_f]}
    stats = fusion.merge_finding_streams(results, [apkleaks_f], platform="android")
    _check(len(results["findings"]) == 1, "duplicate finding must collapse to ONE")
    _check(stats["merged"] == 1, "should merge")
    _check(set(results["findings"][0]["detected_by"]) == {"Beetle Native", "APKLeaks"},
           "merged finding must be detected by both")


# ── Bridge: masked-only, dedup, pipeline-ready ───────────────────────────────
def _masked_secret(detected_by=("APKLeaks",)):
    return {"name": "Heroku API Key", "type": "HEROKU_KEY", "masked_value": "her****ab",
            "value": "her****ab", "severity": "high", "category": "Cloud Credentials",
            "file_path": "sources/com/acme/Config.java", "line": 3,
            "snippet": "heroku = her****ab", "detector_confidence": 70,
            "detected_by": list(detected_by), "id": "BEETLE-SECRET-abc",
            "sources": [{"engine": "APKLeaks", "rule_id": "Heroku API Key"}]}


def test_bridge_mirrors_masked_secret_to_finding():
    results = {"secrets": [_masked_secret()], "findings": []}
    out = fusion.bridge_secrets_to_findings(results, platform="android")
    _check(out["bridged"] == 1, "one APKLeaks secret should bridge")
    f = results["findings"][0]
    _check(f.get(fusion.BRIDGE_MARKER) is True, "bridged finding should be marked")
    _check(f["value"] == "her****ab" and "raw" not in f.get("value", ""),
           "bridged finding must carry only the masked value")
    _check("APKLeaks" in f["detected_by"], "bridged finding keeps attribution")


def test_bridge_refuses_unmasked_secret():
    raw = _masked_secret()
    raw.pop("masked_value")  # simulate a secret that never went through masking
    results = {"secrets": [raw], "findings": []}
    out = fusion.bridge_secrets_to_findings(results, platform="android")
    _check(out["bridged"] == 0 and out["skipped_unmasked"] == 1,
           "an unmasked secret must NEVER be bridged (raw-value safety)")
    _check(results["findings"] == [], "no finding should be created from unmasked secret")


def test_bridge_skips_native_only_secret_by_default():
    results = {"secrets": [_masked_secret(detected_by=("Beetle Native",))], "findings": []}
    out = fusion.bridge_secrets_to_findings(results, platform="android")
    _check(out["bridged"] == 0, "native-only secrets are not bridged (Phase 1.9 scope)")


def test_bridge_is_idempotent():
    results = {"secrets": [_masked_secret()], "findings": []}
    fusion.bridge_secrets_to_findings(results, platform="android")
    fusion.bridge_secrets_to_findings(results, platform="android")
    bridged = [f for f in results["findings"] if f.get(fusion.BRIDGE_MARKER)]
    _check(len(bridged) == 1, "re-running the bridge must not duplicate findings")


def test_reconcile_removes_bridged_findings_and_harvests_intelligence():
    """After enrichment, reconcile must REMOVE every bridged copy from findings
    (so a bridged secret never displays twice in UI/PDF/HTML/JSON/SARIF) and copy
    the engine-computed intelligence back onto the linked secret. This is the
    regression guard for the iOS double-display bug (bridge without reconcile)."""
    results = {"secrets": [_masked_secret()], "findings": [],
               "app_info": {"package": "com.acme"}}
    fusion.bridge_secrets_to_findings(results, platform="android")
    # Simulate an engine writing intelligence onto the bridged finding.
    bridged = [f for f in results["findings"] if f.get(fusion.BRIDGE_MARKER)]
    _check(len(bridged) == 1, "expected exactly one bridged finding pre-reconcile")
    bridged[0]["owner_type"] = "application"
    bridged[0]["overall_confidence"] = 88
    out = fusion.reconcile_bridged_findings(results)
    _check(out["removed"] == 1 and out["reconciled"] == 1, "reconcile stats wrong")
    _check(all(not f.get(fusion.BRIDGE_MARKER) for f in results["findings"]),
           "no bridged finding may remain after reconcile (would double-display)")
    secret = results["secrets"][0]
    _check(secret.get("intelligence", {}).get("owner_type") == "application",
           "reconcile must harvest engine intelligence onto the linked secret")
    _check(secret.get("overall_confidence") == 88,
           "reconcile must expose flat-convenience intelligence on the secret")


def test_bridged_finding_flows_through_pipeline():
    """A bridged finding is a normal finding: engines enrich it like any other."""
    results = {"secrets": [_masked_secret()], "findings": [],
               "app_info": {"package": "com.acme"}}
    fusion.bridge_secrets_to_findings(results, platform="android")
    # Ownership + confidence + bug-bounty must accept it without error and enrich.
    from analyzers import ownership, confidence, bug_bounty
    ownership.annotate(results)
    confidence.annotate(results)
    bug_bounty.annotate(results)
    f = results["findings"][0]
    _check("owner_type" in f, "ownership engine did not enrich the bridged finding")
    _check("overall_confidence" in f, "confidence engine did not enrich the bridged finding")
    _check("bug_bounty" in f, "bug-bounty engine did not enrich the bridged finding")


# ── End-to-end through the public package entrypoint ──────────────────────────
def test_run_detection_sources_end_to_end():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        jadx = _write_tree(tmp)
        results = {"secrets": [_native_secret()], "findings": [], "endpoints": []}
        stats = run_detection_sources(results, [jadx], platform="android")
        _check("APKLeaks" in stats, "APKLeaks source did not run")
        # The native AWS key must have merged (now detected by both), not duplicated.
        aws = [s for s in results["secrets"] if s["name"] == "AWS Access Key ID"]
        _check(len(aws) == 1, "AWS key duplicated across sources")
        _check(set(aws[0]["detected_by"]) == {"Beetle Native", "APKLeaks"},
               "end-to-end attribution union failed")
        _check(any("firebaseio.com" in e for e in results["endpoints"]),
               "endpoint not fused into results")


# ── Canonical model regression ───────────────────────────────────────────────
def test_canonical_round_trips_attribution():
    d = {"title": "X", "rule_id": "X", "detected_by": ["Beetle Native", "APKLeaks"],
         "sources": [{"engine": "APKLeaks", "rule_id": "X", "confidence": 70}]}
    cf = from_legacy(d, platform="android")
    _check(cf.detected_by == ["Beetle Native", "APKLeaks"], "detected_by lost")
    _check(cf.sources[0]["engine"] == "APKLeaks", "sources lost")
    out = cf.to_legacy()
    _check(out["detected_by"] == ["Beetle Native", "APKLeaks"], "to_legacy dropped detected_by")


def test_canonical_merge_unions_attribution():
    a = from_legacy({"title": "X", "rule_id": "X", "detected_by": ["Beetle Native"],
                     "sources": [{"engine": "Beetle Native", "rule_id": "X"}]})
    b = from_legacy({"title": "X", "rule_id": "X", "detected_by": ["APKLeaks"],
                     "sources": [{"engine": "APKLeaks", "rule_id": "X"}]})
    m = a.merge(b)
    _check(set(m.detected_by) == {"Beetle Native", "APKLeaks"}, "merge did not union engines")
    _check(len(m.sources) == 2, "merge did not union per-source detail")


# ── Standalone runner (no pytest required) ───────────────────────────────────
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
