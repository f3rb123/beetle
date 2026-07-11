"""
Regression: a package-restricted Firebase/GCP client key (AIza…) and low-confidence
APKLeaks keyword hits were driving a HIGH "Hardcoded Secret / API Key Abuse" chain
and the "HIGH RISK" headline. A HIGH secret chain must require a CONFIDENTIAL secret:
high-confidence status, a recognized credential FORMAT, and NOT a client-public key.

FAILS on old behavior (AIza = Probable Secret → SECRET → HIGH chain); PASSES on new:
  - AIza → "Client Key" (visible/INFO, not a chain secret);
  - a real provider/service-account secret → CONFIDENTIAL → HIGH chain;
  - an APKLeaks keyword hit whose value == field name → demoted, not confidential.
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.secret_intelligence import assess  # noqa: E402
from analyzers.secret_intelligence import config as SIC  # noqa: E402
from analyzers.attack_chains import engine as eng, AttackChainEngine  # noqa: E402

ENGINE = AttackChainEngine()
_AIZA = "AIza" + "SyB1cD3fGh4jKl5mNo6pQr7sTu8vWx9yZa0"  # 4 + 35


def _sec_finding(value, name, path, snippet):
    a = assess(value, {"name": name, "file_path": path, "line": 3, "snippet": snippet}).to_dict()
    return {
        "title": name, "category": "Secrets", "severity": "low",
        "file_path": path, "canonical_id": name,
        "secret_intelligence": a, "secret_status": a["status"],
        "secret_overall_confidence": a["overall_confidence"],
        "triage": {"decision": "Show", "visibility": "Show"},
        "owner_type": "Application",
    }, a


def _chains(findings):
    return ENGINE.build_chains({"platform": "android", "findings": findings, "attack_surface": {}})


def _secret_chains(chains):
    return [c for c in chains if c["type"] == "Hardcoded Secrets"]


# ── AIza client key ──────────────────────────────────────────────────────────

def test_aiza_classified_as_client_key():
    _f, a = _sec_finding(_AIZA, "google_api_key", "res/values/strings.xml",
                         f'<string name="google_api_key">{_AIZA}</string>')
    assert a["status"] == SIC.Status.CLIENT_KEY
    assert "client" in a["status"].lower()


def test_aiza_visible_not_suppressed():
    from analyzers import secret_intel
    _f, a = _sec_finding(_AIZA, "google_api_key", "res/values/strings.xml", _AIZA)
    sec = {"secret_status": a["status"], "secret_overall_confidence": a["overall_confidence"],
           "secret_intelligence": a}
    # A client key is INFORMATIONAL, not a definitive non-secret — it stays VISIBLE.
    assert secret_intel._intelligence_rejected(sec) is False


def test_aiza_is_not_a_chain_secret():
    f, _a = _sec_finding(_AIZA, "google_api_key", "res/values/strings.xml", _AIZA)
    assert "SECRET" not in eng.tag_capabilities(f)
    assert "CONFIDENTIAL_SECRET" not in eng.tag_capabilities(f)
    # No HIGH secret chain forms from a client key alone.
    assert _secret_chains(_chains([f])) == []


# ── genuine confidential secret still HIGH ───────────────────────────────────

def test_real_provider_secret_drives_high_chain():
    # A non-example AWS key in app code — a genuine confidential credential.
    f, a = _sec_finding("AKIA3XZQWQ7KJ4RTVN2P", "aws_access_key",
                        "sources/com/app/S3.java",
                        'String k = "AKIA3XZQWQ7KJ4RTVN2P"; s3.auth(k);')
    assert a["status"] in ("Probable Secret", "Validated Secret")
    assert eng._is_confidential_secret(f) is True
    chains = _secret_chains(_chains([f]))
    assert chains, "a genuine confidential secret must still form a chain"
    assert chains[0]["severity"] == "high"
    assert "API Key Abuse" in chains[0]["name"]


# ── low-confidence keyword hit: demoted + not HIGH ───────────────────────────

def test_keyword_hit_value_equals_fieldname_demoted():
    # APKLeaks-style: the matched VALUE is the field NAME, not a credential.
    a = assess("artifactoryPassword",
               {"name": "artifactoryPassword", "file_path": "sources/com/app/Cfg.java",
                "snippet": 'String artifactoryPassword = "artifactoryPassword";'}).to_dict()
    assert a["status"] not in ("Probable Secret", "Validated Secret"), a["status"]


def test_keyword_hit_not_confidential_and_not_high():
    # Even if a weak keyword hit reaches "Possible Secret", it lacks a recognized
    # credential format → never CONFIDENTIAL → never a HIGH secret chain.
    f = {
        "title": "Artifactory Password", "category": "Secrets", "severity": "low",
        "file_path": "sources/com/app/Build.java", "canonical_id": "artifactory",
        "secret_intelligence": {"status": "Possible Secret", "secret_type": "Artifactory",
                                "recognized_format": False, "overall_confidence": 50},
        "secret_status": "Possible Secret",
        "triage": {"decision": "Show", "visibility": "Show"}, "owner_type": "Application",
    }
    assert eng._is_confidential_secret(f) is False
    chains = _secret_chains(_chains([f]))
    # It may form an UNVERIFIED chain, but never HIGH.
    for c in chains:
        assert c["severity"] != "high", f"keyword hit must not drive a HIGH chain: {c['severity']}"
        assert "Unverified" in c["name"] or c["severity"] in ("medium", "low", "info")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
