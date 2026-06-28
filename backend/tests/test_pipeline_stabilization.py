"""
Intelligence Pipeline Stabilization tests (Beetle 2.0, Phase 1.998).

Permanent regressions for the three final inconsistencies:

* Secret coverage — AWS non-AKIA credentials (ASIA/STS, IAM principal ids) and
  CloudFront are now detected through the ONE unified catalog (no new matcher).
* Attack-chain synchronization — chain evidence consumes the Evidence Selection
  primary (app/manifest over framework), never an independent file_path; a
  framework-only member is labeled honestly, never silently promoted.
* Manifest snippet — the XML-aware selector always shows the EXACT triggering
  attribute (android:debuggable="true"), even when the captured snippet grabbed the
  wrong manifest line.

Run:  cd backend && python -m tests.test_pipeline_stabilization
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import evidence_selection as es  # noqa: E402
from analyzers import secret_catalog  # noqa: E402
from analyzers import workspaces  # noqa: E402
from analyzers.evidence_scanner import scan_file_for_patterns  # noqa: E402
from analyzers.common import scan_text_for_secrets  # noqa: E402

APP = "com.insecureshop"
D = APP.replace(".", "/")


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _scan(code):
    return {h["name"] for h in scan_file_for_patterns("X.java", code, secret_catalog.combined())}


# ── PART A: secret coverage parity (AWS non-AKIA + CloudFront) ────────────────
def test_aws_sts_temporary_key_detected():
    names = _scan('String k = "ASIAY34FZKBOKMUTVV7A";')
    _check("AWS STS Temporary Access Key" in names,
           "AWS STS (ASIA) temporary credential must now be detected")


def test_aws_iam_unique_id_detected():
    names = _scan('String r = "AROAJ4EXAMPLE7BOKMUTV";')
    _check("AWS IAM Unique ID" in names, "AWS IAM principal id must be detected")


def test_cloudfront_detected():
    names = _scan('String u = "https://d111111abcdef8.cloudfront.net/app.js";')
    _check("AWS CloudFront Distribution" in names, "CloudFront domain must be detected")


def test_aws_akia_still_detected_regression():
    names = _scan('String k = "AKIAIOSFODNN7EXAMPLE";')
    _check("AWS Access Key ID" in names, "the original AKIA detection must not regress")


def test_new_aws_secrets_reachable_on_common_scanner():
    # JS-bundle / DEX-string path must reach the same catalog (no parallel rules).
    hits = scan_text_for_secrets('var k="ASIAY34FZKBOKMUTVV7A";', "index.android.bundle")
    _check(any(h["name"] == "AWS STS Temporary Access Key" for h in hits),
           "ASIA key must be reachable on the common scanner path too")


# ── PART C: manifest snippet shows the EXACT triggering attribute ─────────────
def _manifest(title, snippet, category="Configuration"):
    f = {"title": title, "severity": "medium", "category": category, "evidence_type": "manifest",
         "file_path": "AndroidManifest.xml", "line": 3, "snippet": snippet}
    res = {"platform": "android", "app_info": {"package": APP}, "findings": [f]}
    es.annotate(res, platform="android")
    return res["findings"][0]["evidence_view"]["primary"]["snippet"]


def test_debuggable_snippet_is_exact_even_with_wrong_captured_line():
    # Reproduces the bug: the stored snippet captured a permission line.
    snip = _manifest("Application is Debuggable",
                     '<permission android:name="com.insecureshop.permission.READ"/>')
    _check(snip == 'android:debuggable="true"', f"expected debuggable attr, got {snip!r}")


def test_debuggable_snippet_extracted_when_present():
    snip = _manifest("Application is Debuggable",
                     '<application android:debuggable="true" android:label="x">')
    _check(snip == 'android:debuggable="true"', f"must extract the exact attr, got {snip!r}")


def test_other_manifest_attrs_exact():
    cases = {
        ("Backup Allowed", "Network Security"): 'android:allowBackup="true"',
        ("Cleartext Traffic Permitted", "Network Security"): 'android:usesCleartextTraffic="true"',
        ("Exported Activity", "Exported Components"): 'android:exported="true"',
    }
    for (title, cat), expect in cases.items():
        snip = _manifest(title, '<x android:name="y" android:foo="bar"/>', cat)
        _check(snip == expect, f"{title}: expected {expect}, got {snip!r}")


# ── PART B: attack-chain evidence consumes Evidence Selection ─────────────────
def _crypto_member(framework_only=False):
    fe = [{"path": "sources/androidx/appcompat/app/AppCompatDelegateImpl.java", "lines": [5], "snippet": "c"}]
    if not framework_only:
        fe.append({"path": f"sources/{D}/CryptoUtil.java", "lines": [12], "snippet": "Cipher.getInstance(\"AES/ECB\")"})
    return {"title": "Broken Crypto", "severity": "high", "category": "Cryptography",
            "file_path": "sources/androidx/appcompat/app/AppCompatDelegateImpl.java", "line": 5,
            "file_evidence": fe}


def _run_chain(member):
    chain = {"title": "Crypto exfil chain", "severity": "high", "is_attack_chain": True,
             "components": [{"title": "Broken Crypto"}]}
    res = {"platform": "android", "app_info": {"package": APP}, "findings": [member, chain]}
    es.annotate(res, platform="android")     # corrects member evidence first
    workspaces.enrich_chains(res)            # chains consume the selection
    return next(c for c in res["findings"] if c.get("is_attack_chain"))["chain_evidence"][0]


def test_attack_chain_uses_app_primary_not_framework():
    ev = _run_chain(_crypto_member(framework_only=False))
    _check("CryptoUtil.java" in ev["file"], f"chain must use the app primary, got {ev['file']}")
    _check("AppCompatDelegateImpl" not in ev["file"], "chain must not show the framework file")


def test_attack_chain_labels_framework_only_member():
    ev = _run_chain(_crypto_member(framework_only=True))
    _check("AppCompatDelegateImpl" in ev["file"], "framework-only member keeps framework file")
    _check(ev.get("framework_only") is True, "framework-only member must be flagged in the chain")
    _check("no application-owned implementation" in ev.get("evidence_reason", "").lower(),
           "framework-only chain evidence must carry the honest reason")


def test_attack_chain_carries_ownership_and_detection_sources():
    ev = _run_chain(_crypto_member(framework_only=False))
    _check("ownership" in ev and "detection_sources" in ev,
           "chain evidence must expose ownership + detection sources from the engine")


# ── PART E: evidence synchronization (one source of truth) ────────────────────
def test_view_and_chain_agree_on_primary():
    member = _crypto_member(framework_only=False)
    chain = {"title": "c", "is_attack_chain": True, "components": [{"title": "Broken Crypto"}]}
    res = {"platform": "android", "app_info": {"package": APP}, "findings": [member, chain]}
    es.annotate(res, platform="android")
    workspaces.enrich_chains(res)
    view_primary = member["evidence_view"]["primary"]["file"]
    chain_file = res["findings"][1]["chain_evidence"][0]["file"]
    _check(view_primary == chain_file,
           "finding details and attack chain must render the IDENTICAL primary evidence")


# ── Standalone runner ─────────────────────────────────────────────────────────
def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t(); print(f"PASS  {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failures += 1; print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
