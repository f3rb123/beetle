"""
Attack Chain Engine v2 tests (Beetle 2.0, Phase 1.7).

Covers realistic Android & iOS chains (WebView JS bridge RCE, deep-link/WebView,
exported-component injection, ContentProvider disclosure, cleartext/cert MitM,
hardcoded secret abuse, backup/debuggable/insecure-storage, weak crypto),
mixed ownership/evidence, SAFE CHAINING (framework noise / suppressed / FP
secrets / generated code never required), finding-soup avoidance, blocked chains,
scoring, graph, explainability, determinism and the non-destructive guarantee.

Runnable standalone or under pytest:
    python -m tests.test_attack_chains_v2     # from backend/
    python backend/tests/test_attack_chains_v2.py
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import attack_chains as ac  # noqa: E402
from analyzers.attack_chains import AttackChainEngine  # noqa: E402

ENGINE = AttackChainEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def F(title, category="", *, decision="Show", visibility="Show", owner="Application",
      conf=80, quality="Good", cls="C", method="m", line=10, file="sources/com/app/A.java",
      cid=None, **extra):
    f = {
        "title": title, "severity": extra.pop("severity", "high"), "category": category,
        "owner_type": owner, "overall_confidence": conf,
        "exploitability_confidence": extra.pop("exploit", 60),
        "evidence_bundle": {"quality": quality, "evidence_id": "EV-" + (cid or title)[:6],
                            "primary": {"relative_path": file, "line": line,
                                        "file_path": file, "locator": {"class": cls, "method": method}}},
        "triage": {"decision": decision, "visibility": visibility},
        "canonical_id": cid or title,
    }
    f.update(extra)
    return f


def _results(findings, surface=None, platform="android", bonuses=None):
    r = {"platform": platform, "findings": findings,
         "attack_surface": surface or {}}
    if bonuses:
        r["score"] = {"bonuses": bonuses}
    return r


def _chains(findings, surface=None, platform="android", bonuses=None):
    return ENGINE.build_chains(_results(findings, surface, platform, bonuses))


def _by_type(chains, t):
    return [c for c in chains if c["type"] == t]


_BROWSABLE = {"activities": [{"name": "com.app.WebActivity", "exported": True,
                             "browsable": True, "schemes": ["https"]}]}


# ── Realistic Android chains ──────────────────────────────────────────────────
def test_webview_js_bridge_rce():
    # No taint flow from external input into the JS bridge → the RCE chain may exist
    # but is HEURISTIC: capped below CRITICAL and below 60 confidence (Flaw B). It is
    # no longer allowed to present as a proven critical finding on co-occurrence alone.
    chains = _chains([
        F("WebView JavaScript Enabled", "WebView", cid="wv-js"),
        F("addJavascriptInterface used", "WebView", cid="wv-iface"),
    ], surface=_BROWSABLE)
    c = next((x for x in chains if x["name"].startswith("WebView JavaScript Bridge")), None)
    _check(c, f"no RCE chain in {[x['name'] for x in chains]}")
    _check(c["reachability_proof"] == "heuristic", f"proof {c['reachability_proof']}")
    _check(c["severity"] != "critical", f"heuristic RCE must not be critical: {c['severity']}")
    _check(c["overall_confidence"] < 60, f"heuristic confidence must be < 60: {c['overall_confidence']}")
    _check(len(c["required_findings"]) == 2, "two required links")
    _check(c["entry_point"]["component"] == "com.app.WebActivity", "entry component")
    _check(len(c["narrative"]) >= 4 and c["graph"]["nodes"], "narrative + graph")


def test_exported_sql_injection():
    chains = _chains([
        F("SQL Injection via Intent", "Taint Analysis", cid="sqli",
          taint_flow={"source_cat": "User Input", "sink_cat": "sqlite", "chain": ["A.b"]},
          reachability="YES"),
    ], surface={"activities": [{"name": "com.app.Search", "exported": True}]})
    c = _by_type(chains, "SQL Injection")
    _check(c, "expected SQLi chain")
    _check(c[0]["overall_impact"], "impact present")


def test_content_provider_file_disclosure():
    chains = _chains([
        F("Path Traversal in ContentProvider query", "Taint Analysis", cid="pt",
          taint_flow={"source_cat": "ContentProvider", "sink_cat": "filesystem", "chain": ["P.q"]}),
    ], surface={"providers": [{"name": "com.app.FileProvider", "exported": True}]})
    _check(_by_type(chains, "Content Provider Abuse"), "expected provider disclosure chain")


def test_cleartext_mitm_token_theft():
    chains = _chains([
        F("Cleartext Traffic Permitted", "Network Security", cid="ct"),
        F("Hardcoded Bearer Token", "Secrets", cid="tok",
          secret_intelligence={"status": "Probable Secret", "secret_type": "Bearer Token"}),
    ])
    c = _by_type(chains, "Network Security")
    _check(c, "expected cleartext MitM chain")
    _check(not c[0]["blocked"], "not blocked without pinning")


def test_cert_validation_bypass_mitm():
    chains = _chains([
        F("TrustManager accepts all certificates", "Certificate", cid="trust",
          description="custom trustmanager trust all"),
    ], surface=None)
    # Needs a NETWORK entry; add a network finding.
    chains = _chains([
        F("TrustManager accepts all certificates", "Network Security", cid="trust",
          description="custom trustmanager trust all"),
    ])
    _check(_by_type(chains, "Certificate Validation"), "expected cert-bypass MitM chain")


def test_hardcoded_secret_abuse():
    chains = _chains([
        F("Hardcoded AWS Key", "Secrets", cid="aws",
          secret_intelligence={"status": "Probable Secret", "secret_type": "AWS Access Key"}),
    ])
    c = _by_type(chains, "Hardcoded Secrets")
    _check(c, "expected secret abuse chain")
    _check(c[0]["entry_point"]["kind"] == "distribution", "distribution entry")


def test_backup_debuggable_storage_crypto():
    backup = _by_type(_chains([F("android:allowBackup is true", "Configuration", cid="bk")]), "Backup Abuse")
    dbg = _by_type(_chains([F("Application is debuggable", "Configuration", cid="db",
                               rule_id="manifest_debuggable")]), "Debuggable Abuse")
    store = _by_type(_chains([F("Sensitive data in SharedPreferences", "Data Storage", cid="st")]),
                     "Insecure Storage")
    crypto = _by_type(_chains([F("Weak cipher MD5 used", "Cryptography", cid="cr",
                                 description="weak md5")]), "Weak Cryptography")
    _check(backup and dbg and store and crypto, "expected backup/debuggable/storage/crypto chains")


# ── iOS ───────────────────────────────────────────────────────────────────────
def test_ios_hardcoded_secret_chain():
    chains = _chains([
        F("Hardcoded API Key in plist", "Secrets", platform="ios", file="Payload/App.app/Info.plist",
          secret_intelligence={"status": "Probable Secret", "secret_type": "API Key"}, cid="ios-key"),
    ], platform="ios")
    _check(_by_type(chains, "Hardcoded Secrets"), "expected iOS secret chain")


# ── SAFE CHAINING (no false-positive chains) ──────────────────────────────────
def test_framework_noise_not_chained_as_required():
    chains = _chains([
        F("WebView JavaScript Enabled", "WebView", owner="AndroidFramework",
          decision="FrameworkNoise", visibility="HiddenByDefault", cid="fw1"),
        F("addJavascriptInterface used", "WebView", owner="AndroidFramework",
          decision="FrameworkNoise", visibility="HiddenByDefault", cid="fw2"),
    ], surface=_BROWSABLE)
    _check(not chains, f"framework noise must not form a required chain: {[c['name'] for c in chains]}")


def test_false_positive_secret_not_chained():
    chains = _chains([
        F("Maybe key", "Secrets", secret_intelligence={"status": "False Positive"}, cid="fp"),
    ])
    _check(not _by_type(chains, "Hardcoded Secrets"), "FP secret must not chain")


def test_suppressed_finding_not_required():
    chains = _chains([
        F("Weak cipher MD5", "Cryptography", description="weak md5", suppressed=True, cid="sup"),
    ])
    _check(not _by_type(chains, "Weak Cryptography"), "suppressed finding must not be a required link")


def test_unrelated_findings_do_not_soup():
    # Findings that match no template, plus one that does — only the real chain.
    chains = _chains([
        F("Verbose logging enabled", "Logging", cid="log"),
        F("App uses internet permission", "Permissions", cid="perm"),
        F("Weak cipher MD5", "Cryptography", description="weak md5", cid="cr"),
    ])
    _check(len(chains) == 1 and chains[0]["type"] == "Weak Cryptography", f"finding soup: {[c['name'] for c in chains]}")
    _check("log" not in chains[0]["required_findings"] + chains[0]["supporting_findings"],
           "unrelated finding pulled into chain")


def test_no_findings_no_chains():
    _check(_chains([F("Just an info note", "Meta")]) == [], "no template should match a lone info note")


# ── Blocked chains ────────────────────────────────────────────────────────────
def test_blocked_by_certificate_pinning():
    chains = _chains(
        [F("Cleartext Traffic Permitted", "Network Security", cid="ct"),
         F("Certificate Pinning Detected", "Certificate", cid="pin", description="certificate pinning")],
        bonuses=[["Certificate pinning detected", 5]])
    c = _by_type(chains, "Network Security")
    _check(c, "chain still reported")
    _check(c[0]["blocked"] is True and "cert_pinning" in c[0]["blocked_by"], "should be blocked by pinning")


# ── Mixed ownership / evidence + scoring uses engines not severity ────────────
def test_scoring_uses_evidence_and_confidence():
    strong = _chains([F("Hardcoded AWS Key", "Secrets", conf=95, quality="Excellent",
                        secret_intelligence={"status": "Validated Secret", "secret_type": "AWS"}, cid="s1")])
    weak = _chains([F("Hardcoded AWS Key", "Secrets", conf=40, quality="Weak",
                      secret_intelligence={"status": "Possible Secret", "secret_type": "AWS"}, cid="s2")])
    sc = _by_type(strong, "Hardcoded Secrets")[0]
    wc = _by_type(weak, "Hardcoded Secrets")[0]
    _check(sc["overall_confidence"] > wc["overall_confidence"], "stronger evidence/confidence → higher chain confidence")
    _check(sc["overall_evidence_quality"] == "Excellent" and wc["overall_evidence_quality"] == "Weak", "evidence band")


def test_explainability_present():
    c = _by_type(_chains([F("Hardcoded AWS Key", "Secrets",
                            secret_intelligence={"status": "Probable Secret", "secret_type": "AWS"}, cid="x")]),
                 "Hardcoded Secrets")[0]
    ce = c["confidence_explanation"]
    for k in ("why_exists", "why_members", "why_confidence", "why_exploitability", "why_blocked"):
        _check(k in ce, f"missing explanation: {k}")
    _check(c["evidence_references"] and c["triage_summary"] and c["ownership_summary"], "summaries present")


# ── Determinism + pipeline integration ────────────────────────────────────────
def test_deterministic():
    fs = [F("WebView JavaScript Enabled", "WebView", cid="wv-js"),
          F("addJavascriptInterface used", "WebView", cid="wv-iface")]
    a = ENGINE.build_chains(_results(fs, _BROWSABLE))
    b = ENGINE.build_chains(_results(fs, _BROWSABLE))
    _check(a == b, "engine must be deterministic")


def test_annotate_non_destructive():
    results = _results([
        F("Hardcoded AWS Key", "Secrets", secret_intelligence={"status": "Probable Secret",
          "secret_type": "AWS"}, cid="k", extra_key="keep"),
    ])
    import copy
    before = copy.deepcopy(results["findings"])
    ac.annotate(results)
    _check(results["findings"] == before, "annotate must not modify findings")
    _check("attack_chains_v2" in results and results["attack_chains_v2"], "chains emitted")
    _check(results["attack_chains_v2_summary"]["count"] >= 1, "summary present")


def test_capabilities_and_role_helpers():
    _check("WEBVIEW_JS" in ac.tag_capabilities(F("WebView JavaScript Enabled", "WebView")), "cap tag")
    _check(ac.chain_role(F("x", "Secrets", secret_intelligence={"status": "False Positive"})) == "excluded",
           "FP secret excluded from chaining")
    _check(ac.get_engine() is ac.get_engine(), "singleton")


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
