"""
Attack-chain evidence-discipline tests.

The CLEARTEXT / CERT_BYPASS / SECRET→cloud templates used to fire on capability
co-occurrence, producing chains contradicted by their own evidence:

  * "Cleartext Traffic Token Theft" was emitted for an app whose manifest sets
    usesCleartextTraffic="false" — CLEARTEXT was tagged from the mere word
    "cleartext" in any blob (including a finding saying cleartext is DISABLED) and
    never consulted the resolved security-control state.
  * "Disabled Certificate Validation MitM" was emitted on a plain pass-through
    setter `setSSLSocketFactory(f){ this.b.setSSLSocketFactory(f); }` — not a bypass.
  * The cloud narrative asserted "confirmed public exposure → cloud data access"
    for a secret whose exposure was never probe-confirmed.

Now: CLEARTEXT requires cleartext to be actually permitted (security_controls),
CERT_BYPASS requires real disabled-validation evidence, the cloud narrative gates
its exposure claim on an actual probe, and slots are filled only by matching caps.

Runnable standalone or under pytest:
    python -m tests.test_chain_evidence_discipline      # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.attack_chains.engine import AttackChainEngine, tag_capabilities  # noqa: E402
from analyzers import analyst_intel, security_controls  # noqa: E402

ENGINE = AttackChainEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _f(title, category, cid, **kw):
    f = {
        "title": title, "category": category, "severity": kw.pop("severity", "high"),
        "canonical_id": cid, "rule_id": kw.pop("rule_id", cid), "overall_confidence": 80,
        "evidence_bundle": {"quality": "Good", "evidence_id": "EV-" + cid,
                            "primary": {"relative_path": kw.pop("file", f"sources/app/{cid}.java"),
                                        "line": 10, "locator": {}}},
        "triage": {"decision": "Show", "visibility": "Show"},
    }
    f.update(kw)
    return f


NET = _f("Insecure network configuration", "Network Security", "net")


def _types(chains):
    return {c["type"] for c in chains}


# ════════════════════════════════════════════════════════════════════════════
# 1 — CLEARTEXT requires cleartext to actually be permitted.
# ════════════════════════════════════════════════════════════════════════════
def test_cleartext_blocked_yields_no_cleartext_chain():
    disabled = _f("Cleartext Traffic Disabled", "Network Security", "ctd", severity="info",
                  security_control=True, description='android:usesCleartextTraffic="false"')
    results = {"platform": "android",
               "manifest_xml": '<application android:usesCleartextTraffic="false"/>',
               "findings": [NET, disabled]}
    chains = ENGINE.build_chains(results)
    _check("Network Security" not in _types(chains),
           "an app with usesCleartextTraffic=\"false\" must not produce a cleartext chain")
    _check("CLEARTEXT" not in tag_capabilities(disabled, results),
           "a finding asserting cleartext is DISABLED must not tag CLEARTEXT")


def test_cleartext_disabled_finding_never_tags_cleartext_even_without_state():
    # No results context: still must not tag from a 'disabled' assertion.
    disabled = _f("Cleartext Traffic Disabled", "Network Security", "ctd", description="cleartext disabled")
    _check("CLEARTEXT" not in tag_capabilities(disabled),
           "a 'disabled' cleartext finding must never tag CLEARTEXT")


def test_cleartext_permitted_still_produces_the_chain():
    permitted = _f("Cleartext HTTP Traffic Permitted", "Network Security", "cton",
                   rule_id="manifest_cleartext_traffic")
    results = {"platform": "android",
               "manifest_xml": '<application android:usesCleartextTraffic="true"/>',
               "findings": [NET, permitted]}
    chains = ENGINE.build_chains(results)
    _check("Network Security" in _types(chains),
           "an app that actually permits cleartext must still produce the chain")
    _check("CLEARTEXT" in tag_capabilities(permitted, results),
           "a finding asserting cleartext IS permitted must tag CLEARTEXT")


def test_mere_mention_of_cleartext_does_not_tag():
    # A finding that only mentions the word in remediation prose is not an assertion.
    mention = _f("Some finding", "Network Security", "m1",
                 recommendation="Prefer HTTPS; cleartext should be avoided.")
    _check("CLEARTEXT" not in tag_capabilities(mention),
           "a mere mention of 'cleartext' must not tag CLEARTEXT")


# ════════════════════════════════════════════════════════════════════════════
# 2 — CERT_BYPASS requires real disabled-validation evidence.
# ════════════════════════════════════════════════════════════════════════════
PASS_THROUGH = _f(
    "SSL Context Configured Without Certificate Validation", "Network Security", "ssl",
    rule_id="android_ssl_no_verify",
    snippet="public void setSSLSocketFactory(SSLSocketFactory f) { this.b.setSSLSocketFactory(f); }",
)


def test_pass_through_ssl_setter_is_not_cert_bypass():
    _check("CERT_BYPASS" not in tag_capabilities(PASS_THROUGH),
           "a pass-through setSSLSocketFactory must not tag CERT_BYPASS")
    chains = ENGINE.build_chains({"platform": "android", "findings": [NET, PASS_THROUGH]})
    _check("Certificate Validation" not in _types(chains),
           "a pass-through setter must not yield a Disabled-Certificate-Validation chain")


def test_real_trust_all_is_cert_bypass():
    trust_all = _f("Custom X509TrustManager Accepts All Certificates", "Network Security", "trust",
                   rule_id="android_trust_manager_accept_all",
                   snippet="public void checkServerTrusted(X509Certificate[] c, String s) {}")
    _check("CERT_BYPASS" in tag_capabilities(trust_all),
           "an empty checkServerTrusted (trust-all) must tag CERT_BYPASS")
    chains = ENGINE.build_chains({"platform": "android", "findings": [NET, trust_all]})
    _check("Certificate Validation" in _types(chains),
           "a genuine trust-all TrustManager must still yield the cert-bypass chain")


def test_allow_all_hostname_verifier_is_cert_bypass():
    hv = _f("AllowAllHostnameVerifier — Hostname Verification Disabled", "Network Security", "hv",
            rule_id="android_allow_all_hostname", snippet="setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)")
    _check("CERT_BYPASS" in tag_capabilities(hv), "an allow-all HostnameVerifier must tag CERT_BYPASS")


# ════════════════════════════════════════════════════════════════════════════
# 3 — SECRET → cloud: no fabricated exposure.
# ════════════════════════════════════════════════════════════════════════════
def _cloud_path(confirmed):
    comps = [{"label": "AWS access key", "kind": "credential"},
             {"label": "S3 bucket", "kind": "exposure",
              "state": "valid" if confirmed else "unknown"}]
    return {"provider": "AWS", "title": "AWS Key + S3", "summary": "AWS key found.",
            "confidence": "HIGH" if confirmed else "LOW",
            "components": comps, "validated": confirmed,
            "validation_result": "valid" if confirmed else "skipped"}


def test_unconfirmed_cloud_path_does_not_assert_public_exposure():
    ex = build = analyst_intel.build_chain_explanation(_cloud_path(confirmed=False))
    why = ex["why_it_matters"].lower()
    _check(ex["exposure_confirmed"] is False, "no probe → exposure not confirmed")
    _check("confirmed public exposure" not in why, f"must not assert confirmed exposure: {why!r}")
    _check("actual data access" not in why and "reads the exposed data" not in ex["attack_scenario"].lower(),
           "must not assert reachable cloud data access without confirmation")
    _check("credential-hygiene" in why, "must describe it honestly as a credential-hygiene issue")


def test_confirmed_cloud_path_keeps_the_exposure_narrative():
    ex = analyst_intel.build_chain_explanation(_cloud_path(confirmed=True))
    _check(ex["exposure_confirmed"] is True, "a probe-valid path is confirmed")
    _check("confirmed public exposure" in ex["why_it_matters"].lower(),
           "a confirmed exposure keeps the cloud-data-access narrative")


def test_secret_without_exposure_is_a_distribution_chain_not_cloud_access():
    secret = _f("Hardcoded AWS Key", "Secrets", "s1",
                secret_intelligence={"status": "Probable Secret", "secret_type": "AWS Access Key"})
    chains = ENGINE.build_chains({"platform": "android", "findings": [secret]})
    secret_chains = [c for c in chains if c["type"] == "Hardcoded Secrets"]
    _check(secret_chains, "a real secret should still form its (distribution) chain")
    c = secret_chains[0]
    _check(c["entry_point"]["kind"] == "distribution",
           "a secret with no confirmed exposure stays a distribution chain")
    analyst_intel.annotate({"platform": "android", "findings": [secret] + [c]})
    # its v2 explanation must not claim reachable cloud data access / public exposure
    ex = c.get("analyst_explanation") or {}
    text = (ex.get("why_it_matters", "") + " " + ex.get("attack_scenario", "")).lower()
    _check("confirmed public exposure" not in text and "public exposure confirmed" not in text,
           f"the secret chain must not fabricate a public-exposure step: {text!r}")


# ════════════════════════════════════════════════════════════════════════════
# 4 — no unrelated steps pulled into a chain.
# ════════════════════════════════════════════════════════════════════════════
def test_debuggable_finding_not_pulled_into_cleartext_chain():
    permitted = _f("Cleartext HTTP Traffic Permitted", "Network Security", "cton",
                   rule_id="manifest_cleartext_traffic")
    debuggable = _f("Potentially Debuggable (Flag Missing)", "Configuration", "dbg", severity="medium",
                    description="the debuggable flag is missing")
    results = {"platform": "android",
               "manifest_xml": '<application android:usesCleartextTraffic="true"/>',
               "findings": [NET, permitted, debuggable]}
    net_chains = [c for c in ENGINE.build_chains(results) if c["type"] == "Network Security"]
    _check(net_chains, "the legitimate cleartext chain should still exist")
    for c in net_chains:
        members = " ".join(c["required_findings"] + c["supporting_findings"]).lower()
        steps = " ".join((s.get("title", "") + s.get("description", "")) for s in c["steps"]).lower()
        _check("dbg" not in members, f"unrelated debuggable finding pulled into chain: {members!r}")
        _check("debuggable" not in steps, f"unrelated debuggable step in chain: {steps!r}")


# ════════════════════════════════════════════════════════════════════════════
# The security_controls helper the gating reuses.
# ════════════════════════════════════════════════════════════════════════════
def test_finding_asserts_absent_cleartext():
    permitted = _f("Cleartext HTTP Traffic Permitted", "Network Security", "p", rule_id="manifest_cleartext_traffic")
    disabled = _f("Cleartext Traffic Disabled", "Network Security", "d", description="cleartext disabled")
    _check(security_controls.finding_asserts_absent(permitted, "cleartext"),
           "a 'permitted' finding asserts cleartext is allowed (control absent)")
    _check(not security_controls.finding_asserts_absent(disabled, "cleartext"),
           "a 'disabled' finding does not assert cleartext allowed")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
