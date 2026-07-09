"""
Security Control Resolution tests.

Guards the invariant that made this module necessary: ONE control, ONE decision,
consumed by every subsystem. A finding that asserts a control is MISSING must never
produce a "control present" answer anywhere — not a scoring bonus, not a MASVS
controls_present mark, not an attack-chain blocker.

Each of these fails against the pre-refactor code:

  * scoring.py awarded +5 "Certificate pinning detected" whenever the substring
    "certificate pinning" appeared in any finding title OR description, so
    "No Certificate Pinning Configured" paid its own bonus — as did the
    `android:debuggable` finding, whose description warns an attacker can
    "bypass certificate pinning".
  * attack_chains._detect_mitigations blocked MitM chains on the same substring.
  * masvs_intel marked "Integrity / Attestation" present off the root-detection
    finding's description, which merely *recommends* Play Integrity.

Runnable standalone or under pytest:
    python -m tests.test_security_controls       # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import masvs_intel, security_controls  # noqa: E402
from analyzers.attack_chains.engine import _detect_mitigations  # noqa: E402
from analyzers.scoring import calculate_score  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _results(findings, **extra):
    r = {"platform": "android", "findings": findings, "severity_summary": {}, "secrets": []}
    r.update(extra)
    return r


def _bonus_labels(results):
    return [label for label, _pts in calculate_score(results)["bonuses"]]


# The exact finding from the bug report.
NO_PINNING = {
    "rule_id": "nsc_no_pinning",
    "title": "No Certificate Pinning Configured",
    "severity": "medium",
    "category": "Network Security",
    "description": "network_security_config.xml does not define any <pin-set> elements. "
                   "Without pinning, any trusted CA — including those installed by "
                   "attackers — can issue valid certificates for your domain.",
    "recommendation": "Add <pin-set> to your domain-config with your server certificate's "
                      "public key hash. Include a backup pin.",
}

PINNING_CONFIGURED = {
    "rule_id": "nsc_pinning_configured",
    "title": "Certificate Pinning Configured — api.example.com",
    "severity": "info",
    "category": "Network Security",
    "description": "Certificate pinning is configured for api.example.com with 2 pin(s).",
}

# Its description mentions bypassing pinning; it says nothing about pinning existing.
DEBUGGABLE = {
    "rule_id": "manifest_debuggable",
    "title": "Application Is Debuggable",
    "severity": "high",
    "category": "Configuration",
    "description": 'android:debuggable="true" is set. Any user with ADB access can attach '
                   "a debugger, dump memory, extract data, and bypass certificate pinning.",
}

ROOT_DETECTION = {
    "rule_id": "android_no_root_detection",
    "title": "Root Detection Present",
    "severity": "info",
    "category": "Resilience",
    "security_control": True,
    "snippet": "if (RootBeer(context).isRooted()) { finish(); }",
    "description": "Root detection APIs were detected in the app. For higher assurance, "
                   "layer on-device root detection with server-side Play Integrity / "
                   "SafetyNet attestation.",
}


# ════════════════════════════════════════════════════════════════════════════
# The acceptance case: a "missing pinning" finding, alone.
# ════════════════════════════════════════════════════════════════════════════
def test_no_pinning_finding_yields_absent_and_no_bonus():
    results = _results([NO_PINNING])
    controls = security_controls.resolve(results)

    _check(controls["cert_pinning"]["state"] == "absent",
           f"expected cert_pinning absent, got {controls['cert_pinning']['state']!r}")
    _check(controls["cert_pinning"]["evidence"],
           "absent state must cite the evidence that asserted absence")
    _check(all(e["polarity"] == "negative" for e in controls["cert_pinning"]["evidence"]),
           "a 'no pinning' finding must produce only negative evidence")

    _check("Certificate pinning detected" not in _bonus_labels(results),
           "a 'No Certificate Pinning' finding must not award the pinning bonus")


def test_no_pinning_detected_is_absent_despite_containing_the_positive_phrase():
    """"No certificate pinning detected" contains "certificate pinning detected",
    which IS an assertive presence phrase. Negative phrasing must win."""
    finding = {"title": "No certificate pinning detected", "severity": "medium",
               "category": "Network Security"}
    results = _results([finding])
    controls = security_controls.resolve(results)

    _check(controls["cert_pinning"]["state"] == "absent",
           f"expected absent, got {controls['cert_pinning']['state']!r}")
    _check("Certificate pinning detected" not in _bonus_labels(results),
           "a negated title must not award the pinning bonus")
    _check("cert_pinning" not in _detect_mitigations(results),
           "a negated title must not block a chain")


def test_no_pinning_finding_does_not_block_a_mitm_chain():
    """The blocker suppressed the very chain the finding exists to justify."""
    _check("cert_pinning" not in _detect_mitigations(_results([NO_PINNING])),
           "absent pinning must not register as a chain mitigation")


def test_no_pinning_finding_is_not_a_masvs_present_control():
    results = _results([NO_PINNING])
    results["security_controls"] = security_controls.resolve(results)
    coverage = {c["category"]: c for c in masvs_intel.build_coverage(results)}
    net = coverage["MASVS-NETWORK"]

    _check("Certificate Pinning" not in net["controls_present"],
           "MASVS must not mark pinning present when the scan says it is missing")
    _check("Certificate Pinning" in net["controls_missing"],
           "pinning should be reported as a missing MASVS-NETWORK control")


# ════════════════════════════════════════════════════════════════════════════
# Descriptions are not evidence.
# ════════════════════════════════════════════════════════════════════════════
def test_description_mentioning_pinning_bypass_is_not_evidence_of_pinning():
    results = _results([DEBUGGABLE])
    controls = security_controls.resolve(results)
    _check(controls["cert_pinning"]["state"] == "unknown",
           "a description warning that pinning can be BYPASSED asserts nothing about "
           f"pinning; got {controls['cert_pinning']['state']!r}")
    _check("Certificate pinning detected" not in _bonus_labels(results),
           "the debuggable finding's prose must not pay the pinning bonus")


def test_root_detection_description_does_not_imply_attestation():
    """Its remediation prose recommends Play Integrity — the app does not use it."""
    results = _results([ROOT_DETECTION])
    controls = security_controls.resolve(results)

    _check(controls["root_detection"]["state"] == "present",
           f"RootBeer usage is root detection; got {controls['root_detection']['state']!r}")
    _check(controls["safetynet_play_integrity"]["state"] == "unknown",
           "recommending Play Integrity is not implementing it; got "
           f"{controls['safetynet_play_integrity']['state']!r}")

    labels = _bonus_labels(results)
    _check("Root detection implemented" in labels, "root detection bonus should be awarded")
    _check("SafetyNet/Play Integrity used" not in labels,
           "attestation bonus must not ride along on the root-detection finding's prose")


def test_frida_gadget_artifact_is_not_frida_detection():
    """A bundled frida-gadget is an instrumented build, not a defence against one."""
    gadget = {"rule_id": "android_frida_gadget", "title": "Frida Gadget Artifact Found",
              "severity": "critical", "category": "Tampering",
              "description": "Artifacts of the Frida dynamic instrumentation gadget detected."}
    controls = security_controls.resolve(_results([gadget]))
    _check(controls["frida_detection"]["state"] == "unknown",
           f"frida gadget must not read as frida detection; got {controls['frida_detection']['state']!r}")


# ════════════════════════════════════════════════════════════════════════════
# Positive evidence still resolves to present, everywhere.
# ════════════════════════════════════════════════════════════════════════════
def test_configured_pinning_is_present_bonused_and_blocks_chains():
    results = _results([PINNING_CONFIGURED])
    controls = security_controls.resolve(results)
    _check(controls["cert_pinning"]["state"] == "present",
           f"expected present, got {controls['cert_pinning']['state']!r}")

    _check("Certificate pinning detected" in _bonus_labels(results),
           "configured pinning must award the bonus")
    _check("cert_pinning" in _detect_mitigations(results),
           "configured pinning must block MitM chains")

    results["security_controls"] = controls
    coverage = {c["category"]: c for c in masvs_intel.build_coverage(results)}
    _check("Certificate Pinning" in coverage["MASVS-NETWORK"]["controls_present"],
           "MASVS must mark configured pinning present")


def test_structured_network_config_outranks_nothing_and_decides_pinning():
    """`network_config.summary` is parsed truth, usable with no findings at all."""
    absent = security_controls.resolve(_results([], network_config={
        "present": True, "summary": {"has_pinning": False, "pinned_domain_count": 0}}))
    _check(absent["cert_pinning"]["state"] == "absent",
           "an NSC with no pin-set proves pinning is absent")

    present = security_controls.resolve(_results([], network_config={
        "present": True, "summary": {"has_pinning": True, "pinned_domain_count": 2}}))
    _check(present["cert_pinning"]["state"] == "present",
           "an NSC with a pin-set proves pinning is present")


# ════════════════════════════════════════════════════════════════════════════
# Partial: present but degraded.
# ════════════════════════════════════════════════════════════════════════════
def test_pinning_pinned_on_one_domain_and_missing_elsewhere_is_partial():
    results = _results([PINNING_CONFIGURED, NO_PINNING])
    controls = security_controls.resolve(results)
    _check(controls["cert_pinning"]["state"] == "partial",
           f"conflicting evidence must resolve to partial, got {controls['cert_pinning']['state']!r}")
    _check("Certificate pinning detected" not in _bonus_labels(results),
           "partial pinning has not earned the full good-practice bonus")
    _check("cert_pinning" not in _detect_mitigations(results),
           "partial pinning is not a reliable chain blocker")


def test_debug_override_makes_configured_pinning_partial():
    override = {"rule_id": "nsc_pin_override_debug",
                "title": "Certificate Pinning Override in Debug Config",
                "severity": "medium", "category": "Network Security"}
    controls = security_controls.resolve(_results([PINNING_CONFIGURED, override]))
    _check(controls["cert_pinning"]["state"] == "partial",
           'overridePins="true" makes pinning bypassable, not fully present; got '
           f"{controls['cert_pinning']['state']!r}")


# ════════════════════════════════════════════════════════════════════════════
# Cleartext inverts: the good outcome is denial.
# ════════════════════════════════════════════════════════════════════════════
def test_cleartext_permitted_anywhere_is_allowed():
    finding = {"rule_id": "nsc_domain_cleartext",
               "title": "Cleartext HTTP Permitted for Domain(s): cdn.example.com",
               "severity": "medium", "category": "Network Security"}
    controls = security_controls.resolve(_results(
        [finding], manifest_xml='<application android:usesCleartextTraffic="false"/>'))
    _check(controls["cleartext"]["state"] == "allowed",
           "one domain permitting cleartext means cleartext is allowed; got "
           f"{controls['cleartext']['state']!r}")


def test_manifest_denying_cleartext_is_blocked():
    controls = security_controls.resolve(_results(
        [], manifest_xml='<application android:usesCleartextTraffic="false"/>'))
    _check(controls["cleartext"]["state"] == "blocked",
           f"expected blocked, got {controls['cleartext']['state']!r}")

    results = _results([], manifest_xml='<application android:usesCleartextTraffic="false"/>')
    results["security_controls"] = controls
    coverage = {c["category"]: c for c in masvs_intel.build_coverage(results)}
    _check("No Cleartext Traffic" in coverage["MASVS-NETWORK"]["controls_present"],
           "MASVS must credit a manifest that denies cleartext")


# ════════════════════════════════════════════════════════════════════════════
# Obfuscation: the pre-existing special case, now uniform.
# ════════════════════════════════════════════════════════════════════════════
def test_obfuscation_not_detected_is_absent_and_unbonused():
    finding = {"rule_id": "obfuscation_not_detected", "title": "Code Obfuscation Not Detected",
               "severity": "low", "category": "Resilience"}
    results = _results([finding])
    _check(security_controls.resolve(results)["obfuscation"]["state"] == "absent",
           "'not detected' must resolve to absent")
    _check("Code obfuscation enabled" not in _bonus_labels(results),
           "unobfuscated code must not earn the obfuscation bonus")


def test_obfuscation_detected_is_present_and_bonused():
    finding = {"rule_id": "obfuscation_detected", "title": "Code Obfuscation Detected (ProGuard/R8)",
               "severity": "info", "category": "Resilience"}
    results = _results([finding])
    _check(security_controls.resolve(results)["obfuscation"]["state"] == "present",
           "'detected' must resolve to present")
    _check("Code obfuscation enabled" in _bonus_labels(results),
           "obfuscated code must earn the bonus")


def test_info_finding_named_obfuscation_missing_is_not_present():
    """`android_obfuscation_missing` is INFO severity, so it lands in the positive
    corpus. Only its rule identity keeps it from reading as 'obfuscation present'."""
    finding = {"rule_id": "android_obfuscation_missing", "title": "Code Obfuscation Not Detected",
               "severity": "info", "category": "Resilience",
               "snippet": "BuildConfig.DEBUG",
               "description": "Readable class names suggest code obfuscation may not be applied."}
    controls = security_controls.resolve(_results([finding]))
    _check(controls["obfuscation"]["state"] == "absent",
           f"expected absent, got {controls['obfuscation']['state']!r}")


# ════════════════════════════════════════════════════════════════════════════
# Absence of evidence is not absence of control.
# ════════════════════════════════════════════════════════════════════════════
def test_no_evidence_is_unknown_and_earns_nothing():
    results = _results([])
    controls = security_controls.resolve(results)
    for key in security_controls.CONTROLS:
        _check(controls[key]["state"] == "unknown",
               f"{key} should be unknown with no evidence, got {controls[key]['state']!r}")
        _check(controls[key]["evidence"] == [], f"{key} should cite no evidence")
    _check(_bonus_labels(results) == [], "an empty scan earns no good-practice bonuses")
    _check(_detect_mitigations(results) == set(), "an empty scan implements no mitigations")


# ════════════════════════════════════════════════════════════════════════════
# One decision, consumed everywhere.
# ════════════════════════════════════════════════════════════════════════════
def test_all_consumers_agree_on_the_same_stored_decision():
    """The bug: scoring said present, the findings list said absent, in one report."""
    results = _results([NO_PINNING, DEBUGGABLE])
    results["security_controls"] = security_controls.resolve(results)

    scoring_says_present = "Certificate pinning detected" in _bonus_labels(results)
    chains_say_present = "cert_pinning" in _detect_mitigations(results)
    coverage = {c["category"]: c for c in masvs_intel.build_coverage(results)}
    masvs_says_present = "Certificate Pinning" in coverage["MASVS-NETWORK"]["controls_present"]
    authority_says_present = results["security_controls"]["cert_pinning"]["state"] == "present"

    _check(not authority_says_present, "authority must say pinning is not present")
    _check(scoring_says_present == chains_say_present == masvs_says_present == authority_says_present,
           f"subsystems disagree: scoring={scoring_says_present} chains={chains_say_present} "
           f"masvs={masvs_says_present} authority={authority_says_present}")


def test_consumers_resolve_on_demand_when_pipeline_did_not_store():
    """`security_controls` missing (older scan, or resolve() raised) must not crash
    or silently flip a control to present."""
    results = _results([NO_PINNING])
    _check("security_controls" not in results, "precondition")
    _check("Certificate pinning detected" not in _bonus_labels(results), "scoring must resolve on demand")
    _check("cert_pinning" not in _detect_mitigations(results), "chains must resolve on demand")


# ════════════════════════════════════════════════════════════════════════════
# Determinism.
# ════════════════════════════════════════════════════════════════════════════
def test_resolution_is_deterministic_and_order_independent():
    findings = [PINNING_CONFIGURED, NO_PINNING, DEBUGGABLE, ROOT_DETECTION]
    first = security_controls.resolve(_results(list(findings)))
    again = security_controls.resolve(_results(list(findings)))
    reversed_ = security_controls.resolve(_results(list(reversed(findings))))

    _check(first == again, "resolve() must be stable across identical inputs")
    _check({k: v["state"] for k, v in first.items()} == {k: v["state"] for k, v in reversed_.items()},
           "control states must not depend on finding order")
    _check(first == reversed_, "evidence lists must be sorted, not input-ordered")


def test_resolve_does_not_mutate_results():
    results = _results([NO_PINNING])
    before = repr(results)
    security_controls.resolve(results)
    _check(repr(results) == before, "resolve() must be pure")


def test_negation_guard_checks_every_occurrence():
    """An early "no certificate pinning" must not veto a later genuine token."""
    corpus = "no certificate pinning here. later: okhttp certificatepinner builder"
    _check(security_controls.corpus_asserts(corpus, "certificatepinner"),
           "a real implementation token later in the corpus must still assert")
    _check(not security_controls.corpus_asserts("no certificatepinner configured", "certificatepinner"),
           "a negated token must not assert")


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
