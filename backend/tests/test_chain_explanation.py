"""
Attack-chain analyst-explanation tests.

Bug: analyst_intel.annotate() narrated EVERY is_attack_chain finding with
build_chain_explanation — a template written for cloud_attack_paths that hardcodes
a "{provider} credential … confirmed public exposure" story and a cloud-specific
confidence rubric (PII source / public exposure / credential). So a Command
Injection chain, an Insecure Storage chain and a Weak Crypto chain all told the
same cloud-exfil story.

Fix: v2 (engine) chains are explained from their OWN summary / impact / steps /
entry_point / confidence_explanation via build_v2_chain_explanation; only real
cloud_attack_paths use the cloud narrative. The UI "Why confidence is X" checklist
(workspaces.enrich_chains) is likewise type-aware — v2 chains show real proof
signals (reachability_proof, member evidence), not the cloud rubric.

Runnable standalone or under pytest:
    python -m tests.test_chain_explanation      # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import analyst_intel, workspaces  # noqa: E402


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


_CLOUD_WORDS = ("cloud credential", "public exposure")


def _v2_chain(name, summary, impact, proof, conf, entry_label, sink_step, member_title):
    return {
        "is_attack_chain": True,
        "canonical_id": f"CHAIN-{name[:6]}",
        "rule_id": f"chain_{name[:6]}",
        "title": f"Attack Chain: {name}",
        "name": name,
        "summary": summary,
        "description": summary,
        "overall_impact": impact,
        "impact": impact,
        "reachability_proof": proof,
        "overall_confidence": conf,
        "confidence": conf,
        "confidence_score": conf,
        "chain_confidence": "HIGH" if conf >= 70 else ("MEDIUM" if conf >= 40 else "LOW"),
        "entry_point": {"label": entry_label, "component": "com.app.Entry",
                        "reachable": proof in ("proven", "heuristic")},
        "steps": [{"order": 1, "title": "Entry point"},
                  {"order": 2, "title": sink_step},
                  {"order": 3, "title": "Objective achieved"}],
        "prerequisites": ["A required precondition for this chain"],
        "blocked": False,
        "blocked_by": [],
        "confidence_explanation": {"why_confidence": {"mean_member_confidence": conf,
                                                      "mean_member_evidence": conf}},
        "attack_chain_members": [{"id": "m", "title": member_title}],
    }


CMD = _v2_chain(
    "Exported Component to Command Injection",
    "Attacker-controlled data from an exported component reaches an OS command sink.",
    "Arbitrary command execution in the app's context.",
    "heuristic", 48,
    "Malicious app/intent reaches an exported component",
    "User-controlled data reaches a command-execution sink",
    "OS command injection sink",
)
STORAGE = _v2_chain(
    "Insecure Local Storage Theft",
    "Sensitive data is stored unencrypted on-device and can be read with device access.",
    "Theft of sensitive data from device storage.",
    "manifest-only", 35,
    "Attacker with device access (rooted / physical / malware)",
    "Sensitive data stored without encryption",
    "Sensitive data in SharedPreferences",
)
CLOUD_PATH = {
    "provider": "AWS",
    "title": "AWS Credential + Public S3 Bucket",
    "confidence": "HIGH",
    "summary": "An AWS key ships in the app and pairs with a public S3 bucket.",
    "components": [
        {"label": "AWS access key", "kind": "credential"},
        {"label": "Public S3 bucket", "kind": "exposure", "state": "valid"},
    ],
}


def _annotated():
    results = {"findings": [dict(CMD), dict(STORAGE)], "cloud_attack_paths": [dict(CLOUD_PATH)]}
    analyst_intel.annotate(results)
    return results


# ════════════════════════════════════════════════════════════════════════════
# The acceptance case: type-correct narratives, no cloud leakage.
# ════════════════════════════════════════════════════════════════════════════
def test_command_injection_chain_is_not_narrated_as_cloud():
    ex = _annotated()["findings"][0]["analyst_explanation"]
    why = ex["why_it_matters"].lower()
    for w in _CLOUD_WORDS:
        _check(w not in why, f"command-injection why_it_matters must not contain {w!r}: {why!r}")
    _check("command" in why, f"why_it_matters must describe its own type (command): {why!r}")
    _check(ex["category_template"] == "ATTACK_CHAIN_V2", "must use the v2 template, not the cloud one")


def test_insecure_storage_chain_is_not_narrated_as_cloud():
    ex = _annotated()["findings"][1]["analyst_explanation"]
    why = ex["why_it_matters"].lower()
    for w in _CLOUD_WORDS:
        _check(w not in why, f"insecure-storage why_it_matters must not contain {w!r}: {why!r}")
    _check("storage" in why or "stored" in why,
           f"why_it_matters must describe its own type (storage): {why!r}")


def test_each_chain_scenario_derives_from_its_own_steps():
    results = _annotated()
    cmd_scn = results["findings"][0]["analyst_explanation"]["attack_scenario"]
    store_scn = results["findings"][1]["analyst_explanation"]["attack_scenario"]
    _check("command-execution sink" in cmd_scn,
           f"command scenario must name its own sink step: {cmd_scn!r}")
    _check("stored without encryption" in store_scn,
           f"storage scenario must name its own step: {store_scn!r}")
    _check(cmd_scn != store_scn, "different chains must produce different scenarios")
    # The generic bookend step titles are dropped from the scenario.
    _check("Objective achieved" not in cmd_scn, "generic bookend step must be dropped")


def test_confidence_reason_uses_chain_proof_signals_not_cloud_rubric():
    results = _annotated()
    cmd_reason = results["findings"][0]["analyst_explanation"]["confidence_reason"].lower()
    store_reason = results["findings"][1]["analyst_explanation"]["confidence_reason"].lower()
    # Real proof signals, not the cloud PII/credential/exposure rubric.
    _check("public exposure" not in cmd_reason and "credential" not in cmd_reason,
           f"confidence_reason must not use the cloud rubric: {cmd_reason!r}")
    _check("heuristic" in cmd_reason, f"command chain confidence should cite its heuristic proof: {cmd_reason!r}")
    _check("manifest" in store_reason, f"storage chain confidence should cite manifest-only proof: {store_reason!r}")
    _check("member confidence" in cmd_reason, "should reference member confidence")


def test_cloud_path_still_gets_the_cloud_narrative():
    ex = _annotated()["cloud_attack_paths"][0]["analyst_explanation"]
    why = ex["why_it_matters"].lower()
    _check("credential" in why and "public exposure" in why,
           f"a real cloud path must keep the cloud narrative: {why!r}")
    _check(ex["category_template"] == "ATTACK_CHAIN", "cloud path uses the cloud template")


# ════════════════════════════════════════════════════════════════════════════
# Discriminators.
# ════════════════════════════════════════════════════════════════════════════
def test_discriminators_separate_v2_from_cloud():
    _check(analyst_intel.is_v2_chain(CMD), "v2 chain must be recognised by engine fields")
    _check(not analyst_intel.is_cloud_path(CMD), "v2 chain is not a cloud path")
    _check(analyst_intel.is_cloud_path(CLOUD_PATH), "provider+components with no v2 fields is a cloud path")
    _check(not analyst_intel.is_v2_chain(CLOUD_PATH), "cloud path has no v2 engine fields")


# ════════════════════════════════════════════════════════════════════════════
# Item 3 — the UI "Why confidence" checklist is type-aware.
# ════════════════════════════════════════════════════════════════════════════
def test_v2_confidence_checklist_uses_real_signals_not_cloud_rubric():
    results = _annotated()
    workspaces.enrich_chains(results)
    cx = results["findings"][0]["confidence_explanation"]
    labels = " ".join(c["label"] for c in cx["checks"]).lower()
    _check("public exposure" not in labels and "pii" not in labels and "credential" not in labels,
           f"v2 checklist must not carry the cloud rubric: {labels!r}")
    _check("reachability" in labels, f"v2 checklist should reference reachability: {labels!r}")
    # Heuristic proof: 'proven by data-flow' unmet, 'supported (not manifest-only)' met.
    by_label = {c["label"]: c["met"] for c in cx["checks"]}
    _check(by_label["Reachability proven by data-flow (taint)"] is False,
           "heuristic chain is not taint-proven")
    _check(by_label["Reachability supported (not manifest-only)"] is True,
           "heuristic chain has supported reachability")


def test_enrich_chains_preserves_engine_confidence_explanation():
    results = _annotated()
    workspaces.enrich_chains(results)
    cx = results["findings"][0]["confidence_explanation"]
    _check("why_confidence" in cx, "engine confidence_explanation must be preserved (merged), not clobbered")
    _check("checks" in cx and cx["checks"], "the rendered checklist is added alongside it")


def test_cloud_path_checklist_keeps_the_cloud_rubric():
    results = _annotated()
    workspaces.enrich_chains(results)
    cx = results["cloud_attack_paths"][0]["confidence_explanation"]
    labels = " ".join(c["label"] for c in cx["checks"]).lower()
    _check("public exposure" in labels or "credential" in labels,
           f"a real cloud path keeps the cloud rubric checklist: {labels!r}")


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
