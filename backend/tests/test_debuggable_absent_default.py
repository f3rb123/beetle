"""
Regression: android:debuggable ABSENT == secure default (false).

Beetle used to treat a missing android:debuggable attribute as a risk
("Potentially Debuggable (Flag Missing)") and — worse — the word "debuggable"
in that finding's text acquired the DEBUGGABLE capability, fabricating a
"Debuggable App Runtime Extraction" attack chain for an app that is not
debuggable.

These tests FAIL on the old behavior and PASS on the new one:
  - absent  → no debuggable finding, manifest_security state == "false",
              no DEBUGGABLE capability on any finding, zero DEBUGGABLE-EXTRACTION chains
  - =true   → the real "Application is Debuggable" HIGH finding + its chain survive
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import android_analyzer as aa  # noqa: E402
from analyzers.common import ns  # noqa: E402
from analyzers import attack_chains as ac  # noqa: E402
from analyzers.attack_chains import AttackChainEngine  # noqa: E402

ENGINE = AttackChainEngine()


def _app_elem(attrs: dict) -> dict:
    """A minimal stand-in for the parsed <application> element. `_check_app_flags`
    reads it via app_elem.get(ns(name)) / app_elem.get(name); a dict keyed on the
    namespaced attribute name satisfies both lookups."""
    return {ns(k): v for k, v in attrs.items()}


def _run_flags(attrs: dict) -> dict:
    results = {"findings": [], "manifest_security": {}}
    aa._check_app_flags(_app_elem(attrs), results)
    return results


# ── absent android:debuggable ────────────────────────────────────────────────

def test_absent_debuggable_produces_no_finding_and_false_state():
    results = _run_flags({})  # no android:debuggable at all

    dbg = results["manifest_security"]["debuggable"]
    assert dbg["state"] == "false", f"absent must resolve to false, got {dbg}"

    titles = [f.get("title", "") for f in results["findings"]]
    assert not any("Debuggable" in t or "debuggable" in t for t in titles), \
        f"absent debuggable must emit no debuggable finding, got {titles}"
    rule_ids = [f.get("rule_id") for f in results["findings"]]
    assert "manifest_debuggable_flag_missing" not in rule_ids
    assert "manifest_debuggable" not in rule_ids


def test_absent_debuggable_no_cap_and_no_chain():
    # The old "flag missing" finding: heavily mentions "debuggable" in its text.
    # It must NOT acquire the DEBUGGABLE cap, and no chain must fire.
    textual = {
        "title": "Potentially Debuggable (Flag Missing)",
        "category": "Binary Hardening",
        "description": "android:debuggable is not declared; debuggable debuggable.",
        "severity": "low",
    }
    results = {
        "platform": "android",
        "findings": [textual],
        "manifest_security": {"debuggable": {"state": "false", "value": "absent"}},
        "attack_surface": {},
    }
    caps = ac.tag_capabilities(textual, results)
    assert "DEBUGGABLE" not in caps, "textual-only mention must not get DEBUGGABLE cap"

    chains = ENGINE.build_chains(results)
    dbg_chains = [c for c in chains if c.get("goal") == "DEBUGGABLE-EXTRACTION"
                  or c.get("type") == "Debuggable Abuse"]
    assert not dbg_chains, f"absent debuggable must produce no chain, got {dbg_chains}"


# ── explicit android:debuggable="true" (real risk preserved) ─────────────────

def test_true_debuggable_still_high_finding():
    results = _run_flags({"debuggable": "true"})

    dbg = results["manifest_security"]["debuggable"]
    assert dbg["state"] == "true"

    real = [f for f in results["findings"] if f.get("rule_id") == "manifest_debuggable"]
    assert real, "explicit debuggable=true must emit the real finding"
    assert real[0]["severity"] == "high"
    assert real[0]["title"] == "Application is Debuggable"


def test_true_debuggable_gets_cap_and_chain():
    real = {
        "title": "Application is Debuggable",
        "rule_id": "manifest_debuggable",
        "category": "Binary Hardening",
        "severity": "high",
        "description": "android:debuggable=\"true\" is set.",
    }
    results = {
        "platform": "android",
        "findings": [real],
        "manifest_security": {"debuggable": {"state": "true", "value": "true"}},
        "attack_surface": {},
    }
    caps = ac.tag_capabilities(real, results)
    assert "DEBUGGABLE" in caps

    chains = ENGINE.build_chains(results)
    dbg_chains = [c for c in chains if c.get("type") == "Debuggable Abuse"]
    assert dbg_chains, "explicit debuggable=true must still produce its chain"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
