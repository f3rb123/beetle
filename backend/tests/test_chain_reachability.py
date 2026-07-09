"""
Attack-chain reachability tests (Beetle 2.0).

Covers three coupled correctness fixes in the v2 chain engine + reachability engine:

  FLAW A — a library/framework component (androidx ProfileInstallReceiver,
           com.google.*) must never be chosen as a chain entry node. Only an
           APPLICATION-owned exported component anchors an external chain.

  FLAW B — an injection/RCE template (SQLi, command, file, code-loading, JS bridge)
           may only be CRITICAL/high-confidence when an actual taint flow links
           external input to the matching sink in application code. Without that
           proof the chain is 'heuristic': sub-critical, confidence < 60.

  FLAW C — reachability is derived from taint/entry/manifest evidence alone, never
           from attack-chain membership. Chains consume reachability; a finding is
           not "reachable because it is in a chain" (that was circular, since chains
           are built from co-occurrence).

Every emitted chain carries reachability_proof ∈ {proven, heuristic, manifest-only}.

Runnable standalone or under pytest:
    python -m tests.test_chain_reachability      # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.attack_chains.engine import AttackChainEngine  # noqa: E402
from analyzers import reachability_engine  # noqa: E402

ENGINE = AttackChainEngine()


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _finding(title, category, cid, **extra):
    """A minimally-enriched finding shaped like the ones chains consume."""
    f = {
        "title": title, "category": category, "severity": extra.pop("severity", "high"),
        "canonical_id": cid, "rule_id": cid,
        "owner_type": extra.pop("owner_type", "Application"),
        "overall_confidence": extra.pop("conf", 80),
        "exploitability_confidence": extra.pop("exploit", 60),
        "evidence_bundle": {"quality": extra.pop("quality", "Good"), "evidence_id": "EV-" + cid,
                            "primary": {"relative_path": extra.pop("file", f"sources/{cid}.java"),
                                        "line": 10, "locator": {}}},
        "triage": {"decision": "Show", "visibility": "Show"},
    }
    f.update(extra)
    return f


def _results(findings, surface, *, package="com.company.app", taint_flows=None):
    return {
        "platform": "android",
        "app_info": {"package": package},
        "findings": findings,
        "attack_surface": surface,
        "taint_flows": taint_flows or [],
    }


def _sqli_chains(chains):
    return [c for c in chains if c["type"] == "SQL Injection"]


# The androidx receiver that used to anchor a fake Intent->SQLi chain on Flutter apps.
_ANDROIDX_RECEIVER = {
    "receivers": [{"name": "androidx.profileinstaller.ProfileInstallReceiver",
                   "exported": True, "browsable": False}],
    "activities": [], "services": [], "providers": [],
}

# The same, but with a genuine Application-owned exported activity present too.
_APP_ACTIVITY = {
    "activities": [{"name": "com.company.app.ui.SearchActivity", "exported": True, "browsable": True,
                    "schemes": ["myapp"]}],
    "receivers": [{"name": "androidx.profileinstaller.ProfileInstallReceiver", "exported": True}],
    "services": [], "providers": [],
}

# A raw-SQL sink finding with NO taint flow reaching it.
_RAW_SQL = _finding("Raw SQL query built with string concatenation", "Code", "rawsql",
                    description="db.rawQuery(\"SELECT * FROM t WHERE x=\" + v) — SQL injection risk",
                    file="sources/com/company/app/Db.java")


# ════════════════════════════════════════════════════════════════════════════
# FLAW A + B — androidx receiver + raw SQL, no taint flow.
# ════════════════════════════════════════════════════════════════════════════
def test_androidx_receiver_and_raw_sql_produce_no_critical_sqli_chain():
    """The acceptance fixture: exported androidx receiver + a raw-SQL finding but no
    intent->sql taint flow. No CRITICAL SQLi chain, and the androidx receiver is
    never the entry node."""
    chains = ENGINE.build_chains(_results([_RAW_SQL], _ANDROIDX_RECEIVER))

    sqli = _sqli_chains(chains)
    for c in sqli:
        _check(c["severity"] != "critical",
               f"SQLi chain without taint must not be critical: {c['severity']}")
        _check(c["reachability_proof"] == "heuristic",
               f"co-occurrence SQLi must be heuristic, got {c['reachability_proof']}")
        _check(c["overall_confidence"] < 60,
               f"heuristic confidence must be < 60, got {c['overall_confidence']}")

    # FLAW A: no chain, of any kind, may anchor on the androidx receiver.
    for c in chains:
        comp = c["entry_point"].get("component", "")
        _check("androidx" not in comp.lower(),
               f"library component chosen as entry node: {comp!r}")


def test_androidx_only_surface_yields_no_external_chain_entry():
    """With ONLY a library exported component, an external template has no valid
    entry — it must not fall back to the library component."""
    chains = ENGINE.build_chains(_results([_RAW_SQL], _ANDROIDX_RECEIVER))
    external = [c for c in chains if c["entry_point"].get("kind") == "external"]
    for c in external:
        comp = c["entry_point"].get("component", "")
        _check(comp and "androidx" not in comp.lower(),
               f"external chain fell back to a library entry: {comp!r}")


# ════════════════════════════════════════════════════════════════════════════
# FLAW B — WITH a real intent->sqlite taint flow in an Application-owned class.
# ════════════════════════════════════════════════════════════════════════════
def test_intent_to_sqlite_taint_in_app_class_produces_proven_chain():
    """A taint flow from external input to a SQL sink, in application code reachable
    from an app-owned entry, yields a PROVEN chain at full severity."""
    taint = [{"source_cat": "User Input", "sink_cat": "SQLite",
              "class_name": "com.company.app.SearchDao", "method_name": "find"}]
    sqli_finding = _finding("Taint Flow: Intent.getStringExtra → rawQuery", "Taint Analysis", "taint-sqli",
                            taint_flow={"source_cat": "User Input", "sink_cat": "SQLite",
                                        "chain": ["SearchActivity.onCreate", "SearchDao.find"]},
                            file="sources/com/company/app/SearchDao.java", reachability="YES")

    chains = ENGINE.build_chains(_results([sqli_finding], _APP_ACTIVITY, taint_flows=taint))
    sqli = _sqli_chains(chains)
    _check(sqli, f"expected a SQLi chain, got {[c['type'] for c in chains]}")
    c = sqli[0]

    _check(c["reachability_proof"] == "proven",
           f"taint-backed SQLi must be proven, got {c['reachability_proof']}")
    _check(c["severity"] == "high",
           f"proven SQLi keeps its full (sql_injection=high) severity, got {c['severity']}")
    _check(c["overall_confidence"] >= 60,
           f"proven chain confidence must not be capped, got {c['overall_confidence']}")
    _check("androidx" not in c["entry_point"].get("component", "").lower(),
           "proven chain must still use the application-owned entry")
    _check(c["entry_point"]["component"] == "com.company.app.ui.SearchActivity",
           f"entry should be the app activity, got {c['entry_point'].get('component')!r}")


def test_taint_flow_in_library_class_is_not_proven():
    """Same taint categories but the sink class is a bundled SDK, not app code — the
    dataflow does not live in the application, so the chain stays heuristic."""
    taint = [{"source_cat": "User Input", "sink_cat": "SQLite",
              "class_name": "androidx.room.RoomDatabase", "method_name": "query"}]
    chains = ENGINE.build_chains(_results([_RAW_SQL], _APP_ACTIVITY, taint_flows=taint))
    for c in _sqli_chains(chains):
        _check(c["reachability_proof"] == "heuristic",
               f"taint in library code must not prove the chain, got {c['reachability_proof']}")
        _check(c["severity"] != "critical", "library-class taint must not yield a critical chain")


def test_wrong_sink_category_does_not_prove_sqli():
    """A taint flow into a different sink (FileSystem) must not prove a SQLi chain."""
    taint = [{"source_cat": "User Input", "sink_cat": "FileSystem",
              "class_name": "com.company.app.SearchDao"}]
    chains = ENGINE.build_chains(_results([_RAW_SQL], _APP_ACTIVITY, taint_flows=taint))
    for c in _sqli_chains(chains):
        _check(c["reachability_proof"] == "heuristic",
               f"mismatched sink must not prove SQLi, got {c['reachability_proof']}")


def test_internal_source_does_not_prove_injection():
    """A taint flow into the right sink but from a non-external source (SharedPrefs)
    is not attacker-reachable and must not prove the chain."""
    taint = [{"source_cat": "SharedPrefs", "sink_cat": "SQLite",
              "class_name": "com.company.app.SearchDao"}]
    chains = ENGINE.build_chains(_results([_RAW_SQL], _APP_ACTIVITY, taint_flows=taint))
    for c in _sqli_chains(chains):
        _check(c["reachability_proof"] == "heuristic",
               f"internal-source taint must not prove SQLi, got {c['reachability_proof']}")


# ════════════════════════════════════════════════════════════════════════════
# reachability_proof field is present and honest on every chain.
# ════════════════════════════════════════════════════════════════════════════
def test_every_chain_has_a_reachability_proof():
    taint = [{"source_cat": "User Input", "sink_cat": "SQLite", "class_name": "com.company.app.SearchDao"}]
    findings = [
        _finding("Taint Flow: Intent → rawQuery", "Taint Analysis", "t1",
                 taint_flow={"source_cat": "User Input", "sink_cat": "SQLite", "chain": ["a.b"]}),
        _finding("Cleartext Traffic Permitted", "Network Security", "ct"),
        _finding("Hardcoded AWS Key", "Secrets", "aws",
                 secret_intelligence={"status": "Probable Secret", "secret_type": "AWS Access Key"}),
    ]
    chains = ENGINE.build_chains(_results(findings, _APP_ACTIVITY, taint_flows=taint))
    _check(chains, "expected some chains")
    valid = {"proven", "heuristic", "manifest-only"}
    for c in chains:
        _check(c["reachability_proof"] in valid,
               f"{c['type']} has bad proof {c['reachability_proof']!r}")

    # A non-injection chain (secret abuse) makes no dataflow claim → manifest-only.
    secret = [c for c in chains if c["type"] == "Hardcoded Secrets"]
    if secret:
        _check(secret[0]["reachability_proof"] == "manifest-only",
               f"secret-abuse chain should be manifest-only, got {secret[0]['reachability_proof']}")


# ════════════════════════════════════════════════════════════════════════════
# FLAW C — reachability no longer depends on chain membership.
# ════════════════════════════════════════════════════════════════════════════
def test_chain_membership_does_not_make_a_finding_reachable():
    """A library-owned finding with no taint/entry/manifest evidence must resolve to
    NO even when flagged as a chain member. Previously is_attack_chain forced YES."""
    results = {
        "platform": "android",
        "attack_surface": {"activities": [], "services": [], "receivers": [], "providers": []},
        "findings": [{
            "title": "Weak hash in bundled SDK", "category": "Cryptography",
            "description": "md5 used inside a vendored library",
            "ownership_label": "THIRD_PARTY_SDK",
            # These flags used to short-circuit reachability to YES (Flaw C).
            "is_attack_chain": True, "in_attack_chain": True,
            "exploitability": 10,
        }],
    }
    reachability_engine.analyze_reachability(results)
    f = results["findings"][0]
    _check(f["reachability"] == "NO",
           f"chain membership must not make library code reachable, got {f['reachability']!r}")


def test_reachability_still_derived_from_taint_evidence_independently():
    """The independent taint branch still yields YES for an externally-sourced flow
    with an external entry — reachability stands on its own evidence."""
    results = {
        "platform": "android",
        "attack_surface": {"activities": [{"name": "com.company.app.Search", "exported": True,
                                            "browsable": True, "schemes": ["myapp"]}],
                           "services": [], "receivers": [], "providers": []},
        "findings": [{
            "title": "Taint Flow: Intent → rawQuery", "category": "Taint Analysis",
            "taint_flow": {"source_cat": "User Input", "sink_cat": "SQLite", "chain": ["a.b"]},
            "call_chain": ["SearchActivity.onCreate", "SearchDao.find"],
            "ownership_label": "APPLICATION", "exploitability": 60,
            # deliberately NOT a chain member — reachability must not need that.
        }],
    }
    reachability_engine.analyze_reachability(results)
    _check(results["findings"][0]["reachability"] == "YES",
           "an external-source taint flow with an external entry is reachable on its own evidence")


def test_reachability_is_deterministic():
    results_a = _results([_RAW_SQL], _ANDROIDX_RECEIVER)
    results_b = _results([_RAW_SQL], _ANDROIDX_RECEIVER)
    _check(ENGINE.build_chains(results_a) == ENGINE.build_chains(results_b),
           "chain building must be deterministic")


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
