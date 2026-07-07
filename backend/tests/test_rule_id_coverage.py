"""
Rule-ID coverage regression (Beetle v1.3 stabilization).

Every detector finding MUST carry a stable ``rule_id``. Before v1.3 only the
regex SAST rules did; ownership, collaboration (triage state survives rescans),
suppression matching and dedupe all key on ``rule_id`` (else a title slug), so a
finding without one silently degrades those systems and cannot be suppressed by
rule.

This guard is intentionally STATIC (AST over the detector source), so it fails
the moment a new finding is added without a rule_id — without needing a fixture
APK/IPA. It walks the primary detector modules, finds every dict literal that is
a finding (title + severity) AND is appended into a findings list, and asserts
it declares ``rule_id`` (or the legacy ``id`` alias).

Excluded (by construction, not by whitelist):
  * attack-chain STEP dicts (carry a ``type`` key; the chain finding itself has
    a rule_id) and attack-path objects (carry ``chain_id`` / ``steps``);
  * derived report/summary/coverage projections that copy title/severity out of
    already-identified findings (they are not detectors);
  * factory base literals that receive rule_id via ``**kwargs``.

Run:  cd backend && python -m pytest tests/test_rule_id_coverage.py
"""
from __future__ import annotations

import ast
import os

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ANALYZERS = os.path.join(_BACKEND, "analyzers")

# Primary detector modules — the ones that append findings to results["findings"].
DETECTOR_MODULES = [
    "android_analyzer.py",
    "ios_analyzer.py",
    "cert_analyzer.py",
    "elf_analyzer.py",
    "lief_analyzer.py",
    "live_checks.py",
    "domain_analyzer.py",
    "cloud_config.py",
    "virustotal.py",
    "osv_scanner.py",
    "flutter_analyzer.py",
    "react_native_analyzer.py",
    "js_bundle_analyzer.py",
]


def _is_finding_dict(node: ast.Dict) -> set[str] | None:
    """Return the literal's string keys if it looks like a finding, else None."""
    keys = {k.value for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return keys if {"title", "severity"} <= keys else None


def _is_findings_list(recv: ast.AST) -> bool:
    """True when ``recv`` is a findings list: ``results["findings"]``, a bare
    ``findings`` name, or ``results.setdefault("findings", [])``. This excludes
    sibling summary lists (behavior_analysis, sdks, …) that are finding-shaped
    but never rendered as findings."""
    # results["findings"]
    if isinstance(recv, ast.Subscript):
        sl = recv.slice
        return isinstance(sl, ast.Constant) and sl.value == "findings"
    # findings.append(...)
    if isinstance(recv, ast.Name):
        return recv.id == "findings"
    # results.setdefault("findings", []).append(...)
    if (isinstance(recv, ast.Call)
            and isinstance(recv.func, ast.Attribute)
            and recv.func.attr == "setdefault"
            and recv.args
            and isinstance(recv.args[0], ast.Constant)
            and recv.args[0].value == "findings"):
        return True
    return False


def _appended_finding_dicts(tree: ast.AST) -> list[tuple[int, set[str]]]:
    """Dict literals appended directly to a findings list as an inline literal.

    Anchoring on ``<findings-list>.append({...})`` is what separates an actual
    emitted finding from a rule-table definition or a summary projection. Chain
    STEP dicts (appended to a steps list) are additionally filtered by the
    presence of a ``type`` / ``chain_id`` key.
    """
    out: list[tuple[int, set[str]]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Dict)
                and _is_findings_list(node.func.value)):
            continue
        keys = _is_finding_dict(node.args[0])
        if keys is None:
            continue
        if "type" in keys or "chain_id" in keys:
            continue
        out.append((node.args[0].lineno, keys))
    return out


def test_every_detector_finding_has_rule_id():
    missing: list[str] = []
    for mod in DETECTOR_MODULES:
        path = os.path.join(_ANALYZERS, mod)
        tree = ast.parse(open(path, encoding="utf-8").read())
        for lineno, keys in _appended_finding_dicts(tree):
            if "rule_id" not in keys and "id" not in keys:
                missing.append(f"{mod}:{lineno}  keys={sorted(keys)}")
    assert not missing, "Detector findings missing rule_id:\n" + "\n".join(missing)


def test_dedupe_keeps_distinct_instances_of_one_rule():
    """Two findings sharing a rule_id but describing different components/titles
    must NOT collapse. Regression for the v1.3 dedupe key: now every detector
    carries a rule_id, so keying dedupe on rule_id alone would fold every
    per-component exported finding (all rule_id ``manifest_exported_service``)
    into one. The title/file participate in the key to prevent that."""
    from analyzers.common import dedupe_findings

    findings = [
        {"rule_id": "manifest_exported_service", "title": "Exported Service Without Permission — AlphaService",
         "file_path": "com/app/AlphaService", "severity": "high"},
        {"rule_id": "manifest_exported_service", "title": "Exported Service Without Permission — BetaService",
         "file_path": "com/app/BetaService", "severity": "high"},
    ]
    assert len(dedupe_findings(list(findings))) == 2

    # True duplicates (same rule_id, title AND path) DO collapse, with a counter.
    dup = [dict(findings[0]), dict(findings[0])]
    out = dedupe_findings(dup)
    assert len(out) == 1
    assert out[0].get("duplicates") == 2


if __name__ == "__main__":
    test_every_detector_finding_has_rule_id()
    test_dedupe_keeps_distinct_instances_of_one_rule()
    print("rule-id coverage OK")
