"""
CycloneDX 1.5 JSON SBOM generator for Beetle scan results.

Assembles a Software Bill of Materials from the data already collected
during a scan:
  - Direct dependencies  (results["dependencies"]["deps"])
  - Detected SDK signatures (results["sdks"])
  - Third-party trackers    (results["trackers"])
  - Native .so libraries    (results["binaries"])
  - iOS embedded frameworks (results["embedded_frameworks"])

Vulnerabilities are populated from OSV/CVE findings already in
results["dependencies"]["vulns"] and from SAST findings that carry
a CWE tag.

Output is a valid CycloneDX 1.5 JSON document.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ─── PURL helpers ────────────────────────────────────────────────────────────

def _purl_maven(group: str, artifact: str, version: str = "") -> str:
    g = group.replace(".", "/") if "." in group else group
    base = f"pkg:maven/{group}/{artifact}"
    if version:
        base += f"@{version}"
    return base


def _purl_npm(name: str, version: str = "") -> str:
    base = f"pkg:npm/{name}"
    if version:
        base += f"@{version}"
    return base


def _purl_pypi(name: str, version: str = "") -> str:
    base = f"pkg:pypi/{name.lower().replace('-', '_')}"
    if version:
        base += f"@{version}"
    return base


def _purl_generic(name: str, version: str = "") -> str:
    safe = re.sub(r"[^a-zA-Z0-9._\-]", "-", name)
    base = f"pkg:generic/{safe}"
    if version:
        base += f"@{version}"
    return base


def _make_purl(component: dict) -> str:
    eco = (component.get("ecosystem") or "").lower()
    name = component.get("name", "")
    group = component.get("group", "")
    artifact = component.get("artifact", "")
    version = component.get("version", "")

    if eco in ("maven", "gradle"):
        if group and artifact:
            return _purl_maven(group, artifact, version)
        if ":" in name:
            g, a = name.split(":", 1)
            return _purl_maven(g, a, version)
    if eco == "npm":
        return _purl_npm(name, version)
    if eco in ("pypi", "pip"):
        return _purl_pypi(name, version)
    if eco == "pub":
        return _purl_generic(name, version)
    return _purl_generic(name or group or artifact, version)


# ─── Component builders ───────────────────────────────────────────────────────

def _dep_to_component(dep: dict) -> dict:
    """Build a CycloneDX component from an OSV dependency record."""
    name    = dep.get("name") or f"{dep.get('group', '')}:{dep.get('artifact', '')}"
    version = dep.get("version", "")
    purl    = _make_purl(dep)
    eco     = (dep.get("ecosystem") or "").lower()

    comp: dict[str, Any] = {
        "type":        "library",
        "bom-ref":     purl or f"dep:{name}@{version}",
        "name":        name,
        "purl":        purl,
    }
    if version:
        comp["version"] = version

    # Source file evidence
    src = dep.get("source", "")
    if src:
        comp["evidence"] = {"occurrences": [{"location": src}]}

    return comp


def _sdk_to_component(sdk: dict) -> dict:
    """Build a component from a detected SDK signature."""
    name     = sdk.get("name") or sdk.get("signature", "unknown")
    category = sdk.get("category", "")
    version  = sdk.get("version", "")

    comp: dict[str, Any] = {
        "type":    "library",
        "bom-ref": _purl_generic(name, version),
        "name":    name,
        "purl":    _purl_generic(name, version),
    }
    if version:
        comp["version"] = version
    if category:
        comp["description"] = f"SDK category: {category}"
    return comp


def _tracker_to_component(tracker: dict) -> dict:
    """Build a component from a detected tracker."""
    name     = tracker.get("name", "unknown")
    pkg      = tracker.get("pkg", "")
    url      = tracker.get("url", "")
    category = tracker.get("category", "")

    purl = _purl_generic(name)
    if pkg:
        purl = f"pkg:generic/{pkg}"

    comp: dict[str, Any] = {
        "type":        "library",
        "bom-ref":     purl,
        "name":        name,
        "purl":        purl,
        "description": f"Tracker — {category}" if category else "Third-party tracker",
    }
    if url:
        comp["externalReferences"] = [{"type": "website", "url": url}]
    return comp


def _binary_to_component(binary: dict) -> dict:
    """Build a component from a native .so library."""
    name = binary.get("name") or Path(binary.get("path", "unknown.so")).name
    comp: dict[str, Any] = {
        "type":    "library",
        "bom-ref": f"native:{name}",
        "name":    name,
        "purl":    _purl_generic(name),
    }
    sha256 = binary.get("sha256") or binary.get("hash")
    if sha256:
        comp["hashes"] = [{"alg": "SHA-256", "content": sha256}]

    flags = []
    if binary.get("pie") is False:
        flags.append("No PIE")
    if binary.get("nx") is False:
        flags.append("No NX/DEP")
    if binary.get("stack_canary") is False:
        flags.append("No stack canary")
    if flags:
        comp["description"] = "Hardening missing: " + ", ".join(flags)
    return comp


def _ios_framework_to_component(fw: dict) -> dict:
    """Build a component from an iOS embedded framework."""
    name    = fw.get("name", "unknown")
    version = fw.get("version", "")
    url     = fw.get("url", "")

    comp: dict[str, Any] = {
        "type":    "framework",
        "bom-ref": _purl_generic(name, version),
        "name":    name,
        "purl":    _purl_generic(name, version),
    }
    if version:
        comp["version"] = version
    if url:
        comp["externalReferences"] = [{"type": "website", "url": url}]
    return comp


# ─── Vulnerability builder ────────────────────────────────────────────────────

_SEVERITY_SCORE = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     0.0,
}


def _osv_vuln_to_cdx(vuln: dict, dep_purl: str) -> dict | None:
    """Convert an OSV vulnerability record to a CycloneDX vulnerability."""
    vid = (vuln.get("id") or "").strip()
    if not vid:
        return None

    aliases = [a for a in (vuln.get("aliases") or []) if a != vid]
    summary = (vuln.get("summary") or vuln.get("details") or "")[:300]
    severity = (vuln.get("severity") or "medium").lower()

    v: dict[str, Any] = {
        "bom-ref": f"vuln:{vid}",
        "id":      vid,
        "source":  {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
        "ratings": [{
            "source":   {"name": "OSV"},
            "score":    _SEVERITY_SCORE.get(severity, 5.0),
            "severity": severity,
            "method":   "other",
        }],
        "affects": [{"ref": dep_purl}],
    }
    if summary:
        v["description"] = summary
    if aliases:
        v["advisories"] = [{"url": f"https://osv.dev/vulnerability/{a}"} for a in aliases[:3]]
    return v


def _finding_to_cdx_vuln(finding: dict, app_bom_ref: str) -> dict | None:
    """Convert a SAST/analysis finding with a CWE to a CycloneDX vulnerability."""
    cwe = (finding.get("cwe") or "").strip()
    if not cwe:
        return None

    title    = finding.get("title", "")
    severity = (finding.get("severity") or "medium").lower()
    rule_id  = finding.get("rule_id") or finding.get("source") or "CORTEX"
    vid      = f"CORTEX-{cwe}-{abs(hash(title)) % 100000:05d}"

    return {
        "bom-ref":    f"vuln:{vid}",
        "id":         vid,
        "source":     {"name": "Beetle Static Analysis"},
        "ratings":    [{
            "source":   {"name": "Beetle"},
            "score":    _SEVERITY_SCORE.get(severity, 5.0),
            "severity": severity,
            "method":   "other",
        }],
        "cwes":       [int(cwe.replace("CWE-", ""))] if re.match(r"CWE-\d+", cwe) else [],
        "description": title,
        "affects":    [{"ref": app_bom_ref}],
    }


# ─── Main entry point ─────────────────────────────────────────────────────────

def generate_sbom(results: dict) -> dict:
    """
    Generate a CycloneDX 1.5 JSON SBOM dict from a Beetle scan results dict.
    Returns a Python dict — caller serialises to JSON.
    """
    app_info  = results.get("app_info") or {}
    platform  = results.get("platform", "android")
    app_name  = results.get("app_name") or results.get("filename") or "unknown"
    pkg_name  = app_info.get("package") or app_info.get("bundle_id") or app_name
    version   = (app_info.get("version") or app_info.get("version_name") or
                 app_info.get("app_version") or "unknown")
    sha256    = app_info.get("sha256") or ""
    scan_time = results.get("scan_time") or datetime.now(timezone.utc).isoformat()

    # Root component (the app being analysed)
    app_type = "application"
    app_purl = (
        f"pkg:{'apk' if platform == 'android' else 'ipa'}/{pkg_name}@{version}"
        if pkg_name != "unknown" else f"pkg:generic/{app_name}"
    )
    app_component: dict[str, Any] = {
        "type":    app_type,
        "bom-ref": app_purl,
        "name":    app_name,
        "version": version,
        "purl":    app_purl,
    }
    if sha256:
        app_component["hashes"] = [{"alg": "SHA-256", "content": sha256}]

    # ── Collect components ────────────────────────────────────────────────────
    components: list[dict] = []
    seen_refs: set[str] = set()

    def _add(comp: dict | None):
        if not comp:
            return
        ref = comp.get("bom-ref", "")
        if ref and ref in seen_refs:
            return
        seen_refs.add(ref)
        components.append(comp)

    # 1. OSV-scanned direct dependencies
    deps_obj  = results.get("dependencies") or {}
    deps_list = deps_obj.get("deps") or deps_obj.get("dependencies") or []
    for dep in deps_list:
        _add(_dep_to_component(dep))

    # 2. Detected SDK signatures
    for sdk in (results.get("sdks") or []):
        _add(_sdk_to_component(sdk))

    # 3. Third-party trackers
    for tracker in (results.get("trackers") or []):
        _add(_tracker_to_component(tracker))

    # 4. Native binaries (.so)
    for binary in (results.get("binaries") or []):
        _add(_binary_to_component(binary))

    # 5. iOS embedded frameworks
    for fw in (results.get("embedded_frameworks") or []):
        _add(_ios_framework_to_component(fw))

    # ── Collect vulnerabilities ───────────────────────────────────────────────
    vulnerabilities: list[dict] = []
    seen_vulns: set[str] = set()

    def _add_vuln(v: dict | None):
        if not v:
            return
        vid = v.get("id", "")
        if vid in seen_vulns:
            return
        seen_vulns.add(vid)
        vulnerabilities.append(v)

    # From OSV dep vulns
    for dep in deps_list:
        dep_purl = _make_purl(dep)
        for vuln in (dep.get("vulns") or dep.get("vulnerabilities") or []):
            _add_vuln(_osv_vuln_to_cdx(vuln, dep_purl))

    # From SAST findings (CWE-tagged)
    for finding in (results.get("findings") or []):
        if finding.get("cwe"):
            _add_vuln(_finding_to_cdx_vuln(finding, app_purl))

    # ── Assemble document ─────────────────────────────────────────────────────
    score_obj = results.get("score") or {}
    score_val = score_obj.get("score")
    grade     = score_obj.get("grade", "")

    properties = [
        {"name": "cortex:platform",   "value": platform},
        {"name": "cortex:scan_id",    "value": results.get("scan_id", "")},
        {"name": "cortex:filename",   "value": results.get("filename", "")},
    ]
    if score_val is not None:
        properties.append({"name": "cortex:security_score", "value": str(score_val)})
    if grade:
        properties.append({"name": "cortex:security_grade", "value": grade})

    ss = results.get("severity_summary") or {}
    for sev in ("critical", "high", "medium", "low", "info"):
        count = ss.get(sev, 0)
        if count:
            properties.append({"name": f"cortex:findings_{sev}", "value": str(count)})

    sbom = {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":      1,
        "metadata": {
            "timestamp": scan_time,
            "tools": [{
                "vendor":  "Beetle",
                "name":    "Beetle Mobile Security Scanner",
                "version": "1.2.0",
                "externalReferences": [
                    {"type": "website", "url": "https://github.com/f3rb123/beetle"}
                ],
            }],
            "component":  app_component,
            "properties": properties,
        },
        "components":      components,
        "vulnerabilities": vulnerabilities,
    }

    return sbom


def generate_sbom_json(results: dict) -> str:
    """Return CycloneDX SBOM as a formatted JSON string."""
    return json.dumps(generate_sbom(results), indent=2, ensure_ascii=False)
