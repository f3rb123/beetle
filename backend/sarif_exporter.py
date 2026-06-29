"""
Beetle → SARIF 2.1 Exporter
=============================
Converts a Beetle scan results dict into a SARIF 2.1.0 document.

SARIF is the standard interchange format for static analysis results.
It can be:
  - Uploaded to GitHub Code Scanning (via upload-sarif action)
  - Opened in VS Code with the SARIF Viewer extension
  - Imported into any CI/CD tool that supports SARIF

Spec reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

SARIF_VERSION  = "2.1.0"
SARIF_SCHEMA   = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME      = "Beetle Mobile Security Scanner"
TOOL_VERSION   = "1.2.0"
TOOL_URI       = "https://github.com/f3rb123/beetle"

_LEVEL_MAP = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

_PRECISION_MAP = {
    "critical": "high",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "low",
}


def _rule_id(finding: dict) -> str:
    """Stable rule ID from existing rule_id or derived from title."""
    if finding.get("rule_id"):
        return str(finding["rule_id"])
    title = finding.get("title", "CORTEX-UNKNOWN")
    # Slugify: uppercase letters, digits, hyphens only
    slug = re.sub(r"[^A-Za-z0-9]+", "-", title).strip("-").upper()[:60]
    return f"CORTEX-{slug}"


def _make_rule(finding: dict) -> dict:
    """Build a SARIF rule descriptor from a finding."""
    rule_id  = _rule_id(finding)
    sev      = (finding.get("severity") or "info").lower()
    title    = finding.get("title", rule_id)
    desc     = finding.get("description", title)
    rec      = finding.get("recommendation", "")
    owasp    = finding.get("owasp", "")
    masvs    = finding.get("masvs", "")
    cwe      = finding.get("cwe", "")
    help_url = finding.get("help_url", "")

    # Build full help text
    help_parts = [desc]
    if rec:
        help_parts.append(f"\n\n**Recommendation:** {rec}")
    if owasp:
        help_parts.append(f"\n\n**OWASP Mobile:** {owasp}")
    if masvs:
        help_parts.append(f"\n\n**MASVS:** {masvs}")
    if cwe:
        help_parts.append(f"\n\n**CWE:** {cwe}")

    rule: dict = {
        "id": rule_id,
        "name": re.sub(r"[^A-Za-z0-9]", "", title.title().replace(" ", "")),
        "shortDescription": {"text": title[:1024]},
        "fullDescription":  {"text": desc[:4096]},
        "helpUri": help_url or TOOL_URI,
        "help": {
            "text":     "".join(help_parts)[:4096],
            "markdown": "".join(help_parts)[:4096],
        },
        "defaultConfiguration": {
            "level": _LEVEL_MAP.get(sev, "warning"),
        },
        "properties": {
            "precision": _PRECISION_MAP.get(sev, "medium"),
            "severity":  sev,
            "tags": [t for t in [
                f"owasp:{owasp}" if owasp else None,
                f"masvs:{masvs}" if masvs else None,
                f"cwe:{cwe}"     if cwe   else None,
                finding.get("category", ""),
            ] if t],
        },
    }

    # Optional: CWE relationships
    if cwe:
        cwe_id = re.search(r"\d+", cwe)
        if cwe_id:
            rule["relationships"] = [{
                "target": {
                    "id": cwe_id.group(0),
                    "toolComponent": {"name": "CWE", "guid": ""},
                },
                "kinds": ["superset"],
            }]

    return rule


def _primary_location(finding: dict):
    """The application-relevant primary (file, line, snippet) via the unified
    Evidence Selection view, falling back to legacy fields."""
    try:
        from analyzers.evidence_selection import primary_location
        return primary_location(finding)
    except Exception:  # noqa: BLE001
        return (finding.get("file_path") or finding.get("full_path") or "",
                finding.get("line") or 0,
                finding.get("snippet") or finding.get("code_context") or "")


def _make_location(finding: dict) -> dict | None:
    """Build a SARIF physicalLocation from the SELECTED primary evidence."""
    file_path, line, snippet = _primary_location(finding)

    if not file_path:
        return None

    # Normalise path separators
    uri = file_path.replace("\\", "/")
    if not uri.startswith("/") and ":" not in uri:
        uri = f"/{uri}"

    location: dict = {
        "artifactLocation": {
            "uri":       uri,
            "uriBaseId": "%SRCROOT%",
        },
    }

    if line:
        region: dict = {"startLine": int(line)}
        if snippet:
            region["snippet"] = {"text": snippet[:512]}
        location["region"] = region

    return {"physicalLocation": location}


def _make_result(finding: dict, rule_index_map: dict) -> dict:
    """Build a SARIF result entry."""
    rule_id  = _rule_id(finding)
    sev      = (finding.get("severity") or "info").lower()
    message  = finding.get("description") or finding.get("title") or rule_id

    result: dict = {
        "ruleId":    rule_id,
        "ruleIndex": rule_index_map.get(rule_id, 0),
        "level":     _LEVEL_MAP.get(sev, "warning"),
        "message":   {"text": message[:2048]},
        "properties": {
            "severity":   sev,
            "category":   finding.get("category", ""),
            "confidence": finding.get("confidence", 70),
        },
    }

    # Primary location
    loc = _make_location(finding)
    if loc:
        result["locations"] = [loc]

    # Related locations = the SELECTED supporting evidence (Evidence Selection view),
    # falling back to legacy file_evidence when selection did not run.
    related = []
    supporting = []
    try:
        from analyzers.evidence_selection import build_evidence_view
        supporting = [{"path": s.get("file"), "lines": [s.get("line")] if s.get("line") else [],
                       "snippet": s.get("snippet", "")}
                      for s in (build_evidence_view(finding).get("supporting") or [])]
    except Exception:  # noqa: BLE001
        supporting = (finding.get("file_evidence") or [])[1:4]
    for ev in supporting[:3]:
        ev_path = ev.get("path", "")
        ev_lines = ev.get("lines", [])
        ev_snip  = ev.get("snippet", "")
        if ev_path and ev_lines:
            uri = ev_path.replace("\\", "/")
            if not uri.startswith("/") and ":" not in uri:
                uri = f"/{uri}"
            r_loc = {
                "message": {"text": f"Also found at {ev_path}:{ev_lines[0]}"},
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": int(ev_lines[0]),
                        "snippet":   {"text": ev_snip[:256]},
                    },
                },
            }
            related.append(r_loc)
    if related:
        result["relatedLocations"] = related

    # PoC / fix text as fix suggestion
    rec = finding.get("recommendation", "")
    if rec:
        result["fixes"] = [{
            "description": {"text": rec[:1024]},
        }]

    return result


def results_to_sarif(scan_results: dict) -> dict:
    """
    Convert a Beetle results dict to SARIF 2.1 document.
    Returns the SARIF dict (JSON-serialisable).
    """
    findings = scan_results.get("findings", [])
    secrets  = scan_results.get("secrets",  [])
    app_info = scan_results.get("app_info", {})
    platform = scan_results.get("platform", "android")
    scan_id  = scan_results.get("scan_id",  "unknown")
    scan_time = scan_results.get("scan_time", datetime.now(timezone.utc).isoformat())
    score    = scan_results.get("score", {})
    filename = scan_results.get("filename", "")

    # Convert secrets → findings-like objects for SARIF inclusion
    secret_findings = []
    for s in secrets:
        secret_findings.append({
            "title":          s.get("name", "Hardcoded Secret"),
            "severity":       s.get("severity", "high"),
            "category":       f"Secret — {s.get('category', 'Credentials')}",
            "description":    s.get("description", f"Hardcoded secret: {s.get('name', 'unknown')}"),
            "recommendation": s.get("recommendation", "Rotate this credential immediately."),
            "file_path":      s.get("file_path") or s.get("full_path", ""),
            "line":           s.get("line", 0),
            "snippet":        s.get("snippet", ""),
            "rule_id":        f"CORTEX-SECRET-{re.sub(r'[^A-Z0-9]+', '-', (s.get('name') or 'UNKNOWN').upper())}",
            "confidence":     s.get("confidence", 85),
            "owasp":          "M1",
            "masvs":          "MASVS-CRYPTO-2",
        })

    all_findings = findings + secret_findings

    # Build deduped rule list
    rules_seen: dict[str, dict] = {}
    for f in all_findings:
        rid = _rule_id(f)
        if rid not in rules_seen:
            rules_seen[rid] = _make_rule(f)

    rules_list = list(rules_seen.values())
    rule_index_map = {r["id"]: i for i, r in enumerate(rules_list)}

    # Build results list
    sarif_results = [_make_result(f, rule_index_map) for f in all_findings]

    # Build artifacts list (unique file paths)
    artifact_uris: set[str] = set()
    for f in all_findings:
        fp = f.get("file_path") or ""
        if fp:
            artifact_uris.add(fp.replace("\\", "/"))
    artifacts = [
        {"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
        for uri in sorted(artifact_uris)
    ]

    # Build the SARIF document
    sarif: dict = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name":            TOOL_NAME,
                    "version":         TOOL_VERSION,
                    "informationUri":  TOOL_URI,
                    "rules":           rules_list,
                    "properties": {
                        "platform": platform,
                    },
                },
            },
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc":        scan_time,
                "properties": {
                    "scan_id":   scan_id,
                    "filename":  filename,
                    "score":     score.get("score"),
                    "grade":     score.get("grade"),
                },
            }],
            "artifacts":  artifacts,
            "results":    sarif_results,
            "properties": {
                "cortex_scan_id":   scan_id,
                "cortex_score":     score.get("score"),
                "cortex_grade":     score.get("grade"),
                "cortex_platform":  platform,
                "app_package":      app_info.get("package", ""),
                "app_version":      app_info.get("version_name", ""),
            },
        }],
    }

    return sarif


def results_to_sarif_json(scan_results: dict, indent: int = 2) -> str:
    """Return SARIF document as a formatted JSON string."""
    return json.dumps(results_to_sarif(scan_results), indent=indent, ensure_ascii=False)
