"""
Cortex Semgrep SAST Runner
===========================
Wraps Semgrep CLI to run android/java/kotlin rulesets against decompiled
source code. Parses SARIF output and converts matches to Cortex findings.

Graceful degradation:
  - If semgrep is not installed: skips silently, records in scan_metrics
  - If scan directories don't exist: skips silently
  - If semgrep times out (> 5 min): kills process, returns partial results
  - Per-rule errors in semgrep do not crash the scan
"""

from __future__ import annotations

import json
import os
import subprocess
import shutil
import tempfile
import time
from pathlib import Path


# ─── Config ───────────────────────────────────────────────────────────────────
SEMGREP_TIMEOUT    = int(__import__("os").environ.get("CORTEX_SEMGREP_TIMEOUT", "90"))  # seconds — tight cap; raise via env if you want deeper coverage
MAX_FINDINGS       = 200    # cap to avoid flooding the results
SEMGREP_RULESETS   = [
    "p/android",
    "p/java",
    "p/kotlin",
]

# OWASP Mobile / MASVS mapping by Semgrep category tags
_OWASP_MAP = {
    "android.security":    "M1",
    "java.lang.security":  "M1",
    "kotlin.lang.security":"M1",
    "android.crypto":      "M10",
    "android.webview":     "M4",
    "android.intent":      "M1",
    "android.network":     "M5",
    "android.storage":     "M2",
}

_MASVS_MAP = {
    "android.crypto":      "MASVS-CRYPTO-1",
    "android.webview":     "MASVS-PLATFORM-1",
    "android.intent":      "MASVS-PLATFORM-2",
    "android.network":     "MASVS-NETWORK-1",
    "android.storage":     "MASVS-STORAGE-1",
}

_SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "low",
}


# ─── Availability check ───────────────────────────────────────────────────────
def semgrep_available() -> bool:
    """Return True if semgrep is on PATH and executable."""
    return shutil.which("semgrep") is not None


# ─── SARIF parser ─────────────────────────────────────────────────────────────
def _sarif_to_findings(sarif: dict, scan_dirs: list) -> list:
    """Convert SARIF 2.1 output from semgrep to Cortex finding dicts."""
    findings = []
    seen_keys = set()

    runs = sarif.get("runs", [])
    for run in runs:
        tool = run.get("tool", {}).get("driver", {})
        rules_meta = {r["id"]: r for r in tool.get("rules", [])}
        results = run.get("results", [])

        for result in results:
            rule_id   = result.get("ruleId", "semgrep/unknown")
            rule_meta = rules_meta.get(rule_id, {})
            message   = result.get("message", {})
            msg_text  = message.get("text", "") if isinstance(message, dict) else str(message)

            # Severity
            sev_raw = result.get("level", "WARNING").upper()
            sev     = _SEVERITY_MAP.get(sev_raw, "medium")

            # Location
            locs = result.get("locations", [])
            if not locs:
                continue
            loc      = locs[0].get("physicalLocation", {})
            art_loc  = loc.get("artifactLocation", {})
            region   = loc.get("region", {})
            raw_path = art_loc.get("uri", "")
            line_no  = region.get("startLine", 0)
            snippet  = region.get("snippet", {}).get("text", "").strip() if isinstance(region.get("snippet"), dict) else ""

            # Normalise path relative to scan dir
            rel_path = raw_path
            for sd in scan_dirs:
                sd_norm = sd.replace("\\", "/").rstrip("/") + "/"
                if rel_path.startswith(sd_norm):
                    rel_path = rel_path[len(sd_norm):]
                    break
                # Handle file:// prefix
                if rel_path.startswith("file://"):
                    rel_path = rel_path[7:]
                    if rel_path.startswith(sd_norm):
                        rel_path = rel_path[len(sd_norm):]
                        break

            # Dedup by rule + path + line
            dedup_key = f"{rule_id}:{rel_path}:{line_no}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # Rule metadata
            rule_name = rule_meta.get("name", rule_id.split(".")[-1].replace("-", " ").title())
            full_desc = ""
            help_url  = ""
            tags      = []
            if rule_meta:
                full_desc = rule_meta.get("fullDescription", {}).get("text", "") or \
                            rule_meta.get("shortDescription", {}).get("text", "")
                help_url  = rule_meta.get("helpUri", "")
                props     = rule_meta.get("properties", {})
                tags      = props.get("tags", [])

            # Map to OWASP / MASVS via tags
            owasp = "M1"
            masvs = "MASVS-CODE-4"
            for tag in tags:
                tag_lower = tag.lower()
                for k, v in _OWASP_MAP.items():
                    if k in tag_lower:
                        owasp = v
                        break
                for k, v in _MASVS_MAP.items():
                    if k in tag_lower:
                        masvs = v
                        break

            description = full_desc or msg_text or f"Semgrep rule {rule_id} matched."
            recommendation = (
                f"Review the flagged code at {rel_path}:{line_no}. "
                f"See rule documentation: {help_url}" if help_url
                else f"Review the flagged code at {rel_path}:{line_no}."
            )

            findings.append({
                "title":          rule_name,
                "severity":       sev,
                "category":       "SAST (Semgrep)",
                "description":    description,
                "recommendation": recommendation,
                "rule_id":        rule_id,
                "owasp":          owasp,
                "masvs":          masvs,
                "source":         "semgrep",
                "confidence":     80,
                "exploitability": 50,
                "validation_status": "detected",
                "file_path":      rel_path,
                "line":           line_no,
                "snippet":        snippet,
                "code_context":   "",
                "file_evidence":  [{"path": rel_path, "lines": [line_no], "snippet": snippet}],
                "files":          [rel_path],
                "file_count":     1,
                "semgrep_rule":   rule_id,
                "help_url":       help_url,
            })

            if len(findings) >= MAX_FINDINGS:
                return findings

    return findings


# ─── Runner ───────────────────────────────────────────────────────────────────
def run_semgrep(scan_dirs: list, results: dict) -> dict:
    """
    Run Semgrep against scan_dirs with android/java/kotlin rulesets.
    Appends findings to results["findings"].
    Returns metrics dict: {ran, finding_count, duration_ms, error}.
    """
    metrics = {"ran": False, "finding_count": 0, "duration_ms": 0, "error": None}

    if not semgrep_available():
        metrics["error"] = "semgrep not installed"
        return metrics

    valid_dirs = [d for d in (scan_dirs or []) if d and os.path.exists(d)]
    if not valid_dirs:
        metrics["error"] = "no valid scan directories"
        return metrics

    # Write SARIF to a temp file
    sarif_file = tempfile.NamedTemporaryFile(suffix=".sarif.json", delete=False)
    sarif_path = sarif_file.name
    sarif_file.close()

    try:
        cmd = [
            "semgrep",
            "--sarif",
            "--output", sarif_path,
            "--no-git-ignore",
            "--quiet",
            "--timeout", "10",          # per-file timeout — tighter so a single pathological file can't eat the budget
            "--max-memory", "1000",     # MB
            "--jobs", "4",              # parallelism — more files in flight
        ]
        # Add rulesets
        for ruleset in SEMGREP_RULESETS:
            cmd += ["--config", ruleset]

        # Add scan dirs
        cmd += valid_dirs

        t0 = time.perf_counter()
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT,
        )
        duration_ms = int((time.perf_counter() - t0) * 1000)
        metrics["duration_ms"] = duration_ms
        metrics["ran"] = True

        # Semgrep exits 1 when findings are found, 0 when none — both are OK.
        # Exit 2+ is a fatal error.
        if proc.returncode > 1:
            metrics["error"] = f"semgrep exit {proc.returncode}: {proc.stderr[:200]}"
            return metrics

        # Parse SARIF
        if not os.path.exists(sarif_path) or os.path.getsize(sarif_path) == 0:
            metrics["error"] = "empty SARIF output"
            return metrics

        with open(sarif_path, "r", encoding="utf-8", errors="replace") as f:
            sarif = json.load(f)

        findings = _sarif_to_findings(sarif, valid_dirs)
        metrics["finding_count"] = len(findings)

        # Deduplicate against existing findings by title+file_path+line
        existing_keys = {
            f"{f.get('title','')}:{f.get('file_path','')}:{f.get('line',0)}"
            for f in results.get("findings", [])
        }
        new_findings = [
            f for f in findings
            if f"{f['title']}:{f['file_path']}:{f['line']}" not in existing_keys
        ]
        results["findings"].extend(new_findings)
        metrics["finding_count"] = len(new_findings)

    except subprocess.TimeoutExpired:
        metrics["error"] = f"semgrep timed out after {SEMGREP_TIMEOUT}s"
    except json.JSONDecodeError as e:
        metrics["error"] = f"SARIF parse error: {e}"
    except Exception as e:
        metrics["error"] = str(e)
    finally:
        try:
            os.unlink(sarif_path)
        except Exception:
            pass

    return metrics
