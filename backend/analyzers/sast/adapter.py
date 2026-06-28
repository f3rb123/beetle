"""
SAST adapter contract + SARIF → Canonical Finding normalizer (Beetle 2.0, Phase 2.4).

This is the seam that keeps Beetle's intelligence pipeline isolated from any specific
SAST engine. An adapter does ONE job — execute an external engine and hand back
Beetle-shaped *canonical findings*; everything after (Ownership, Confidence, Evidence,
Finding Fusion, Attack Chains, Bug Bounty, Source/Security Explorer, Reports) is the
unchanged pipeline.

* :class:`SastAdapter` — the abstract contract every engine implements (Semgrep today;
  CodeQL / other SAST tomorrow plug in here WITHOUT touching the pipeline).
* :func:`sarif_to_canonical` — a reusable SARIF 2.1 → canonical converter. Because it is
  engine-agnostic, it doubles as the **SARIF-import** seam: any tool that emits SARIF
  becomes a detection source by passing its output through here.

Canonical conversion preserves exactly what the spec lists — Rule ID, Rule Name,
Message, Severity, File, Line, Metadata, CWE, OWASP, References — and stamps
``detected_by:[source]`` / ``source_module:source`` so Finding Fusion credits the engine
and merges duplicates. Nothing else.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

# SARIF result level → Beetle severity.
SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "NOTE": "low", "NONE": "info"}

# OWASP-Mobile / MASVS hints by Semgrep category tag (kept from the original runner).
_OWASP_MAP = {
    "android.security": "M1", "java.lang.security": "M1", "kotlin.lang.security": "M1",
    "android.crypto": "M10", "android.webview": "M4", "android.intent": "M1",
    "android.network": "M5", "android.storage": "M2",
}
_MASVS_MAP = {
    "android.crypto": "MASVS-CRYPTO-1", "android.webview": "MASVS-PLATFORM-1",
    "android.intent": "MASVS-PLATFORM-2", "android.network": "MASVS-NETWORK-1",
    "android.storage": "MASVS-STORAGE-1",
}
_CWE_RE = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)


class SastAdapter(ABC):
    """The contract a SAST engine implements to feed Beetle's canonical pipeline.

    Future engines (CodeQL, other SAST) subclass this and are wired exactly like the
    Semgrep adapter — produce canonical findings, append to ``results["findings"]``,
    and the pipeline does the rest. No pipeline change is ever required.
    """

    name: str = "SAST"

    @abstractmethod
    def available(self) -> bool:
        """True when the engine binary/runtime is installed and runnable."""

    @abstractmethod
    def languages_for(self, platform: str | None, framework: str | None = None) -> list[str]:
        """Languages this engine will analyze for the detected project."""

    @abstractmethod
    def run(self, scan_dirs: list[str], *, platform: str | None = None,
            framework: str | None = None) -> list[dict]:
        """Execute the engine over ``scan_dirs`` and return canonical finding dicts.
        MUST be safe (no raise) and a no-op (return []) when ``available()`` is False."""


# ── SARIF → canonical ─────────────────────────────────────────────────────────
def _relativize(raw_path: str, scan_dirs: list[str]) -> str:
    p = (raw_path or "").replace("\\", "/")
    if p.startswith("file://"):
        p = p[7:]
    for sd in scan_dirs or []:
        sd_norm = sd.replace("\\", "/").rstrip("/") + "/"
        if p.startswith(sd_norm):
            return p[len(sd_norm):]
    return p


def _extract_cwe(rule_meta: dict, tags: list, message: str) -> str:
    """First CWE-NNN found in rule metadata / tags / message ('' if none)."""
    props = (rule_meta or {}).get("properties", {}) if isinstance(rule_meta, dict) else {}
    candidates = []
    cwe_field = props.get("cwe")
    if isinstance(cwe_field, list):
        candidates.extend(str(c) for c in cwe_field)
    elif cwe_field:
        candidates.append(str(cwe_field))
    candidates.extend(str(t) for t in (tags or []))
    candidates.append(message or "")
    for c in candidates:
        m = _CWE_RE.search(c)
        if m:
            return f"CWE-{m.group(1)}"
    return ""


def _extract_refs(rule_meta: dict, help_url: str) -> list[str]:
    props = (rule_meta or {}).get("properties", {}) if isinstance(rule_meta, dict) else {}
    refs: list[str] = []
    for r in props.get("references", []) or []:
        if r and r not in refs:
            refs.append(str(r))
    src = props.get("source")
    if src and src not in refs:
        refs.append(str(src))
    if help_url and help_url not in refs:
        refs.append(help_url)
    return refs


def _owasp_masvs(tags: list) -> tuple[str, str]:
    owasp, masvs = "M1", "MASVS-CODE-4"
    for tag in tags or []:
        tl = str(tag).lower()
        for k, v in _OWASP_MAP.items():
            if k in tl:
                owasp = v
                break
        for k, v in _MASVS_MAP.items():
            if k in tl:
                masvs = v
                break
    return owasp, masvs


def sarif_to_canonical(sarif: dict, scan_dirs: list[str], *, source_name: str,
                       max_findings: int = 500) -> list[dict]:
    """Convert SARIF 2.1 output into canonical finding dicts attributed to
    ``source_name`` (e.g. "Semgrep"). Reusable by any SARIF-producing engine.

    Preserves Rule ID / Name / Message / Severity / File / Line / Metadata / CWE /
    OWASP / References and stamps detection attribution for Finding Fusion. De-dups
    only WITHIN this engine's output (rule+file+line) — cross-engine merge is fusion's
    job, never a silent drop here.
    """
    findings: list[dict] = []
    seen: set = set()
    for run in (sarif or {}).get("runs", []) or []:
        driver = run.get("tool", {}).get("driver", {})
        rules_meta = {r.get("id"): r for r in driver.get("rules", []) if isinstance(r, dict)}
        for result in run.get("results", []) or []:
            if len(findings) >= max_findings:
                return findings
            rule_id = result.get("ruleId", f"{source_name.lower()}/unknown")
            rule_meta = rules_meta.get(rule_id, {})
            msg = result.get("message", {})
            msg_text = msg.get("text", "") if isinstance(msg, dict) else str(msg)

            sev = SEVERITY_MAP.get(str(result.get("level", "WARNING")).upper(), "medium")

            locs = result.get("locations", []) or []
            if not locs:
                continue
            loc = locs[0].get("physicalLocation", {})
            region = loc.get("region", {})
            rel_path = _relativize(loc.get("artifactLocation", {}).get("uri", ""), scan_dirs)
            line_no = region.get("startLine", 0) or 0
            snip = region.get("snippet", {})
            snippet = (snip.get("text", "") if isinstance(snip, dict) else "").strip()

            key = f"{rule_id}:{rel_path}:{line_no}"
            if key in seen:
                continue
            seen.add(key)

            props = rule_meta.get("properties", {}) if isinstance(rule_meta, dict) else {}
            tags = props.get("tags", []) or []
            rule_name = rule_meta.get("name") or rule_id.split(".")[-1].replace("-", " ").title()
            full_desc = (rule_meta.get("fullDescription", {}) or {}).get("text", "") or \
                        (rule_meta.get("shortDescription", {}) or {}).get("text", "")
            help_url = rule_meta.get("helpUri", "") or ""
            cwe = _extract_cwe(rule_meta, tags, msg_text)
            owasp, masvs = _owasp_masvs(tags)
            references = _extract_refs(rule_meta, help_url)

            findings.append({
                "title": rule_name,
                "severity": sev,
                "category": "SAST",
                "description": full_desc or msg_text or f"{source_name} rule {rule_id} matched.",
                "recommendation": (f"Review {rel_path}:{line_no}. See: {help_url}" if help_url
                                   else f"Review the flagged code at {rel_path}:{line_no}."),
                "file_path": rel_path,
                "line": line_no, "line_number": line_no,
                "snippet": snippet, "code_context": "",
                "file_evidence": [{"path": rel_path, "lines": [line_no] if line_no else [], "snippet": snippet}],
                "cwe": cwe, "owasp": owasp, "masvs": masvs,
                "references": references,
                "rule_id": rule_id, "rule_name": rule_name,
                "help_url": help_url,
                "confidence": 80, "exploitability": 50, "validation_status": "detected",
                # Detection attribution → Finding Fusion credits the engine + merges dupes.
                "source": source_name, "source_module": source_name,
                "detected_by": [source_name],
                "discovery_method": "sast",
                "metadata": {"engine": source_name, "tags": list(tags)},
            })
    return findings
