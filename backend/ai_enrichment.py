"""
Cortex AI Finding Enrichment
==============================
Uses the Anthropic Claude API to enrich security findings with:
  - Detailed exploit scenario (step-by-step attack narrative)
  - Real-world impact assessment
  - App-specific remediation advice (tailored to context: language, framework)
  - CVSS-style exploitability notes
  - Related CVEs / references (if applicable)

Design decisions
  - On-demand only: called per finding via API endpoint, not auto-run on every scan
  - Results cached in SQLite (cortex.db) with a TTL of 7 days
  - Graceful: if Anthropic SDK not installed or API key absent → returns empty enrichment
  - Model: claude-haiku-4-5-20251001 (fast + cheap for structured enrichment tasks)
  - Each enrichment is one API call with a system prompt + structured JSON output request

Cache schema (added to cortex.db):
  ai_enrichment_cache(cache_key TEXT PK, enrichment TEXT, created_at TEXT)
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

_DATA_DIR   = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
_DB_PATH    = _DATA_DIR / "cortex.db"
_MODEL      = os.environ.get("CORTEX_AI_MODEL", "claude-haiku-4-5-20251001")
_CACHE_TTL  = timedelta(days=7)
_MAX_TOKENS = 1024

try:
    import anthropic as _anthropic
    _CLIENT = _anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    AI_AVAILABLE = bool(os.environ.get("ANTHROPIC_API_KEY", ""))
except ImportError:
    _anthropic = None  # type: ignore
    _CLIENT    = None  # type: ignore
    AI_AVAILABLE = False


# ── DB ────────────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_ai_db():
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ai_enrichment_cache (
                cache_key  TEXT PRIMARY KEY,
                enrichment TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
        """)


# ── Cache helpers ─────────────────────────────────────────────────────────────

def _cache_key(finding: dict) -> str:
    """Stable hash from the fields that define a finding's identity."""
    identity = json.dumps({
        "title":    finding.get("title", ""),
        "rule_id":  finding.get("rule_id", ""),
        "cwe":      finding.get("cwe", ""),
        "category": finding.get("category", ""),
        "severity": finding.get("severity", ""),
    }, sort_keys=True)
    return hashlib.sha256(identity.encode()).hexdigest()


def _cache_get(key: str) -> dict | None:
    try:
        with _conn() as conn:
            row = conn.execute(
                "SELECT enrichment, created_at FROM ai_enrichment_cache WHERE cache_key = ?",
                (key,)
            ).fetchone()
        if not row:
            return None
        # Check TTL
        created = datetime.fromisoformat(row["created_at"])
        if datetime.utcnow() - created > _CACHE_TTL:
            return None
        return json.loads(row["enrichment"])
    except Exception:
        return None


def _cache_set(key: str, enrichment: dict):
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ai_enrichment_cache (cache_key, enrichment) VALUES (?,?)",
                (key, json.dumps(enrichment)),
            )
    except Exception:
        pass


# ── Prompt builder ────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a senior mobile application security engineer. You analyse security findings from \
static analysis of Android and iOS applications and provide concise, actionable enrichment.

Your output must be valid JSON matching this exact schema — no markdown, no commentary:
{
  "exploit_scenario": "<2-4 sentences: concrete step-by-step attack an adversary would perform>",
  "real_world_impact": "<2-3 sentences: what an attacker gains; reference real incidents where relevant>",
  "remediation": "<3-6 bullet points as a JSON array of strings: specific code-level fixes for this finding>",
  "exploitability_notes": "<1-2 sentences: conditions required for exploitation — local/remote, prerequisites>",
  "references": ["<URL or CVE or standard reference>"]
}

Be specific to the finding. Do not give generic advice. If the finding includes a code snippet, \
reference it directly. Keep each field concise."""


def _build_user_prompt(finding: dict, app_context: dict) -> str:
    lines = [
        f"Finding title: {finding.get('title', 'N/A')}",
        f"Severity: {finding.get('severity', 'N/A')}",
        f"Category: {finding.get('category', 'N/A')}",
        f"CWE: {finding.get('cwe', 'N/A')}",
        f"MASVS: {finding.get('masvs', 'N/A')}",
        f"OWASP Mobile: {finding.get('owasp', 'N/A')}",
        "",
        f"Description: {finding.get('description', 'N/A')}",
        "",
        f"App context:",
        f"  Platform: {app_context.get('platform', 'android')}",
        f"  Framework: {app_context.get('framework', 'native')}",
        f"  Package: {app_context.get('package', 'N/A')}",
    ]

    snippet = finding.get("snippet") or finding.get("code_context")
    if snippet:
        lines += ["", f"Code snippet:", f"```", snippet[:600], "```"]

    file_path = finding.get("file_path")
    if file_path:
        lines.append(f"File: {file_path}")

    return "\n".join(lines)


# ── Main enrichment function ──────────────────────────────────────────────────

def enrich_finding(finding: dict, app_context: dict | None = None) -> dict:
    """
    Return AI enrichment for a finding.
    Result shape: { exploit_scenario, real_world_impact, remediation, exploitability_notes, references, cached, model }
    On failure: returns { error, cached: False }
    """
    ctx = app_context or {}
    key = _cache_key(finding)

    cached = _cache_get(key)
    if cached:
        cached["cached"] = True
        return cached

    if not AI_AVAILABLE:
        return {"error": "AI enrichment unavailable — set ANTHROPIC_API_KEY environment variable", "cached": False}

    try:
        user_prompt = _build_user_prompt(finding, ctx)
        message = _CLIENT.messages.create(
            model=_MODEL,
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        raw = message.content[0].text.strip()

        # Strip markdown code fences if the model added them
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        enrichment = json.loads(raw)
        enrichment["cached"] = False
        enrichment["model"]  = _MODEL

        _cache_set(key, enrichment)
        return enrichment

    except json.JSONDecodeError as e:
        return {"error": f"AI response was not valid JSON: {e}", "cached": False, "raw": raw if 'raw' in dir() else ""}
    except Exception as e:
        return {"error": str(e), "cached": False}


def enrich_findings_batch(findings: list[dict], app_context: dict | None = None, max_findings: int = 20) -> list[dict]:
    """
    Enrich up to max_findings (prioritise critical/high).
    Returns list of { finding_index, title, enrichment } dicts.
    """
    severity_order = ["critical", "high", "medium", "low", "info"]
    sorted_findings = sorted(
        enumerate(findings),
        key=lambda x: severity_order.index(x[1].get("severity", "info")) if x[1].get("severity") in severity_order else 5
    )

    results = []
    for idx, finding in sorted_findings[:max_findings]:
        enrichment = enrich_finding(finding, app_context)
        results.append({
            "finding_index": idx,
            "title":         finding.get("title", ""),
            "enrichment":    enrichment,
        })

    return results
