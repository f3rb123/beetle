"""
Cortex Custom SAST Rules
=========================
Stores admin-defined regex rules in SQLite.
These are merged with built-in rules at scan time.

Rule schema:
  id           INTEGER PK
  rule_id      TEXT UNIQUE   — machine identifier, auto-generated if blank
  platform     TEXT          — 'android' | 'ios' | 'both'
  title        TEXT
  pattern      TEXT          — Python-compatible regex
  severity     TEXT          — critical|high|medium|low|info
  category     TEXT
  cwe          TEXT          — e.g. CWE-89
  masvs        TEXT          — e.g. MASVS-CODE-4
  owasp        TEXT          — e.g. M9
  description  TEXT
  recommendation TEXT
  enabled      INTEGER       — 0|1
  created_by   TEXT
  created_at   TEXT
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
import os

_DATA_DIR = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
_DB_PATH  = _DATA_DIR / "cortex.db"

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_PLATFORMS  = {"android", "ios", "both"}


def _conn() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_custom_rules_db() -> None:
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS custom_rules (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id        TEXT    UNIQUE NOT NULL,
                platform       TEXT    NOT NULL DEFAULT 'both',
                title          TEXT    NOT NULL,
                pattern        TEXT    NOT NULL,
                severity       TEXT    NOT NULL DEFAULT 'medium',
                category       TEXT    DEFAULT '',
                cwe            TEXT    DEFAULT '',
                masvs          TEXT    DEFAULT '',
                owasp          TEXT    DEFAULT '',
                description    TEXT    DEFAULT '',
                recommendation TEXT    DEFAULT '',
                enabled        INTEGER NOT NULL DEFAULT 1,
                created_by     TEXT    DEFAULT '',
                created_at     TEXT    DEFAULT (datetime('now'))
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_custom_rules_platform ON custom_rules(platform, enabled)")
        c.commit()


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["enabled"] = bool(d.get("enabled", 1))
    return d


def list_rules(platform: str = "", enabled_only: bool = False) -> list[dict]:
    clauses, params = [], []
    if platform and platform != "both":
        clauses.append("(platform = ? OR platform = 'both')")
        params.append(platform)
    if enabled_only:
        clauses.append("enabled = 1")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    try:
        with _conn() as c:
            rows = c.execute(
                f"SELECT * FROM custom_rules {where} ORDER BY id", params
            ).fetchall()
            return [_row_to_dict(r) for r in rows]
    except Exception:
        return []


def get_rule(rule_id: str) -> dict | None:
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM custom_rules WHERE rule_id = ?", (rule_id,)
            ).fetchone()
            return _row_to_dict(row) if row else None
    except Exception:
        return None


def create_rule(data: dict, created_by: str = "") -> dict:
    rule_id = (data.get("rule_id") or "").strip() or f"custom_{uuid.uuid4().hex[:8]}"
    title   = data.get("title", "").strip()
    pattern = data.get("pattern", "").strip()
    if not title:
        raise ValueError("title is required")
    if not pattern:
        raise ValueError("pattern is required")
    # Validate regex compiles
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")
    severity = data.get("severity", "medium").lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}")
    platform = data.get("platform", "both").lower()
    if platform not in VALID_PLATFORMS:
        raise ValueError(f"platform must be one of: {', '.join(sorted(VALID_PLATFORMS))}")

    with _conn() as c:
        c.execute("""
            INSERT INTO custom_rules
              (rule_id, platform, title, pattern, severity, category,
               cwe, masvs, owasp, description, recommendation, enabled, created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)
        """, (
            rule_id, platform, title, pattern, severity,
            data.get("category", ""),
            data.get("cwe", ""), data.get("masvs", ""), data.get("owasp", ""),
            data.get("description", ""), data.get("recommendation", ""),
            created_by,
        ))
        c.commit()
    return get_rule(rule_id)


def update_rule(rule_id: str, data: dict) -> dict | None:
    existing = get_rule(rule_id)
    if not existing:
        return None
    if "pattern" in data:
        try:
            re.compile(data["pattern"])
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
    updatable = ("title", "pattern", "severity", "category", "cwe", "masvs",
                 "owasp", "description", "recommendation", "platform", "enabled")
    sets, params = [], []
    for field in updatable:
        if field in data:
            val = data[field]
            if field == "enabled":
                val = 1 if val else 0
            sets.append(f"{field} = ?")
            params.append(val)
    if not sets:
        return existing
    params.append(rule_id)
    with _conn() as c:
        c.execute(
            f"UPDATE custom_rules SET {', '.join(sets)} WHERE rule_id = ?", params
        )
        c.commit()
    return get_rule(rule_id)


def delete_rule(rule_id: str) -> bool:
    try:
        with _conn() as c:
            c.execute("DELETE FROM custom_rules WHERE rule_id = ?", (rule_id,))
            c.commit()
        return True
    except Exception:
        return False


def get_rules_for_scanner(platform: str) -> list[dict]:
    """Return enabled custom rules for a given platform, formatted like CODE_RULES entries."""
    rows = list_rules(platform=platform, enabled_only=True)
    result = []
    for r in rows:
        result.append({
            "id":             r["rule_id"],
            "title":          r["title"],
            "pattern":        r["pattern"],
            "severity":       r["severity"],
            "category":       r.get("category") or "Custom",
            "cwe":            r.get("cwe", ""),
            "masvs":          r.get("masvs", ""),
            "owasp":          r.get("owasp", ""),
            "description":    r.get("description", ""),
            "recommendation": r.get("recommendation", ""),
            "source":         "CUSTOM_RULE",
        })
    return result
