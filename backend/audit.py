"""
Cortex Audit Log
=================
Records security-relevant events to SQLite for compliance and investigation.

Logged events:
  auth.login          user, outcome (success/failure), ip
  auth.logout         user
  auth.key_created    user, key_prefix
  auth.key_revoked    user, key_prefix
  scan.started        user, scan_id, filename, platform
  scan.completed      user, scan_id, score, findings_count
  scan.deleted        user, scan_id
  triage.set          user, scan_id, finding_key, old_state, new_state
  policy.updated      user, changes
  user.created        actor, new_user, role
  user.activated      actor, target_user, active

Each row: id, event, actor, scan_id, detail_json, ip, created_at
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import os

_DATA_DIR = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
_DB_PATH  = _DATA_DIR / "cortex.db"

_MAX_RECENT = 500   # cap for the list endpoint


def _conn() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_audit_db() -> None:
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event      TEXT    NOT NULL,
                actor      TEXT    NOT NULL DEFAULT '',
                scan_id    TEXT    DEFAULT '',
                detail     TEXT    DEFAULT '{}',
                ip         TEXT    DEFAULT '',
                created_at TEXT    DEFAULT (datetime('now'))
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_time  ON audit_log(created_at)")
        c.commit()


def log_event(event: str, actor: str = "", scan_id: str = "",
              detail: dict | None = None, ip: str = "") -> None:
    """Write one audit record. Never raises — silently swallows errors."""
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO audit_log (event, actor, scan_id, detail, ip) VALUES (?,?,?,?,?)",
                (event, actor or "", scan_id or "",
                 json.dumps(detail or {}), ip or ""),
            )
            c.commit()
    except Exception:
        pass


def get_audit_log(limit: int = 100, event_filter: str = "",
                  actor_filter: str = "") -> list[dict]:
    """Return recent audit entries, newest first."""
    try:
        clauses, params = [], []
        if event_filter:
            clauses.append("event LIKE ?")
            params.append(f"%{event_filter}%")
        if actor_filter:
            clauses.append("actor = ?")
            params.append(actor_filter)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(min(limit, _MAX_RECENT))
        with _conn() as c:
            rows = c.execute(
                f"SELECT id, event, actor, scan_id, detail, ip, created_at "
                f"FROM audit_log {where} ORDER BY id DESC LIMIT ?",
                params,
            ).fetchall()
            result = []
            for row in rows:
                entry = dict(row)
                try:
                    entry["detail"] = json.loads(entry["detail"] or "{}")
                except Exception:
                    entry["detail"] = {}
                result.append(entry)
            return result
    except Exception as e:
        return [{"error": str(e)}]
