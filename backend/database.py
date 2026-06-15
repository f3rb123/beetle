"""
Cortex Database Layer
SQLite-based persistent storage for scan history and findings.
"""
import sqlite3
import json
import logging
import os
from datetime import datetime
from pathlib import Path

log = logging.getLogger("cortex.db")

try:
    from analyzers.common import normalize_severity, compute_severity_summary, ALLOWED_SEVERITIES, dedupe_findings
except Exception:
    ALLOWED_SEVERITIES = ("critical", "high", "medium", "low", "info")
    def normalize_severity(s):
        v = (str(s or "info")).strip().lower()
        return v if v in ALLOWED_SEVERITIES else "info"
    def compute_severity_summary(findings):
        out = {k: 0 for k in ALLOWED_SEVERITIES}
        for f in findings or []:
            out[normalize_severity(f.get("severity"))] += 1
        return out
    def dedupe_findings(findings):
        return findings or []

DATA_DIR = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
DB_PATH  = DATA_DIR / "cortex.db"


def get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create tables if they don't exist."""
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                app_name    TEXT,
                package     TEXT,
                filename    TEXT,
                platform    TEXT,
                score       INTEGER,
                grade       TEXT,
                risk        TEXT,
                version     TEXT,
                size_mb     REAL,
                sha256      TEXT,
                framework   TEXT,
                scan_time   TEXT,
                created_at  TEXT DEFAULT (datetime('now')),
                -- Severity summary
                s_critical  INTEGER DEFAULT 0,
                s_high      INTEGER DEFAULT 0,
                s_medium    INTEGER DEFAULT 0,
                s_low       INTEGER DEFAULT 0,
                s_info      INTEGER DEFAULT 0,
                -- Counts
                secrets_count   INTEGER DEFAULT 0,
                trackers_count  INTEGER DEFAULT 0,
                -- Full results JSON (compressed)
                results_json TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                title       TEXT,
                severity    TEXT,
                category    TEXT,
                rule_id     TEXT,
                source      TEXT,
                cwe         TEXT,
                masvs       TEXT,
                owasp       TEXT,
                file_path   TEXT,
                line_number INTEGER,
                snippet     TEXT,
                confidence  INTEGER,
                exploitability INTEGER,
                validation_status TEXT DEFAULT 'detected',
                description TEXT,
                recommendation TEXT,
                cve         TEXT,
                cvss        REAL,
                kev         INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(created_at);
            -- Prevent exact-duplicate finding rows within one scan
            CREATE UNIQUE INDEX IF NOT EXISTS uniq_findings_key
                ON findings(scan_id, IFNULL(rule_id, ''), IFNULL(file_path, ''), IFNULL(line_number, 0), IFNULL(title, ''));

            CREATE TABLE IF NOT EXISTS triage (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id    TEXT    NOT NULL,
                finding_key TEXT  NOT NULL,
                state      TEXT    NOT NULL DEFAULT 'open',
                note       TEXT    DEFAULT '',
                triaged_by TEXT    DEFAULT '',
                updated_at TEXT    DEFAULT (datetime('now')),
                UNIQUE(scan_id, finding_key)
            );

            CREATE INDEX IF NOT EXISTS idx_triage_scan ON triage(scan_id);

            CREATE TABLE IF NOT EXISTS scan_notes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id    TEXT    NOT NULL,
                note       TEXT    NOT NULL DEFAULT '',
                author     TEXT    DEFAULT '',
                created_at TEXT    DEFAULT (datetime('now')),
                updated_at TEXT    DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_notes_scan ON scan_notes(scan_id);
        """)

        # Lightweight, idempotent column migrations for pre-existing DBs.
        existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
        for col, ddl in (
            ("cve",  "ALTER TABLE findings ADD COLUMN cve  TEXT"),
            ("cvss", "ALTER TABLE findings ADD COLUMN cvss REAL"),
            ("kev",  "ALTER TABLE findings ADD COLUMN kev  INTEGER DEFAULT 0"),
        ):
            if col not in existing_cols:
                try:
                    conn.execute(ddl)
                except Exception as e:
                    print(f"[DB] migration skip {col}: {e}")
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve)")
        except Exception:
            pass


def save_scan(results: dict):
    """Persist full scan results to DB."""
    try:
        init_db()
        # Normalize severity on every finding, then recompute the authoritative
        # severity_summary from that list so DB counts, severity_summary, and
        # actual findings rows can never disagree.
        findings_list = results.get("findings") or []
        for f in findings_list:
            f["severity"] = normalize_severity(f.get("severity"))
        pre_dedup = len(findings_list)
        findings_list = dedupe_findings(findings_list)
        dropped = pre_dedup - len(findings_list)
        if dropped:
            log.info(f"[{results.get('scan_id')}] dedupe: collapsed {dropped} duplicate finding(s)")
        results["findings"] = findings_list
        ss = compute_severity_summary(findings_list)
        results["severity_summary"] = ss
        info = results.get("app_info", {})
        score = results.get("score", {})

        with get_conn() as conn:
            # Upsert scan record
            conn.execute("""
                INSERT OR REPLACE INTO scans
                (scan_id, app_name, package, filename, platform, score, grade, risk,
                 version, size_mb, sha256, framework, scan_time,
                 s_critical, s_high, s_medium, s_low, s_info,
                 secrets_count, trackers_count, results_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                results.get("scan_id"),
                results.get("app_name"),
                info.get("package") or info.get("bundle_id"),
                results.get("filename"),
                results.get("platform"),
                score.get("score"),
                score.get("grade"),
                score.get("risk"),
                info.get("version_name") or info.get("version"),
                info.get("size_mb"),
                info.get("sha256"),
                results.get("framework", {}).get("type"),
                results.get("scan_time"),
                ss.get("critical", 0),
                ss.get("high", 0),
                ss.get("medium", 0),
                ss.get("low", 0),
                ss.get("info", 0),
                len(results.get("secrets", [])),
                len(results.get("trackers", [])),
                json.dumps(results),
            ))

            # Insert findings
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (results.get("scan_id"),))
            for f in findings_list:
                conn.execute("""
                    INSERT INTO findings
                    (scan_id, title, severity, category, rule_id, source, cwe, masvs,
                     owasp, file_path, line_number, snippet, confidence, exploitability,
                     validation_status, description, recommendation,
                     cve, cvss, kev)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT DO NOTHING
                """, (
                    results.get("scan_id"),
                    f.get("title"),
                    normalize_severity(f.get("severity")),
                    f.get("category"),
                    f.get("rule_id"),
                    f.get("source"),
                    f.get("cwe"),
                    f.get("masvs"),
                    f.get("owasp"),
                    f.get("file_path") or (f.get("files", [None])[0] if f.get("files") else None),
                    f.get("line"),
                    f.get("snippet"),
                    f.get("confidence"),
                    f.get("exploitability"),
                    f.get("validation_status", "detected"),
                    f.get("description"),
                    f.get("recommendation"),
                    f.get("cve"),
                    f.get("cvss"),
                    1 if f.get("kev") else 0,
                ))
    except Exception as e:
        print(f"[DB] save_scan error: {e}")


def get_scan_history(limit: int = 20) -> list:
    """Return recent scan summaries."""
    try:
        init_db()
        with get_conn() as conn:
            rows = conn.execute("""
                SELECT scan_id, app_name, package, filename, platform,
                       score, grade, risk, scan_time, created_at,
                       s_critical, s_high, s_medium, s_low, s_info,
                       secrets_count, trackers_count, framework, results_json
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                raw_results = item.pop("results_json", None)
                if raw_results:
                    try:
                        parsed = json.loads(raw_results)
                        item["icon_data"] = (
                            (parsed.get("app_info") or {}).get("icon_data")
                            or parsed.get("icon_data")
                            or ""
                        )
                    except Exception:
                        item["icon_data"] = ""
                else:
                    item["icon_data"] = ""
                items.append(item)
            return items
    except Exception as e:
        print(f"[DB] get_scan_history error: {e}")
        return []


def get_scan_results(scan_id: str) -> dict | None:
    """Return full scan results JSON."""
    try:
        init_db()
        with get_conn() as conn:
            row = conn.execute(
                "SELECT results_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if row and row["results_json"]:
                return json.loads(row["results_json"])
    except Exception as e:
        print(f"[DB] get_scan_results error: {e}")
    return None


def get_scan_findings(scan_id: str, severity: str = None) -> list:
    """Return findings for a scan, optionally filtered by severity."""
    try:
        init_db()
        with get_conn() as conn:
            if severity:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ? AND severity = ? ORDER BY id",
                    (scan_id, normalize_severity(severity))
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE scan_id = ? ORDER BY id",
                    (scan_id,)
                ).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] get_scan_findings error: {e}")
        return []


def get_triage(scan_id: str) -> dict:
    """Return all triage entries for a scan as {finding_key: {state, note, triaged_by, updated_at}}."""
    try:
        init_db()
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT finding_key, state, note, triaged_by, updated_at FROM triage WHERE scan_id = ?",
                (scan_id,)
            ).fetchall()
            return {r["finding_key"]: dict(r) for r in rows}
    except Exception as e:
        print(f"[DB] get_triage error: {e}")
        return {}


def set_triage(scan_id: str, finding_key: str, state: str,
               note: str = "", triaged_by: str = "") -> dict:
    """Upsert a triage entry. Deletes the row when state is 'open'."""
    try:
        init_db()
        with get_conn() as conn:
            if not state or state == "open":
                conn.execute(
                    "DELETE FROM triage WHERE scan_id = ? AND finding_key = ?",
                    (scan_id, finding_key)
                )
            else:
                conn.execute("""
                    INSERT INTO triage (scan_id, finding_key, state, note, triaged_by, updated_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                    ON CONFLICT(scan_id, finding_key)
                    DO UPDATE SET state      = excluded.state,
                                  note       = excluded.note,
                                  triaged_by = excluded.triaged_by,
                                  updated_at = excluded.updated_at
                """, (scan_id, finding_key, state, note or "", triaged_by or ""))
            conn.commit()
        return {"scan_id": scan_id, "finding_key": finding_key,
                "state": state or "open", "note": note or "", "triaged_by": triaged_by or ""}
    except Exception as e:
        print(f"[DB] set_triage error: {e}")
        return {"error": str(e)}


def get_scan_notes(scan_id: str) -> list[dict]:
    """Return all analyst notes for a scan, newest first."""
    try:
        init_db()
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT id, scan_id, note, author, created_at, updated_at "
                "FROM scan_notes WHERE scan_id = ? ORDER BY id DESC",
                (scan_id,),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] get_scan_notes error: {e}")
        return []


def add_scan_note(scan_id: str, note: str, author: str = "") -> dict:
    """Append an analyst note to a scan."""
    try:
        init_db()
        with get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO scan_notes (scan_id, note, author) VALUES (?, ?, ?)",
                (scan_id, note.strip(), author or ""),
            )
            conn.commit()
            row = conn.execute(
                "SELECT id, scan_id, note, author, created_at, updated_at FROM scan_notes WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
            return dict(row) if row else {}
    except Exception as e:
        print(f"[DB] add_scan_note error: {e}")
        return {"error": str(e)}


def update_scan_note(note_id: int, note: str) -> dict | None:
    """Edit an existing scan note."""
    try:
        init_db()
        with get_conn() as conn:
            conn.execute(
                "UPDATE scan_notes SET note = ?, updated_at = datetime('now') WHERE id = ?",
                (note.strip(), note_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT id, scan_id, note, author, created_at, updated_at FROM scan_notes WHERE id = ?",
                (note_id,),
            ).fetchone()
            return dict(row) if row else None
    except Exception as e:
        print(f"[DB] update_scan_note error: {e}")
        return None


def delete_scan_note(note_id: int) -> bool:
    """Delete a scan note."""
    try:
        init_db()
        with get_conn() as conn:
            conn.execute("DELETE FROM scan_notes WHERE id = ?", (note_id,))
            conn.commit()
        return True
    except Exception as e:
        print(f"[DB] delete_scan_note error: {e}")
        return False


def delete_scan(scan_id: str) -> bool:
    """Delete a scan and all associated data."""
    try:
        init_db()
        with get_conn() as conn:
            conn.execute("DELETE FROM scan_notes WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM triage     WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM findings   WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans      WHERE scan_id = ?", (scan_id,))
            conn.commit()
        return True
    except Exception as e:
        print(f"[DB] delete_scan error: {e}")
        return False


def compare_scans(scan_id_a: str, scan_id_b: str) -> dict:
    """Diff two scans — return new, fixed, and changed findings."""
    try:
        findings_a = {f["rule_id"] or f["title"]: f for f in get_scan_findings(scan_id_a) if f.get("rule_id") or f.get("title")}
        findings_b = {f["rule_id"] or f["title"]: f for f in get_scan_findings(scan_id_b) if f.get("rule_id") or f.get("title")}

        keys_a = set(findings_a.keys())
        keys_b = set(findings_b.keys())

        new_findings     = [findings_b[k] for k in keys_b - keys_a]
        fixed_findings   = [findings_a[k] for k in keys_a - keys_b]
        common_findings  = [findings_b[k] for k in keys_a & keys_b]

        return {
            "new":    new_findings,
            "fixed":  fixed_findings,
            "common": common_findings,
            "summary": {
                "new_count":   len(new_findings),
                "fixed_count": len(fixed_findings),
                "unchanged":   len(common_findings),
            }
        }
    except Exception as e:
        print(f"[DB] compare_scans error: {e}")
        return {"new": [], "fixed": [], "common": [], "summary": {}}


