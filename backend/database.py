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
# Phase 11.99: full results JSON lives on disk, one dir per scan; the DB keeps
# metadata + a pointer (result_path). Reports written by the PDF/SARIF endpoints
# also land under the scan dir so a workspace export captures everything.
RESULTS_DIR = DATA_DIR / "scans"


def get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _scalar(v):
    """Coerce a value to something sqlite3 can bind. Lists/dicts are the reason
    persistence silently failed before: attack-chain findings carry `masvs` /
    `owasp` as lists, and a single unbindable value aborts the whole save_scan
    transaction (rolling back the scan row too). Lists → comma-joined; dicts →
    JSON; everything else passes through unchanged."""
    if v is None or isinstance(v, (str, int, float, bytes)):
        return v
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        try:
            return json.dumps(v)
        except Exception:
            return str(v)
    return str(v)


def _results_dir(scan_id: str) -> Path:
    return RESULTS_DIR / scan_id


def _results_path(scan_id: str) -> Path:
    return _results_dir(scan_id) / "results.json"


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

            -- Phase 11.98: Ask-AI conversations, persisted per scan.
            CREATE TABLE IF NOT EXISTS ai_conversations (
                chat_id    TEXT PRIMARY KEY,
                scan_id    TEXT NOT NULL,
                title      TEXT DEFAULT 'New conversation',
                provider   TEXT DEFAULT '',
                model      TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_convo_scan ON ai_conversations(scan_id);

            CREATE TABLE IF NOT EXISTS ai_messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id    TEXT NOT NULL,
                role       TEXT NOT NULL,
                content    TEXT NOT NULL DEFAULT '',
                meta       TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_msg_chat ON ai_messages(chat_id);
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

        # Phase 11.99: scan persistence metadata (status, completed_at, trust,
        # findings_count, result_path on disk, icon_data for history thumbnails).
        scan_cols = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
        for col, ddl in (
            ("status",         "ALTER TABLE scans ADD COLUMN status TEXT DEFAULT 'completed'"),
            ("completed_at",   "ALTER TABLE scans ADD COLUMN completed_at TEXT"),
            ("trust_score",    "ALTER TABLE scans ADD COLUMN trust_score INTEGER"),
            ("findings_count", "ALTER TABLE scans ADD COLUMN findings_count INTEGER DEFAULT 0"),
            ("result_path",    "ALTER TABLE scans ADD COLUMN result_path TEXT"),
            ("icon_data",      "ALTER TABLE scans ADD COLUMN icon_data TEXT"),
        ):
            if col not in scan_cols:
                try:
                    conn.execute(ddl)
                except Exception as e:
                    print(f"[DB] migration skip scans.{col}: {e}")
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve)")
        except Exception:
            pass


def _write_results_file(scan_id: str, results: dict) -> str | None:
    """Persist the full results JSON to /data/scans/<scan_id>/results.json.
    Returns the path (str) or None on failure (DB metadata still saved)."""
    try:
        d = _results_dir(scan_id)
        d.mkdir(parents=True, exist_ok=True)
        path = _results_path(scan_id)
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(results, fh, default=str)
        os.replace(tmp, path)  # atomic — never leaves a half-written results.json
        return str(path)
    except Exception as e:
        log.warning(f"[{scan_id}] results.json write failed: {e}")
        return None


def save_scan(results: dict):
    """Persist a completed scan: full results JSON to disk, metadata to SQLite.

    The DB row is metadata-only (results_json is NULL); the full blob lives at
    result_path on disk. Findings rows are also written (deduped) for fast
    queries + the compare engine. All bound values are coerced via _scalar so a
    list-typed field (e.g. attack-chain masvs/owasp) can never abort the save."""
    try:
        init_db()
        scan_id = results.get("scan_id")
        # Normalize severity on every finding, then recompute the authoritative
        # severity_summary so DB counts, severity_summary, and findings agree.
        findings_list = results.get("findings") or []
        for f in findings_list:
            f["severity"] = normalize_severity(f.get("severity"))
        pre_dedup = len(findings_list)
        findings_list = dedupe_findings(findings_list)
        dropped = pre_dedup - len(findings_list)
        if dropped:
            log.info(f"[{scan_id}] dedupe: collapsed {dropped} duplicate finding(s)")
        results["findings"] = findings_list
        # Respect persistent suppressions (lazy import avoids a circular dep:
        # collaboration imports database). Suppressed findings are moved out of
        # results['findings'] into results['suppressed_findings'] so severity
        # counts, DB rows, exports and the UI all see only the active set.
        try:
            from collaboration import apply_suppressions
            apply_suppressions(results)
            findings_list = results.get("findings") or []
        except Exception as _e:
            log.debug(f"[{scan_id}] apply_suppressions skipped: {_e}")
        ss = compute_severity_summary(findings_list)
        results["severity_summary"] = ss
        info = results.get("app_info", {})
        score = results.get("score", {})
        trust = results.get("trust_score", {})

        # 1) Full results JSON → disk (metadata-only stays in the DB).
        result_path = _write_results_file(scan_id, results)

        # 2) Metadata → DB. Every value passes through _scalar().
        with get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scans
                (scan_id, app_name, package, filename, platform, score, grade, risk,
                 version, size_mb, sha256, framework, scan_time, created_at, completed_at,
                 status, trust_score, findings_count, result_path, icon_data,
                 s_critical, s_high, s_medium, s_low, s_info,
                 secrets_count, trackers_count, results_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,
                        COALESCE((SELECT created_at FROM scans WHERE scan_id=?), datetime('now')),
                        datetime('now'),
                        ?,?,?,?,?,?,?,?,?,?,?,?,NULL)
            """, tuple(_scalar(v) for v in (
                scan_id,
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
                (results.get("framework") or {}).get("type"),
                results.get("scan_time"),
                scan_id,                       # for the COALESCE created_at subquery
                "completed",
                (trust or {}).get("score"),
                len(findings_list),
                result_path,
                (info.get("icon_data") or results.get("icon_data") or ""),
                ss.get("critical", 0),
                ss.get("high", 0),
                ss.get("medium", 0),
                ss.get("low", 0),
                ss.get("info", 0),
                len(results.get("secrets", [])),
                len(results.get("trackers", [])),
            )))

            # Findings rows (deduped) — _scalar() neutralizes list-typed fields.
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            for f in findings_list:
                conn.execute("""
                    INSERT INTO findings
                    (scan_id, title, severity, category, rule_id, source, cwe, masvs,
                     owasp, file_path, line_number, snippet, confidence, exploitability,
                     validation_status, description, recommendation,
                     cve, cvss, kev)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT DO NOTHING
                """, tuple(_scalar(v) for v in (
                    scan_id,
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
                )))
    except Exception as e:
        print(f"[DB] save_scan error: {e}")


_HISTORY_COLS = """scan_id, app_name, package, filename, platform,
                   score, grade, risk, version, scan_time, created_at, completed_at,
                   status, trust_score, findings_count, result_path, icon_data,
                   s_critical, s_high, s_medium, s_low, s_info,
                   secrets_count, trackers_count, framework"""

_SORT_COLUMNS = {
    "created_at": "created_at", "date": "created_at", "app_name": "app_name",
    "app": "app_name", "score": "score", "risk": "score",
    "trust": "trust_score", "findings": "findings_count",
}


def get_scan_history(limit: int = 20, offset: int = 0, search: str = "",
                     sort: str = "created_at", order: str = "desc") -> dict:
    """Return scan history (metadata only) with search / sort / pagination.

    Returns {"items": [...], "total": n}. icon_data comes from its own column
    (no results_json read), so listing is cheap and survives the on-disk move."""
    try:
        init_db()
        sort_col = _SORT_COLUMNS.get((sort or "created_at").lower(), "created_at")
        direction = "ASC" if (order or "desc").lower() == "asc" else "DESC"
        where, params = "", []
        if search:
            where = ("WHERE app_name LIKE ? OR package LIKE ? OR filename LIKE ? "
                     "OR scan_id LIKE ?")
            like = f"%{search}%"
            params = [like, like, like, like]
        with get_conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) c FROM scans {where}", params).fetchone()["c"]
            rows = conn.execute(
                f"SELECT {_HISTORY_COLS} FROM scans {where} "
                f"ORDER BY {sort_col} {direction} LIMIT ? OFFSET ?",
                params + [int(limit), int(offset)],
            ).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                item["icon_data"] = item.get("icon_data") or ""
                items.append(item)
            return {"items": items, "total": total}
    except Exception as e:
        print(f"[DB] get_scan_history error: {e}")
        return {"items": [], "total": 0}


def get_scan_results(scan_id: str) -> dict | None:
    """Return the full scan results JSON, preferring the on-disk file and
    falling back to a legacy results_json blob if one exists."""
    try:
        init_db()
        path = _results_path(scan_id)
        if path.exists():
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
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
    """Delete a scan: DB rows (scan, findings, triage, notes, AI cache) and its
    on-disk results/reports directory."""
    try:
        init_db()
        with get_conn() as conn:
            conn.execute("DELETE FROM scan_notes WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM triage     WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM findings   WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans      WHERE scan_id = ?", (scan_id,))
            conn.commit()
        # Remove the on-disk results/report dir.
        import shutil
        d = _results_dir(scan_id)
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        return True
    except Exception as e:
        print(f"[DB] delete_scan error: {e}")
        return False


# ─── Phase 11.99: startup restore, cleanup, export/import ────────────────────
def restore_scans_on_startup() -> dict:
    """Verify each persisted scan still has its results.json. Missing files are
    marked status='BROKEN' (kept in the list, never crash). Returns a summary."""
    summary = {"total": 0, "ok": 0, "broken": 0, "broken_ids": []}
    try:
        init_db()
        with get_conn() as conn:
            rows = conn.execute("SELECT scan_id, result_path, status FROM scans").fetchall()
            summary["total"] = len(rows)
            for row in rows:
                sid = row["scan_id"]
                path = Path(row["result_path"]) if row["result_path"] else _results_path(sid)
                if path.exists():
                    summary["ok"] += 1
                    # Heal a previously-broken row whose file came back.
                    if row["status"] == "BROKEN":
                        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (sid,))
                else:
                    summary["broken"] += 1
                    summary["broken_ids"].append(sid)
                    conn.execute("UPDATE scans SET status='BROKEN' WHERE scan_id=?", (sid,))
            conn.commit()
    except Exception as e:
        print(f"[DB] restore_scans_on_startup error: {e}")
    return summary


def cleanup_workspace(active_ids: set | None = None) -> dict:
    """Remove orphaned result directories (no DB row) and broken DB records
    (status BROKEN with a missing file). Never touches active scans."""
    active_ids = active_ids or set()
    report = {"orphan_dirs_removed": [], "broken_records_removed": []}
    try:
        init_db()
        import shutil
        with get_conn() as conn:
            db_ids = {r["scan_id"] for r in conn.execute("SELECT scan_id FROM scans").fetchall()}
            # Orphaned dirs on disk with no DB row and not currently active.
            if RESULTS_DIR.exists():
                for child in RESULTS_DIR.iterdir():
                    if not child.is_dir():
                        continue
                    sid = child.name
                    if sid in db_ids or sid in active_ids:
                        continue
                    shutil.rmtree(child, ignore_errors=True)
                    report["orphan_dirs_removed"].append(sid)
            # Broken DB records whose file is still missing and aren't active.
            broken = conn.execute("SELECT scan_id, result_path FROM scans WHERE status='BROKEN'").fetchall()
            for row in broken:
                sid = row["scan_id"]
                if sid in active_ids:
                    continue
                path = Path(row["result_path"]) if row["result_path"] else _results_path(sid)
                if not path.exists():
                    conn.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
                    conn.execute("DELETE FROM triage   WHERE scan_id=?", (sid,))
                    conn.execute("DELETE FROM scan_notes WHERE scan_id=?", (sid,))
                    conn.execute("DELETE FROM scans    WHERE scan_id=?", (sid,))
                    report["broken_records_removed"].append(sid)
            conn.commit()
    except Exception as e:
        print(f"[DB] cleanup_workspace error: {e}")
    return report


def export_workspace(out_path: str, reports_dir: str | None = None) -> str:
    """Bundle the whole workspace into a zip: every scan's results dir, the DB
    metadata as metadata.json, and any generated reports. Returns out_path."""
    import zipfile
    init_db()
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute(f"SELECT {_HISTORY_COLS} FROM scans").fetchall()]
    meta = {"version": 1, "exported_at": datetime.utcnow().isoformat(), "scans": rows}
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("metadata.json", json.dumps(meta, default=str))
        # results (+ any per-scan reports written under the scan dir)
        if RESULTS_DIR.exists():
            for path in RESULTS_DIR.rglob("*"):
                if path.is_file():
                    zf.write(path, arcname=str(Path("scans") / path.relative_to(RESULTS_DIR)))
        # standalone reports dir, if provided. Skip any .zip (never re-bundle a
        # prior workspace export — that's what produced a runaway self-include).
        if reports_dir:
            rp = Path(reports_dir)
            if rp.exists():
                for path in rp.rglob("*"):
                    if path.is_file() and path.suffix.lower() != ".zip":
                        zf.write(path, arcname=str(Path("reports") / path.relative_to(rp)))
    return out_path


# ─── Phase 11.98: Ask-AI conversation persistence ───────────────────────────
def create_conversation(scan_id: str, title: str = "New conversation",
                        provider: str = "", model: str = "", chat_id: str | None = None) -> dict:
    import uuid
    cid = chat_id or str(uuid.uuid4())
    try:
        init_db()
        with get_conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO ai_conversations (chat_id, scan_id, title, provider, model) "
                "VALUES (?,?,?,?,?)", (cid, scan_id, title, provider or "", model or ""))
            conn.commit()
    except Exception as e:
        print(f"[DB] create_conversation error: {e}")
    return {"chat_id": cid, "scan_id": scan_id, "title": title, "provider": provider, "model": model}


def list_conversations(scan_id: str) -> list[dict]:
    try:
        init_db()
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT c.*, (SELECT COUNT(*) FROM ai_messages m WHERE m.chat_id=c.chat_id) AS message_count "
                "FROM ai_conversations c WHERE scan_id=? ORDER BY updated_at DESC", (scan_id,)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB] list_conversations error: {e}")
        return []


def get_conversation(chat_id: str) -> dict | None:
    try:
        init_db()
        with get_conn() as conn:
            convo = conn.execute("SELECT * FROM ai_conversations WHERE chat_id=?", (chat_id,)).fetchone()
            if not convo:
                return None
            msgs = conn.execute(
                "SELECT id, role, content, meta, created_at FROM ai_messages WHERE chat_id=? ORDER BY id",
                (chat_id,)).fetchall()
            out = dict(convo)
            out["messages"] = []
            for m in msgs:
                md = dict(m)
                try:
                    md["meta"] = json.loads(md["meta"]) if md.get("meta") else {}
                except Exception:
                    md["meta"] = {}
                out["messages"].append(md)
            return out
    except Exception as e:
        print(f"[DB] get_conversation error: {e}")
        return None


def add_message(chat_id: str, role: str, content: str, meta: dict | None = None) -> dict:
    try:
        init_db()
        with get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO ai_messages (chat_id, role, content, meta) VALUES (?,?,?,?)",
                (chat_id, role, content or "", json.dumps(meta or {})))
            conn.execute("UPDATE ai_conversations SET updated_at=datetime('now') WHERE chat_id=?", (chat_id,))
            conn.commit()
            return {"id": cur.lastrowid, "chat_id": chat_id, "role": role, "content": content, "meta": meta or {}}
    except Exception as e:
        print(f"[DB] add_message error: {e}")
        return {"error": str(e)}


def rename_conversation(chat_id: str, title: str) -> bool:
    try:
        init_db()
        with get_conn() as conn:
            conn.execute("UPDATE ai_conversations SET title=?, updated_at=datetime('now') WHERE chat_id=?",
                         (title.strip() or "Untitled", chat_id))
            conn.commit()
        return True
    except Exception as e:
        print(f"[DB] rename_conversation error: {e}")
        return False


def delete_conversation(chat_id: str) -> bool:
    try:
        init_db()
        with get_conn() as conn:
            conn.execute("DELETE FROM ai_messages WHERE chat_id=?", (chat_id,))
            conn.execute("DELETE FROM ai_conversations WHERE chat_id=?", (chat_id,))
            conn.commit()
        return True
    except Exception as e:
        print(f"[DB] delete_conversation error: {e}")
        return False


def import_workspace(zip_path: str) -> dict:
    """Restore a workspace.zip: extract results to disk and upsert DB metadata.
    Existing scans with the same id are replaced (no duplicates)."""
    import zipfile
    init_db()
    report = {"imported": 0, "skipped": 0, "scan_ids": []}
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        # 1) extract scan result dirs
        for name in names:
            if name.startswith("scans/") and not name.endswith("/"):
                target = RESULTS_DIR / Path(name).relative_to("scans")
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(name) as src, open(target, "wb") as dst:
                    dst.write(src.read())
        # 2) upsert metadata
        meta = {}
        if "metadata.json" in names:
            try:
                meta = json.loads(zf.read("metadata.json").decode("utf-8", "replace"))
            except Exception:
                meta = {}
    for row in (meta.get("scans") or []):
        sid = row.get("scan_id")
        if not sid:
            continue
        res = get_scan_results(sid)  # reads the just-extracted disk file
        if res:
            save_scan(res)           # rebuilds metadata + findings rows (idempotent upsert)
            report["imported"] += 1
            report["scan_ids"].append(sid)
        else:
            report["skipped"] += 1
    return report


def compare_scans(scan_id_a: str, scan_id_b: str) -> dict:
    """Diff two persisted scans (A=baseline, B=current): added / removed findings,
    severity changes, trust-score delta, and attack-chain changes. Read-only —
    never mutates findings or chains."""
    try:
        findings_a = {f["rule_id"] or f["title"]: f for f in get_scan_findings(scan_id_a) if f.get("rule_id") or f.get("title")}
        findings_b = {f["rule_id"] or f["title"]: f for f in get_scan_findings(scan_id_b) if f.get("rule_id") or f.get("title")}

        keys_a, keys_b = set(findings_a), set(findings_b)
        added    = [findings_b[k] for k in keys_b - keys_a]   # in B, not A
        removed  = [findings_a[k] for k in keys_a - keys_b]   # in A, not B
        common   = [findings_b[k] for k in keys_a & keys_b]

        severity_changes = []
        for k in keys_a & keys_b:
            sa, sb = normalize_severity(findings_a[k].get("severity")), normalize_severity(findings_b[k].get("severity"))
            if sa != sb:
                severity_changes.append({"key": k, "title": findings_b[k].get("title"),
                                          "from": sa, "to": sb})

        # Trust + attack-chain deltas from the on-disk results (best-effort).
        res_a, res_b = get_scan_results(scan_id_a) or {}, get_scan_results(scan_id_b) or {}
        ta = (res_a.get("trust_score") or {}).get("score")
        tb = (res_b.get("trust_score") or {}).get("score")
        def _chain_titles(res):
            qs = res.get("quick_summary") or {}
            titles = {c.get("title") for c in (qs.get("attack_chain") or []) if isinstance(c, dict) and c.get("title")}
            titles |= {f.get("title") for f in (res.get("findings") or []) if f.get("is_attack_chain") and f.get("title")}
            return titles
        chains_a, chains_b = _chain_titles(res_a), _chain_titles(res_b)

        return {
            # legacy keys kept for any existing callers
            "new": added, "fixed": removed, "common": common,
            # Phase 11.99 explicit naming
            "added": added, "removed": removed,
            "severity_changes": severity_changes,
            "trust": {"a": ta, "b": tb,
                      "delta": (tb - ta) if isinstance(ta, (int, float)) and isinstance(tb, (int, float)) else None},
            "attack_chains": {
                "added":   sorted(chains_b - chains_a),
                "removed": sorted(chains_a - chains_b),
                "a_count": len(chains_a), "b_count": len(chains_b),
            },
            "summary": {
                "new_count": len(added), "added_count": len(added),
                "fixed_count": len(removed), "removed_count": len(removed),
                "unchanged": len(common),
                "severity_changed": len(severity_changes),
            },
        }
    except Exception as e:
        print(f"[DB] compare_scans error: {e}")
        return {"new": [], "fixed": [], "added": [], "removed": [], "common": [],
                "severity_changes": [], "trust": {}, "attack_chains": {}, "summary": {}}


