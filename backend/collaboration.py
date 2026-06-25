"""
Collaboration layer — finding states, comments, assignment, suppression.

Design note (the "survive rescans" guarantee):
  Every collaborative artifact is keyed by ``(app_id, finding_key)``, NOT by
  ``scan_id``. A rescan of the same app mints a new scan_id but keeps the same
  ``app_id`` (the package / bundle id) and the same ``finding_key``
  (rule_id, else a title slug — identical to the frontend's _triageKey). So a
  triage state, comment, assignment, or suppression set on one scan is
  automatically inherited by every later scan of the same app.

All functions are best-effort: a DB error degrades to an empty/no-op result
rather than crashing a scan or a request. Reuses database.get_conn().
"""
from __future__ import annotations

import logging
import re

from database import get_conn, init_db, normalize_severity

log = logging.getLogger("cortex.collab")

# ── Vocabulary ───────────────────────────────────────────────────────────────
# The six formal finding states (point 2 of the spec). 'open' is the default.
FINDING_STATES = (
    "open", "confirmed", "false_positive", "accepted_risk", "mitigated", "need_review",
)
# States that take a finding out of the "active / needs work" bucket.
RESOLVED_STATES = ("false_positive", "accepted_risk", "mitigated")

PRIORITIES = ("P1", "P2", "P3", "P4")


def finding_key(finding: dict) -> str:
    """Stable identity for a finding. MUST match the frontend's _triageKey:
    rule_id if present, else a slug of the title."""
    rid = (finding.get("rule_id") or "").strip()
    if rid:
        return rid
    title = (finding.get("title") or "").strip()
    return re.sub(r"\s+", "_", title)[:80] or "unknown"


def app_id_for(results_or_info: dict) -> str:
    """Derive a stable app identity from a results blob (or app_info dict).
    Prefers package/bundle_id; falls back to sha256, then app_name."""
    info = results_or_info.get("app_info") or results_or_info
    return (
        (info.get("package") or info.get("bundle_id") or "").strip()
        or (info.get("sha256") or "").strip()
        or (results_or_info.get("app_name") or info.get("app_name") or "").strip()
        or "unknown-app"
    )


# ── Schema ─────────────────────────────────────────────────────────────────
def init_collab_db():
    """Create collaboration tables + sharing columns. Idempotent."""
    init_db()  # ensure base tables/connection exist
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS finding_meta (
                app_id      TEXT NOT NULL,
                finding_key TEXT NOT NULL,
                state       TEXT DEFAULT 'open',
                priority    TEXT DEFAULT '',
                assignee    TEXT DEFAULT '',
                updated_by  TEXT DEFAULT '',
                updated_at  TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (app_id, finding_key)
            );

            CREATE TABLE IF NOT EXISTS finding_comments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id      TEXT NOT NULL,
                finding_key TEXT NOT NULL,
                author      TEXT DEFAULT '',
                body        TEXT NOT NULL,
                created_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_fcomments ON finding_comments(app_id, finding_key);

            CREATE TABLE IF NOT EXISTS suppressions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id       TEXT DEFAULT '',   -- '' = applies to every app (global)
                rule_id      TEXT DEFAULT '',   -- '' = any rule
                file_pattern TEXT DEFAULT '',   -- '' = any file; substring/glob match
                reason       TEXT DEFAULT '',
                created_by   TEXT DEFAULT '',
                created_at   TEXT DEFAULT (datetime('now')),
                active       INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_suppress_app ON suppressions(app_id, active);
        """)
        # Sharing columns on the existing scans table (point 6). Default 'team'
        # preserves the pre-existing behaviour (every authenticated user sees it).
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}
        for col, ddl in (
            ("share_mode", "ALTER TABLE scans ADD COLUMN share_mode TEXT DEFAULT 'team'"),
            ("owner",      "ALTER TABLE scans ADD COLUMN owner TEXT DEFAULT ''"),
        ):
            if col not in cols:
                try:
                    conn.execute(ddl)
                except Exception as e:
                    log.debug(f"scans.{col} migration skip: {e}")
        conn.commit()


# ── Finding state / assignment / priority ────────────────────────────────────
def get_finding_meta(app_id: str) -> dict:
    """All per-finding metadata for an app, as {finding_key: {state, priority,
    assignee, updated_by, updated_at}}."""
    try:
        init_collab_db()
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT finding_key, state, priority, assignee, updated_by, updated_at "
                "FROM finding_meta WHERE app_id = ?", (app_id,),
            ).fetchall()
        return {r["finding_key"]: {k: r[k] for k in r.keys() if k != "finding_key"} for r in rows}
    except Exception as e:
        log.debug(f"get_finding_meta error: {e}")
        return {}


def _upsert_meta(app_id: str, key: str, fields: dict, by: str) -> dict:
    """Insert-or-update one finding_meta row, touching only the given fields."""
    init_collab_db()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT state, priority, assignee FROM finding_meta WHERE app_id=? AND finding_key=?",
            (app_id, key),
        ).fetchone()
        cur = dict(existing) if existing else {"state": "open", "priority": "", "assignee": ""}
        cur.update(fields)
        conn.execute("""
            INSERT INTO finding_meta (app_id, finding_key, state, priority, assignee, updated_by, updated_at)
            VALUES (?,?,?,?,?,?, datetime('now'))
            ON CONFLICT(app_id, finding_key) DO UPDATE SET
                state=excluded.state, priority=excluded.priority, assignee=excluded.assignee,
                updated_by=excluded.updated_by, updated_at=excluded.updated_at
        """, (app_id, key, cur["state"], cur["priority"], cur["assignee"], by or ""))
        conn.commit()
    return {"finding_key": key, **cur, "updated_by": by or ""}


def set_finding_state(app_id: str, key: str, state: str, by: str = "") -> dict:
    if state not in FINDING_STATES:
        raise ValueError(f"state must be one of: {', '.join(FINDING_STATES)}")
    return _upsert_meta(app_id, key, {"state": state}, by)


def assign_finding(app_id: str, key: str, assignee: str = "", priority: str = "", by: str = "") -> dict:
    fields = {"assignee": assignee or ""}
    if priority:
        if priority not in PRIORITIES:
            raise ValueError(f"priority must be one of: {', '.join(PRIORITIES)}")
        fields["priority"] = priority
    return _upsert_meta(app_id, key, fields, by)


# ── Comments ─────────────────────────────────────────────────────────────────
def list_comments(app_id: str, key: str | None = None) -> list[dict] | dict:
    """If key is given, a list of comments for that finding (oldest first).
    Otherwise a {finding_key: [comments]} map for the whole app."""
    try:
        init_collab_db()
        with get_conn() as conn:
            if key is not None:
                rows = conn.execute(
                    "SELECT id, finding_key, author, body, created_at FROM finding_comments "
                    "WHERE app_id=? AND finding_key=? ORDER BY id", (app_id, key),
                ).fetchall()
                return [dict(r) for r in rows]
            rows = conn.execute(
                "SELECT id, finding_key, author, body, created_at FROM finding_comments "
                "WHERE app_id=? ORDER BY id", (app_id,),
            ).fetchall()
        out: dict[str, list] = {}
        for r in rows:
            out.setdefault(r["finding_key"], []).append(dict(r))
        return out
    except Exception as e:
        log.debug(f"list_comments error: {e}")
        return [] if key is not None else {}


def add_comment(app_id: str, key: str, body: str, author: str = "") -> dict:
    body = (body or "").strip()
    if not body:
        raise ValueError("comment body is required")
    init_collab_db()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO finding_comments (app_id, finding_key, author, body) VALUES (?,?,?,?)",
            (app_id, key, author or "", body),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id, finding_key, author, body, created_at FROM finding_comments WHERE id=?",
            (cur.lastrowid,),
        ).fetchone()
    return dict(row) if row else {}


def delete_comment(comment_id: int) -> bool:
    try:
        init_collab_db()
        with get_conn() as conn:
            conn.execute("DELETE FROM finding_comments WHERE id=?", (comment_id,))
            conn.commit()
        return True
    except Exception as e:
        log.debug(f"delete_comment error: {e}")
        return False


# ── Suppressions ─────────────────────────────────────────────────────────────
def list_suppressions(app_id: str | None = None) -> list[dict]:
    """Active suppressions. If app_id given, returns global ('' app_id) plus
    that app's suppressions; otherwise every suppression."""
    try:
        init_collab_db()
        with get_conn() as conn:
            if app_id is None:
                rows = conn.execute(
                    "SELECT * FROM suppressions WHERE active=1 ORDER BY id DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM suppressions WHERE active=1 AND (app_id='' OR app_id=?) ORDER BY id DESC",
                    (app_id,),
                ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        log.debug(f"list_suppressions error: {e}")
        return []


def add_suppression(rule_id: str = "", file_pattern: str = "", reason: str = "",
                    app_id: str = "", created_by: str = "") -> dict:
    rule_id, file_pattern = (rule_id or "").strip(), (file_pattern or "").strip()
    if not rule_id and not file_pattern:
        raise ValueError("a suppression needs at least a rule or a file pattern")
    if not (reason or "").strip():
        raise ValueError("a reason is required")
    init_collab_db()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO suppressions (app_id, rule_id, file_pattern, reason, created_by) "
            "VALUES (?,?,?,?,?)",
            (app_id or "", rule_id, file_pattern, reason.strip(), created_by or ""),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM suppressions WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row) if row else {}


def delete_suppression(supp_id: int) -> bool:
    try:
        init_collab_db()
        with get_conn() as conn:
            conn.execute("UPDATE suppressions SET active=0 WHERE id=?", (supp_id,))
            conn.commit()
        return True
    except Exception as e:
        log.debug(f"delete_suppression error: {e}")
        return False


def _matches(supp: dict, finding: dict) -> bool:
    rid = supp.get("rule_id") or ""
    fpat = supp.get("file_pattern") or ""
    if rid and (finding.get("rule_id") or "") != rid:
        return False
    if fpat:
        path = finding.get("file_path") or ""
        if not path and finding.get("files"):
            path = (finding["files"] or [""])[0] or ""
        # Glob-ish: treat '*' as wildcard, otherwise substring match.
        if "*" in fpat:
            rx = "^" + re.escape(fpat).replace(r"\*", ".*") + "$"
            if not re.search(rx, path):
                return False
        elif fpat not in path:
            return False
    return True


def apply_suppressions(results: dict) -> dict:
    """Partition results['findings'] into active vs suppressed using the stored
    suppressions for this app. Suppressed findings are MOVED to
    results['suppressed_findings'] (tagged with the reason) so every downstream
    consumer — severity summary, DB rows, PDF/SARIF, UI — sees only the active
    set, while the suppressed ones remain inspectable. Called from save_scan, so
    future scans automatically respect suppressions (point 5)."""
    try:
        findings = results.get("findings") or []
        if not findings:
            return results
        app_id = app_id_for(results)
        supps = list_suppressions(app_id)
        if not supps:
            return results
        active, suppressed = [], []
        for f in findings:
            hit = next((s for s in supps if _matches(s, f)), None)
            if hit:
                f = {**f, "suppressed": True,
                     "suppression_reason": hit.get("reason", ""),
                     "suppression_id": hit.get("id")}
                suppressed.append(f)
            else:
                active.append(f)
        if suppressed:
            results["findings"] = active
            results["suppressed_findings"] = (results.get("suppressed_findings") or []) + suppressed
            log.info(f"[{results.get('scan_id')}] suppressed {len(suppressed)} finding(s) "
                     f"via {len(supps)} active suppression(s)")
    except Exception as e:
        log.debug(f"apply_suppressions error: {e}")
    return results


# ── Sharing (point 6) ────────────────────────────────────────────────────────
SHARE_MODES = ("private", "shared", "team")


def set_share_mode(scan_id: str, mode: str) -> dict:
    if mode not in SHARE_MODES:
        raise ValueError(f"mode must be one of: {', '.join(SHARE_MODES)}")
    init_collab_db()
    with get_conn() as conn:
        conn.execute("UPDATE scans SET share_mode=? WHERE scan_id=?", (mode, scan_id))
        conn.commit()
    return {"scan_id": scan_id, "share_mode": mode}


def get_share(scan_id: str) -> dict:
    try:
        init_collab_db()
        with get_conn() as conn:
            row = conn.execute(
                "SELECT share_mode, owner FROM scans WHERE scan_id=?", (scan_id,)
            ).fetchone()
        if not row:
            return {"share_mode": "team", "owner": ""}
        return {"share_mode": row["share_mode"] or "team", "owner": row["owner"] or ""}
    except Exception:
        return {"share_mode": "team", "owner": ""}


def can_view(scan_id: str, user: dict | None) -> bool:
    """Soft sharing enforcement. 'team'/'shared' → any authenticated user;
    'private' → owner, admin, or manager only."""
    share = get_share(scan_id)
    if share["share_mode"] != "private":
        return True
    if not user:
        return False
    from auth import role_at_least
    return (user.get("username") and user["username"] == share["owner"]) or \
        role_at_least(user.get("role"), "manager")


# ── Combined view for one scan ───────────────────────────────────────────────
def collab_for_scan(scan_id: str) -> dict:
    """Everything the workspace UI needs for a scan in one call, resolved via
    the scan's app_id so prior-scan triage/comments/assignments carry over."""
    from database import get_scan_results
    res = get_scan_results(scan_id) or {}
    app_id = app_id_for(res) if res else "unknown-app"
    return {
        "app_id": app_id,
        "states": FINDING_STATES,
        "priorities": PRIORITIES,
        "meta": get_finding_meta(app_id),
        "comments": list_comments(app_id),
        "suppressions": list_suppressions(app_id),
        "share": get_share(scan_id),
    }
