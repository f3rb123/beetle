"""
Cortex Webhook / Notification Engine
======================================
Stores webhook endpoints in SQLite and fires them asynchronously
after each scan completes.

Supported target types
  - slack    : Slack Incoming Webhook — sends a formatted Block Kit message
  - generic  : Arbitrary HTTP POST — sends a JSON payload

Schema (added to the cortex.db managed by auth.py / _conn())
  webhooks(id, label, url, type, events, secret, active, created_at, last_fired, last_status)

  events: comma-separated list, currently: 'scan.completed', 'scan.failed'
  secret: if non-empty, added as X-Cortex-Signature HMAC-SHA256 header
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
import os

import httpx

_DATA_DIR = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
_DB_PATH  = _DATA_DIR / "cortex.db"

VALID_EVENTS = {"scan.completed", "scan.failed"}
VALID_TYPES  = {"slack", "generic"}
TIMEOUT_S    = 10
MAX_RETRIES  = 2

# SSRF defense: block internal ranges and cloud metadata endpoints by default.
# Set CORTEX_WEBHOOKS_ALLOW_INTERNAL=1 only on isolated dev boxes.
_ALLOW_INTERNAL = os.environ.get("CORTEX_WEBHOOKS_ALLOW_INTERNAL", "0") == "1"
_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",   # AWS / Azure / GCP IMDS
    "metadata.google.internal",
    "metadata",
    "fd00:ec2::254",
}


def _is_blocked_host(hostname: str) -> tuple[bool, str]:
    """Resolve hostname and reject private/link-local/loopback/metadata IPs.

    Called at create/update (for immediate feedback) and at delivery time
    (mitigates DNS rebinding — an attacker who swaps A records after admin
    approval still gets blocked here).
    """
    if not hostname:
        return True, "missing host"
    host_l = hostname.lower().strip(".")
    if host_l in _CLOUD_METADATA_HOSTS:
        return True, f"cloud metadata host: {hostname}"
    # Also reject anything that resolves to / literally IS a blocked range.
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return True, f"DNS resolution failed: {e}"
    for info in infos:
        addr = info[4][0]
        # Strip scope id from IPv6 addrs
        addr = addr.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local \
           or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True, f"blocked internal address: {addr}"
        # Explicit metadata IPs
        if str(ip) in _CLOUD_METADATA_HOSTS:
            return True, f"cloud metadata address: {addr}"
    return False, ""


def _validate_webhook_url(url: str):
    """Raise ValueError if the URL fails SSRF policy."""
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValueError(f"invalid URL: {e}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if _ALLOW_INTERNAL:
        return
    blocked, why = _is_blocked_host(parsed.hostname)
    if blocked:
        raise ValueError(f"webhook URL rejected: {why}")


# ── DB helpers ────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_webhooks_db():
    """Create webhooks table. Safe to call multiple times."""
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                label       TEXT NOT NULL DEFAULT '',
                url         TEXT NOT NULL,
                type        TEXT NOT NULL DEFAULT 'generic',
                events      TEXT NOT NULL DEFAULT 'scan.completed',
                secret      TEXT NOT NULL DEFAULT '',
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT DEFAULT (datetime('now')),
                last_fired  TEXT,
                last_status TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(active);
        """)


# ── CRUD ──────────────────────────────────────────────────────────────────────

def create_webhook(label: str, url: str, type_: str = "generic",
                   events: list[str] | None = None, secret: str = "") -> dict:
    if type_ not in VALID_TYPES:
        raise ValueError(f"type must be one of {VALID_TYPES}")
    _validate_webhook_url(url)
    ev = events or ["scan.completed"]
    invalid = set(ev) - VALID_EVENTS
    if invalid:
        raise ValueError(f"Unknown events: {invalid}")
    events_str = ",".join(ev)
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO webhooks (label, url, type, events, secret) VALUES (?,?,?,?,?)",
            (label, url, type_, events_str, secret),
        )
        wid = cur.lastrowid
    return get_webhook(wid)


def get_webhook(wid: int) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM webhooks WHERE id = ?", (wid,)).fetchone()
        if row:
            d = dict(row)
            d["events"] = d["events"].split(",")
            return d
    return None


def list_webhooks() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM webhooks ORDER BY id"
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["events"] = d["events"].split(",")
        d.pop("secret", None)   # never expose secret over API
        result.append(d)
    return result


def update_webhook(wid: int, **fields) -> dict | None:
    allowed = {"label", "url", "type", "events", "secret", "active"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if "events" in updates and isinstance(updates["events"], list):
        updates["events"] = ",".join(updates["events"])
    if "type" in updates and updates["type"] not in VALID_TYPES:
        raise ValueError(f"type must be one of {VALID_TYPES}")
    if "url" in updates:
        _validate_webhook_url(updates["url"])
    if not updates:
        return get_webhook(wid)
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [wid]
    with _conn() as conn:
        conn.execute(f"UPDATE webhooks SET {set_clause} WHERE id = ?", values)
    return get_webhook(wid)


def delete_webhook(wid: int):
    with _conn() as conn:
        conn.execute("DELETE FROM webhooks WHERE id = ?", (wid,))


def _set_webhook_status(wid: int, status: str):
    with _conn() as conn:
        conn.execute(
            "UPDATE webhooks SET last_fired = datetime('now'), last_status = ? WHERE id = ?",
            (status, wid),
        )


# ── Fire webhooks (called after scan) ────────────────────────────────────────

def fire_scan_event(event: str, scan_summary: dict):
    """
    Non-blocking: fires all active webhooks that subscribe to `event`
    in a background thread pool (one thread per webhook).
    """
    try:
        with _conn() as conn:
            rows = conn.execute(
                "SELECT * FROM webhooks WHERE active = 1"
            ).fetchall()
    except Exception:
        return

    for row in rows:
        wh = dict(row)
        wh_events = wh.get("events", "").split(",")
        if event not in wh_events:
            continue
        t = threading.Thread(
            target=_deliver_with_retry,
            args=(wh, event, scan_summary),
            daemon=True,
        )
        t.start()


def _deliver_with_retry(wh: dict, event: str, summary: dict):
    for attempt in range(MAX_RETRIES):
        try:
            _deliver(wh, event, summary)
            _set_webhook_status(wh["id"], "ok")
            return
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                _set_webhook_status(wh["id"], f"error: {str(e)[:120]}")
            else:
                time.sleep(2 ** attempt)


def _deliver(wh: dict, event: str, summary: dict):
    wtype = wh.get("type", "generic")
    url   = wh["url"]

    # DNS-rebinding defense: re-validate at delivery time. Also disable redirects
    # so a 302 can't be used to pivot to an internal target after policy passes.
    _validate_webhook_url(url)

    if wtype == "slack":
        payload = _build_slack_payload(event, summary)
    else:
        payload = _build_generic_payload(event, summary)

    body    = json.dumps(payload, default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Cortex/1.0"}

    secret = wh.get("secret", "")
    if secret:
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Cortex-Signature"] = f"sha256={sig}"

    with httpx.Client(timeout=TIMEOUT_S, follow_redirects=False) as client:
        resp = client.post(url, content=body, headers=headers)
        resp.raise_for_status()


# ── Payload builders ──────────────────────────────────────────────────────────

def _build_generic_payload(event: str, summary: dict) -> dict:
    return {
        "event":      event,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "scan_id":    summary.get("scan_id"),
        "app_name":   summary.get("app_name"),
        "platform":   summary.get("platform"),
        "status":     summary.get("status"),
        "score":      summary.get("score"),
        "grade":      summary.get("grade"),
        "findings":   summary.get("findings_by_severity", {}),
        "url":        summary.get("report_url", ""),
    }


def _build_slack_payload(event: str, summary: dict) -> dict:
    app      = summary.get("app_name", "Unknown App")
    platform = summary.get("platform", "").capitalize()
    status   = summary.get("status", "")
    score    = summary.get("score")
    grade    = summary.get("grade", "?")
    sev      = summary.get("findings_by_severity", {})
    scan_id  = summary.get("scan_id", "")

    # Emoji / color by status
    if status == "completed":
        color  = "#10b981"
        emoji  = ":white_check_mark:"
        title  = f"{emoji} Scan Complete — {app}"
    else:
        color  = "#ef4444"
        emoji  = ":x:"
        title  = f"{emoji} Scan Failed — {app}"

    finding_lines = []
    for sev_level in ("critical", "high", "medium", "low"):
        n = sev.get(sev_level, 0)
        if n:
            icons = {"critical": ":red_circle:", "high": ":orange_circle:",
                     "medium": ":yellow_circle:", "low": ":white_circle:"}
            finding_lines.append(f"{icons[sev_level]} *{sev_level.capitalize()}*: {n}")

    score_str = f"Grade *{grade}* ({score}/100)" if score is not None else ""

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title, "emoji": True},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*App:*\n{app}"},
                {"type": "mrkdwn", "text": f"*Platform:*\n{platform}"},
                {"type": "mrkdwn", "text": f"*Score:*\n{score_str or '—'}"},
                {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id[:8]}`"},
            ],
        },
    ]

    if finding_lines:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Findings*\n" + "\n".join(finding_lines)},
        })

    report_url = summary.get("report_url", "")
    if report_url:
        blocks.append({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "View Report", "emoji": True},
                "url": report_url,
                "style": "primary",
            }],
        })

    return {
        "attachments": [{
            "color":  color,
            "blocks": blocks,
        }]
    }


# ── Build scan summary from results dict ──────────────────────────────────────

def build_scan_summary(results: dict, base_url: str = "") -> dict:
    sev = results.get("severity_summary", {})
    score_data = results.get("score", {})
    scan_id = results.get("scan_id", "")
    return {
        "scan_id":            scan_id,
        "app_name":           results.get("app_name", ""),
        "platform":           results.get("platform", ""),
        "status":             "completed",
        "score":              score_data.get("score"),
        "grade":              score_data.get("grade"),
        "findings_by_severity": {
            "critical": sev.get("critical", 0),
            "high":     sev.get("high", 0),
            "medium":   sev.get("medium", 0),
            "low":      sev.get("low", 0),
        },
        "report_url": f"{base_url}/scans/{scan_id}/dashboard" if scan_id else "",
    }
