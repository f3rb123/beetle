"""
Cortex Scan Policy Engine
==========================
Stores a configurable pass/fail threshold policy in SQLite and evaluates
scan results against it.

Policy fields (all stored as JSON in a single row):
  max_critical        int  — fail if critical findings > this  (-1 = disabled)
  max_high            int  — fail if high findings > this       (-1 = disabled)
  max_medium          int  — fail if medium findings > this     (-1 = disabled)
  max_low             int  — fail if low findings > this        (-1 = disabled)
  min_score           int  — fail if security score < this      (0  = disabled)
  block_on_malware    bool — fail if VirusTotal detects malware
  block_on_secrets    bool — fail if validated live secrets found

check_policy() returns:
  {
    "passed":  bool,
    "verdict": "pass" | "fail",
    "score":   int | None,
    "reasons": [str, ...],   # human-readable failure reasons
    "policy":  {current thresholds},
    "summary": {findings_by_severity, secrets_count, malware_detected}
  }
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
import os

_DATA_DIR = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
_DB_PATH  = _DATA_DIR / "cortex.db"

DEFAULT_POLICY: dict = {
    "max_critical":     0,      # any critical finding → fail
    "max_high":        -1,      # disabled
    "max_medium":      -1,
    "max_low":         -1,
    "min_score":        0,      # disabled (0 = no minimum)
    "block_on_malware":  True,
    "block_on_secrets":  False,
}

_THRESHOLD_FIELDS = ("max_critical", "max_high", "max_medium", "max_low", "min_score")
_BOOL_FIELDS      = ("block_on_malware", "block_on_secrets")


def _conn() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_policy_db() -> None:
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_policy (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                policy  TEXT    NOT NULL
            )
        """)
        # Seed with defaults if empty
        row = c.execute("SELECT id FROM scan_policy WHERE id = 1").fetchone()
        if not row:
            c.execute(
                "INSERT INTO scan_policy (id, policy) VALUES (1, ?)",
                (json.dumps(DEFAULT_POLICY),),
            )
        c.commit()


def get_policy() -> dict:
    try:
        with _conn() as c:
            row = c.execute("SELECT policy FROM scan_policy WHERE id = 1").fetchone()
            if row:
                stored = json.loads(row["policy"])
                # Merge with defaults so new fields are always present
                merged = {**DEFAULT_POLICY, **stored}
                return merged
    except Exception:
        pass
    return dict(DEFAULT_POLICY)


def set_policy(updates: dict) -> dict:
    current = get_policy()
    for field in _THRESHOLD_FIELDS:
        if field in updates:
            val = int(updates[field])
            current[field] = val
    for field in _BOOL_FIELDS:
        if field in updates:
            current[field] = bool(updates[field])
    with _conn() as c:
        c.execute(
            "INSERT INTO scan_policy (id, policy) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET policy = excluded.policy",
            (json.dumps(current),),
        )
        c.commit()
    return current


def check_policy(results: dict, overrides: dict | None = None) -> dict:
    """
    Evaluate scan results against the stored policy (merged with any overrides).

    overrides: optional dict of threshold overrides for one-shot CI checks
               (same keys as the policy, not persisted).
    """
    policy = get_policy()
    if overrides:
        for field in _THRESHOLD_FIELDS:
            if field in overrides:
                policy[field] = int(overrides[field])
        for field in _BOOL_FIELDS:
            if field in overrides:
                policy[field] = bool(overrides[field])

    ss     = results.get("severity_summary") or {}
    score  = (results.get("score") or {}).get("score")
    secrets = results.get("secrets") or []
    vt     = results.get("virustotal") or {}

    counts = {
        "critical": ss.get("critical", 0),
        "high":     ss.get("high",     0),
        "medium":   ss.get("medium",   0),
        "low":      ss.get("low",      0),
    }

    reasons: list[str] = []

    # Threshold checks
    for sev in ("critical", "high", "medium", "low"):
        threshold = policy.get(f"max_{sev}", -1)
        if threshold >= 0 and counts[sev] > threshold:
            reasons.append(
                f"{counts[sev]} {sev} finding{'s' if counts[sev] != 1 else ''} "
                f"(threshold: {threshold})"
            )

    # Score check
    min_score = policy.get("min_score", 0)
    if min_score > 0 and score is not None and score < min_score:
        reasons.append(f"Security score {score} below minimum {min_score}")

    # Malware check
    if policy.get("block_on_malware"):
        main_report = vt.get("main") or {}
        malicious_main = main_report.get("malicious", 0)
        malicious_dex  = sum(d.get("malicious", 0) for d in (vt.get("dex_files") or []))
        if malicious_main + malicious_dex > 0:
            reasons.append(
                f"VirusTotal: {malicious_main + malicious_dex} engine(s) flagged file as malicious"
            )

    # Live secrets check
    if policy.get("block_on_secrets"):
        live = sum(1 for s in secrets if s.get("validated") or s.get("live"))
        if live > 0:
            reasons.append(f"{live} validated live secret{'s' if live != 1 else ''} found")

    passed  = len(reasons) == 0
    verdict = "pass" if passed else "fail"

    return {
        "passed":  passed,
        "verdict": verdict,
        "score":   score,
        "reasons": reasons,
        "policy":  policy,
        "summary": {
            "findings_by_severity": counts,
            "secrets_count":        len(secrets),
            "malware_detected":     bool(
                (vt.get("main") or {}).get("malicious", 0) > 0
            ),
        },
    }
