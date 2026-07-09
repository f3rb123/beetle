"""
Raw-SQL severity tests (android_sqlite_raw_query).

The rule fires on every rawQuery/execSQL/compileStatement, so it used to flag safe
parameterized calls — rawQuery("… WHERE id = ?", args) — as HIGH alongside genuinely
injectable concatenated ones. Severity is now reconciled from real evidence:

  * parameterized ('?' + selectionArgs, no string building) → INFO
  * string-built SQL ('+' concat / String.format / Kotlin interpolation) → HIGH
  * a taint flow reaching the SQLite sink → HIGH
  * a taint SQLite FINDING for the same class → the SAST finding is dropped
    (deduped, so a single raw query is not double-counted)

Runnable standalone or under pytest:
    python -m tests.test_sql_raw_query_severity      # from backend/
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers.code_analyzer import (  # noqa: E402
    _has_sql_string_building,
    resolve_sql_raw_query_severity,
)


def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


# The two snippets the task asks for.
PARAMETERIZED = 'db.rawQuery("SELECT * FROM users WHERE id = ?", new String[]{ userId });'
CONCATENATED = 'db.rawQuery("SELECT * FROM users WHERE id = " + userId, null);'


def _raw_finding(path, snippet):
    return {
        "rule_id": "android_sqlite_raw_query",
        "title": "Raw SQL Query — SQL Injection Risk",
        "severity": "high",  # the rule's static default, before reconciliation
        "category": "Data Storage",
        "file_path": path,
        "snippet": snippet,
        "code_context": snippet,
        "file_evidence": [{"path": path, "lines": [10], "snippet": snippet}],
    }


# ════════════════════════════════════════════════════════════════════════════
# Task acceptance: parameterized → INFO, concatenated → HIGH.
# ════════════════════════════════════════════════════════════════════════════
def test_parameterized_raw_query_downgraded_to_info():
    results = {"findings": [_raw_finding("sources/com/app/SafeDao.java", PARAMETERIZED)]}
    resolve_sql_raw_query_severity(results)
    f = results["findings"][0]
    _check(f["severity"] == "info",
           f"parameterized raw query must be INFO, got {f['severity']!r}")
    _check("parameterized" in f.get("sql_injection_evidence", ""),
           "downgrade should record it was parameterized")
    _check("Parameterized" in f["title"], "title should reflect the parameterized downgrade")


def test_concatenated_raw_query_stays_high():
    results = {"findings": [_raw_finding("sources/com/app/UnsafeDao.java", CONCATENATED)]}
    resolve_sql_raw_query_severity(results)
    f = results["findings"][0]
    _check(f["severity"] == "high",
           f"concatenated raw query must stay HIGH, got {f['severity']!r}")
    _check("string-building" in f.get("sql_injection_evidence", ""),
           "HIGH should cite the string-building evidence")


def test_both_snippets_in_one_pass():
    """One parameterized (INFO) and one concatenated (HIGH), reconciled together."""
    results = {"findings": [
        _raw_finding("sources/com/app/SafeDao.java", PARAMETERIZED),
        _raw_finding("sources/com/app/UnsafeDao.java", CONCATENATED),
    ]}
    stats = resolve_sql_raw_query_severity(results)
    by_path = {f["file_path"]: f["severity"] for f in results["findings"]}
    _check(by_path["sources/com/app/SafeDao.java"] == "info", "safe → INFO")
    _check(by_path["sources/com/app/UnsafeDao.java"] == "high", "unsafe → HIGH")
    _check(stats["downgraded_info"] == 1 and stats["concat_high"] == 1, f"stats: {stats}")


# ════════════════════════════════════════════════════════════════════════════
# String-building heuristic detail.
# ════════════════════════════════════════════════════════════════════════════
def test_string_building_heuristic_variants():
    building = [
        CONCATENATED,
        'db.execSQL("DROP TABLE " + tableName)',
        'db.rawQuery(String.format("SELECT * FROM t WHERE id = %s", id), null)',
        'db.rawQuery("SELECT * FROM users WHERE name = $userName", null)',      # Kotlin $var
        'db.rawQuery("SELECT * FROM users WHERE name = ${user.name}", null)',   # Kotlin ${…}
    ]
    safe = [
        PARAMETERIZED,
        'db.execSQL("INSERT INTO t (a, b) VALUES (?, ?)", args)',
        'db.compileStatement("UPDATE t SET a = ? WHERE id = ?")',
        'db.rawQuery("SELECT * FROM t", null)',  # no params, no building
    ]
    for s in building:
        _check(_has_sql_string_building(s), f"should detect string building: {s!r}")
    for s in safe:
        _check(not _has_sql_string_building(s), f"should be safe (no building): {s!r}")


def test_concat_signal_outside_sql_call_is_ignored():
    """A '+' on a nearby unrelated line before the sink must not flag the query."""
    snippet = 'int total = a + b;\ndb.rawQuery("SELECT * FROM t WHERE id = ?", args);'
    _check(not _has_sql_string_building(snippet),
           "concatenation before the sink call must not count as SQL string building")


# ════════════════════════════════════════════════════════════════════════════
# Taint preference + dedupe.
# ════════════════════════════════════════════════════════════════════════════
def test_taint_flow_forces_high_even_without_concat():
    """A parameterized-looking query that a taint flow reaches is still HIGH."""
    results = {
        "taint_flows": [{"sink_cat": "SQLite", "class_name": "com.app.SafeDao"}],
        "findings": [_raw_finding("sources/com/app/SafeDao.java", PARAMETERIZED)],
    }
    resolve_sql_raw_query_severity(results)
    f = results["findings"][0]
    _check(f["severity"] == "high", f"taint-reached sink must be HIGH, got {f['severity']!r}")
    _check("taint" in f.get("sql_injection_evidence", ""), "HIGH should cite the taint flow")


def test_taint_finding_dedupes_the_sast_finding():
    """When a taint SQLite FINDING already represents the sink, the SAST raw-query
    finding is dropped so the single query is not double-counted."""
    results = {
        "taint_flows": [{"sink_cat": "SQLite", "class_name": "com.app.UnsafeDao"}],
        "findings": [
            _raw_finding("sources/com/app/UnsafeDao.java", CONCATENATED),
            {"rule_id": "TAINT-SQLITE", "severity": "high", "file_path": "com.app.UnsafeDao",
             "taint_flow": {"sink_cat": "SQLite"}},
        ],
    }
    stats = resolve_sql_raw_query_severity(results)
    rule_ids = [f.get("rule_id") for f in results["findings"]]
    _check("android_sqlite_raw_query" not in rule_ids,
           "the SAST raw-query finding must be deduped away")
    _check("TAINT-SQLITE" in rule_ids, "the richer taint finding is kept")
    _check(stats["deduped_taint"] == 1, f"stats: {stats}")


def test_unrelated_taint_class_does_not_dedupe():
    """A SQLite taint finding in a DIFFERENT class must not drop this finding."""
    results = {
        "findings": [
            _raw_finding("sources/com/app/UnsafeDao.java", CONCATENATED),
            {"rule_id": "TAINT-SQLITE", "severity": "high", "file_path": "com.other.Thing",
             "taint_flow": {"sink_cat": "SQLite"}},
        ],
    }
    resolve_sql_raw_query_severity(results)
    rule_ids = [f.get("rule_id") for f in results["findings"]]
    _check("android_sqlite_raw_query" in rule_ids, "must not dedupe across unrelated classes")


# ════════════════════════════════════════════════════════════════════════════
# Robustness.
# ════════════════════════════════════════════════════════════════════════════
def test_resolver_is_idempotent():
    results = {"findings": [_raw_finding("sources/com/app/SafeDao.java", PARAMETERIZED)]}
    resolve_sql_raw_query_severity(results)
    first = dict(results["findings"][0])
    resolve_sql_raw_query_severity(results)
    _check(results["findings"][0]["severity"] == first["severity"],
           "re-running must not change the resolved severity")
    _check(len(results["findings"]) == 1, "re-running must not add/remove findings")


def test_other_findings_untouched():
    other = {"rule_id": "android_hardcoded_ip", "severity": "low", "file_path": "x"}
    results = {"findings": [other, _raw_finding("sources/com/app/UnsafeDao.java", CONCATENATED)]}
    resolve_sql_raw_query_severity(results)
    _check(results["findings"][0] is other and other["severity"] == "low",
           "unrelated findings must be left exactly as-is")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    sys.exit(1 if failures else 0)
