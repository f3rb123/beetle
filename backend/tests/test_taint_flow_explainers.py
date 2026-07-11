"""
Feature: every Data Flow card must explain, in plain English, WHAT happens, WHY it
matters, and what the source/sink actually ARE — for a reader who doesn't know
Android APIs. The backend emits that copy per flow (taint_analyzer.explain_flow) and
build_taint_graph attaches it to each graph entry the panel renders.

These assert the copy exists and is correct (specific pairs + generic fallback +
sink glossary). They fail on the old behavior (no human copy on the graph entry).
"""
from __future__ import annotations

import os
import sys

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzers import taint_analyzer as ta  # noqa: E402
from analyzers import workspaces  # noqa: E402


def _flow(source, source_cat, sink, sink_cat, sink_sev, cls="com.app.X"):
    f = {"source": source, "source_cat": source_cat, "sink": sink, "sink_cat": sink_cat,
         "sink_sev": sink_sev, "raw_sink_sev": sink_sev,
         "call_chain": [f"{cls}.f", sink], "class_name": cls, "method_name": "f",
         "owner_type": "Application"}
    f["risk"] = ta.calibrate_flow_severity(f)
    return f


# ── explain_flow: specific pair ──────────────────────────────────────────────

def test_location_logging_explainer_is_human_and_complete():
    e = ta.explain_flow("Location", "Logging", "Location.getLatitude", "Log.w")
    assert e["plain_summary"] and "location" in e["plain_summary"].lower()
    assert "log" in e["plain_summary"].lower()
    assert e["why_it_matters"] and "privacy" in e["why_it_matters"].lower()
    # Source/sink glossary: a non-specialist hovering Log.w learns what logcat is.
    assert "gps" in e["source_explainer"].lower() or "location" in e["source_explainer"].lower()
    assert "logcat" in e["sink_explainer"].lower()
    for v in e.values():
        assert 0 < len(v) <= 160


def test_sharedprefs_logging_specific_pair():
    e = ta.explain_flow("SharedPrefs", "Logging", "SharedPreferences.getString", "Log.d")
    assert "preferences" in e["plain_summary"].lower()
    assert "logcat" in e["sink_explainer"].lower()


# ── generic fallback by sink category ────────────────────────────────────────

def test_generic_pair_falls_back_to_sink_category_copy():
    # No (Accounts, Network) specific entry → generic Network copy, but the sink
    # glossary still resolves from the sink label.
    e = ta.explain_flow("Accounts", "Network", "AccountManager.getAccounts", "OkHttp.url")
    assert "network" in e["plain_summary"].lower()
    assert e["why_it_matters"]
    assert "account" in e["source_explainer"].lower()
    assert "network" in e["sink_explainer"].lower()


def test_unknown_pair_uses_default_copy():
    e = ta.explain_flow("MysterySource", "MysterySink", "x.y", "z.w")
    assert e["plain_summary"] and e["why_it_matters"]
    assert e["source_explainer"] and e["sink_explainer"]


def test_sink_glossary_prefixes():
    assert "logcat" in ta._sink_explainer("Log.e", "Logging").lower()
    assert "secret" in ta._sink_explainer("SharedPrefs.putString", "Storage").lower()
    assert "hash" in ta._sink_explainer("MessageDigest.digest", "Crypto").lower()
    assert "script" in ta._sink_explainer("WebView.evaluateJavascript", "WebView").lower()
    assert "command" in ta._sink_explainer("Runtime.exec", "Execution").lower()
    assert "sql" in ta._sink_explainer("SQLiteDatabase.execSQL", "SQLite").lower()


# ── build_taint_graph attaches the copy to each entry (what the panel reads) ──

def test_graph_entries_carry_human_copy():
    results = {"findings": [], "taint_flows": [
        _flow("Location.getLatitude", "Location", "Log.w", "Logging", "high"),
    ]}
    workspaces.build_taint_graph(results)
    g = results["taint_graph"][0]
    for field in ("plain_summary", "why_it_matters", "source_explainer", "sink_explainer"):
        assert g.get(field), f"graph entry missing {field}"
    # The exact acceptance: a Location→Logging card explains GPS→log and hovering the
    # sink teaches what logcat is.
    assert "location" in g["plain_summary"].lower()
    assert "logcat" in g["sink_explainer"].lower()
    assert "privacy" in g["why_it_matters"].lower()


def test_copy_stays_within_length_budget():
    # Every string across every occurring pair/category stays ≤160 chars.
    for (sc, kc) in list(ta._FLOW_EXPLAINERS.keys()) + [("User Input", k) for k in ta._SINK_CAT_EXPLAINERS]:
        e = ta.explain_flow(sc, kc, "a.b", "c.d")
        for v in e.values():
            assert len(v) <= 160, f"{sc}->{kc}: '{v[:40]}...' is {len(v)} chars"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
