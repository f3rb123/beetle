"""
AI finding-action orchestrator — Phase 11.97.

One entry point, `run_action`, that powers the Finding Drawer AI actions
(explain / verify / worth_testing / generate_poc / generate_fix) and the
executive summary. It is provider-agnostic and offline-safe:

  • If a provider is configured + available, the matching provider method is
    called (the model reasons ONLY about analyzer evidence — see providers/base).
  • Otherwise (or on provider error / non-JSON) it falls back to a DETERMINISTIC
    result built strictly from the analyzer's own evidence (analyst_explanation,
    reachability, snippet, masvs…). Nothing is invented; no network is touched.

Guarantees:
  • Never raises into the request handler.
  • Never suppresses or mutates a finding — `verify` is advisory only; the human
    analyst is the final authority (deterministic verify always reports
    false_positive=false and says so).
  • Responses are cached in SQLite (ai_action_cache) keyed on
    action+provider+model+evidence, so repeats reuse the previous response.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger("cortex.ai_actions")

_DATA_DIR = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
_DB_PATH = _DATA_DIR / "cortex.db"
_CACHE_TTL = timedelta(days=7)

ACTIONS = ("explain", "verify", "worth_testing", "generate_poc", "generate_fix", "summary")


# ─── Cache ───────────────────────────────────────────────────────────────────
def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_ai_actions_db() -> None:
    try:
        with _conn() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ai_action_cache (
                       cache_key   TEXT PRIMARY KEY,
                       response    TEXT NOT NULL,
                       created_at  TEXT NOT NULL
                   )"""
            )
    except Exception:
        log.exception("[ai_actions] cache table init failed")


def _evidence_signature(action: str, finding: dict, results: dict) -> str:
    if action == "summary":
        ss = results.get("severity_summary") or {}
        basis = f"{results.get('scan_id','')}|{json.dumps(ss, sort_keys=True)}|{(results.get('score') or {}).get('score','')}"
    else:
        f = finding or {}
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        basis = "|".join(str(x) for x in [
            f.get("id") or f.get("canonical_id") or "",
            f.get("title") or f.get("name") or "",
            f.get("file_path") or ev.get("file_path") or "",
            f.get("line") or ev.get("line") or "",
            (f.get("snippet") or ev.get("snippet") or "")[:120],
            f.get("severity") or "",
        ])
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()


def _cache_key(action: str, provider: str, model: str, sig: str) -> str:
    return hashlib.sha256(f"{action}|{provider}|{model}|{sig}".encode()).hexdigest()


def _cache_get(key: str) -> dict | None:
    try:
        with _conn() as conn:
            row = conn.execute("SELECT response, created_at FROM ai_action_cache WHERE cache_key=?", (key,)).fetchone()
        if not row:
            return None
        if datetime.utcnow() - datetime.fromisoformat(row["created_at"]) > _CACHE_TTL:
            return None
        data = json.loads(row["response"])
        data["cached"] = True
        return data
    except Exception:
        return None


def _cache_set(key: str, payload: dict) -> None:
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ai_action_cache (cache_key, response, created_at) VALUES (?,?,?)",
                (key, json.dumps(payload), datetime.utcnow().isoformat()),
            )
    except Exception:
        log.exception("[ai_actions] cache set failed")


# ─── Deterministic, evidence-only fallbacks (offline-safe, non-fabricating) ──
def _ex(finding: dict) -> dict:
    return finding.get("analyst_explanation") or {}


def _conf_band(finding: dict) -> str:
    q = finding.get("evidence_quality")
    if q:
        return q.lower()
    try:
        s = float(finding.get("confidence_score") if finding.get("confidence_score") is not None else finding.get("confidence"))
        return "high" if s >= 70 else "medium" if s >= 40 else "low"
    except (TypeError, ValueError):
        return "medium"


def _loc(finding: dict) -> str:
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    p = finding.get("file_path") or finding.get("full_path") or ev.get("file_path") or ""
    ln = finding.get("line") or finding.get("line_number") or ev.get("line")
    return f"{p}:{ln}" if p and ln else (p or "the reported location")


def _det_explain(f: dict) -> dict:
    ex = _ex(f)
    summary = ex.get("why_it_matters") or f.get("description") or "No analyzer description was attached to this finding."
    reasoning = "\n\n".join(x for x in [ex.get("why_dangerous"), ex.get("attack_scenario")] if x) or summary
    return {"summary": summary, "reasoning": reasoning, "confidence": _conf_band(f),
            "limitations": "Built from analyzer evidence without an LLM; configure a provider for a model-written explanation."}


def _det_verify(f: dict) -> dict:
    reach = str(f.get("reachability", "")).upper()
    band = _conf_band(f)
    likelihood = "high" if reach == "YES" else ("medium" if reach in ("MAYBE", "") and band != "low" else "low")
    steps = list((_ex(f).get("prerequisites") or []))
    steps.append(f"Open {_loc(f)} and confirm the matched pattern is real (not a comment, test, or dead code).")
    if _ex(f).get("attack_scenario"):
        steps.append("Reproduce the attack scenario described in the finding to confirm exploitability.")
    return {
        "likelihood": likelihood,
        "false_positive": False,  # advisory only — never auto-suppress; human decides
        "reasoning": _ex(f).get("confidence_reason") or f"Reachability is {reach or 'unknown'} and evidence confidence is {band}.",
        "manual_steps": steps,
        "confidence": band,
        "limitations": "Advisory only — the analyst remains the final authority. This deterministic check never marks a finding as a false positive; configure a provider for a model-assisted assessment.",
    }


def _det_worth(f: dict) -> dict:
    sev = str(f.get("severity", "")).lower()
    reach = str(f.get("reachability", "")).upper()
    priority = "high" if (sev in ("critical", "high") and reach != "NO") else ("medium" if sev in ("high", "medium") else "low")
    ex = _ex(f)
    steps = []
    if ex.get("attack_scenario"):
        steps.append(ex["attack_scenario"])
    steps.append(f"Inspect {_loc(f)} and trace the data/flow to a reachable entry point.")
    return {
        "priority": priority,
        "expected_impact": ex.get("impact") or f.get("impact") or "Impact depends on reachability; confirm during testing.",
        "manual_validation_steps": steps,
        "required_prerequisites": list(ex.get("prerequisites") or []) or ["Installed app / device or emulator", "adb access"],
        "confidence": _conf_band(f),
        "limitations": "Prioritization derived from severity + reachability evidence; configure a provider for model-assisted triage.",
    }


def _det_poc(f: dict) -> dict:
    ex = _ex(f)
    tmpl = ex.get("category_template") or ""
    title = f.get("title") or f.get("name") or "finding"
    commands, assumptions, steps = [], [], []
    if tmpl in ("INTENT_INJECTION",) or "exported" in title.lower() or "component" in title.lower():
        commands.append("adb shell am start -n <package>/<ExportedComponent> --es <key> <value>")
        assumptions += ["<package> = the app package id", "<ExportedComponent> = the exported component from the manifest"]
        steps.append("Invoke the exported component from another app context and observe behavior.")
    elif tmpl == "DEEP_LINKS" or "deep" in title.lower() or "scheme" in title.lower():
        commands.append('adb shell am start -W -a android.intent.action.VIEW -d "<scheme>://<host>/<path>"')
        assumptions += ["<scheme>/<host>/<path> = the deep-link route declared in the manifest"]
        steps.append("Open the crafted deep link and confirm it drives the app into the sensitive flow.")
    elif tmpl in ("NETWORK", "FIREBASE"):
        commands.append("curl -i <endpoint-from-evidence>")
        assumptions += ["<endpoint-from-evidence> = a URL observed in the finding evidence"]
        steps.append("Replay the request through a proxy (Burp) and inspect/modify traffic.")
    else:
        steps.append(f"Open {_loc(f)} in the decompiled source and trace how the flagged code is reached.")
        steps.append("Drive the code path from a reachable entry point and observe the effect.")
    return {
        "summary": f"Validation steps for: {title}. Replace every <PLACEHOLDER> with a value confirmed from the evidence — none are fabricated here.",
        "steps": steps,
        "commands": commands,
        "assumptions": assumptions or ["No external parameters are required beyond the reported source location."],
        "confidence": _conf_band(f),
        "limitations": "Commands use <PLACEHOLDER> tokens where the parameter is not present in the evidence; fill them from the manifest/source before running. Configure a provider for a tailored PoC.",
    }


def _det_fix(f: dict) -> dict:
    ex = _ex(f)
    rem = ex.get("remediation") or {}
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    return {
        "why_vulnerable": ex.get("why_dangerous") or ex.get("why_it_matters") or f.get("description") or "",
        "current_code": f.get("snippet") or ev.get("snippet") or f.get("code_context") or "(no code snippet was captured for this finding)",
        "patched_code": ex.get("code_example") or "(configure a provider for a generated patch; see best practice below)",
        "best_practice": ex.get("developer_fix") or rem.get("summary") or f.get("recommendation") or "Apply the platform secure-coding guidance for this weakness class.",
        "masvs": f.get("masvs") or rem.get("masvs") or "",
        "owasp": f.get("owasp") or rem.get("owasp") or "",
        "confidence": _conf_band(f),
        "limitations": "Patched code shown is the analyzer's reference example; configure a provider for a fix tailored to this exact snippet.",
    }


def _det_summary(results: dict) -> dict:
    ciso = results.get("ciso_summary") or {}
    ss = results.get("severity_summary") or {}
    score = results.get("score") or {}
    summary = ciso.get("overall_posture") or (
        f"{results.get('app_name', 'This app')} scored {score.get('score', '—')}/100 (grade {score.get('grade', '—')}) "
        f"with {ss.get('critical', 0)} critical and {ss.get('high', 0)} high-severity findings."
    )
    return {
        "summary": summary,
        "reasoning": ciso.get("most_critical_issue") or "Derived from the analyzer's severity, score and MASVS rollups.",
        "confidence": "high",
        "limitations": "Built from deterministic analyzer rollups (CISO/MASVS/severity); configure a provider for a model-written narrative.",
    }


_DET = {
    "explain": _det_explain, "verify": _det_verify, "worth_testing": _det_worth,
    "generate_poc": _det_poc, "generate_fix": _det_fix,
}


def _deterministic(action: str, finding: dict, results: dict) -> dict:
    if action == "summary":
        return _det_summary(results)
    return _DET[action](finding or {})


# ─── Provider dispatch ───────────────────────────────────────────────────────
def _call_provider(provider, action: str, finding: dict, results: dict, model: str | None) -> dict:
    if action == "summary":
        return provider.generate_summary(results, model=model)
    method = {
        "explain": provider.explain_finding, "verify": provider.verify_finding,
        "worth_testing": provider.worth_testing, "generate_poc": provider.generate_poc,
        "generate_fix": provider.generate_fix,
    }[action]
    return method(finding or {}, model=model)


def list_providers() -> list[dict]:
    try:
        from analyzers import providers
        return providers.list_providers()
    except Exception:
        log.exception("[ai_actions] provider listing failed")
        return []


def run_action(action: str, *, finding: dict | None = None, results: dict | None = None,
               provider_name: str | None = None, model: str | None = None,
               use_cache: bool = True) -> dict:
    """Run one AI action. Returns a uniform envelope; never raises."""
    finding = finding or {}
    results = results or {}
    if action not in ACTIONS:
        return {"error": f"unknown action '{action}'", "action": action}

    try:
        from analyzers import providers
        provider = providers.get_provider(provider_name)
    except Exception:
        provider = None

    used_provider = provider.id if provider else (provider_name or "deterministic")
    used_model = model or (provider.default_model if provider else "")
    sig = _evidence_signature(action, finding, results)
    key = _cache_key(action, used_provider, used_model or "", sig)

    if use_cache:
        hit = _cache_get(key)
        if hit is not None:
            return hit

    mode = "deterministic"
    note = None
    result: dict = {}

    if provider is not None:
        try:
            llm = _call_provider(provider, action, finding, results, model)
        except Exception as e:  # defensive — providers shouldn't raise
            llm = {"error": f"{type(e).__name__}"}
        if llm and not llm.get("error"):
            result = {k: v for k, v in llm.items() if k not in ("provider", "model")}
            mode = "llm"
            used_provider = llm.get("provider", used_provider)
            used_model = llm.get("model", used_model)
        else:
            note = (llm or {}).get("error") or "provider returned no usable result"

    if mode == "deterministic":
        result = _deterministic(action, finding, results)

    envelope = {
        "action": action,
        "provider": used_provider,
        "model": used_model,
        "mode": mode,
        "cached": False,
        "note": note,
        "result": result,
        # convenience top-level fields for the result drawer
        "summary": result.get("summary", ""),
        "reasoning": result.get("reasoning", ""),
        "confidence": result.get("confidence", ""),
        "limitations": result.get("limitations", ""),
    }
    if use_cache:
        _cache_set(key, envelope)
    return envelope
