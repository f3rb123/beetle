"""
Ask-AI conversational analysis — Phase 11.98.

A conversational layer over the analyzer evidence. It builds a SUMMARIZED
context automatically (the analyst never pastes evidence), supports multi-finding
reasoning, persists conversations per scan (survives restart), reuses the AI
cache, and degrades to a deterministic, evidence-only answer when no provider is
configured.

Hard rules (Task 11):
  • AI reasons over evidence ONLY — never rediscovers vulnerabilities, never
    invents attack chains, code, paths, or parameters.
  • Never suppresses findings, never auto-marks false positives, never mutates
    results. The human analyst is the final authority.
  • Answers always carry a `mode` (llm | deterministic) so analyzer evidence and
    AI reasoning stay distinguishable.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time

import ai_actions
import database as db

log = logging.getLogger("cortex.ai_chat")

_SNIPPET_CAP = 280
_MAX_FINDINGS_CONTEXT = 8


# ─── Finding selection ───────────────────────────────────────────────────────
def _finding_key(f: dict) -> str:
    return f.get("id") or f.get("canonical_id") or f"{f.get('title') or f.get('name','')}|{f.get('file_path','')}|{f.get('line','')}"


def _select_findings(results: dict, finding_ids: list[str]) -> list[dict]:
    findings = [f for f in (results.get("findings") or []) if isinstance(f, dict)]
    if finding_ids:
        wanted = set(finding_ids)
        picked = [f for f in findings if _finding_key(f) in wanted or f.get("id") in wanted
                  or f.get("title") in wanted]
        if picked:
            return picked[:_MAX_FINDINGS_CONTEXT]
    # No explicit selection → the most severe app findings for general questions.
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: rank.get(str(f.get("severity", "info")).lower(), 4))[:5]


# ─── Context builder (Task 2) — summarized, evidence-only ────────────────────
def _finding_brief(f: dict) -> str:
    ex = f.get("analyst_explanation") or {}
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    parts = [
        f"- {f.get('title') or f.get('name','finding')} [{f.get('severity','')}]",
        f"category={f.get('category') or ex.get('category_template','')}",
        f"file={f.get('file_path') or ev.get('file_path','')}:{f.get('line') or ev.get('line','')}",
        f"ownership={f.get('ownership_label') or f.get('ownership','')}",
        f"reachability={f.get('reachability','')}",
        f"masvs={f.get('masvs') or (ex.get('remediation') or {}).get('masvs','')}",
        f"owasp={f.get('owasp') or (ex.get('remediation') or {}).get('owasp','')}",
    ]
    snip = (f.get("snippet") or ev.get("snippet") or "")[:_SNIPPET_CAP]
    why = (ex.get("why_dangerous") or ex.get("why_it_matters") or f.get("description") or "")[:240]
    line = "  ".join(p for p in parts if not p.endswith("="))
    if why:
        line += f"\n    why: {why}"
    if snip:
        line += f"\n    snippet: {snip}"
    return line


def _chains(results: dict) -> list[dict]:
    qs = results.get("quick_summary") or {}
    out = [c for c in (qs.get("attack_chain") or []) if isinstance(c, dict)]
    return out


def build_context(results: dict, findings: list[dict]) -> tuple[str, list[str]]:
    """Return (context_text, evidence_used_labels). Summarized to keep tokens low."""
    info = results.get("app_info") or {}
    score = results.get("score") or {}
    trust = results.get("trust_score") or {}
    ss = results.get("severity_summary") or {}
    cert = results.get("certificate") or {}
    used: list[str] = []
    lines = ["=== SCAN ==="]
    lines.append(
        f"app={results.get('app_name','')} package={info.get('package') or info.get('bundle_id','')} "
        f"version={info.get('version_name') or info.get('version','')} platform={results.get('platform','')}")
    lines.append(
        f"risk_score={score.get('score','')}/100 grade={score.get('grade','')} "
        f"risk_rating={(results.get('ciso_summary') or {}).get('risk_rating','')} trust_score={trust.get('score','')}")
    lines.append(f"severity_counts={ {k: ss.get(k, 0) for k in ('critical','high','medium','low','info')} }")
    used.append("scan metadata")

    if findings:
        lines.append("\n=== SELECTED FINDINGS ===")
        for f in findings:
            lines.append(_finding_brief(f))
            used.append(f.get("title") or f.get("name") or "finding")

    chains = _chains(results)
    if chains:
        lines.append("\n=== ATTACK CHAINS (analyzer-synthesized; do not invent new ones) ===")
        for c in chains[:4]:
            steps = "; ".join(s.get("title", "") for s in (c.get("steps") or []) if isinstance(s, dict))
            lines.append(
                f"- {c.get('title','')} [{c.get('severity','')}] confidence={c.get('chain_confidence','')} "
                f"exploitability={c.get('exploitability','')}\n    prerequisites={c.get('prerequisites') or []}\n"
                f"    impact={(c.get('impact') or '')[:200]}\n    contributing={steps[:300]}")
        used.append(f"{len(chains)} attack chain(s)")

    # Compact supporting context.
    if cert.get("available"):
        lines.append(f"\ncertificate: debug={cert.get('debug_cert')} expired={cert.get('expired')} "
                     f"scheme={cert.get('scheme')} key={cert.get('key_type')} {cert.get('key_size')}")
        used.append("certificate")
    perms = (results.get("permissions") or {}).get("dangerous") or []
    if perms:
        names = [p.get("name", p) if isinstance(p, dict) else p for p in perms][:10]
        lines.append(f"dangerous_permissions={names}")
        used.append("permissions")
    nc = results.get("network_config") or {}
    if nc:
        lines.append(f"network_config_cleartext={nc.get('cleartextTrafficPermitted', nc.get('cleartext', ''))}")
        used.append("network config")
    return "\n".join(lines), used


# ─── Deterministic, evidence-only answer (offline-safe) ──────────────────────
_INTENTS = [
    ("multi_chain", r"combine|chain|together|account takeover|escalat|pivot|both|all three|all of these"),
    ("poc", r"\bpoc\b|proof of concept|adb|burp|curl|frida|exploit (script|steps|command)|payload|command"),
    ("false_positive", r"false positive|\bfp\b|real (issue|finding)|legit|genuine"),
    ("reportability", r"report|disclos|bug bounty|reportable|worth reporting"),
    ("rce", r"\brce\b|remote code|remotely exploit|remote exploit"),
    ("fix", r"\bfix\b|remediat|patch|secure (this|it|the)|how (do|to) (i|we) fix"),
    ("standards", r"masvs|owasp|standard|compliance|cwe"),
    ("business", r"business (impact|risk)|cost|revenue|brand|executive"),
    ("user_risk", r"user|privacy|customer|data at risk|pii"),
    ("prioritized", r"prioriti|what (should|to) (i|we)? ?(test|fix) first|triage|order"),
    ("manual", r"manual|test|validate|verify|steps|reproduce"),
    ("pentester", r"pentester|attacker|offensive|red team|exploit"),
    ("developer", r"developer|engineer|how does this work|code"),
    ("threat_model", r"threat model|attack surface|stride|adversary"),
    ("exploitable", r"exploit|dangerous|severity|how bad|impact"),
]


def _classify(question: str) -> str:
    q = question.lower()
    for intent, pat in _INTENTS:
        if re.search(pat, q):
            return intent
    return "explain"


def _band_from_findings(findings: list[dict]) -> str:
    if not findings:
        return "low"
    return ai_actions._conf_band(findings[0])


def deterministic_ask(question: str, results: dict, findings: list[dict]) -> dict:
    """Compose an evidence-grounded answer without an LLM. Intent-routed; reuses
    the deterministic action builders. Never invents anything."""
    intent = _classify(question)
    f0 = findings[0] if findings else {}
    ex0 = ai_actions._ex(f0)
    chains = _chains(results)
    note = "Deterministic answer composed from analyzer evidence (no LLM configured). Reasoning only — the analyst is the final authority."

    def envelope(answer, reasoning, confidence="medium"):
        return {"answer": answer, "reasoning": reasoning, "confidence": confidence, "limitations": note}

    if intent == "multi_chain":
        # Respect existing chains; never synthesize a new one.
        titles = [f.get("title") or f.get("name") for f in findings]
        related = [c for c in chains if any(
            (t or "") in " ".join(s.get("title", "") for s in (c.get("steps") or []) if isinstance(s, dict))
            for t in titles)]
        if related:
            c = related[0]
            ans = (f"These findings map onto the analyzer-synthesized chain “{c.get('title')}” "
                   f"(confidence {c.get('chain_confidence','?')}, exploitability {c.get('exploitability','?')}). "
                   f"Realistic impact: {c.get('impact','see chain')}. ")
            reasoning = (f"Prerequisites: {c.get('prerequisites') or []}. Contributing steps: "
                         + "; ".join(s.get("title", "") for s in (c.get("steps") or []) if isinstance(s, dict)))
            return envelope(ans, reasoning, str(c.get("chain_confidence", "medium")).lower())
        ans = ("The analyzer did not synthesize a single attack chain linking these specific findings, so a "
               "combined path (e.g. account takeover / RCE) is NOT confirmed. To assess it manually, verify that "
               "each finding is independently reachable, then test whether the output of one feeds the input of "
               "the next. Do not assume a chain that the analyzer did not produce.")
        reasoning = "Selected: " + "; ".join(f"{f.get('title')} [{f.get('severity')}], reachability {f.get('reachability','?')}" for f in findings)
        return envelope(ans, reasoning, "low")

    if intent in ("poc",):
        poc = ai_actions._det_poc(f0)
        ans = poc["summary"] + ("\nCommands:\n" + "\n".join(poc["commands"]) if poc["commands"] else "")
        return envelope(ans, "Steps: " + " | ".join(poc["steps"]) + "\nAssumptions: " + "; ".join(poc["assumptions"]), poc["confidence"])

    if intent == "false_positive":
        v = ai_actions._det_verify(f0)
        ans = (f"Likelihood this is a true positive: {v['likelihood']}. I cannot and do not mark it a false "
               f"positive automatically — confirm manually: " + " ".join(v["manual_steps"][:3]))
        return envelope(ans, v["reasoning"], v["confidence"])

    if intent in ("reportability",):
        sev = str(f0.get("severity", "")).lower()
        reach = str(f0.get("reachability", "")).upper()
        own = f0.get("ownership_label") or f0.get("ownership", "")
        worth = sev in ("critical", "high") and reach != "NO"
        ans = (f"Reportability: {'likely worth reporting' if worth else 'lower priority'} — severity {sev}, "
               f"reachability {reach or 'unknown'}, ownership {own}. Confirm exploitability before reporting; "
               "report the analyzer evidence (file:line + snippet), not a claim the tool did not make.")
        return envelope(ans, ex0.get("impact") or "Based on severity + reachability + ownership.", ai_actions._conf_band(f0))

    if intent in ("fix",):
        fx = ai_actions._det_fix(f0)
        ans = f"Why vulnerable: {fx['why_vulnerable']}\nFix: {fx['best_practice']}"
        return envelope(ans, f"Reference patch: {fx['patched_code']}\nMASVS {fx['masvs']} OWASP {fx['owasp']}", fx["confidence"])

    if intent == "standards":
        maps = [(f.get("title"), f.get("masvs") or (ai_actions._ex(f).get('remediation') or {}).get('masvs'),
                 f.get("owasp") or (ai_actions._ex(f).get('remediation') or {}).get('owasp')) for f in findings]
        ans = "MASVS / OWASP mapping for the selected findings:\n" + "\n".join(
            f"- {t}: MASVS {m or '—'}, OWASP {o or '—'}" for t, m, o in maps)
        return envelope(ans, "Mappings come directly from the analyzer's finding metadata.", "high")

    if intent in ("business", "user_risk"):
        ciso = results.get("ciso_summary") or {}
        risks = ciso.get("business_risks") or []
        ans = (f"Overall posture: {ciso.get('overall_posture','')}. "
               + ("Key business risks: " + "; ".join(b.get("risk") for b in risks) if risks else ""))
        return envelope(ans, "; ".join(f"{b.get('risk')}: {b.get('detail')}" for b in risks) or ciso.get("most_critical_issue", ""), "high")

    if intent == "prioritized":
        ciso = results.get("ciso_summary") or {}
        rem = ciso.get("prioritized_remediation") or []
        ans = "Prioritized remediation (by exploitability + severity):\n" + "\n".join(
            f"{r.get('priority')}. {r.get('item')}" for r in rem[:6]) if rem else \
            "No critical/high remediation items were prioritized for this scan."
        return envelope(ans, "Ordering from the CISO summary (analyzer-derived).", "high")

    if intent in ("manual",):
        w = ai_actions._det_worth(f0)
        ans = f"Priority: {w['priority']}. Manual validation:\n- " + "\n- ".join(w["manual_validation_steps"])
        return envelope(ans, "Prerequisites: " + "; ".join(w["required_prerequisites"]), w["confidence"])

    if intent in ("rce", "exploitable", "threat_model", "pentester"):
        sev = str(f0.get("severity", "")).lower()
        reach = str(f0.get("reachability", "")).upper()
        ans = (f"“{f0.get('title','This finding')}” is severity {sev} with reachability {reach or 'unknown'}. "
               + (ex0.get("attack_scenario") or ex0.get("why_dangerous") or "")
               + (" An attacker would need: " + ", ".join(ex0.get("prerequisites") or []) if ex0.get("prerequisites") else ""))
        verdict = ("Remote exploitation/RCE is only credible if reachability is YES and untrusted input reaches a "
                   "code-execution sink — verify both from the evidence; do not assume it.")
        return envelope(ans, verdict, ai_actions._conf_band(f0))

    # default → explain (pentester/developer flavored)
    e = ai_actions._det_explain(f0)
    return envelope(e["summary"], e["reasoning"], e["confidence"])


# ─── Cache (reuse ai_action_cache) ───────────────────────────────────────────
def _context_signature(scan_id: str, findings: list[dict], results: dict) -> str:
    ss = results.get("severity_summary") or {}
    basis = scan_id + "|" + ",".join(sorted(_finding_key(f) for f in findings)) + "|" + str(sorted(ss.items()))
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def _chat_cache_key(provider: str, model: str, ctx_sig: str, question: str) -> str:
    q = re.sub(r"\s+", " ", question.strip().lower())
    return hashlib.sha256(f"chat|{provider}|{model}|{ctx_sig}|{q}".encode()).hexdigest()


def _estimate_tokens(*texts: str) -> int:
    return sum(len(t or "") for t in texts) // 4  # rough ~4 chars/token


# ─── Orchestrator ────────────────────────────────────────────────────────────
def run_chat(*, scan_id: str, question: str, results: dict, finding_ids: list[str] | None = None,
             provider_name: str | None = None, model: str | None = None,
             history: list | None = None, use_cache: bool = True) -> dict:
    """Answer one conversational turn. Returns a uniform envelope; never raises."""
    t0 = time.time()
    finding_ids = finding_ids or []
    results = results or {}
    findings = _select_findings(results, finding_ids)
    context_text, evidence_used = build_context(results, findings)

    try:
        from analyzers import providers
        provider = providers.get_provider(provider_name)
    except Exception:
        provider = None

    used_provider = provider.id if provider else (provider_name or "deterministic")
    used_model = model or (provider.default_model if provider else "")
    ctx_sig = _context_signature(scan_id, findings, results)
    key = _chat_cache_key(used_provider, used_model or "", ctx_sig, question)

    if use_cache:
        hit = ai_actions._cache_get(key)
        if hit is not None:
            hit["cached"] = True
            hit["generation_ms"] = 0
            return hit

    mode, note, result = "deterministic", None, {}
    log.info("[ask] scan=%s provider_requested=%s provider_selected=%s findings=%d",
             scan_id, provider_name or "(auto)", used_provider, len(findings))
    if provider is not None:
        try:
            llm = provider.ask(question, context_text, history=history or [], model=model)
        except Exception as e:
            llm = {"error": f"{type(e).__name__}: {e}"}
        if llm and not llm.get("error"):
            result = {k: v for k, v in llm.items() if k not in ("provider", "model")}
            mode = "llm"
            used_provider = llm.get("provider", used_provider)
            used_model = llm.get("model", used_model)
            log.info("[ask] llm answer from provider=%s model=%s", used_provider, used_model)
        else:
            note = (llm or {}).get("error") or "provider returned no usable result"
            # Surface, never hide: a provider was requested but failed.
            log.warning("[ask] provider=%s FAILED, falling back to deterministic: %s", used_provider, note)

    if mode == "deterministic":
        result = deterministic_ask(question, results, findings)

    # Prefer the provider's real token count; fall back to a char-based estimate.
    real_tokens = (result.get("usage") or {}).get("total_tokens") if isinstance(result.get("usage"), dict) else None
    tokens = real_tokens or _estimate_tokens(context_text, question, result.get("answer", "") or result.get("summary", ""), result.get("reasoning", ""))

    envelope = {
        "answer": result.get("answer") or result.get("summary", ""),
        "reasoning": result.get("reasoning", ""),
        "confidence": result.get("confidence", ""),
        "limitations": result.get("limitations", ""),
        "provider": used_provider,
        "model": used_model,
        "mode": mode,
        "note": note,
        "cached": False,
        "evidence_used": evidence_used,
        "tokens": tokens,
        "token_estimate": real_tokens is None,
        "generation_ms": result.get("latency_ms") or int((time.time() - t0) * 1000),
    }
    if use_cache:
        ai_actions._cache_set(key, dict(envelope))
    return envelope


# ─── Conversation API (thin wrappers over database) ──────────────────────────
def send_message(*, scan_id: str, question: str, results: dict, chat_id: str | None = None,
                 finding_ids: list[str] | None = None, provider_name: str | None = None,
                 model: str | None = None) -> dict:
    """Create/continue a conversation: persist the user turn, generate + persist
    the assistant turn, and return the assistant envelope + chat_id."""
    if not chat_id:
        title = (question.strip()[:60] or "New conversation")
        convo = db.create_conversation(scan_id, title=title, provider=provider_name or "", model=model or "")
        chat_id = convo["chat_id"]

    prior = db.get_conversation(chat_id) or {"messages": []}
    history = [{"role": m["role"], "content": m["content"]} for m in prior.get("messages", [])]

    db.add_message(chat_id, "user", question, {"finding_ids": finding_ids or []})
    env = run_chat(scan_id=scan_id, question=question, results=results, finding_ids=finding_ids,
                   provider_name=provider_name, model=model, history=history)
    db.add_message(chat_id, "assistant", env.get("answer", ""), {
        k: env.get(k) for k in ("reasoning", "confidence", "limitations", "provider", "model",
                                 "mode", "cached", "evidence_used", "tokens", "generation_ms")})
    env["chat_id"] = chat_id
    return env
