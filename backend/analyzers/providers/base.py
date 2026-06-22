"""
AI provider abstraction — Phase 11.75 Task 10 / Phase 11.97.

A minimal, network-free-at-import interface so Beetle can talk to any LLM without
hardcoding one. Existing Claude support continues via the Claude provider, which
delegates to the established `ai_enrichment` path. No provider is required: when
none is configured, the orchestrator (ai_actions) falls back to deterministic
analyst intelligence and nothing breaks.

The six structured methods (generate_summary / explain_finding / verify_finding /
worth_testing / generate_poc / generate_fix) live HERE on the base class so every
provider gets them for free — a provider only implements `complete()`. Each method
builds an EVIDENCE-ONLY prompt, calls complete(), and parses a JSON object. The
model is asked to reason strictly about the analyzer evidence it is handed and to
never invent findings, code, paths, or parameters.
"""
from __future__ import annotations

import json
import os
import re

# ── System prompt: the guardrail that keeps the model on the evidence ────────
_SYSTEM = (
    "You are a senior mobile application security analyst assisting a human analyst. "
    "You are given the EVIDENCE that a static analyzer has ALREADY produced for a single "
    "finding (or scan). Reason ONLY about the evidence provided. Do NOT discover new "
    "vulnerabilities, do NOT invent file paths, code, class names, endpoints, or exploit "
    "parameters that are not present in the evidence. If a detail is unknown, state that it "
    "is unknown rather than guessing. You are advisory only — the human analyst is the final "
    "authority and decides whether a finding is real. Respond with ONLY a single minified "
    "JSON object matching the requested schema, no prose, no markdown fences."
)


def _evidence_block(finding: dict) -> str:
    """Render the analyzer evidence for one finding — nothing the analyzer did
    not already produce. This is the ONLY material the model may reason about."""
    f = finding or {}
    ex = f.get("analyst_explanation") or {}
    rem = ex.get("remediation") or {}
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    parts = [
        f"title: {f.get('title') or f.get('name') or ''}",
        f"severity: {f.get('severity') or ''}",
        f"category: {f.get('category') or ex.get('category_template') or ''}",
        f"file: {f.get('file_path') or f.get('full_path') or ev.get('file_path') or ''}",
        f"line: {f.get('line') or f.get('line_number') or ev.get('line') or ''}",
        f"masvs: {f.get('masvs') or rem.get('masvs') or ''}",
        f"owasp: {f.get('owasp') or rem.get('owasp') or ''}",
        f"cwe: {f.get('cwe') or ''}",
        f"reachability: {f.get('reachability') or ''} ({f.get('reachability_confidence') or ''})",
        f"confidence: {f.get('confidence_score') if f.get('confidence_score') is not None else f.get('confidence') or ''}",
        f"ownership: {f.get('ownership_label') or f.get('ownership') or ''}",
        f"description: {(f.get('description') or ex.get('why_it_matters') or '')[:600]}",
        f"snippet: {(f.get('snippet') or ev.get('snippet') or f.get('code_context') or '')[:600]}",
    ]
    if f.get("is_attack_chain") or ex.get("attack_scenario"):
        parts.append(f"attack_scenario: {(ex.get('attack_scenario') or '')[:400]}")
    steps = f.get("steps") or []
    if steps:
        parts.append("chain_steps: " + "; ".join(str(s.get("title", "")) for s in steps if isinstance(s, dict))[:400])
    return "\n".join(p for p in parts if p.split(": ", 1)[-1].strip())


def _parse_json(text: str) -> dict | None:
    """Extract the first JSON object from an LLM response. Tolerant of fences."""
    if not text:
        return None
    s = text.strip()
    s = re.sub(r"^```(?:json)?|```$", "", s, flags=re.MULTILINE).strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    m = re.search(r"\{.*\}", s, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return None
    return None


class BaseProvider:
    """One LLM backend. Subclasses override `available()` and `complete()`.

    The structured action methods are provider-agnostic: they build a prompt,
    call `complete()`, and parse JSON. Each returns either the parsed dict
    (merged with {provider, model}) or {error, provider} — and NEVER raises."""

    id = "base"
    name = "Base Provider"
    #: environment variable holding this provider's API key (None for local/no-key)
    api_key_env: str | None = None
    default_model = ""

    def available(self) -> bool:
        """True only when this provider could actually run (key/host present).
        Never performs I/O — safe to call cheaply and repeatedly."""
        if self.api_key_env is None:
            return False
        return bool(os.environ.get(self.api_key_env, "").strip())

    def complete(self, prompt: str, *, model: str | None = None, system: str | None = None) -> dict:
        """Return {text, model, provider} or {error, provider}. Must never raise."""
        return {"error": f"{self.name} not configured", "provider": self.id}

    # ── Structured task helper ───────────────────────────────────────────────
    def _structured(self, prompt: str, model: str | None) -> dict:
        res = self.complete(prompt, model=model or self.default_model, system=_SYSTEM)
        if res.get("error"):
            return {"error": res["error"], "provider": self.id}
        parsed = _parse_json(res.get("text", ""))
        if parsed is None:
            # Model replied but not as JSON — surface the raw text rather than fail.
            return {"summary": (res.get("text") or "").strip()[:1200],
                    "provider": self.id, "model": res.get("model", model)}
        parsed.setdefault("provider", self.id)
        parsed.setdefault("model", res.get("model", model or self.default_model))
        return parsed

    # ── The six structured actions (Phase 11.97) ─────────────────────────────
    def generate_summary(self, results: dict, *, model: str | None = None) -> dict:
        ss = results.get("severity_summary") or {}
        prompt = (
            "Write an executive security summary for this app from the evidence.\n"
            f"app: {results.get('app_name', '')}\n"
            f"grade: {(results.get('score') or {}).get('grade', '')}\n"
            f"severity_counts: {json.dumps(ss)}\n"
            f"risk_rating: {(results.get('ciso_summary') or {}).get('risk_rating', '')}\n"
            f"top_risks: {json.dumps([r.get('title') for r in (results.get('analyst_summary') or {}).get('top_risks', [])][:5])}\n"
            'Respond JSON: {"summary": str, "reasoning": str, "confidence": "high|medium|low", "limitations": str}'
        )
        return self._structured(prompt, model)

    def explain_finding(self, finding: dict, *, model: str | None = None) -> dict:
        prompt = (
            "Explain this finding to a security engineer using only the evidence.\n"
            + _evidence_block(finding) +
            '\nRespond JSON: {"summary": str, "reasoning": str, "confidence": "high|medium|low", "limitations": str}'
        )
        return self._structured(prompt, model)

    def verify_finding(self, finding: dict, *, model: str | None = None) -> dict:
        prompt = (
            "Assess whether this finding is a true positive, using only the evidence. "
            "You are advisory; you cannot suppress the finding.\n"
            + _evidence_block(finding) +
            '\nRespond JSON: {"likelihood": "high|medium|low", "false_positive": true|false, '
            '"reasoning": str, "manual_steps": [str], "confidence": "high|medium|low", "limitations": str}'
        )
        return self._structured(prompt, model)

    def worth_testing(self, finding: dict, *, model: str | None = None) -> dict:
        prompt = (
            "Decide whether this finding is worth manual testing, using only the evidence.\n"
            + _evidence_block(finding) +
            '\nRespond JSON: {"priority": "high|medium|low", "expected_impact": str, '
            '"manual_validation_steps": [str], "required_prerequisites": [str], '
            '"confidence": "high|medium|low", "limitations": str}'
        )
        return self._structured(prompt, model)

    def generate_poc(self, finding: dict, *, model: str | None = None) -> dict:
        prompt = (
            "Produce a proof-of-concept for validating this finding using only the evidence. "
            "Use concrete commands (adb shell am start, curl, deeplink URL, Intent invocation, "
            "Burp steps) ONLY where the evidence provides the needed parameter (component, scheme, "
            "URL). Where a parameter is unknown, use an explicit <PLACEHOLDER> token and list it as "
            "an assumption — never fabricate a real value.\n"
            + _evidence_block(finding) +
            '\nRespond JSON: {"summary": str, "steps": [str], "commands": [str], '
            '"assumptions": [str], "confidence": "high|medium|low", "limitations": str}'
        )
        return self._structured(prompt, model)

    def generate_fix(self, finding: dict, *, model: str | None = None) -> dict:
        prompt = (
            "Produce a remediation for this finding using only the evidence.\n"
            + _evidence_block(finding) +
            '\nRespond JSON: {"why_vulnerable": str, "current_code": str, "patched_code": str, '
            '"best_practice": str, "masvs": str, "owasp": str, '
            '"confidence": "high|medium|low", "limitations": str}'
        )
        return self._structured(prompt, model)

    def ask(self, question: str, context: str, *, history: list | None = None,
            model: str | None = None) -> dict:
        """Free-form conversational analysis (Phase 11.98). `context` is the
        pre-summarized analyzer evidence for the scan/selected findings; `history`
        is prior [{role, content}] turns. The model answers ONLY from the evidence
        and conversation — it must not invent findings, chains, or parameters."""
        convo = ""
        for turn in (history or [])[-8:]:
            role = "User" if turn.get("role") == "user" else "Assistant"
            convo += f"\n{role}: {str(turn.get('content', ''))[:800]}"
        prompt = (
            "Answer the analyst's question using ONLY the analyzer evidence below and the "
            "conversation so far. Do not invent vulnerabilities, attack chains, code, file "
            "paths, or exploit parameters. If the evidence is insufficient, say so and explain "
            "what to check manually.\n\n=== ANALYZER EVIDENCE ===\n" + context +
            ("\n\n=== CONVERSATION ===" + convo if convo else "") +
            f"\n\n=== QUESTION ===\n{question}\n\n"
            'Respond JSON: {"answer": str, "reasoning": str, "confidence": "high|medium|low", '
            '"limitations": str}'
        )
        return self._structured(prompt, model)

    def enrich_finding(self, finding: dict, app_context: dict | None = None) -> dict:
        """Legacy hook retained for the existing enrichment path."""
        return self.explain_finding(finding)
