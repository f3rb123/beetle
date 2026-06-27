"""
Attack Chain Engine v2 — engine (Beetle 2.0, Phase 1.7).

Builds realistic, evidence-backed, explainable attacker journeys by:
  1. tagging every active finding with deterministic capabilities,
  2. deciding each finding's chaining role from Triage / Secret Intelligence
     (SAFE CHAINING — framework noise / suppressed / FP secrets / generated code
     are never required links),
  3. filling each template's required capability slots from the eligible findings
     (and entry points from the manifest attack surface),
  4. scoring the chain from the prior engines' outputs (no arbitrary numbers),
  5. emitting a graph, an analyst narrative and a full explanation.

Additive and non-destructive: writes `results["attack_chains_v2"]`; the legacy
chain output is untouched. Deterministic and modular (templates + capabilities).
"""
from __future__ import annotations

import hashlib
import logging

from . import config as C
from . import templates as T
from .model import (
    AttackChain, ChainEdge, ChainGraph, ChainNode, EdgeRelation, NodeType,
)

log = logging.getLogger("cortex.attack_chains_v2")


# ════════════════════════════════════════════════════════════════════════════
# Capability tagging (deterministic) + eligibility
# ════════════════════════════════════════════════════════════════════════════
def _blob(f: dict) -> str:
    return " ".join(str(f.get(k) or "") for k in
                    ("title", "category", "description", "snippet", "rule_id")).lower()


def _secret_status(f: dict) -> str:
    si = f.get("secret_intelligence") or {}
    return si.get("status") or f.get("secret_status") or ""


_STRUCTURAL_CAPS = frozenset(("WEBVIEW", "WEBVIEW_JS", "JS_INTERFACE", "WEBVIEW_FILE",
                              "WEBVIEW_SSL", "EXPORTED", "DEEPLINK", "EXPORTED_PROVIDER",
                              "NATIVE", "NETWORK"))


def tag_capabilities(f: dict) -> set:
    """Deterministic capability tags for a finding (the chaining vocabulary)."""
    caps: set = set()
    cat = (f.get("category") or "").lower()
    blob = _blob(f)
    tf = f.get("taint_flow") or {}
    sink = str(tf.get("sink_cat") or "").replace(" ", "").lower()
    src = str(tf.get("source_cat") or "").lower()

    # Entry / surface
    if cat == "attack surface" or f.get("exported"):
        caps.add("EXPORTED")
    if cat in ("deeplinks", "deeplink") or f.get("browsable"):
        caps.add("DEEPLINK")
    if "content provider" in blob or "contentprovider" in blob:
        caps.add("EXPORTED_PROVIDER")
    # WebView
    if cat == "webview" or "webview" in blob:
        caps.add("WEBVIEW")
        if "javascript" in blob or "setjavascriptenabled" in blob:
            caps.add("WEBVIEW_JS")
        if "addjavascriptinterface" in blob or "javascriptinterface" in blob:
            caps.add("JS_INTERFACE")
        if "allowfileaccess" in blob or "file access" in blob or "file://" in blob:
            caps.add("WEBVIEW_FILE")
        if "ssl" in blob or "onreceivedsslerror" in blob:
            caps.add("WEBVIEW_SSL")
    # Injection sinks (taint or title)
    if sink in ("sqlite", "sql") or "sql injection" in blob:
        caps.add("SQL_SINK")
    if sink in ("execution", "command") or "command injection" in blob or "os command" in blob:
        caps.add("CMD_SINK")
    if sink in ("filesystem", "file") or "path traversal" in blob:
        caps.add("FILE_SINK")
    if sink in ("reflection", "dynamicloading", "dynamic_loading") or "dexclassloader" in blob \
            or "dynamic code" in blob or "reflection" in blob:
        caps.add("CODE_LOADING")
    if src in ("user input", "intent", "contentprovider", "content provider"):
        caps.add("EXTERNAL_INPUT")
    # Secrets (only REAL secrets qualify)
    if _secret_status(f) in C.REAL_SECRET_STATUSES or (
            cat == "secrets" and _secret_status(f) not in C.REJECT_SECRET_STATUSES
            and (f.get("secret_intelligence") or f.get("value"))):
        caps.add("SECRET")
        st = ((f.get("secret_intelligence") or {}).get("secret_type") or "").lower()
        if "api" in st or "key" in st or "aws" in st or "google" in st or "stripe" in st:
            caps.add("API_KEY")
        if "token" in st or "jwt" in st or "bearer" in blob or "session" in blob:
            caps.add("TOKEN")
    # Network / crypto / cert
    if "cleartext" in blob:
        caps.add("CLEARTEXT")
    # CERT_BYPASS requires evidence of DISABLED validation — never a generic
    # certificate finding (a debug cert, or "pinning detected", is not a bypass).
    if any(k in blob for k in ("certificate validation", "trustmanager", "trust all",
                               "trustall", "onreceivedsslerror", "hostnameverifier",
                               "allow_all_hostname", "disable ssl", "ignore ssl")):
        caps.add("CERT_BYPASS")
    if cat == "network security":
        caps.add("NETWORK")
    if (cat in ("cryptography", "crypto")) and any(w in blob for w in
            ("weak", "insecure", "ecb", "md5", "sha-1", "sha1", "des", "rc4", "static iv")):
        caps.add("WEAK_CRYPTO")
    # Storage / manifest posture
    if cat == "data storage" or "sharedpreferences" in blob or "insecure storage" in blob \
            or "world readable" in blob or "world writable" in blob:
        caps.add("INSECURE_STORAGE")
    if "allowbackup" in blob or "backup enabled" in blob or "backup allowed" in blob:
        caps.add("BACKUP")
    if "debuggable" in blob:
        caps.add("DEBUGGABLE")
    if cat == "binary hardening" or str(f.get("file_path") or "").endswith((".so", ".dylib")):
        caps.add("NATIVE")
    if "jni" in blob:
        caps.add("JNI")
    return caps


def chain_role(f: dict) -> str:
    """required | supporting | excluded — SAFE CHAINING from Triage + Secret status."""
    if _secret_status(f) in C.REJECT_SECRET_STATUSES:
        return "excluded"
    tri = f.get("triage") or {}
    decision = tri.get("decision", "")
    if decision in C.EXCLUDED_DECISIONS:
        return "excluded"
    if f.get("suppressed"):
        # Suppressed findings may only lend structural context.
        return "supporting" if (tag_capabilities(f) & _STRUCTURAL_CAPS) else "excluded"
    if decision in C.SUPPORTING_ONLY_DECISIONS:
        return "supporting"
    vis = tri.get("visibility", "")
    if vis == "HiddenByDefault":
        return "supporting" if (tag_capabilities(f) & _STRUCTURAL_CAPS) else "excluded"
    return "required"


# ════════════════════════════════════════════════════════════════════════════
# Context
# ════════════════════════════════════════════════════════════════════════════
class ChainContext:
    def __init__(self, results: dict):
        self.results = results
        self.platform = results.get("platform") or "android"
        self.surface = results.get("attack_surface") or {}
        self.findings = [f for f in (results.get("findings") or []) if isinstance(f, dict)]
        self.mitigations = _detect_mitigations(results)

        # Tag + role each finding once (deterministic).
        self.tagged: list[dict] = []
        for f in self.findings:
            role = chain_role(f)
            if role == "excluded":
                continue
            self.tagged.append({"f": f, "caps": tag_capabilities(f), "role": role,
                                "id": _finding_id(f)})
        # Stable ordering: strongest first (confidence, then evidence), then id.
        self.tagged.sort(key=lambda t: (-_conf(t["f"]), C.EVIDENCE_RANK.get(_equality(t["f"]), 4), t["id"]))

    def entry_point(self, template) -> tuple[dict | None, str]:
        """Return (entry_dict, reach_key) or (None, '') when no entry exists."""
        if template.entry_kind in ("distribution", "device"):
            return ({"label": template.entry_label, "kind": template.entry_kind,
                     "reachable": True, "component": ""},
                    "distribution" if template.entry_kind == "distribution" else "device")
        # external — need a structural entry from components or findings.
        comp = self._surface_entry(template.entry_caps)
        if comp:
            return ({"label": template.entry_label, "kind": "external",
                     "component": comp["name"], "reachable": True}, "external_reachable")
        ft = self._first_with_caps(template.entry_caps)
        if ft:
            reach = str(ft["f"].get("reachability") or "").upper()
            key = "external_reachable" if reach == "YES" else "external"
            return ({"label": template.entry_label, "kind": "external",
                     "component": ft["f"].get("component") or ft["f"].get("title", ""),
                     "reachable": reach in ("YES", "MAYBE", "")}, key)
        return None, ""

    def _surface_entry(self, caps: frozenset) -> dict | None:
        """First exported manifest component satisfying ANY requested entry cap."""
        want_provider = "EXPORTED_PROVIDER" in caps
        want_deeplink = "DEEPLINK" in caps
        want_exported = "EXPORTED" in caps
        for key in ("providers", "activities", "services", "receivers"):
            for c in sorted(self.surface.get(key) or [], key=lambda x: str(x.get("name", ""))):
                if not c.get("exported"):
                    continue
                if want_provider and key == "providers":
                    return {"name": c.get("name", key), "type": key}
                if want_deeplink and (c.get("browsable") or c.get("schemes")):
                    return {"name": c.get("name", key), "type": key}
                if want_exported:
                    return {"name": c.get("name", key), "type": key}
        return None

    def _first_with_caps(self, caps: frozenset) -> dict | None:
        for t in self.tagged:
            if t["caps"] & caps:
                return t
        return None

    def supporting(self, caps: frozenset, used: set) -> list[dict]:
        out = []
        for t in self.tagged:
            if t["id"] in used:
                continue
            if t["caps"] & caps:
                out.append(t)
        return out


def _detect_mitigations(results: dict) -> set:
    m: set = set()
    blob = " ".join(str((f or {}).get("title", "")) for f in (results.get("findings") or [])).lower()
    bonuses = " ".join(str(b) for b in ((results.get("score") or {}).get("bonuses") or [])).lower()
    text = blob + " " + bonuses
    if "certificate pinning" in text or "pinning detected" in text:
        m.add("cert_pinning")
    if "root detection" in text:
        m.add("root_detection")
    if "play integrity" in text or "safetynet" in text:
        m.add("attestation")
    return m


# ── small accessors ──────────────────────────────────────────────────────────
def _coerce_int(v, default: int) -> int:
    try:
        return int(round(float(v)))
    except (TypeError, ValueError):
        return default


def _conf(f: dict) -> int:
    for key in ("overall_confidence", "confidence_score", "confidence"):
        v = f.get(key)
        if v not in (None, ""):
            return max(0, min(100, _coerce_int(v, 50)))
    return 50


def _equality(f: dict) -> str:
    return ((f.get("evidence_bundle") or {}).get("quality")) or "Missing"


def _finding_id(f: dict) -> str:
    return f.get("canonical_id") or f.get("rule_id") or f.get("id") or \
        ("F-" + hashlib.sha1(str(f.get("title", "")).encode("utf-8", "replace")).hexdigest()[:8])


# ════════════════════════════════════════════════════════════════════════════
# Scoring (from prior-engine outputs only)
# ════════════════════════════════════════════════════════════════════════════
def _evidence_quality(findings: list[dict]) -> str:
    if not findings:
        return "Missing"
    worst = max(C.EVIDENCE_RANK.get(_equality(f), 4) for f in findings)
    return C.EVIDENCE_BY_RANK[worst]


def _chain_confidence(required: list[dict], reach_key: str) -> tuple[int, dict]:
    mean_conf = sum(_conf(f) for f in required) / len(required)
    mean_ev = sum(C.EVIDENCE_SCORE.get(_equality(f), 10) for f in required) / len(required)
    blend = (C.CONFIDENCE_BLEND["member_confidence"] * mean_conf
             + C.CONFIDENCE_BLEND["member_evidence"] * mean_ev)
    mult = C.ENTRY_REACH_MULTIPLIER.get(reach_key, 0.85)
    score = max(0, min(100, round(blend * mult)))
    return score, {"mean_member_confidence": round(mean_conf), "mean_member_evidence": round(mean_ev),
                   "entry_reach_multiplier": mult, "formula": "0.55*conf + 0.45*evidence, scaled by reachability"}


def _chain_exploitability(required: list[dict], reach_key: str, app_control: bool,
                          blocked: bool) -> tuple[int, dict]:
    base = C.EXPLOIT_BASE.get(reach_key, 55)
    expl_conf = [_coerce_int(f.get("exploitability_confidence"), 0) for f in required]
    avg_expl = round(sum(expl_conf) / len(expl_conf)) if expl_conf else 0
    # Blend the entry-kind base with the members' own exploitability confidence.
    score = round((base + avg_expl) / 2) if avg_expl else base
    if app_control:
        score += C.EXPLOIT_APP_CONTROL_BONUS
    if blocked:
        score -= C.EXPLOIT_BLOCKED_PENALTY
    score = max(0, min(100, score))
    return score, {"entry_base": base, "avg_member_exploitability": avg_expl,
                   "app_control_bonus": C.EXPLOIT_APP_CONTROL_BONUS if app_control else 0,
                   "blocked_penalty": C.EXPLOIT_BLOCKED_PENALTY if blocked else 0}


def _chain_severity(goal: str, exploitability: int, blocked: bool) -> str:
    rank = C.sev_rank(C.GOAL_SEVERITY.get(goal, C.GOAL_SEVERITY["default"]))
    if exploitability < C.SEVERITY_DOWNGRADE_EXPLOIT:
        rank += 1
    if blocked:
        rank += 1
    return C.sev_by_rank(rank)


# ════════════════════════════════════════════════════════════════════════════
# Chain assembly
# ════════════════════════════════════════════════════════════════════════════
def _aggregate_evidence(findings: list[dict]):
    files, classes, methods, refs = [], [], [], []
    for f in findings:
        eb = f.get("evidence_bundle") or {}
        prim = eb.get("primary") or {}
        fp = prim.get("relative_path") or prim.get("file_path") or f.get("file_path")
        if fp and fp not in files:
            files.append(fp)
        loc = prim.get("locator") or {}
        if loc.get("class") and loc["class"] not in classes:
            classes.append(loc["class"])
        if loc.get("method") and loc["method"] not in methods:
            methods.append(loc["method"])
        if eb.get("evidence_id"):
            refs.append({"finding": _finding_id(f), "evidence_id": eb["evidence_id"],
                         "file": fp, "line": prim.get("line")})
    return files, classes, methods, refs


def _build_graph(entry: dict, required: list[dict], supporting: list[dict],
                 goal_label: str, mitigations: list[str]) -> ChainGraph:
    g = ChainGraph()
    en = g.add_node(ChainNode(id="entry", type=NodeType.ENTRY_POINT,
                              label=entry.get("label", "Entry"),
                              ref=entry.get("component", ""),
                              metadata={"kind": entry.get("kind")}))
    if entry.get("component"):
        cn = g.add_node(ChainNode(id="component", type=NodeType.ACTIVITY,
                                  label=entry["component"], ref=entry["component"]))
        g.add_edge(ChainEdge(en.id, cn.id, EdgeRelation.EXPOSES, "exposes"))
        prev = cn.id
    else:
        prev = en.id
    for i, f in enumerate(required):
        nid = f"req{i}"
        g.add_node(ChainNode(id=nid, type=NodeType.FINDING, label=f.get("title", "finding"),
                             ref=_finding_id(f),
                             metadata={"owner": f.get("owner_type"),
                                       "confidence": f.get("overall_confidence"),
                                       "evidence": (f.get("evidence_bundle") or {}).get("quality")}))
        g.add_edge(ChainEdge(prev, nid, EdgeRelation.LEADS_TO, "enables"))
        prev = nid
    for i, f in enumerate(supporting):
        nid = f"sup{i}"
        g.add_node(ChainNode(id=nid, type=NodeType.FINDING, label=f.get("title", "finding"),
                             ref=_finding_id(f), metadata={"role": "supporting"}))
        g.add_edge(ChainEdge(nid, prev, EdgeRelation.WEAKENS, "supports"))
    goal = g.add_node(ChainNode(id="goal", type=NodeType.GOAL, label=goal_label))
    g.add_edge(ChainEdge(prev, goal.id, EdgeRelation.LEADS_TO, "achieves"))
    for m in mitigations:
        mn = g.add_node(ChainNode(id="mit-" + hashlib.sha1(m.encode()).hexdigest()[:6],
                                  type=NodeType.RESOURCE, label=m, metadata={"role": "mitigation"}))
        g.add_edge(ChainEdge(mn.id, goal.id, EdgeRelation.PROTECTS, "mitigates"))
    return g


def _build_narrative(template, entry: dict, required: list[dict], goal_label: str) -> list[dict]:
    steps = [{"order": 1, "title": "Entry point", "description": entry.get("label", ""),
              "finding": "", "evidence": entry.get("component", "")}]
    for i, f in enumerate(required):
        eb = f.get("evidence_bundle") or {}
        prim = eb.get("primary") or {}
        ev = ""
        if prim.get("relative_path") or prim.get("file_path"):
            ev = (prim.get("relative_path") or prim.get("file_path"))
            if prim.get("line"):
                ev += f":{prim['line']}"
        label = template.slot_labels[i] if i < len(template.slot_labels) else f.get("title", "")
        steps.append({"order": i + 2, "title": label, "description": f.get("title", ""),
                      "finding": _finding_id(f), "evidence": ev})
    steps.append({"order": len(required) + 2, "title": "Objective achieved",
                  "description": goal_label, "finding": "", "evidence": ""})
    return steps


def _summary_counts(findings: list[dict], key_path) -> dict:
    out: dict = {}
    for f in findings:
        v = key_path(f)
        if v:
            out[v] = out.get(v, 0) + 1
    return out


# ════════════════════════════════════════════════════════════════════════════
# The engine
# ════════════════════════════════════════════════════════════════════════════
class AttackChainEngine:
    version = C.CHAIN_VERSION

    def __init__(self, templates: list | None = None):
        tmpl = templates if templates is not None else T.TEMPLATES
        self._templates = sorted(tmpl, key=lambda t: (-t.priority, t.id))

    def build_chains(self, results: dict) -> list[dict]:
        ctx = ChainContext(results)
        chains: list[AttackChain] = []
        emitted_member_sets: list[frozenset] = []

        for tmpl in self._templates:
            entry, reach_key = ctx.entry_point(tmpl)
            if entry is None:
                continue
            # Constrained slot matching: fill the most-constrained slot (fewest
            # candidate findings) first, so a versatile finding that matches
            # several slots is not greedily consumed by an earlier one.
            slots = list(enumerate(tmpl.required_slots))
            cand = {i: [t for t in ctx.tagged if t["role"] == "required" and (t["caps"] & s)]
                    for i, s in slots}
            used: set = set()
            assign: dict = {}
            ok = True
            for i, _s in sorted(slots, key=lambda x: (len(cand[x[0]]), x[0])):
                pick = next((t for t in cand[i] if t["id"] not in used), None)
                if pick is None:
                    ok = False
                    break
                used.add(pick["id"])
                assign[i] = pick
            if not ok:
                continue
            required_t = [assign[i] for i, _ in slots]
            required = [t["f"] for t in required_t]
            member_set = frozenset(_finding_id(f) for f in required)
            # Avoid "finding soup": skip if these required findings are already
            # fully represented by a higher-priority chain.
            if any(member_set <= prev for prev in emitted_member_sets):
                continue

            support_t = ctx.supporting(tmpl.supporting_caps, used) if tmpl.supporting_caps else []
            supporting = [t["f"] for t in support_t]
            chains.append(self._assemble(tmpl, entry, reach_key, required, supporting, ctx))
            emitted_member_sets.append(member_set)

        chains.sort(key=lambda c: (C.sev_rank(c.severity), -c.overall_confidence, c.id))
        return [c.to_dict() for c in chains]

    def _assemble(self, tmpl, entry, reach_key, required, supporting, ctx) -> AttackChain:
        blocked_by = [b for b in tmpl.blockers if b in ctx.mitigations]
        blocked = bool(blocked_by)
        app_control = any((f.get("owner_type") == "Application") for f in required)

        confidence, conf_expl = _chain_confidence(required, reach_key)
        exploitability, expl_expl = _chain_exploitability(required, reach_key, app_control, blocked)
        evidence_q = _evidence_quality(required)
        severity = _chain_severity(tmpl.goal, exploitability, blocked)
        files, classes, methods, refs = _aggregate_evidence(required + supporting)
        components = [entry["component"]] if entry.get("component") else []

        members = required + supporting
        chain = AttackChain(
            id=self._chain_id(tmpl, required),
            name=tmpl.name, type=tmpl.type, goal=tmpl.summary,
            summary=tmpl.summary,
            prerequisites=list(tmpl.prerequisites),
            entry_point=entry,
            steps=_build_narrative(tmpl, entry, required, tmpl.impact),
            required_findings=[_finding_id(f) for f in required],
            supporting_findings=[_finding_id(f) for f in supporting],
            blocked_by=blocked_by, mitigations=list(tmpl.mitigations), blocked=blocked,
            overall_confidence=confidence, overall_evidence_quality=evidence_q,
            overall_exploitability=exploitability, overall_impact=tmpl.impact,
            severity=severity,
            affected_components=components, affected_files=files,
            affected_classes=classes, affected_methods=methods,
            evidence_references=refs,
            triage_summary=_summary_counts(members, lambda f: (f.get("triage") or {}).get("decision")),
            ownership_summary=_summary_counts(members, lambda f: f.get("owner_type")),
            narrative=_build_narrative(tmpl, entry, required, tmpl.impact),
            graph=_build_graph(entry, required, supporting, tmpl.impact, tmpl.mitigations).to_dict(),
            version=self.version,
        )
        chain.confidence_explanation = {
            "why_exists": f"Required links for '{tmpl.name}' are all present with a real entry point "
                          f"({entry.get('kind')}).",
            "why_members": [{"finding": _finding_id(f), "title": f.get("title"),
                             "owner": f.get("owner_type"),
                             "evidence": (f.get("evidence_bundle") or {}).get("quality"),
                             "triage": (f.get("triage") or {}).get("decision")} for f in required],
            "why_supporting": [_finding_id(f) for f in supporting],
            "why_confidence": conf_expl,
            "why_exploitability": expl_expl,
            "why_blocked": (f"Mitigation(s) {blocked_by} break this chain." if blocked
                            else "No blocking mitigation detected."),
        }
        return chain

    @staticmethod
    def _chain_id(tmpl, required) -> str:
        basis = tmpl.id + "|" + "|".join(sorted(_finding_id(f) for f in required))
        return "CHAIN-" + hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:10]


# ── cached singleton + public API ────────────────────────────────────────────
_ENGINE: AttackChainEngine | None = None


def get_engine() -> AttackChainEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = AttackChainEngine()
    return _ENGINE


def build_chains(results: dict) -> list[dict]:
    return get_engine().build_chains(results)


def annotate(results: dict) -> dict:
    """Pipeline integration — emit `results['attack_chains_v2']` (+ summary).

    ADDITIVE and NON-DESTRUCTIVE: it reads the enriched findings and writes a new
    key; the legacy chain output, findings, severity, reports and UI are
    untouched. Runs after Triage (the final quality gate). Deterministic.
    """
    engine = get_engine()
    chains = engine.build_chains(results)
    by_type: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for c in chains:
        by_type[c["type"]] = by_type.get(c["type"], 0) + 1
        by_sev[c["severity"]] = by_sev.get(c["severity"], 0) + 1
    results["attack_chains_v2"] = chains
    results["attack_chains_v2_summary"] = {
        "count": len(chains), "by_type": by_type, "by_severity": by_sev,
        "blocked": sum(1 for c in chains if c["blocked"]), "version": engine.version,
    }
    log.info("[attack_chains_v2] %d chains | severity=%s", len(chains), by_sev)
    return results
