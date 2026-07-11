"""
Security Posture Analyzer — Phases C / F / H.

Runs once during finalize, AFTER attack chains have been synthesized and the
finding list has been cleaned. Pure over the ``results`` dict: it only READS the
attack surface / chains / findings already produced by the pipeline and ADDS
high-level aggregate objects the analyst workflow (and report) consumes:

  * Phase C — Attack Surface Inventory
        results["deep_link_inventory"]
        results["exported_component_inventory"]
        results["high_risk_components"]
        results["attack_surface_score"]
  * Phase H — Exploitability Scoring
        results["exploitability_score"]              (overall 0-100 + reason)
        per-finding f["exploitability"] for reachable categories
  * Phase F — Attack Graph
        results["attack_graph"]   {nodes, edges, paths}

Nothing here invents findings or mutates severities — it summarizes what the
detection engine already established so the data is correlated, scored and
navigable rather than a flat list.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cortex.posture")

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_HTTP_SCHEMES = ("http", "https")


def _rank(sev: str) -> int:
    return _SEV_RANK.get(str(sev or "").lower(), 4)


# ═════════════════════════════════════════════════════════════════════════════
# Phase C — Attack Surface Inventory
# ═════════════════════════════════════════════════════════════════════════════
_SENSITIVE_NAME_TOKENS = (
    "login", "auth", "pay", "transfer", "account", "admin", "webview",
    "deeplink", "url", "browser", "sync", "upload", "download", "export",
    "reset", "token", "oauth", "file", "share", "import", "profile",
)


def _is_library_owned_component(fqn: str) -> bool:
    """Whether the component's implementing CLASS is library/framework-owned,
    resolved by the shared ownership engine (never a bespoke prefix list)."""
    if not fqn or "." not in fqn:
        return False
    try:
        from .ownership import classify_component_class, is_library_owner
        return is_library_owner(classify_component_class(fqn, platform="android").owner_type)
    except Exception:
        return False


def _is_signature_protected(comp: dict) -> bool:
    """Whether the component sits behind a permission no third-party app can hold
    (signature / signatureOrSystem / privileged / internal / system).

    Reads the already-resolved ``permission_protection`` first (from
    ``_permission_protection_level``), then falls back to the authoritative
    signature/system permission table for the raw permission name.
    """
    prot = str(comp.get("permission_protection") or "").lower()
    if any(tok in prot for tok in ("signature", "privileged", "internal", "system")):
        return True
    perm = comp.get("permission")
    if not perm:
        return False
    try:
        from .common import is_signature_or_system_permission
        return is_signature_or_system_permission(perm)
    except Exception:
        return False


def _component_risk(comp: dict, comp_type: str) -> str:
    """Reachable-impact risk for a single exported component (mirrors the
    detection engine's _exported_severity, recomputed here so the inventory is
    self-contained and does not depend on finding text)."""
    if not comp.get("exported"):
        return "info"

    # (a) Ownership gate — a library/framework-provided receiver/activity is the
    # library vendor's surface, not the app's. Cap it low unless it carries
    # app-owned reachability evidence (a taint flow / call chain into app code).
    fqn = comp.get("name") or comp.get("short_name") or ""
    has_app_reach = bool(comp.get("taint_flow") or comp.get("call_chain")
                         or comp.get("app_owned_reachability"))
    if _is_library_owned_component(fqn) and not has_app_reach:
        return "low"

    # (b) Permission-boundary gate — a component that is NOT reachable without a
    # permission (it declares one) AND that permission is signature/privileged/
    # system/internal cannot be triggered by any third-party app → not high-risk.
    reachable_without_permission = not bool(comp.get("permission"))
    if not reachable_without_permission and _is_signature_protected(comp):
        return "low"

    name = (comp.get("short_name") or "").lower()
    schemes = comp.get("schemes") or []
    deeplinks = comp.get("deeplinks") or []
    browsable = bool(comp.get("browsable"))
    actions = comp.get("actions") or []
    url_like = browsable or bool(deeplinks) or any(s in _HTTP_SCHEMES for s in schemes)
    sensitive = any(tok in name for tok in _SENSITIVE_NAME_TOKENS)
    # An exported provider with no permission boundary is always high-impact.
    if comp_type == "providers":
        prot = (comp.get("permission_protection") or "").lower()
        if not comp.get("permission") or prot in ("normal", "dangerous", "unknown", ""):
            return "high"
        return "medium"
    if comp_type == "activities":
        if url_like or sensitive:
            return "high"
        return "medium" if actions else "low"
    if comp_type == "services":
        return "high" if sensitive else "medium"
    if comp_type == "receivers":
        return "high" if sensitive else ("medium" if actions else "low")
    return "medium"


def _singular(key: str) -> str:
    return {"activities": "activity", "services": "service",
            "receivers": "receiver", "providers": "provider"}.get(key, key)


# Taint sink categories a deep-link value must NEVER reach unvalidated, → a reader note.
_DEEP_LINK_CONSUMER_SINKS = {
    "WebView":    "a WebView load (script/URL injection)",
    "FileSystem": "a file path (path traversal / arbitrary write)",
    "SQLite":     "a SQL query (SQL injection)",
    "Execution":  "an OS command (command injection)",
    "Crypto":     "a crypto call (key/IV misuse)",
    "Network":    "a network request (SSRF / exfiltration)",
}


def _deep_link_consumer(results: dict, activity_fqn: str, short_name: str) -> dict | None:
    """Best-effort: REUSE the taint result (never re-scan) to note whether a value
    entering this activity (deep-link data via getIntent().getData()/getQueryParameter)
    reaches a high-value sink unvalidated. Matches taint flows whose source class is
    this activity."""
    if not activity_fqn and not short_name:
        return None
    for tf in results.get("taint_flows") or []:
        if not isinstance(tf, dict):
            continue
        cls = str(tf.get("class_name") or "")
        if not cls:
            continue
        same = (cls == activity_fqn
                or (activity_fqn and (cls.endswith(activity_fqn) or activity_fqn.endswith(cls)))
                or (short_name and cls.rsplit(".", 1)[-1] == short_name))
        sink_cat = str(tf.get("sink_cat") or "")
        if same and sink_cat in _DEEP_LINK_CONSUMER_SINKS:
            return {
                "sink_cat": sink_cat, "sink": tf.get("sink"),
                "source_cat": tf.get("source_cat"),
                "note": (f"deep-link input may reach {_DEEP_LINK_CONSUMER_SINKS[sink_cat]} "
                         f"via {tf.get('sink')} — validate the URI/query before use"),
            }
    return None


def _build_deep_link_map(results: dict, surface: dict) -> list[dict]:
    """Per exported activity: its structured deep-link entries (scheme→host→path with
    BROWSABLE/autoVerify badges, App Link vs custom-scheme) + a best-effort taint
    consumer note. Sorted custom-scheme (higher attack surface) first."""
    out: list[dict] = []
    for c in (surface.get("activities") or []):
        entries = c.get("deep_links") or []
        if not entries:
            continue
        fqn = c.get("name") or ""
        short = c.get("short_name") or (fqn.rsplit(".", 1)[-1] if fqn else "")
        has_custom = any(e.get("custom_scheme") for e in entries)
        out.append({
            "activity": fqn,
            "short_name": short,
            "exported": bool(c.get("exported")),
            "entries": entries,
            "has_custom_scheme": has_custom,
            "verified_app_link": any(e.get("verified") for e in entries),
            "consumer": _deep_link_consumer(results, fqn, short),
        })
    # Custom-scheme (unverified, hijackable) first — the higher attack surface.
    out.sort(key=lambda a: (0 if a["has_custom_scheme"] else 1, a["short_name"]))
    return out


def build_attack_surface_inventory(results: dict) -> None:
    surface = results.get("attack_surface") or {}

    exported_components: list[dict] = []
    high_risk: list[dict] = []
    by_type: dict[str, dict] = {}

    for key in ("activities", "services", "receivers", "providers"):
        items = surface.get(key) or []
        exported = [c for c in items if c.get("exported")]
        by_type[key] = {"total": len(items), "exported": len(exported)}
        for c in exported:
            risk = _component_risk(c, key)
            entry = {
                "name": c.get("name") or c.get("short_name"),
                "short_name": c.get("short_name"),
                "type": _singular(key),
                "exported": True,
                "permission": c.get("permission") or None,
                "permission_protection": c.get("permission_protection") or None,
                "browsable": bool(c.get("browsable")),
                "schemes": c.get("schemes") or [],
                "deeplinks": c.get("deeplinks") or [],
                "actions": c.get("actions") or [],
                "authorities": c.get("authorities") or "",
                "risk": risk,
                "reachable_without_permission": not bool(c.get("permission")),
            }
            exported_components.append(entry)
            if _rank(risk) <= 1:  # high or critical
                high_risk.append(entry)

    exported_components.sort(key=lambda e: _rank(e["risk"]))
    high_risk.sort(key=lambda e: _rank(e["risk"]))

    results["exported_component_inventory"] = {
        "total": sum(b["total"] for b in by_type.values()),
        "exported_total": len(exported_components),
        "by_type": by_type,
        "components": exported_components,
    }
    results["high_risk_components"] = high_risk

    # ── Deep link inventory ──────────────────────────────────────────────────
    dl_entries: list[dict] = []
    all_schemes: set[str] = set()
    all_hosts: set[str] = set()
    for c in (surface.get("activities") or []):
        schemes = c.get("schemes") or []
        hosts = c.get("hosts") or []
        deeplinks = c.get("deeplinks") or []
        browsable = bool(c.get("browsable"))
        if not (schemes or deeplinks or browsable):
            continue
        all_schemes.update(schemes)
        all_hosts.update(hosts)
        is_app_link = any(s in _HTTP_SCHEMES for s in schemes)
        dl_entries.append({
            "activity": c.get("name") or c.get("short_name"),
            "schemes": schemes,
            "hosts": hosts,
            "deeplinks": deeplinks,
            "browsable": browsable,
            "type": "app_link" if is_app_link else "custom_scheme",
            # App Links require a verified assetlinks.json; custom schemes can
            # never be verified and are hijackable by any installed app.
            "verified": False,
            "hijackable": not is_app_link,
        })

    custom = [e for e in dl_entries if e["type"] == "custom_scheme"]
    app_links = [e for e in dl_entries if e["type"] == "app_link"]
    results["deep_link_inventory"] = {
        "total": len(dl_entries),
        "schemes": sorted(all_schemes),
        "hosts": sorted(all_hosts),
        "custom_scheme_count": len(custom),
        "app_link_count": len(app_links),
        "hijackable_count": len(custom),
        "entries": dl_entries,
    }

    # ── Structured deep-link map (scheme→host→path + badges + taint consumer) ──
    results["deep_link_map"] = _build_deep_link_map(results, surface)

    # ── Attack Surface Score (0-100; higher = larger / riskier surface) ──────
    factors: list[str] = []
    score = 0
    n_exported = len(exported_components)
    if n_exported:
        score += min(n_exported * 6, 40)
        factors.append(f"{n_exported} exported component(s)")
    n_highrisk = len(high_risk)
    if n_highrisk:
        score += min(n_highrisk * 10, 35)
        factors.append(f"{n_highrisk} high-risk exported component(s)")
    n_exp_provider = by_type.get("providers", {}).get("exported", 0)
    if n_exp_provider:
        score += min(n_exp_provider * 8, 16)
        factors.append(f"{n_exp_provider} exported content provider(s)")
    if custom:
        score += min(len(custom) * 6, 18)
        factors.append(f"{len(custom)} hijackable custom-scheme deep link(s)")
    if app_links:
        score += 4
        factors.append(f"{len(app_links)} app-link host(s)")
    score = min(score, 100)
    rating = ("critical" if score >= 75 else "high" if score >= 50
              else "medium" if score >= 25 else "low")
    results["attack_surface_score"] = {
        "score": score,
        "rating": rating,
        "factors": factors,
        "exported_components": n_exported,
        "high_risk_components": n_highrisk,
        "deep_links": len(dl_entries),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Phase H — Exploitability Scoring
# ═════════════════════════════════════════════════════════════════════════════
# Factor → weight. Mirrors the brief's exploitability factor list. A finding's
# (or chain's) exploitability is the capped sum of the factors it exhibits.
_FACTOR_WEIGHTS = {
    "exported": 25,
    "user_controlled": 18,
    "auth_bypass": 22,
    "network_reachable": 14,
    "webview": 16,
    "javascript": 14,
    "ssl_bypass": 20,
    "storage_access": 10,
    "file_access": 14,
}
_FACTOR_PHRASE = {
    "exported": "an externally reachable exported component",
    "user_controlled": "attacker-controlled input",
    "auth_bypass": "an authentication/authorization bypass",
    "network_reachable": "network reachability",
    "webview": "a WebView",
    "javascript": "JavaScript execution enabled",
    "ssl_bypass": "SSL validation bypass",
    "storage_access": "sensitive storage access",
    "file_access": "local file access",
}


def _finding_factors(f: dict) -> list[str]:
    blob = " ".join(str(f.get(k) or "") for k in
                    ("title", "category", "description", "snippet", "evidence")).lower()
    factors: list[str] = []
    if "export" in blob or f.get("category") in ("Attack Surface", "Deeplinks"):
        factors.append("exported")
    if any(t in blob for t in ("url", "intent", "deeplink", "user-controlled",
                               "attacker-controlled", "browsable", "extra")):
        factors.append("user_controlled")
    if any(t in blob for t in ("auth bypass", "authentication bypass",
                               "access control", "insecure access")):
        factors.append("auth_bypass")
    if any(t in blob for t in ("cleartext", "http", "network", "ssl", "tls", "mitm")):
        factors.append("network_reachable")
    if "webview" in blob:
        factors.append("webview")
    if "javascript" in blob or "setjavascriptenabled" in blob:
        factors.append("javascript")
    if any(t in blob for t in ("ssl error", "sslerror", "trust all", "trustmanager",
                               "certificate errors", "hostname")):
        factors.append("ssl_bypass")
    if any(t in blob for t in ("sharedpreferences", "external storage",
                               "world-readable", "backup", "database", "sqlite")):
        factors.append("storage_access")
    if any(t in blob for t in ("file access", "setallowfileaccess", "file://",
                               "file system", "path traversal")):
        factors.append("file_access")
    return factors


def _score_from_factors(factors: list[str]) -> int:
    return min(sum(_FACTOR_WEIGHTS.get(x, 0) for x in set(factors)), 100)


# Rating + its qualitative label are a PURE function of the score bucket, so the
# number, the one-word rating and the sentence lead can never disagree.
_RATING_BUCKETS = (
    (80, "critical", "Critical exploitability"),
    (60, "high",     "High exploitability"),
    (35, "medium",   "Moderate exploitability"),
    (0,  "low",      "Limited exploitability"),
)


def _rating_for(score: int) -> tuple[str, str]:
    for threshold, rating, label in _RATING_BUCKETS:
        if score >= threshold:
            return rating, label
    return "low", "Limited exploitability"


def _reason_from_factors(score: int, factors: list[str], context: str = "") -> str:
    """A sentence whose qualitative claim is fixed by the SCORE bucket and whose
    body enumerates the SAME factors that produced that score. Because both the
    lead and the score come from one factor set, the prose cannot contradict the
    number."""
    _, label = _rating_for(score)
    uniq = [x for x in _FACTOR_WEIGHTS if x in set(factors)]  # weight order
    if not uniq:
        # A named path with a real score (a v2 chain) but no recognized token factors
        # is still a path — attribute it rather than claiming none exists.
        return f"{label} — attacker path via {context}." if context \
            else f"{label} — no externally reachable attacker path identified."
    phrases = [_FACTOR_PHRASE[x] for x in uniq[:5]]
    lead = (context + ": ") if context else ""
    if len(phrases) == 1:
        body = phrases[0]
    else:
        body = ", ".join(phrases[:-1]) + " and " + phrases[-1]
    return f"{label} — {lead}attack path combines {body}."


def _v2_chain_factors(chain: dict) -> list[str]:
    """Attacker-path factors for a v2 chain, from its entry point + step titles —
    the same signals the reason sentence enumerates."""
    entry = chain.get("entry_point") or {}
    parts = [str(entry.get("label") or ""), str(entry.get("component") or "")]
    for s in chain.get("steps") or []:
        if isinstance(s, dict):
            parts.append(str(s.get("title") or ""))
            parts.append(str(s.get("description") or ""))
    return _finding_factors({"title": " ".join(parts)})


def compute_exploitability(results: dict) -> None:
    findings = results.get("findings", [])

    # Per-finding exploitability for reachable categories (additive field).
    reachable_cats = {"Attack Surface", "Deeplinks", "Network", "WebView",
                      "Data Storage", "Network Security", "Binary Hardening"}
    for f in findings:
        if not isinstance(f, dict) or f.get("is_attack_chain"):
            continue
        if f.get("category") in reachable_cats or _finding_factors(f):
            factors = _finding_factors(f)
            if factors:
                f.setdefault("exploitability", _score_from_factors(factors))
                f.setdefault("exploitability_factors", sorted(set(factors)))

    # Overall = the strongest attacker path. Each candidate is (score, factors,
    # context). The rating and the reason's qualitative lead are a pure function of
    # `score`, and the factors enumerate what produced it, so the number and the
    # sentence can never contradict.
    #
    # The dominant CHAIN is the v2 engine's #1 (attack_chains_v2[0]) — the SAME chain
    # the CISO summary and the chain list display as #1 — carrying the v2 engine's
    # own overall_exploitability. Sourcing exploitability and the chain ranking from
    # ONE engine keeps the exploitability sentence and the displayed #1 chain in sync
    # (they previously disagreed: exploitability read the legacy hint feeder).
    candidates: list[tuple[int, list[str], str]] = []
    v2_chains = results.get("attack_chains_v2") or []
    if v2_chains:
        top = v2_chains[0]
        candidates.append((int(top.get("overall_exploitability") or 0),
                           _v2_chain_factors(top),
                           top.get("name") or top.get("title") or "Attack chain"))
    for hr in results.get("high_risk_components", []):
        factors = ["exported"]
        if hr.get("browsable") or hr.get("deeplinks"):
            factors.append("user_controlled")
        if hr.get("type") == "provider":
            factors.append("storage_access")
        ctx = f"Exported {hr.get('type','component')} {hr.get('short_name','')}".strip()
        candidates.append((_score_from_factors(factors), factors, ctx))
    for f in findings:
        if isinstance(f, dict) and not f.get("is_attack_chain") and f.get("severity") == "critical":
            factors = _finding_factors(f)
            if factors:
                candidates.append((_score_from_factors(factors), factors,
                                   f.get("title", "Critical finding")))

    # Keep candidates with a real score. A v2 chain keeps the engine's number even if
    # its step titles yield no token factors; component/finding scores come from their
    # factors, so a positive score there already implies factors.
    scored = [t for t in candidates if t[0] > 0]

    if scored:
        score, factors, context = max(scored, key=lambda t: t[0])
        reason = _reason_from_factors(score, factors, context)
    else:
        score, reason = 0, _reason_from_factors(0, [], "")

    rating, _ = _rating_for(score)
    results["exploitability_score"] = {
        "score": int(score),
        "rating": rating,
        "reason": reason,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Phase F — Attack Graph
# ═════════════════════════════════════════════════════════════════════════════
def build_attack_graph(results: dict) -> None:
    """Build a node/edge attack graph from synthesized chains.

    Each chain becomes a directed path: an ENTRY node → its ordered steps. Nodes
    are deduplicated by (type,label) so steps shared across chains converge.
    """
    chain_data = results.get("_chain_data") or {}
    chains = chain_data.get("attack_chains", [])

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    paths: list[dict] = []

    def node(label: str, ntype: str, severity: str = "info") -> str:
        nid = f"{ntype}:{label}"
        existing = nodes.get(nid)
        if existing is None:
            nodes[nid] = {"id": nid, "label": label, "type": ntype, "severity": severity}
        elif _rank(severity) < _rank(existing["severity"]):
            existing["severity"] = severity
        return nid

    # Attacker root — the common origin for every chain.
    attacker = node("Attacker / Remote Input", "entry", "info")

    for c in chains:
        seq = [attacker]
        steps = c.get("steps", [])
        for s in steps:
            stype = {"entry_point": "entry", "vulnerability": "vuln",
                     "impact": "impact"}.get(s.get("type"), "vuln")
            nid = node(s.get("title", "step"), stype, s.get("severity", "medium"))
            seq.append(nid)
        # Terminal impact node summarizing the chain outcome.
        sink = node(c.get("impact") or c.get("title", "Impact"), "sink", c.get("severity", "high"))
        seq.append(sink)

        for a, b in zip(seq, seq[1:]):
            edges.append({"from": a, "to": b, "chain_id": c.get("id")})
        paths.append({
            "chain_id": c.get("id"),
            "title": c.get("title"),
            "severity": c.get("severity"),
            "exploitability": c.get("exploitability", 0),
            "sequence": seq,
        })

    # De-duplicate identical edges (same from/to/chain).
    seen = set()
    uniq_edges = []
    for e in edges:
        k = (e["from"], e["to"], e["chain_id"])
        if k in seen:
            continue
        seen.add(k)
        uniq_edges.append(e)

    results["attack_graph"] = {
        "nodes": list(nodes.values()),
        "edges": uniq_edges,
        "paths": paths,
        "node_count": len(nodes),
        "path_count": len(paths),
    }


def analyze_posture(results: dict) -> None:
    """Single finalize entry point for Phases C / F / H. Never raises."""
    for fn in (build_attack_surface_inventory, compute_exploitability, build_attack_graph):
        try:
            fn(results)
        except Exception:  # posture analysis must never break a scan
            log.exception("posture: %s failed", getattr(fn, "__name__", fn))
