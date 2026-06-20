"""
Reachability Engine — Phase 7 Tasks 1 & 2.

Stops the tool thinking like a scanner ("does this setting exist?") and makes it
think like an analyst ("can this actually be exploited?").

Runs in finalize AFTER posture_analyzer (so attack surface, chains and
exploitability already exist) and BEFORE the priority sort / security score.

For every finding it determines:
  * reachability       — "YES" | "MAYBE" | "NO"
  * reachability_path  — ordered human steps from an entry point to the sink
  * likelihood         — "High" | "Medium" | "Low"
and lets reachability INFLUENCE severity (an unreachable setting is de-emphasised
one notch; severity_original is preserved).

It also generates results["attack_paths"]: human-readable, automatically
narrated exploit paths (steps + impact + likelihood) for the analyst overview.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cortex.reachability")

YES, MAYBE, NO = "YES", "MAYBE", "NO"

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_BY_RANK = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}
_HTTP = ("http", "https")


def _rank(s: str) -> int:
    return _SEV_RANK.get(str(s or "").lower(), 4)


# ── Entry points ─────────────────────────────────────────────────────────────
def _entry_points(results: dict) -> dict:
    """Summarize how an attacker can reach the app. Returns a dict of booleans +
    a list of human entry labels used to build reachability paths."""
    surface = results.get("attack_surface") or {}
    activities = surface.get("activities") or []
    services = surface.get("services") or []
    receivers = surface.get("receivers") or []
    providers = surface.get("providers") or []
    findings = results.get("findings") or []

    browsable = [a for a in activities if a.get("browsable")]
    custom_scheme = [a for a in browsable if not any(s in _HTTP for s in (a.get("schemes") or []))]
    exported_act = [a for a in activities if a.get("exported")]
    exported_provider = [p for p in providers if p.get("exported")]
    exported_other = [c for c in (services + receivers) if c.get("exported")]

    cleartext = any("cleartext" in (f.get("title", "") + f.get("category", "")).lower() for f in findings)
    network_finding = any(
        f.get("category") in ("Network", "Network Security") or "ssl" in f.get("title", "").lower()
        for f in findings
    )

    ep = {
        "has_browsable": bool(browsable),
        "has_custom_scheme": bool(custom_scheme),
        "has_exported_activity": bool(exported_act),
        "has_exported_provider": bool(exported_provider),
        "has_exported_service_or_receiver": bool(exported_other),
        "network_reachable": bool(cleartext or network_finding),
        # The APK itself is always retrievable from a store / sideload — secrets
        # and signing material are reachable by anyone who downloads it.
        "apk_distributable": True,
    }
    # Primary external entry label, strongest first.
    if custom_scheme:
        ep["primary"] = "Attacker sends a crafted custom-scheme deep link"
    elif browsable:
        ep["primary"] = "Attacker sends a crafted deep link / URI"
    elif exported_act:
        ep["primary"] = "Malicious app sends an intent to an exported activity"
    elif exported_other:
        ep["primary"] = "Malicious app sends an intent to an exported component"
    elif exported_provider:
        ep["primary"] = "Malicious app queries an exported content provider"
    else:
        ep["primary"] = ""
    ep["any_external_component"] = bool(
        browsable or exported_act or exported_other or exported_provider
    )
    return ep


# ── Per-finding reachability ─────────────────────────────────────────────────
_WEBVIEW_TOKENS = ("webview", "javascript", "loadurl", "addjavascriptinterface",
                   "setallowfileaccess", "ssl certificate errors")


def _blob(f: dict) -> str:
    return " ".join(str(f.get(k) or "") for k in ("title", "category", "description")).lower()


def _is_app_owned(f: dict) -> bool:
    label = f.get("ownership_label")
    if label:
        return label == "APPLICATION"
    return f.get("ownership") == "APP" or f.get("is_app_code") is True


def _classify(f: dict, ep: dict) -> tuple[str, list[str]]:
    """Return (reachability, path_steps) for one finding."""
    cat = str(f.get("category") or "")
    blob = _blob(f)
    tf = f.get("taint_flow") or {}

    # 1. Already correlated into an attack chain → proven reachable.
    if f.get("is_attack_chain") or f.get("in_attack_chain"):
        steps = []
        for s in (f.get("steps") or []):
            if isinstance(s, dict) and s.get("title"):
                steps.append(s["title"])
        if not steps and ep.get("primary"):
            steps = [ep["primary"], f.get("title", "Exploited")]
        return YES, steps or [f.get("title", "Exploited")]

    # 2. Exported component / deep link findings ARE the entry point.
    if cat in ("Attack Surface", "Deeplinks"):
        comp = f.get("component") or f.get("title", "exported component")
        return YES, [ep.get("primary") or "Any app on the device", f"Reaches {comp}"]

    # 3. Secrets & certificate material ship inside the APK.
    if cat in ("Certificate",) or f.get("source") in ("EVIDENCE", "SECRET") or "secret" in cat.lower():
        return YES, ["Attacker downloads the APK", "Extracts embedded material", f.get("title", "")]

    # 4. Manifest / config posture.
    if "debuggable" in blob:
        return (YES, ["Attacker with ADB / physical access", "Attaches debugger", "Reads memory & secrets"])
    if "backup" in blob and "allowbackup" in blob.replace(" ", "") or "backup enabled" in blob:
        return (YES, ["Attacker with ADB access", "adb backup", "Extracts app data directory"])
    if "cleartext" in blob:
        return (MAYBE, ["Attacker gains network position (same Wi-Fi / MitM)", "Intercepts cleartext HTTP", "Reads/modifies traffic"])

    # 5. WebView findings — reachable when an external entry feeds the WebView.
    if cat == "WebView" or any(t in blob for t in _WEBVIEW_TOKENS):
        if ep["any_external_component"]:
            path = [ep["primary"] or "External intent", "URL passed into WebView"]
            if "javascript" in blob:
                path.append("JavaScript executes in app context")
            if "ssl" in blob:
                path.append("SSL validation bypassed (MitM)")
            if "file" in blob:
                path.append("Local files read via file:// URLs")
            return YES, path
        return MAYBE, ["WebView loads content", f.get("title", "")]

    # 6. Taint flows — reachable when the source is externally controllable.
    if tf or cat == "Taint Analysis":
        src = str(tf.get("source_cat") or f.get("source_cat") or "").lower()
        externally_sourced = src in ("user input", "intent", "contentprovider")
        if externally_sourced and ep["any_external_component"]:
            chain = f.get("call_chain") or tf.get("chain") or []
            path = [ep.get("primary") or "External input"]
            path += [str(c) for c in chain[:4]] if chain else [f.get("title", "")]
            return YES, path
        if externally_sourced:
            return MAYBE, ["User-controlled input", f.get("title", "")]
        return MAYBE, [f.get("title", "")]

    # 7. Library / framework code with no external entry → not app-reachable.
    if not _is_app_owned(f):
        return NO, []

    # 8. App code, no identified external entry point.
    return MAYBE, []


# Likelihood from reachability + exploitability score.
def _likelihood(reach: str, exploitability: int) -> str:
    if reach == YES:
        return "High" if exploitability >= 60 else "Medium"
    if reach == MAYBE:
        return "Medium" if exploitability >= 70 else "Low"
    return "Low"


def analyze_reachability(results: dict) -> None:
    """Annotate every finding with reachability + path + likelihood, let it
    influence severity, and emit results["attack_paths"] + reachability_summary.
    """
    findings = results.get("findings") or []
    ep = _entry_points(results)
    counts = {YES: 0, MAYBE: 0, NO: 0}

    for f in findings:
        if not isinstance(f, dict):
            continue
        reach, path = _classify(f, ep)
        exploit = int(f.get("exploitability") or 0)
        f["reachability"] = reach
        f["reachability_path"] = path
        f["likelihood"] = _likelihood(reach, exploit)
        counts[reach] += 1

        # Reachability influences severity: a genuinely unreachable setting is
        # de-emphasised one notch (preserve the original). Never touch chains.
        if reach == NO and not f.get("is_attack_chain"):
            cur = _rank(f.get("severity"))
            if cur < 3:  # critical/high/medium -> down one notch, floor at low
                f.setdefault("severity_original", _SEV_BY_RANK.get(cur, "info"))
                f["severity"] = _SEV_BY_RANK[cur + 1]
                f["reachability_adjusted"] = True

    results["reachability_summary"] = {
        "reachable": counts[YES],
        "maybe": counts[MAYBE],
        "not_reachable": counts[NO],
        "entry_points": {k: v for k, v in ep.items() if k != "primary"},
        "primary_entry_point": ep.get("primary", ""),
    }
    _generate_attack_paths(results, ep)


# ── Attack path generation (Task 2) ──────────────────────────────────────────
def _generate_attack_paths(results: dict, ep: dict) -> None:
    """Build human-readable attack paths (steps + impact + likelihood). Chains
    are the primary source; standalone reachable critical/high findings that are
    not already represented by a chain are added as single-vector paths."""
    chain_data = results.get("_chain_data") or {}
    chains = chain_data.get("attack_chains", [])
    findings = results.get("findings") or []
    paths: list[dict] = []

    for c in chains:
        steps = [s.get("title", "") for s in c.get("steps", []) if isinstance(s, dict)]
        # Lead with the external trigger when the chain has an entry point.
        narrative_steps = ([ep["primary"]] if ep.get("primary") else []) + steps
        expl = int(c.get("exploitability") or 0)
        paths.append({
            "title": c.get("title", "Attack Chain"),
            "chain_id": c.get("id"),
            "steps": narrative_steps,
            "impact": c.get("impact", ""),
            "likelihood": "High" if expl >= 80 else ("Medium" if expl >= 50 else "Low"),
            "exploitability": expl,
            "severity": c.get("severity", "high"),
        })

    # Standalone reachable, high-impact findings not already inside a chain.
    covered = {p["title"].lower() for p in paths}
    for f in findings:
        if f.get("is_attack_chain") or f.get("in_attack_chain"):
            continue
        if f.get("reachability") != YES:
            continue
        if _rank(f.get("severity")) > 1:  # only critical/high
            continue
        title = f.get("title", "")
        if not title or any(title.lower() in c for c in covered):
            continue
        paths.append({
            "title": title,
            "chain_id": None,
            "steps": f.get("reachability_path") or [ep.get("primary") or "Reachable", title],
            "impact": f.get("impact", "") or "See finding detail.",
            "likelihood": f.get("likelihood", "Medium"),
            "exploitability": int(f.get("exploitability") or 0),
            "severity": f.get("severity", "high"),
        })

    paths.sort(key=lambda p: (_rank(p["severity"]), -(p.get("exploitability") or 0)))
    results["attack_paths"] = paths
