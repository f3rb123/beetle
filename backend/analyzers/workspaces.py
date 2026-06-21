"""
Analyst Workspaces & Evidence Intelligence — Phase 11.75 (backend).

Builds graph-ready, analyst-oriented data structures from the intelligence the
pipeline ALREADY produced. Purely additive and deterministic: it only reads
existing result keys and writes NEW ones. No detection, no network, no changes to
findings logic / trust scoring / chain generation.

Adds:
  * chain_evidence[] + confidence_explanation on every attack chain (Task 1)
  * results["permissions_workspace"]   (Task 4)
  * results["certificate_workspace"]   (Task 5)
  * results["android_posture"]         (Task 6)
  * results["network_workspace"]       (Task 7)
  * used_in_files[] enrichment         (Task 8)
  * results["taint_graph"]             (Task 9, graph-ready)
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger("cortex.workspaces")

_WS = re.compile(r"^wss?://", re.I)


def _findings(results: dict) -> list:
    return [f for f in (results.get("findings") or []) if isinstance(f, dict)]


def _conf(f: dict) -> str:
    if f.get("evidence_quality"):
        return f["evidence_quality"]
    n = f.get("confidence_score") or f.get("confidence")
    try:
        n = float(n)
        return "HIGH" if n >= 70 else ("MEDIUM" if n >= 40 else "LOW")
    except (TypeError, ValueError):
        return "LOW"


# ═══════════════════════ Task 1 — chain evidence + confidence ═══════════════
# Role detection from a member finding's title/category, used both for the
# per-member "why_it_contributes" and the chain's self-explaining confidence.
_ROLE_RULES = [
    ("pii_source", re.compile(r"read_contacts|read_sms|location|get_accounts|camera|microphone|read_phone|pii|contacts|fine_location", re.I),
     "Collects sensitive user data (PII)."),
    ("transport_weakness", re.compile(r"cleartext|http traffic|tls|ssl|pinning|trustmanager|hostname", re.I),
     "Weak transport — traffic can be intercepted (MITM)."),
    ("exfil_sink", re.compile(r"exfil|upload|loadurl|webview|network request|http post|sendto|outbound", re.I),
     "Data can leave the device through this sink."),
    ("credential", re.compile(r"secret|credential|api key|token|password|private key|aws|firebase|stripe", re.I),
     "A usable credential is present in the app."),
    ("exposure", re.compile(r"public|s3|firebase.*read|unrestricted|exposed", re.I),
     "A public cloud exposure is confirmed."),
    ("entry_point", re.compile(r"exported|deeplink|deep link|browsable|intent", re.I),
     "An externally reachable entry point."),
]


def _role(title: str) -> tuple[str, str]:
    for role, rx, why in _ROLE_RULES:
        if rx.search(title or ""):
            return role, why
    return "step", "Contributes a step to the attack path."


def _all_chains(results: dict) -> list:
    chains = [f for f in _findings(results) if f.get("is_attack_chain")]
    chains += [c for c in (results.get("cloud_attack_paths") or []) if isinstance(c, dict)]
    return chains


def enrich_chains(results: dict) -> None:
    findings = _findings(results)
    by_id, by_title = {}, {}
    for f in findings:
        fid = f.get("canonical_id") or f.get("rule_id") or f.get("id")
        if fid:
            by_id.setdefault(str(fid), f)
        if f.get("title"):
            by_title.setdefault(f["title"], f)

    for chain in _all_chains(results):
        members = chain.get("attack_chain_members") or chain.get("components") or []
        evidence, roles = [], set()
        for m in members:
            if not isinstance(m, dict):
                continue
            title = m.get("title") or m.get("label") or ""
            fid = str(m.get("id") or m.get("ref") or "")
            full = by_id.get(fid) or by_title.get(title) or {}
            file = (m.get("file_path") or m.get("file")
                    or full.get("file_path") or (full.get("evidence") or {}).get("file_path") or "")
            line = full.get("line") or (full.get("evidence") or {}).get("line") or 0
            role, why = _role(title)
            roles.add(role)
            evidence.append({
                "finding_id": fid or (full.get("canonical_id") or ""),
                "title": title, "file": file, "line": line,
                "confidence": _conf(full) if full else (m.get("state") and "HIGH" or "LOW"),
                "why_it_contributes": why,
            })
        chain["chain_evidence"] = evidence

        has_runtime = any(
            (by_id.get(e["finding_id"]) or by_title.get(e["title"]) or {}).get("taint_flow")
            or e["line"] for e in evidence
        )
        checks = [
            {"label": "PII / sensitive source confirmed", "met": "pii_source" in roles},
            {"label": "Transport / control weakness confirmed", "met": "transport_weakness" in roles},
            {"label": "Exfiltration sink / endpoint found", "met": "exfil_sink" in roles},
            {"label": "Usable credential present", "met": "credential" in roles},
            {"label": "Public exposure confirmed", "met": "exposure" in roles},
            {"label": "Runtime / data-flow proof", "met": bool(has_runtime)},
        ]
        conf = chain.get("chain_confidence") or chain.get("confidence") or "LOW"
        met = [c["label"] for c in checks if c["met"]]
        missing = [c["label"] for c in checks if not c["met"]]
        chain["confidence_explanation"] = {
            "confidence": conf,
            "checks": checks,
            "summary": (
                f"Confidence {conf} — confirmed: {', '.join(met) or 'none'}."
                + (f" Missing: {', '.join(missing)}." if missing else "")
            ),
        }


# ═══════════════════════ Task 4 — permissions workspace ═════════════════════
def _permission_usage(results: dict) -> dict:
    """Best-effort permission→files map from EXISTING signals (android_api files,
    finding paths). Deterministic; empty when no signal — never scans new code."""
    usage: dict[str, set] = {}
    api = results.get("android_api") or {}
    api_files = sorted({f for files in api.values() for f in (files or [])})
    for f in _findings(results):
        path = f.get("file_path") or f.get("full_path")
        if not path:
            continue
        blob = f"{f.get('title','')} {f.get('description','')}".upper()
        for tok in re.findall(r"[A-Z_]{6,}", blob):
            usage.setdefault(tok, set()).add(path)
    return {k: sorted(v) for k, v in usage.items()}


def build_permissions_workspace(results: dict) -> None:
    perms = (results.get("permissions") or {}).get("classified") or []
    if not perms:
        all_perms = (results.get("permissions") or {}).get("all") or []
        perms = [{"permission": p, "short_name": str(p).split(".")[-1], "status": "normal"} for p in all_perms]
    findings = _findings(results)
    usage = _permission_usage(results)

    out = []
    for p in perms:
        name = p.get("permission") or ""
        short = p.get("short_name") or name.split(".")[-1]
        related = [f.get("title") for f in findings
                   if short and short.lower() in f"{f.get('title','')} {f.get('description','')}".lower()]
        out.append({
            "permission": name,
            "short_name": short,
            "type": p.get("status") or "normal",
            "description": p.get("description", ""),
            "where_used": usage.get(short.upper(), []),
            "used_in_files": usage.get(short.upper(), []),
            "findings": related[:10],
        })
    results["permissions_workspace"] = out


# ═══════════════════════ Task 5 — certificate workspace ═════════════════════
def build_certificate_workspace(results: dict) -> None:
    c = results.get("certificate") or {}
    if not c:
        results["certificate_workspace"] = {}
        return
    schemes = c.get("scheme") or c.get("schemes") or []
    has = lambda v: any(v in str(s).lower() for s in schemes)
    janus = c.get("janus_risk")
    if janus is None:
        janus = has("v1") and not has("v2") and not has("v3")
    subj = c.get("subject") or {}
    iss = c.get("issuer") or {}
    self_signed = bool(subj) and subj == iss
    cert_findings = [f.get("title") for f in _findings(results)
                     if "certificate" in f"{f.get('category','')} {f.get('title','')}".lower()]
    results["certificate_workspace"] = {
        "subject": ", ".join(f"{k}={v}" for k, v in subj.items()),
        "issuer": ", ".join(f"{k}={v}" for k, v in iss.items()),
        "serial": c.get("serial"),
        "sha1": c.get("sha1_fingerprint") or c.get("sha1"),
        "sha256": c.get("sha256_fingerprint") or c.get("sha256"),
        "sha512": c.get("sha512_fingerprint") or c.get("sha512"),
        "algorithm": c.get("signature_algo"),
        "key_size": c.get("key_size"),
        "key_type": c.get("key_type"),
        "signature_schemes": schemes,
        "debug_cert": bool(c.get("debug_cert")),
        "self_signed": self_signed,
        "janus_possible": bool(janus),
        "valid_from": c.get("valid_from"),
        "valid_to": c.get("valid_to"),
        "expired": bool(c.get("expired")),
        "findings": cert_findings,
    }


# ═══════════════════════ Task 6 — android posture ══════════════════════════
def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _item(value, risk):
    return {"value": value, "risk": risk}


def build_android_posture(results: dict) -> None:
    if results.get("platform") == "ios":
        return
    ms = results.get("manifest_security") or {}
    info = results.get("app_info") or {}
    nc = results.get("network_config") or {}
    sumc = nc.get("summary") or {}
    cert = results.get("certificate") or {}
    findings = _findings(results)
    has = lambda rx: any(re.search(rx, f"{f.get('title','')} {f.get('category','')}", re.I) for f in findings)

    min_sdk = _as_int(ms.get("min_sdk") if ms.get("min_sdk") is not None else info.get("min_sdk"))
    target_sdk = _as_int(ms.get("target_sdk") if ms.get("target_sdk") is not None else info.get("target_sdk"))
    debuggable = ms.get("debuggable") if ms.get("debuggable") is not None else info.get("debuggable")
    allow_backup = ms.get("allow_backup")
    schemes = cert.get("scheme") or cert.get("schemes") or []
    janus = cert.get("janus_risk")
    if janus is None:
        janus = any("v1" in str(s).lower() for s in schemes) and not any(("v2" in str(s).lower() or "v3" in str(s).lower()) for s in schemes)

    results["android_posture"] = {
        "debuggable": _item(debuggable, "risk" if debuggable else "good"),
        "allowBackup": _item(allow_backup, "warn" if allow_backup else "good"),
        "minSdk": _item(min_sdk, "warn" if (min_sdk is not None and min_sdk < 24) else "good"),
        "targetSdk": _item(target_sdk, "warn" if (target_sdk is not None and target_sdk < 30) else "good"),
        "cleartextTraffic": _item(sumc.get("cleartext_global"), "risk" if sumc.get("cleartext_global") else "good"),
        "networkSecurityConfig": _item(nc.get("present"), "good" if nc.get("present") else "warn"),
        "signatureScheme": _item(schemes, "good" if any(("v2" in str(s).lower() or "v3" in str(s).lower()) for s in schemes) else "warn"),
        "janusRisk": _item(bool(janus), "risk" if janus else "good"),
        "backupRisk": _item(bool(allow_backup), "warn" if allow_backup else "good"),
        "legacyAndroidSupport": _item(bool(min_sdk is not None and min_sdk < 24), "warn" if (min_sdk is not None and min_sdk < 24) else "good"),
        "installationOnOldVersions": _item(bool(min_sdk is not None and min_sdk < 21), "warn" if (min_sdk is not None and min_sdk < 21) else "good"),
        "rootDetection": _item(has(r"root detection|rootbeer"), "good" if has(r"root detection|rootbeer") else "warn"),
        "fridaDetection": _item(has(r"frida|instrumentation"), "good" if has(r"frida") else "warn"),
        "screenshotProtection": _item(has(r"flag_secure|screenshot"), "good" if has(r"flag_secure|screenshot") else "warn"),
        "certificatePinning": _item(sumc.get("has_pinning"), "good" if sumc.get("has_pinning") else "warn"),
    }


# ═══════════════════════ Task 7 — network workspace ════════════════════════
def build_network_workspace(results: dict) -> None:
    nc = results.get("network_config") or {}
    sumc = nc.get("summary") or {}
    base = nc.get("base_config") or {}
    ta = base.get("trust_anchors") or {}
    eps = results.get("endpoints") or []
    domains = [d.get("domain") for d in (results.get("domain_intel") or []) if isinstance(d, dict) and d.get("domain")]
    if not domains:
        domains = sorted({re.sub(r"^[a-z]+://", "", u).split("/")[0] for u in eps if "://" in u})

    results["network_workspace"] = {
        "domains": domains,
        "urls": [u for u in eps if not _WS.match(u)],
        "websockets": [u for u in eps if _WS.match(u)],
        "endpoints": eps,
        "ips": results.get("ips") or [],
        "trust_anchors": {
            "system": ta.get("system"),
            "user": ta.get("user"),
            "custom": [c.get("src") for c in (ta.get("custom_certs") or []) if isinstance(c, dict)],
        },
        "cleartext_enabled": bool(sumc.get("cleartext_global")),
        "pinning_detected": bool(sumc.get("has_pinning")),
        "network_security_config": bool(nc.get("present")),
    }


# ═══════════════════════ Task 9 — taint graph (graph-ready) ═════════════════
def build_taint_graph(results: dict) -> None:
    graph = []
    for f in _findings(results):
        tf = f.get("taint_flow")
        if not isinstance(tf, dict):
            continue
        graph.append({
            "id": f.get("canonical_id") or f.get("rule_id") or "",
            "source": tf.get("source"),
            "source_cat": tf.get("source_cat"),
            "sink": tf.get("sink"),
            "sink_cat": tf.get("sink_cat"),
            "call_chain": tf.get("chain") or [],
            "file": f.get("file_path") or "",
            "line": f.get("line") or 0,
            "risk": f.get("severity") or "info",
        })
    # Also accept a pre-built taint_flows list if present.
    for tf in results.get("taint_flows") or []:
        if isinstance(tf, dict) and tf.get("source") and not any(g["source"] == tf.get("source") and g["sink"] == tf.get("sink") for g in graph):
            graph.append({
                "id": "", "source": tf.get("source"), "source_cat": tf.get("source_cat"),
                "sink": tf.get("sink"), "sink_cat": tf.get("sink_cat"),
                "call_chain": tf.get("chain") or tf.get("call_chain") or [],
                "file": tf.get("file") or tf.get("class_name") or "", "line": tf.get("line") or 0,
                "risk": tf.get("risk") or tf.get("severity") or "info",
            })
    results["taint_graph"] = graph


# ═══════════════════════ Orchestrator ══════════════════════════════════════
def annotate(results: dict) -> None:
    """Build every workspace structure. Each step is independently guarded so a
    failure in one never blocks the others or the scan."""
    for fn in (enrich_chains, build_permissions_workspace, build_certificate_workspace,
               build_android_posture, build_network_workspace, build_taint_graph):
        try:
            fn(results)
        except Exception:
            log.exception("[workspaces] %s failed", fn.__name__)
    log.info("[workspaces] perms=%d cert=%s posture=%s net_urls=%d taint=%d chains=%d",
             len(results.get("permissions_workspace") or []),
             bool(results.get("certificate_workspace")),
             bool(results.get("android_posture")),
             len((results.get("network_workspace") or {}).get("urls") or []),
             len(results.get("taint_graph") or []),
             len(_all_chains(results)))
