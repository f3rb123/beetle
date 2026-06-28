"""
Source / Security Explorer model (Beetle 2.0, Phase 2.3).

The investigation workspace's backend is a thin OVERLAY, not a new analyzer: it
reuses metadata the platform analyzers already produced — ``results["findings"]``
(file_path / line / severity / category / cwe), ``results["secrets"]``,
``results["ips"]`` and the Flutter/React-Native ``project_structure`` — and projects
it into two indexes the frontend Source Explorer + Security Explorer consume:

* ``file_index``     — per file path: aggregated max-severity, per-severity counts,
  security categories, finding count and secret/network/certificate flags. Folders
  aggregate their children's severity on the client.
* ``security_index`` — each security category → the file paths that carry it, so a
  Security-Explorer category click filters the source tree.

It parses NOTHING new and adds no endpoint — it rides the existing ``results`` blob
the frontend already loads, and the file TREE itself is built client-side from the
existing ``/api/scans/{id}/files`` listing. Runs late in both analyzers' finalize, so
it sees the final (evidence-selected, fused) findings; Flutter/RN are covered
automatically because their findings are already in ``results``.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("cortex.source_explorer")

SOURCE_EXPLORER_VERSION = "1.0.0"

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0}

# The Security Explorer categories (spec order). Each maps to keyword/CWE signals on
# a finding; a finding may belong to several. Data, not logic — extend the tuples.
SECURITY_CATEGORIES = (
    "secrets", "crypto", "network", "storage", "components",
    "permissions", "certificates", "native", "authentication",
    "authorization", "ipc",
)

# (bucket, category/title keywords, cwe ids)
_BUCKET_RULES = (
    ("secrets", ("secret", "credential", "api key", "api token", "hardcoded password",
                 "auth token", "private key", "embedded secret"),
     ("cwe-798", "cwe-259", "cwe-321", "cwe-312")),
    ("crypto", ("crypto", "cipher", "cryptograph", "weak hash", "ecb", "encryption"),
     ("cwe-327", "cwe-326", "cwe-328", "cwe-916", "cwe-696", "cwe-780")),
    ("network", ("network security", "cleartext", "tls", "ssl", "transport", "http ",
                 "certificate validation", "websocket", "axios", "dio"),
     ("cwe-319", "cwe-295", "cwe-297", "cwe-296")),
    ("storage", ("storage", "database", "sharedpref", "asyncstorage", "mmkv", "realm",
                 "sqlite", "hive", "backup", "external storage"),
     ("cwe-312", "cwe-313", "cwe-922", "cwe-359")),
    ("components", ("component", "exported", "activity", "service", "receiver",
                    "provider", "task affinity", "launchmode"),
     ("cwe-926", "cwe-927")),
    ("permissions", ("permission",),
     ("cwe-276", "cwe-250", "cwe-732")),
    ("certificates", ("certificate", "signing", "code signing", "apk signing", "janus"),
     ("cwe-295", "cwe-347")),
    ("native", ("native", "jni", "elf", "mach-o", "binary protection", "instrumentation",
                "frida", "pie", "relro", "stack canary"),
     ("cwe-1188",)),
    ("authentication", ("authentication", "auth bypass", "login", "biometric",
                        "passcode", "missing auth"),
     ("cwe-287", "cwe-306", "cwe-304", "cwe-303")),
    ("authorization", ("authorization", "access control", "idor", "privilege"),
     ("cwe-285", "cwe-862", "cwe-863", "cwe-639", "cwe-269")),
    ("ipc", ("ipc", "intent", "platform channel", "native bridge", "methodchannel",
             "eventchannel", "broadcast", "deep link", "pending intent", "nativemodule",
             "turbomodule"),
     ("cwe-927", "cwe-926", "cwe-925", "cwe-749", "cwe-939")),
)


def _norm(p: str) -> str:
    return (p or "").replace("\\", "/").strip()


def _buckets_for(finding: dict) -> set[str]:
    cat = str(finding.get("category") or "").lower()
    title = str(finding.get("title") or "").lower()
    cwe = str(finding.get("cwe") or "").lower()
    blob = f"{cat} {title} {cwe}"
    out: set[str] = set()
    # A secret-bearing finding is always a secret regardless of wording.
    if finding.get("masked_value") or finding.get("value") or \
            str(finding.get("source") or "").upper() in ("SECRET", "EVIDENCE", "JWT_SCANNER"):
        out.add("secrets")
    for bucket, kws, cwes in _BUCKET_RULES:
        if any(k in blob for k in kws) or any(c in cwe for c in cwes):
            out.add(bucket)
    return out


def _finding_paths(finding: dict) -> list[str]:
    """Every source path a finding touches (primary + evidence locations)."""
    paths: list[str] = []
    primary = _norm(finding.get("file_path") or finding.get("file") or "")
    if primary:
        paths.append(primary)
    ev = finding.get("evidence_view") or {}
    pv = (ev.get("primary") or {}).get("file")
    if pv:
        paths.append(_norm(pv))
    for e in finding.get("file_evidence") or []:
        if isinstance(e, dict) and e.get("path"):
            paths.append(_norm(e["path"]))
    # De-dup, drop empties / synthetic artifact labels (no slash AND no extension).
    seen: list[str] = []
    for p in paths:
        if p and p not in seen:
            seen.append(p)
    return seen


def _merge(into: dict, path: str, severity: str, buckets: set[str], *,
           is_secret=False, is_network=False, is_cert=False, is_component=False):
    rec = into.get(path)
    if rec is None:
        rec = into[path] = {
            "max_severity": "info", "counts": {}, "categories": set(),
            "findings": 0, "secret": False, "network": False,
            "certificate": False, "component": False,
        }
    sev = (severity or "info").lower()
    if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(rec["max_severity"], 0):
        rec["max_severity"] = sev
    rec["counts"][sev] = rec["counts"].get(sev, 0) + 1
    rec["findings"] += 1
    rec["categories"].update(buckets)
    rec["secret"] = rec["secret"] or is_secret or ("secrets" in buckets)
    rec["network"] = rec["network"] or is_network or ("network" in buckets)
    rec["certificate"] = rec["certificate"] or is_cert or ("certificates" in buckets)
    rec["component"] = rec["component"] or is_component or ("components" in buckets)


def annotate(results: dict) -> dict:
    """Build ``results["source_explorer"]`` from existing finding/secret/IP metadata.
    Additive and defensive — never raises into the caller."""
    findings = results.get("findings") or []
    file_index: dict[str, dict] = {}
    security_index: dict[str, set] = {c: set() for c in SECURITY_CATEGORIES}

    # ── Findings → file_index + security_index ────────────────────────────────
    for f in findings:
        if not isinstance(f, dict) or f.get("secret_bridge"):
            continue
        buckets = _buckets_for(f)
        sev = str(f.get("severity") or "info").lower()
        for path in _finding_paths(f):
            _merge(file_index, path, sev, buckets)
            for b in buckets:
                security_index[b].add(path)

    # ── Secrets → secrets bucket + flag (reuse, no re-detection) ──────────────
    for s in results.get("secrets") or []:
        if not isinstance(s, dict):
            continue
        path = _norm(s.get("file_path") or (s.get("evidence") or {}).get("file_path") or "")
        if not path:
            continue
        _merge(file_index, path, s.get("severity") or "info", {"secrets"}, is_secret=True)
        security_index["secrets"].add(path)

    # ── IPs → network bucket + flag ───────────────────────────────────────────
    for ip in results.get("ips") or []:
        if not isinstance(ip, dict) or ip.get("suppressed"):
            continue
        path = _norm(ip.get("file_path") or "")
        if not path:
            continue
        _merge(file_index, path, ip.get("severity") or "info", {"network"}, is_network=True)
        security_index["network"].add(path)

    # ── Serialize (sets → sorted lists) ───────────────────────────────────────
    out_file_index = {
        p: {**rec, "categories": sorted(rec["categories"])}
        for p, rec in file_index.items()
    }
    out_security_index = {c: sorted(paths) for c, paths in security_index.items()}

    # Reuse the framework project structure (Flutter / React Native) when present.
    project_structure = None
    for key in ("flutter", "react_native"):
        meta = results.get(key)
        if isinstance(meta, dict) and meta.get("project_structure"):
            project_structure = {
                "framework": key,
                "dirs": meta["project_structure"],
                "key_files": meta.get("key_files", {}),
            }
            break

    by_sev: dict[str, int] = {}
    for rec in out_file_index.values():
        by_sev[rec["max_severity"]] = by_sev.get(rec["max_severity"], 0) + 1

    summary = {
        "version": SOURCE_EXPLORER_VERSION,
        "platform": results.get("platform"),
        "framework": (results.get("framework") or {}).get("type"),
        "file_index": out_file_index,
        "security_index": out_security_index,
        "project_structure": project_structure,
        "stats": {
            "annotated_files": len(out_file_index),
            "by_severity": by_sev,
            "by_category": {c: len(paths) for c, paths in out_security_index.items()},
        },
    }
    results["source_explorer"] = summary
    log.info("[source_explorer] files=%d categories=%s",
             len(out_file_index), summary["stats"]["by_category"])
    return results
