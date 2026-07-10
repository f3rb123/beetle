"""
Cloud Configuration Discovery (Beetle 2.5.5) — static, network-free.

Detects cloud storage / backend configuration that the URL extractor misses
because the values are BARE hostnames or non-http URIs (so ``extract_urls`` —
which only matches ``http(s)://…`` — never sees them). The motivating gap:

    <string name="google_storage_bucket">damn-vulnerable-bank.appspot.com</string>

is a real Firebase / Google Cloud Storage bucket but was previously invisible.

Covers (low false-positive, vendor-specific tokens only):
  * Firebase / Google Cloud Storage buckets — ``*.appspot.com``, ``gs://…``,
    ``firebasestorage.googleapis.com/v0/b/<bucket>``, ``storage.googleapis.com/<bucket>``
  * Firebase app endpoints — ``*.firebaseapp.com``, ``*.web.app``
  * Google Cloud Functions — ``*.cloudfunctions.net/…``

It deliberately does NOT re-detect the Firebase Realtime Database URL
(``*.firebaseio.com``) — that is already a first-class secret detector, and
re-emitting it here would duplicate findings.

Two stages, mirroring :mod:`network_intel`:

* :func:`scan` — raw hits over the decompiled tree (one per canonical value),
  reusing the evidence scanner's file caps / dir-skip / binary-dump filters.
* :func:`annotate` — classify provider/type, attribute ownership (reusing the
  Ownership Engine), de-duplicate, build ``results["cloud_config"]`` +
  ``results["cloud_config_summary"]`` and append canonical findings (category
  "Cloud Configuration") so Ownership / Evidence / Confidence / Finding Fusion
  process them exactly like any other finding.
"""
from __future__ import annotations

import logging
import os
import re

from .evidence_scanner import (
    is_binary_dump_path, _ev_should_skip_dir, _EV_MAX_FILES, _EV_MAX_FILE_BYTES,
)
from .path_utils import relativize_path
from .source_corpus import SourceCorpus

log = logging.getLogger("cortex.cloud_config")

CLOUD_CONFIG_VERSION = "1.0.0"

# Source / resource / config extensions across Android, iOS, Flutter and RN.
# Smali is excluded (kept for 2.5.6's broader sweep) — cloud config overwhelmingly
# lives in resources/strings/json/source, and the patterns below are vendor-specific.
_CC_EXTENSIONS = (
    ".java", ".kt", ".kts", ".xml", ".json", ".properties", ".txt", ".gradle",
    ".js", ".ts", ".jsx", ".tsx", ".dart", ".yaml", ".yml", ".conf", ".cfg",
    ".config", ".ini", ".env", ".swift", ".m", ".mm", ".h", ".plist", ".html",
)

# (type, provider, severity, regex). Each regex's group(1) is the bucket/host.
_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    ("FIREBASE_STORAGE_BUCKET", "Firebase", "low",
     re.compile(r"\b([a-z0-9][a-z0-9\-]{1,62}\.appspot\.com)\b", re.I)),
    ("FIREBASE_STORAGE_BUCKET", "Firebase", "low",
     re.compile(r"gs://([a-z0-9][a-z0-9_\-.]{1,62})", re.I)),
    ("FIREBASE_STORAGE_BUCKET", "Firebase", "low",
     re.compile(r"firebasestorage\.googleapis\.com/v0/b/([a-z0-9][a-z0-9_\-.]{1,62})", re.I)),
    ("GCS_BUCKET", "Google Cloud", "low",
     re.compile(r"\bstorage\.googleapis\.com/([a-z0-9][a-z0-9_\-.]{1,62})", re.I)),
    ("GCS_BUCKET", "Google Cloud", "low",
     re.compile(r"\b([a-z0-9][a-z0-9_\-.]{1,62})\.storage\.googleapis\.com\b", re.I)),
    ("FIREBASE_APP_ENDPOINT", "Firebase", "info",
     re.compile(r"\b([a-z0-9][a-z0-9\-]{1,62}\.(?:firebaseapp\.com|web\.app))\b", re.I)),
    ("GCP_CLOUD_FUNCTION", "Google Cloud", "info",
     re.compile(r"\b((?:[a-z0-9\-]+\.)?cloudfunctions\.net/[a-zA-Z0-9_\-]+)", re.I)),
]

_TYPE_LABEL = {
    "FIREBASE_STORAGE_BUCKET": "Firebase Storage Bucket",
    "GCS_BUCKET": "Google Cloud Storage Bucket",
    "FIREBASE_APP_ENDPOINT": "Firebase App Endpoint",
    "GCP_CLOUD_FUNCTION": "Google Cloud Function Endpoint",
}


def _canonical_value(stype: str, raw: str) -> str:
    """Normalize so the same bucket written different ways collapses to one hit
    (e.g. ``gs://x.appspot.com`` and ``x.appspot.com``)."""
    v = (raw or "").strip().strip("/").lower()
    # Reduce storage forms to the underlying bucket id so cross-pattern hits dedup.
    if stype in ("FIREBASE_STORAGE_BUCKET", "GCS_BUCKET"):
        v = v.removesuffix(".appspot.com")
    return v


def _project_id(stype: str, raw: str) -> str:
    """Best-effort Firebase project id from a bucket value (``<project>.appspot.com``)."""
    v = (raw or "").strip().strip("/").lower()
    if v.endswith(".appspot.com"):
        return v[: -len(".appspot.com")]
    return ""


def scan(base_dir: str, extra_dirs: list | None = None, *, corpus: SourceCorpus | None = None) -> list[dict]:
    """Raw cloud-config extraction over the decompiled tree. Returns one hit per
    (canonical value, file, line). No classification/ownership yet."""
    corpus = corpus or SourceCorpus()
    dirs: list[str] = []
    if extra_dirs:
        dirs.extend(d for d in extra_dirs if d and os.path.exists(d))
    if base_dir and os.path.exists(base_dir):
        dirs.append(base_dir)

    hits: list[dict] = []
    seen: set = set()           # (stype, canonical_value, rel_path, line)
    files_scanned = 0
    for scan_dir in dirs:
        if files_scanned >= _EV_MAX_FILES:
            break
        for root, subdirs, files in corpus.walk(scan_dir):
            rel_root = os.path.relpath(root, scan_dir)
            if rel_root != "." and _ev_should_skip_dir(rel_root):
                subdirs[:] = []
                continue
            for fname in files:
                if files_scanned >= _EV_MAX_FILES:
                    break
                if not fname.lower().endswith(_CC_EXTENSIONS) or is_binary_dump_path(fname):
                    continue
                fpath = os.path.join(root, fname)
                content = corpus.read_text(fpath, max_bytes=_EV_MAX_FILE_BYTES)
                if content is None:
                    continue
                files_scanned += 1
                if "appspot.com" not in content.lower() and "gs://" not in content.lower() \
                        and "googleapis.com" not in content.lower() \
                        and "firebaseapp.com" not in content.lower() \
                        and "web.app" not in content.lower() \
                        and "cloudfunctions.net" not in content.lower():
                    continue  # fast reject — no cloud token in this file
                lines = content.splitlines()
                rel_path = relativize_path(fpath, scan_dir)
                for stype, provider, severity, rx in _PATTERNS:
                    for m in rx.finditer(content):
                        value = m.group(1).strip().strip("/")
                        canon = _canonical_value(stype, value)
                        if not canon:
                            continue
                        line_no = content[:m.start()].count("\n") + 1
                        snippet = (lines[line_no - 1].strip() if line_no <= len(lines) else value)[:240]
                        key = (stype, canon, rel_path, line_no)
                        if key in seen:
                            continue
                        seen.add(key)
                        hits.append({
                            "type": stype, "provider": provider, "severity": severity,
                            "value": value, "canonical": canon,
                            "project_id": _project_id(stype, value),
                            "file_path": rel_path, "line": line_no, "snippet": snippet,
                        })
    return hits


def _finding(entry: dict) -> dict:
    label = _TYPE_LABEL.get(entry["type"], "Cloud Configuration")
    value = entry["value"]
    proj = f" (project `{entry['project_id']}`)" if entry.get("project_id") else ""
    return {
        "rule_id": f"cloud_{entry['type'].lower()}",
        "title": f"{label} Reference — {value}",
        "severity": entry["severity"],
        "category": "Cloud Configuration",
        "description": (
            f"A {entry['provider']} cloud configuration value was hardcoded in the app: "
            f"`{value}`{proj}. Storage buckets and cloud endpoints embedded in the client "
            f"reveal backend infrastructure and become exploitable if the bucket/endpoint "
            f"is world-readable or world-writable."
        ),
        "impact": (
            "Exposed cloud storage configuration lets an attacker probe the bucket/endpoint "
            "directly. Misconfigured Firebase/GCS buckets frequently allow unauthenticated "
            "read or write of user data."
        ),
        "recommendation": (
            "Verify the bucket/endpoint enforces authentication and least-privilege rules. "
            "For Firebase Storage, audit storage.rules; for GCS, review bucket IAM and ACLs. "
            "Avoid shipping non-production buckets in release builds."
        ),
        "file_path": entry["file_path"],
        "line": entry["line"],
        "snippet": entry["snippet"],
        "file_evidence": entry.get("file_evidence") or [],
        "confidence": 85,
        "exploitability": 50,
        "validation_status": "validated",
        "source": "CLOUD_CONFIG",
        "cwe": "CWE-200",
        "masvs": "MASVS-STORAGE-2",
        "owasp": "M2",
        "cloud_provider": entry["provider"],
        "cloud_type": entry["type"],
    }


def annotate(results: dict, *, platform: str | None = None) -> dict:
    """Consume the raw hits (``results["_cloud_config_hits"]``), de-duplicate by
    canonical value, attribute ownership, build ``results["cloud_config"]`` +
    summary, and append canonical "Cloud Configuration" findings. The transient
    hits key is removed so it never serializes."""
    raw = results.pop("_cloud_config_hits", None) or []
    if not isinstance(raw, list) or not raw:
        results.setdefault("cloud_config", [])
        results.setdefault("cloud_config_summary",
                           {"version": CLOUD_CONFIG_VERSION, "total": 0, "by_provider": {}, "by_type": {}})
        return results

    # Ownership context — reuse the Ownership Engine (best-effort, never fatal).
    classify_file = ctx = None
    try:
        from .ownership import context_from_results
        from .evidence_selection.library import classify_file as _cf
        ctx = context_from_results(results)
        if platform and (not ctx.platform or ctx.platform == "unknown"):
            from .ownership.types import OwnershipContext
            ctx = OwnershipContext(platform=platform, app_packages=ctx.app_packages,
                                   bundle_ids=ctx.bundle_ids, app_modules=ctx.app_modules,
                                   app_name=ctx.app_name)
        classify_file = _cf
    except Exception:
        log.exception("[cloud_config] ownership context unavailable; entries left unattributed")

    # Merge repeated occurrences by canonical value (most-specific type wins on tie
    # via _PATTERNS order, which scan() already honored). First hit is the evidence.
    merged: dict[str, dict] = {}
    order: list[str] = []
    for h in raw:
        if not isinstance(h, dict):
            continue
        key = (h.get("type", ""), h.get("canonical", ""))
        if key not in merged:
            merged[key] = {"hit": h, "files": []}
            order.append(key)
        fp = h.get("file_path") or ""
        if fp and fp not in merged[key]["files"]:
            merged[key]["files"].append(fp)

    entries: list[dict] = []
    findings: list[dict] = []
    by_provider: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for key in order:
        h = merged[key]["hit"]
        files = merged[key]["files"]
        owner_type, owner_name = "Unknown", ""
        if classify_file is not None:
            try:
                fc = classify_file(h.get("file_path") or "", ctx)
                owner_type, owner_name = fc.owner_type, fc.owner_name
            except Exception:
                pass
        file_evidence = [{
            "path": f,
            "lines": [h.get("line", 0)] if f == h.get("file_path") else [],
            "snippet": h.get("snippet", "") if f == h.get("file_path") else "",
        } for f in files]
        entry = {
            "type": h["type"],
            "label": _TYPE_LABEL.get(h["type"], "Cloud Configuration"),
            "provider": h["provider"],
            "value": h["value"],
            "project_id": h.get("project_id", ""),
            "severity": h["severity"],
            "file_path": h.get("file_path", ""),
            "line": h.get("line", 0),
            "snippet": h.get("snippet", ""),
            "file_evidence": file_evidence,
            "occurrences": len(files),
            "owner_type": owner_type,
            "owner_name": owner_name,
        }
        entries.append(entry)
        findings.append(_finding(entry))
        by_provider[h["provider"]] = by_provider.get(h["provider"], 0) + 1
        by_type[h["type"]] = by_type.get(h["type"], 0) + 1

    entries.sort(key=lambda e: (e["provider"], e["type"], e["value"]))
    results["cloud_config"] = entries
    results.setdefault("findings", []).extend(findings)
    results["cloud_config_summary"] = {
        "version": CLOUD_CONFIG_VERSION,
        "total": len(entries),
        "by_provider": by_provider,
        "by_type": by_type,
        "platform": platform or (ctx.platform if ctx else "unknown"),
    }
    log.info("[cloud_config] %s | total=%d providers=%s",
             platform or "?", len(entries), ",".join(sorted(by_provider)) or "-")
    return results
