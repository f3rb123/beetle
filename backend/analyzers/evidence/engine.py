"""
Evidence Engine — collection, correlation, verification & scoring
(Beetle 2.0, Phase 1.5).

Builds one structured :class:`Evidence` bundle per finding from the evidence the
finding already carries (file_evidence, snippet, taint/call chains, manifest
components, binary symbols, secret metadata). It normalizes those into typed,
deduplicated :class:`EvidenceItem`s, then derives quality, verification status,
reproduction steps, correlation between items, a data-flow view and a
deterministic content hash.

Pure and deterministic (no wall-clock in the hash; the scan timestamp is injected
by :func:`annotate`). It ONLY enriches — never changes severity, suppression,
reports or the loose legacy evidence fields (which stay for compatibility).

Constants live in `config.py`; the data model in `model.py`.
"""
from __future__ import annotations

import hashlib
import logging
import os

from ..canonical_finding import CanonicalFinding
from . import config as C
from .model import Evidence, EvidenceItem

log = logging.getLogger("cortex.evidence")

_ROOT_PREFIXES = ("jadx/sources/", "jadx/", "apktool/", "apk_extract/",
                  "ipa_extract/", "sources/", "smali/")


def _clamp(n) -> int:
    return max(0, min(100, int(round(n))))


def _basename(path: str) -> str:
    return os.path.basename((path or "").replace("\\", "/"))


def _relative(path: str) -> str:
    p = (path or "").replace("\\", "/").lstrip("/")
    for pre in _ROOT_PREFIXES:
        if p.startswith(pre):
            return p[len(pre):]
    return p


# ════════════════════════════════════════════════════════════════════════════
# Type / source / status classification
# ════════════════════════════════════════════════════════════════════════════
def classify_type(path: str, finding: CanonicalFinding) -> str:
    p = (path or "").replace("\\", "/").lower()
    if p:
        base = _basename(p)
        if base in C.BASENAME_TO_TYPE:
            return C.BASENAME_TO_TYPE[base]
        for tok, t in C.PATH_TOKEN_TO_TYPE:
            if tok in p:
                return t
        ext = os.path.splitext(base)[1]
        if ext in C.EXT_TO_TYPE:
            return C.EXT_TO_TYPE[ext]
    return _type_from_finding(finding)


def _type_from_finding(finding: CanonicalFinding) -> str:
    if (finding.evidence_type or "").lower() == "manifest":
        return C.EvidenceType.MANIFEST
    cat = (finding.category or "").lower()
    return {
        "certificate": C.EvidenceType.CERTIFICATE,
        "taint analysis": C.EvidenceType.TAINT_FLOW,
        "binary hardening": C.EvidenceType.BINARY,
        "vulnerable component": C.EvidenceType.DEPENDENCY,
        "supply chain / dependencies": C.EvidenceType.DEPENDENCY,
        "webview": C.EvidenceType.WEBVIEW,
        "secrets": C.EvidenceType.SECRET,
        "network security": C.EvidenceType.NETWORK_CONFIG,
    }.get(cat, C.EvidenceType.SOURCE_CODE if (finding.snippet or finding.file_path)
           else C.EvidenceType.UNKNOWN)


def _source_for(etype: str, finding: CanonicalFinding) -> str:
    if (finding.evidence_type or "").lower() == "semgrep":
        return C.Source.SEMGREP
    if etype in C.MANIFEST_TYPES:
        return C.Source.MANIFEST_PARSER
    if etype in C.BINARY_TYPES:
        return C.Source.BINARY_ANALYZER
    if etype == C.EvidenceType.CERTIFICATE or etype == C.EvidenceType.CODE_SIGNATURE:
        return C.Source.CERT_PARSER
    if etype == C.EvidenceType.TAINT_FLOW or etype == C.EvidenceType.CALL_GRAPH:
        return C.Source.TAINT_ENGINE
    if etype == C.EvidenceType.DEPENDENCY:
        return C.Source.DEPENDENCY_SCANNER
    if etype == C.EvidenceType.SECRET:
        return C.Source.SECRET_SCANNER
    if etype in C.DECOMPILED_TYPES:
        return C.Source.DECOMPILER
    if etype in (C.EvidenceType.RESOURCE_XML, C.EvidenceType.STRINGS_XML,
                 C.EvidenceType.JSON, C.EvidenceType.YAML, C.EvidenceType.GRADLE,
                 C.EvidenceType.CONFIGURATION, C.EvidenceType.PROPERTIES):
        return C.Source.RESOURCE_PARSER
    return C.Source.UNKNOWN


def _status(etype: str, finding: CanonicalFinding) -> tuple[str, str, bool]:
    """Return (decompiler_status, source_availability, generated_code)."""
    generated = finding.owner_type == "GeneratedCode"
    if finding.raw.get("unresolved_evidence"):
        return "unavailable", "unavailable", generated
    if etype == C.EvidenceType.SMALI:
        return "smali", "available", generated
    if etype in C.DECOMPILED_TYPES:
        return "succeeded", "available", generated
    if etype in C.MANIFEST_TYPES or etype in (C.EvidenceType.RESOURCE_XML,
                                              C.EvidenceType.STRINGS_XML):
        return "decoded", "available", generated
    if etype in C.BINARY_TYPES:
        return "binary", "binary-only", generated
    return "", ("available" if finding.snippet else "unavailable"), generated


# ════════════════════════════════════════════════════════════════════════════
# Item collection
# ════════════════════════════════════════════════════════════════════════════
def _locator(finding: CanonicalFinding) -> dict:
    raw = finding.raw
    return {
        "class": finding.class_name or raw.get("component") or raw.get("class"),
        "method": finding.method_name or raw.get("method"),
        "package": finding.package or raw.get("owner_package"),
        "namespace": raw.get("namespace"),
        "component": raw.get("component") or raw.get("component_name"),
        "permission": raw.get("permission"),
        "intent": raw.get("intent"),
        "uri": raw.get("uri"),
        "deep_link": raw.get("deep_link") or raw.get("scheme"),
        "resource_name": raw.get("resource_name"),
        "property": raw.get("property"),
        "field": raw.get("field"),
        "function": raw.get("function"),
        "native_library": raw.get("native_library") or raw.get("library"),
        "swift_module": raw.get("swift_module") or finding.framework_name,
        "objc_class": raw.get("objc_class"),
        "jni_library": raw.get("jni_library"),
    }


def _item_id(etype: str, file_path: str, line, snippet: str) -> str:
    basis = f"{etype}|{file_path}|{line}|{(snippet or '')[:120]}".lower()
    return "EI-" + hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:10]


def _score_item(item: EvidenceItem, finding: CanonicalFinding) -> int:
    base = C.SOURCE_BASE_CONFIDENCE.get(item.source, C.SOURCE_BASE_CONFIDENCE[C.Source.UNKNOWN])
    p = C.ITEM_POINTS
    score = base
    if item.line:
        score += p["line"]
    if item.snippet:
        score += p["snippet"]
    if any(item.locator.get(k) for k in ("class", "method", "component", "function")):
        score += p["symbol"]
    if item.end_line:
        score += p["region"]
    score = _clamp(score)
    if finding.raw.get("unresolved_evidence") and item.source_availability == "unavailable":
        score = min(score, C.ITEM_UNRESOLVED_CAP)
    return score


def _make_item(finding: CanonicalFinding, *, file_path="", line=None, snippet="",
               etype=None, source=None, locator=None, metadata=None) -> EvidenceItem:
    etype = etype or classify_type(file_path, finding)
    source = source or _source_for(etype, finding)
    dec, avail, generated = _status(etype, finding)
    loc = {**_locator(finding), **(locator or {})}
    loc = {k: v for k, v in loc.items() if v}
    snip = snippet or ""
    end_line = (line + snip.count("\n")) if (line and snip) else None
    item = EvidenceItem(
        type=etype, source=source, file_path=file_path or "",
        relative_path=_relative(file_path), line=line, snippet=snip,
        end_line=end_line, decompiler_status=dec, source_availability=avail,
        generated_code=generated, locator=loc, metadata=metadata or {},
    )
    item.id = _item_id(etype, file_path, line, snip)
    item.confidence = _score_item(item, finding)
    return item


def collect_items(finding: CanonicalFinding) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    seen: set = set()

    def add(it: EvidenceItem):
        key = (it.type, it.file_path, it.line, (it.snippet or "")[:80])
        if key in seen:
            return
        seen.add(key)
        items.append(it)

    # 1. Multi-source code/resource items from file_evidence (aggregate, never overwrite).
    for e in finding.file_evidence:
        if not isinstance(e, dict):
            continue
        lines = e.get("lines") or []
        add(_make_item(finding, file_path=e.get("path", ""),
                       line=lines[0] if lines else (finding.line or None),
                       snippet=e.get("snippet", "") or ""))
    # 2. Primary code/resource item from file_path + snippet when there was no
    # file_evidence. Built even for taint findings (the taint item in step 3 is
    # additional) so a finding that carries a real code line stays reproducible.
    tf = finding.raw.get("taint_flow") or {}
    chain = finding.raw.get("call_chain") or tf.get("chain") or []
    is_manifest = (finding.evidence_type or "").lower() == "manifest"
    if not items and (finding.file_path or finding.snippet or is_manifest):
        fp = finding.file_path or ""
        if not fp and is_manifest:
            fp = "Info.plist" if finding.platform == "ios" else "AndroidManifest.xml"
        add(_make_item(finding, file_path=fp, line=finding.line, snippet=finding.snippet or ""))

    # 3. Taint / data-flow item.
    if tf or chain:
        add(_make_item(
            finding, etype=C.EvidenceType.TAINT_FLOW, source=C.Source.TAINT_ENGINE,
            snippet=" → ".join(str(c) for c in chain) if chain else "",
            line=finding.line,
            locator={"source": tf.get("source"), "sink": tf.get("sink"),
                     "source_cat": tf.get("source_cat"), "sink_cat": tf.get("sink_cat"),
                     "caller": str(chain[0]) if chain else None,
                     "callee": str(chain[-1]) if chain else None}))

    # 4. Manifest item when manifest-derived but no manifest file item exists yet.
    if (finding.evidence_type or "").lower() == "manifest" or \
            (finding.category or "").lower() in ("configuration", "permissions",
                                                 "network security", "attack surface", "deeplinks"):
        if not any(i.type in C.MANIFEST_TYPES for i in items):
            mpath = finding.file_path if (finding.file_path or "").lower().endswith(".xml") \
                else ("Info.plist" if (finding.platform == "ios") else "AndroidManifest.xml")
            add(_make_item(finding, etype=C.EvidenceType.MANIFEST,
                           source=C.Source.MANIFEST_PARSER, file_path=mpath,
                           line=finding.line, snippet=finding.snippet or ""))

    # 5. Certificate item.
    if (finding.category or "").lower() == "certificate" and \
            not any(i.type == C.EvidenceType.CERTIFICATE for i in items):
        add(_make_item(finding, etype=C.EvidenceType.CERTIFICATE,
                       source=C.Source.CERT_PARSER,
                       snippet=finding.snippet or str(finding.raw.get("evidence") or "")))

    # 6. Secret-metadata item (links Phase 1.4 assessment into the evidence).
    if finding.secret_intelligence:
        si = finding.secret_intelligence
        add(_make_item(finding, etype=C.EvidenceType.SECRET, source=C.Source.SECRET_SCANNER,
                       file_path=finding.file_path or "", line=finding.line,
                       metadata={"secret_status": si.get("status"),
                                 "secret_type": si.get("secret_type"),
                                 "provider": si.get("provider")}))
    return items


# ════════════════════════════════════════════════════════════════════════════
# Aggregation: quality, verification, reproduction, correlation, hash
# ════════════════════════════════════════════════════════════════════════════
def _has_symbol(item: EvidenceItem) -> bool:
    return any(item.locator.get(k) for k in ("class", "method", "component", "function"))


def _quality(primary: EvidenceItem | None, items: list[EvidenceItem],
             finding: CanonicalFinding) -> tuple[str, str]:
    if not primary:
        return C.Quality.MISSING, "No evidence could be attached to this finding."
    has_line = bool(primary.line)
    has_snip = bool(primary.snippet)
    has_sym = _has_symbol(primary)
    resolved = primary.source_availability == "available" and not finding.raw.get("unresolved_evidence")
    has_taint = any(i.type == C.EvidenceType.TAINT_FLOW for i in items)

    if has_line and has_snip and has_sym and resolved:
        band, reason = C.Quality.EXCELLENT, "Exact file, line, code snippet and symbol — reproducible by line."
    elif has_line and has_snip and resolved:
        band, reason = C.Quality.GOOD, "Exact file, line and code snippet."
    elif has_snip or has_taint or (has_line and resolved):
        band, reason = C.Quality.MODERATE, "Located evidence without a fully pinned code line."
    else:
        band, reason = C.Quality.WEAK, "Only a reference/heuristic location; no verifiable snippet."

    # Numeric backstop: don't claim Excellent/Good above what the item supports.
    if band == C.Quality.EXCELLENT and primary.confidence < C.QUALITY_EXCELLENT_MIN:
        band, reason = C.Quality.GOOD, reason + " (confidence-capped)"
    if band == C.Quality.GOOD and primary.confidence < C.QUALITY_GOOD_MIN:
        band, reason = C.Quality.MODERATE, reason + " (confidence-capped)"
    return band, reason


def _verification(items: list[EvidenceItem], finding: CanonicalFinding) -> tuple[str, str]:
    if not items:
        return C.Verification.UNKNOWN, "No evidence to verify."
    if finding.raw.get("unresolved_evidence"):
        return C.Verification.NEEDS_REVIEW, "A claimed source location could not be resolved."
    if finding.owner_type == "GeneratedCode":
        return C.Verification.GENERATED, "Evidence is in machine-generated code."
    types = {i.type for i in items}
    code_items = [i for i in items if i.type in C.DECOMPILED_TYPES]
    if code_items and not (types - C.DECOMPILED_TYPES - {C.EvidenceType.SECRET, C.EvidenceType.TAINT_FLOW}):
        strong = any(i.line and i.snippet and i.source_availability == "available" for i in code_items)
        if strong:
            return C.Verification.VERIFIED, "Confirmed against decompiled source with an exact line+snippet."
        return C.Verification.DECOMPILER_ONLY, "Evidence is from decompiled source."
    if types and types <= C.MANIFEST_TYPES | {C.EvidenceType.RESOURCE_XML, C.EvidenceType.STRINGS_XML}:
        return C.Verification.MANIFEST_ONLY, "Evidence is from the manifest/resources only."
    if types and types <= C.BINARY_TYPES:
        return C.Verification.BINARY_ONLY, "Evidence is from binary/native analysis only."
    if any(i.line and i.snippet for i in items):
        return C.Verification.VERIFIED, "At least one item has an exact line and snippet."
    return C.Verification.PARTIALLY_VERIFIED, "Evidence is present but not fully pinned to source."


def _reproduction(primary: EvidenceItem | None, items: list[EvidenceItem],
                  finding: CanonicalFinding) -> dict:
    if not primary:
        return {"summary": "No reproducible evidence.", "steps": []}
    loc = primary.locator
    chain = [str(c) for c in (finding.raw.get("call_chain")
             or (finding.raw.get("taint_flow") or {}).get("chain") or [])]
    repro = {
        "file": primary.relative_path or primary.file_path,
        "line": primary.line,
        "class": loc.get("class"),
        "method": loc.get("method"),
        "manifest_entry": loc.get("component") or loc.get("permission"),
        "call_path": chain,
        "snippet": primary.snippet,
    }
    steps: list[str] = []
    if primary.type in C.DECOMPILED_TYPES:
        steps = ["Decompile the package (jadx for Java/Kotlin, otherwise apktool smali).",
                 f"Open {repro['file']}" + (f" at line {primary.line}." if primary.line else "."),
                 "Observe the highlighted snippet."]
    elif primary.type in C.MANIFEST_TYPES:
        steps = ["Decode the manifest (apktool d, or read Info.plist).",
                 f"Locate {repro['manifest_entry'] or 'the relevant entry'}"
                 + (f" at line {primary.line}." if primary.line else "."),
                 "Confirm the configured attribute/value."]
    elif primary.type in C.BINARY_TYPES:
        steps = [f"Extract {loc.get('native_library') or primary.file_path or 'the binary'}.",
                 "Inspect the relevant symbol/section with the binary analyzer."]
    elif primary.type == C.EvidenceType.TAINT_FLOW:
        steps = [f"Start at the source: {loc.get('source') or 'user-controlled input'}.",
                 "Follow the call path:"] + chain + [f"Reach the sink: {loc.get('sink') or 'sensitive operation'}."]
    else:
        steps = [f"Open {repro['file'] or 'the referenced location'}.",
                 "Confirm the evidence snippet."]
    repro["steps"] = [s for s in steps if s]
    return {k: v for k, v in repro.items() if v not in (None, "", [])}


def _correlation(items: list[EvidenceItem]) -> list[dict]:
    """Relate items that share a class, component or file — the deterministic
    manifest→source / source→taint links a reviewer would draw by hand."""
    edges: list[dict] = []
    for i, a in enumerate(items):
        for b in items[i + 1:]:
            rel = None
            ca, cb = a.locator.get("class"), b.locator.get("class")
            compa = a.locator.get("component")
            if (compa and cb and _basename(str(compa)).split(".")[-1] == str(cb).split(".")[-1]) or \
               (ca and cb and ca == cb):
                rel = "same_class"
            elif a.type in C.MANIFEST_TYPES and b.type in C.DECOMPILED_TYPES:
                rel = "manifest_declares_source"
            elif a.type in C.DECOMPILED_TYPES and b.type == C.EvidenceType.TAINT_FLOW:
                rel = "source_participates_in_flow"
            elif a.file_path and a.file_path == b.file_path:
                rel = "same_file"
            if rel:
                edges.append({"from": a.id, "to": b.id, "relation": rel})
    return edges


def _data_flow(items: list[EvidenceItem], finding: CanonicalFinding) -> dict:
    tf = finding.raw.get("taint_flow") or {}
    chain = finding.raw.get("call_chain") or tf.get("chain") or []
    if not (tf or chain):
        return {}
    return {
        "source": tf.get("source"), "sink": tf.get("sink"),
        "source_category": tf.get("source_cat"), "sink_category": tf.get("sink_cat"),
        "entry_point": str(chain[0]) if chain else tf.get("source"),
        "exit_point": str(chain[-1]) if chain else tf.get("sink"),
        "path": [str(c) for c in chain],
    }


def _content_hash(items: list[EvidenceItem]) -> str:
    parts = sorted(f"{i.type}|{i.file_path}|{i.line}|{(i.snippet or '')[:200]}" for i in items)
    return hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()


# ════════════════════════════════════════════════════════════════════════════
# The engine
# ════════════════════════════════════════════════════════════════════════════
class EvidenceEngine:
    """Deterministic evidence builder. Stateless; build once."""

    version = C.EVIDENCE_VERSION

    def build(self, finding: CanonicalFinding, *, timestamp: str = "") -> Evidence:
        items = collect_items(finding)
        primary = max(items, key=lambda i: i.confidence) if items else None

        ev = Evidence(version=self.version)
        ev.items = [i.to_dict() for i in items]
        ev.primary = primary.to_dict() if primary else {}
        ev.evidence_types = sorted({i.type for i in items})
        ev.sources = sorted({i.source for i in items})
        ev.item_count = len(items)
        ev.location_count = len({(i.file_path, i.line) for i in items if i.file_path})
        ev.generated_code = finding.owner_type == "GeneratedCode"
        ev.source_availability = primary.source_availability if primary else "unavailable"

        ev.quality, ev.quality_reason = _quality(primary, items, finding)
        ev.verification_status, ev.verification_reason = _verification(items, finding)
        ev.reproducible = ev.quality in (C.Quality.EXCELLENT, C.Quality.GOOD) and bool(
            primary and primary.line and primary.file_path)
        ev.reproduction = _reproduction(primary, items, finding)
        ev.correlation = _correlation(items)
        ev.data_flow = _data_flow(items, finding)
        ev.cross_references = [
            {"id": i.id, "file": i.relative_path or i.file_path, "line": i.line, "type": i.type}
            for i in items if primary and i.id != primary.id
        ]

        # Summarize sibling-engine metadata (links, not duplication).
        ev.ownership = {k: v for k, v in (
            ("owner_type", finding.owner_type), ("owner_name", finding.owner_name)) if v}
        if finding.overall_confidence:
            ev.confidence = {"overall": finding.overall_confidence,
                             "band": (finding.confidence_breakdown or {}).get("band", "")}
        if finding.secret_intelligence:
            si = finding.secret_intelligence
            ev.secret = {"status": si.get("status"), "type": si.get("secret_type"),
                         "provider": si.get("provider")}

        ev.content_hash = _content_hash(items)
        ev.evidence_id = "EV-" + (ev.content_hash[:12] if items else "empty")
        ev.timestamp = timestamp
        return ev


# ── cached singleton + public API ────────────────────────────────────────────
_ENGINE: EvidenceEngine | None = None


def get_engine() -> EvidenceEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = EvidenceEngine()
    return _ENGINE


def build(finding: CanonicalFinding, *, timestamp: str = "") -> Evidence:
    return get_engine().build(finding, timestamp=timestamp)


def annotate(results: dict) -> dict:
    """Pipeline integration — attach a structured `evidence_bundle` to every
    finding. ADDITIVE ONLY: it reads the finding's existing evidence and writes a
    new `evidence_bundle` key; the loose `file_evidence`/`snippet`/`evidence`
    fields are left untouched. Runs after ownership/confidence so it can summarize
    their metadata. Deterministic (the scan timestamp is the only injected value).
    """
    engine = get_engine()
    ts = str(results.get("completed_at") or results.get("scan_time") or "")
    by_quality: dict[str, int] = {}
    n = 0
    for key in ("findings", "suppressed_findings"):
        for f in results.get(key) or []:
            if not isinstance(f, dict):
                continue
            cf = CanonicalFinding.from_legacy(f, platform=results.get("platform"))
            ev = engine.build(cf, timestamp=ts)
            f["evidence_bundle"] = ev.to_dict()
            if key == "findings":
                by_quality[ev.quality] = by_quality.get(ev.quality, 0) + 1
            n += 1
    results["evidence_summary"] = {"by_quality": by_quality, "version": engine.version}
    log.info("[evidence] built bundles for %d findings | quality=%s | v%s",
             n, by_quality, engine.version)
    return results
