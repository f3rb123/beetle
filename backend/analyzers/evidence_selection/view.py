"""
Report Accuracy — unified evidence rendering view (Beetle 2.0, Phase 1.97).

ONE function builds the rendering model every report surface consumes — PDF, HTML,
SARIF, JSON/REST, dashboard, attack chains, developer guide — so they all show the
SAME, correct, application-owned proof selected by the Evidence Selection Engine
(Phase 1.96) instead of legacy ``file_path`` (which could be an AndroidX / Google
Play Services / framework file).

``build_evidence_view(finding)`` returns a stable, presentation-only structure:

    primary                 the one proof an analyst should review (+ reason)
    supporting              other useful app/manifest proofs
    additional_references   non-library extras beyond the supporting cap
    hidden_library_evidence {count, owners, items} — collapsed by default
    evidence_score / selection_reason / evidence_confidence
    evidence_ownership / evidence_source / provenance / detection_sources
    reachability / in_attack_chain

It is pure and cheap: it reads the precomputed ``evidence_selection`` block, with a
graceful fallback to legacy fields for any finding that never went through selection.
No evidence is recomputed at render time.
"""
from __future__ import annotations

import re

from ..ownership.types import OwnerType
from . import config as C

# Owner types that are NOT the analyst's app code → "hidden library evidence".
_LIBRARY_OWNER_TYPES = {
    OwnerType.THIRD_PARTY_SDK, OwnerType.GOOGLE_SDK, OwnerType.VENDOR_SDK,
    OwnerType.OPEN_SOURCE_LIBRARY, OwnerType.ANDROID_FRAMEWORK,
    OwnerType.APPLE_FRAMEWORK, OwnerType.GENERATED_CODE,
}

_QUALITY_TO_CONFIDENCE = {"Excellent": 95, "Good": 80, "Adequate": 60,
                          "Weak": 40, "Missing": 15}


def _is_library(owner_type: str) -> bool:
    return owner_type in _LIBRARY_OWNER_TYPES


def _proof(entry: dict) -> dict:
    """Public-facing proof shape (no internal scoring implementation details)."""
    return {
        "file": entry.get("file_path") or "",
        "line": entry.get("line") or 0,
        "snippet": entry.get("snippet") or "",
        "owner_type": entry.get("owner_type") or "",
        "owner_name": entry.get("owner_name") or "",
        "source": entry.get("source") or "",
        "score": entry.get("score", 0),
        "reasons": entry.get("selected_because") or [],
    }


# Manifest attributes worth surfacing as a focused snippet (instead of a long XML
# excerpt). Matches e.g. android:debuggable="true".
_MANIFEST_ATTR_RE = re.compile(r'android:[A-Za-z]+\s*=\s*"[^"]*"')


def _is_manifest_file(path: str) -> bool:
    return (path or "").replace("\\", "/").lower().rsplit("/", 1)[-1] in C.MANIFEST_FILENAMES


def _expected_manifest_attr(finding: dict):
    """The exact manifest attribute a finding triggers, e.g. ('debuggable','true').
    Returns (attr, default_value) or None. Keyed on the finding title/rule."""
    blob = f"{(finding or {}).get('title','')} {(finding or {}).get('rule_id','')}".lower()
    for keyword, attr, default in C.MANIFEST_FINDING_ATTRS:
        if keyword in blob:
            return attr, default
    return None


def _focus_manifest_snippet(snippet: str, finding: dict | None = None) -> str:
    """XML-aware focused snippet. First resolves the EXACT attribute the finding
    triggers (e.g. android:debuggable) and returns it from the snippet — or
    synthesizes it when the captured snippet grabbed the wrong manifest line. Falls
    back to a security-attribute filter, dropping benign attrs (label/icon/theme)."""
    # 1) Finding-aware: the attribute this finding type is ABOUT.
    expected = _expected_manifest_attr(finding)
    if expected:
        attr, default = expected
        m = re.search(rf'android:{attr}\s*=\s*"[^"]*"', snippet or "", re.IGNORECASE)
        if m:
            return m.group(0)
        # The stored snippet captured the wrong manifest line — synthesize the
        # triggering attribute so the analyst always sees the right one.
        return f'android:{attr}="{default}"' if default is not None else f'android:{attr}'
    if not snippet:
        return snippet
    attrs = _MANIFEST_ATTR_RE.findall(snippet)
    if attrs:
        sec, seen = [], set()
        for a in attrs:
            name = a.split(":", 1)[1].split("=", 1)[0].strip().lower()
            if name in C.SECURITY_MANIFEST_ATTRS and a not in seen:
                seen.add(a); sec.append(a)
        if sec:
            return "\n".join(sec[:4])
        # No security attribute matched — fall back to the first attribute only.
        return attrs[0]
    return snippet.strip()[:240]


def _is_certificate_finding(finding: dict) -> bool:
    cat = str(finding.get("category") or "").strip().lower()
    return cat in C.ARTIFACT_CATEGORIES


def _certificate_artifact_label(finding: dict) -> str:
    title = str(finding.get("title") or "").lower()
    for needle, label in C.CERTIFICATE_ARTIFACT_LABELS:
        if needle in title:
            return label
    return C.CERTIFICATE_ARTIFACT


def _certificate_view(finding: dict) -> dict:
    """A rich evidence view for certificate/signing findings (no Java source). Names
    the real artifact the analyst should inspect — never 'Unknown file'."""
    label = _certificate_artifact_label(finding)
    primary = {
        "file": label, "line": 0, "snippet": finding.get("snippet") or "",
        "owner_type": "Application", "owner_name": "APK Signing",
        "source": (finding.get("detected_by") or ["Beetle Native"])[0],
        "score": 0, "reasons": ["Signing/certificate metadata — no decompiled source applies"],
        "artifact": True, "language": C.CERTIFICATE_ARTIFACT_LANG,
    }
    return {
        "primary": primary, "supporting": [], "additional_references": [],
        "hidden_library_evidence": {"count": 0, "owners": [], "items": []},
        "evidence_score": 0,
        "selection_reason": f"Certificate finding — evidence is the {label}, not a source file.",
        "evidence_confidence": _evidence_confidence(finding),
        "evidence_ownership": "Application", "evidence_source": primary["source"],
        "provenance": finding.get("fusion") or {},
        "detection_sources": finding.get("detected_by") or ["Beetle Native"],
        "reachability": str(finding.get("reachability") or ""),
        "in_attack_chain": False, "framework_only": False,
        "artifact": True, "fallback": False,
    }


BINARY_EVIDENCE_LANG = "Mach-O Binary"


def _is_ios_binary_path(path: str) -> bool:
    """True for a Mach-O in the .app bundle (main executable, *.framework/*, *.dylib).

    These are extension-less or framework binaries, and the SAST does not read them as
    source: ``code_analyzer._collect_ios_files`` replaces their content with
    ``_extract_strings(raw)`` — printable runs joined by newlines. So a rule "match" on
    such a file carries the INDEX OF A STRING in that synthetic listing, which is neither
    a source line nor a byte address. Callers must never render it as a source line.
    """
    p = (path or "").replace("\\", "/").strip()
    if not p:
        return False
    low = p.lower()
    if low.endswith(".dylib") or ".framework/" in low:
        return True
    base = p.rsplit("/", 1)[-1]
    if low.startswith("payload/"):
        return "." not in base          # Payload/Runner.app/Runner — extension-less Mach-O
    return "/" not in p and "." not in base and bool(base)   # bare executable name


BPLIST_EVIDENCE_LANG = "Binary Property List"

# Android compiled binaries + their printable-strings dumps. A rule/secret match on one
# carries an INDEX into the extracted-strings listing (string_analyzer/scan_storage dump raw
# .dex/.so strings when no decompiled source exists), NOT a source line — the exact Android twin
# of an iOS Mach-O match. RUN 26 (L1): carding these was previously iOS-only, so an Android
# binary-primary finding rendered its string index as a misleading file:line.
_ANDROID_BINARY_SUFFIXES = (
    ".dex", ".so", ".arsc", ".odex", ".vdex", ".oat",
    ".dex.txt", ".so.txt", ".arsc.txt",
)


def _is_android_binary_path(path: str) -> bool:
    """True for an Android compiled binary (or its strings dump) whose match 'line' is a
    string index, not a source line."""
    return (path or "").replace("\\", "/").lower().endswith(_ANDROID_BINARY_SUFFIXES)


def _is_binary_evidence(path: str, binary_files: set | None, platform: str | None = None) -> bool:
    """True when the primary's file is binary-format — its match 'line' indexes an extracted-
    strings listing, not source. Prefers the scan's content-detected set (Mach-O magic / bplist00,
    recorded by ios_analyzer._record_binary_format_files); otherwise uses platform path shapes:
    iOS Mach-O/framework shapes, or Android .dex/.so/.arsc binaries (RUN 26)."""
    if not path:
        return False
    if binary_files and path.replace("\\", "/").lower() in binary_files:
        return True
    if platform == "android":
        return _is_android_binary_path(path)
    if platform == "ios":
        return _is_ios_binary_path(path)
    # Unknown platform: be conservative and recognise either shape family.
    return _is_ios_binary_path(path) or _is_android_binary_path(path)


def _as_binary_evidence(view: dict, is_plist: bool = False) -> dict:
    """Re-render a view whose primary is a binary file as BINARY evidence.

    A compiled binary has no source line. For a Mach-O, the SAST's "line" indexes the
    extracted-strings listing; for a binary plist there are no text lines at all (the
    scanner reports e.g. line 3 with an empty snippet). Either way the number must never be
    shown as a source line, so it moves into string_index and ``line`` is zeroed. Sets
    artifact=True, which the UI already uses to hide View Source / View Smali — so no one is
    sent to a source line that does not exist. iOS only.
    """
    prim = view.get("primary") or {}
    idx = prim.get("line") or 0
    symbol = (prim.get("snippet") or "").strip()
    prim["string_index"] = int(idx) if idx else 0
    prim["symbol"] = symbol
    prim["line"] = 0                     # NOT a source line — never render it as one
    prim["artifact"] = True
    prim["binary"] = True
    prim["language"] = BPLIST_EVIDENCE_LANG if is_plist else BINARY_EVIDENCE_LANG
    where = prim.get("file") or "the binary"
    if is_plist:
        reason = (f"Binary evidence — {where} is a binary property list with no text lines; "
                  "the proof is the decoded key, not a source line.")
    else:
        reason = (f"Binary evidence — the symbol/string {symbol!r} was matched in the "
                  f"extracted strings of {where}"
                  + (f" (string #{prim['string_index']} of the strings listing, "
                     "not a source line)." if prim["string_index"] else "."))
    prim["reasons"] = list(prim.get("reasons") or []) + [reason]
    view["primary"] = prim
    view["artifact"] = True
    view["binary"] = True
    view["selection_reason"] = reason
    return view


def primary_location(finding: dict) -> tuple[str, int, str]:
    """The (file, line, snippet) every renderer should show — the selected primary,
    falling back to the legacy fields when selection did not run."""
    sel = finding.get("evidence_selection") or {}
    prim = sel.get("primary") or {}
    if prim.get("file_path"):
        return prim["file_path"], prim.get("line") or 0, prim.get("snippet") or ""
    fp = finding.get("file_path") or finding.get("file") or ""
    line = finding.get("line") or finding.get("line_number") or 0
    return fp, line, (finding.get("snippet") or finding.get("code_context") or "")


def _evidence_confidence(finding: dict) -> int:
    if finding.get("overall_confidence"):
        return int(finding["overall_confidence"])
    eb = finding.get("evidence_bundle") or {}
    return _QUALITY_TO_CONFIDENCE.get(eb.get("quality", ""), int(finding.get("confidence") or 0))


def _fallback_view(finding: dict) -> dict:
    """Build a view from legacy fields when evidence_selection is absent."""
    fp, line, snip = primary_location(finding)
    supporting = []
    for e in (finding.get("file_evidence") or [])[1:5]:
        if isinstance(e, dict) and e.get("path"):
            lines = e.get("lines") or []
            supporting.append({"file": e["path"], "line": lines[0] if lines else 0,
                               "snippet": e.get("snippet") or "", "owner_type": "",
                               "owner_name": "", "source": "file_evidence",
                               "score": 0, "reasons": []})
    return {
        "primary": {"file": fp, "line": line, "snippet": snip,
                    "owner_type": finding.get("owner_type") or "", "owner_name": finding.get("owner_name") or "",
                    "source": (finding.get("detected_by") or [finding.get("source_module") or ""])[0],
                    "score": 0, "reasons": []},
        "supporting": supporting,
        "additional_references": [],
        "hidden_library_evidence": {"count": 0, "owners": [], "items": []},
        "evidence_score": 0,
        "selection_reason": "Legacy evidence (selection engine did not run for this finding).",
        "evidence_confidence": _evidence_confidence(finding),
        "evidence_ownership": finding.get("owner_type") or "",
        "evidence_source": (finding.get("detected_by") or [finding.get("source_module") or ""])[0],
        "provenance": finding.get("fusion") or {},
        "detection_sources": finding.get("detected_by") or [],
        "reachability": str(finding.get("reachability") or ""),
        "in_attack_chain": bool(finding.get("in_attack_chain") or finding.get("is_attack_chain")),
        "fallback": True,
    }


def build_evidence_view(finding: dict, platform: str | None = None,
                        binary_files: set | None = None) -> dict:
    """The single rendering model for a finding. Reads evidence_selection; falls
    back to legacy fields. Pure — does not mutate the finding.

    ``platform`` and ``binary_files`` are optional and only gate iOS binary-evidence
    rendering; omitting them reproduces the previous behaviour exactly (Android unaffected).
    """
    if not isinstance(finding, dict):
        return _fallback_view({})
    # Certificate / signing findings have no source file — render the real artifact
    # (APK Signing Block / Signing Certificate / …), never "Unknown file".
    if _is_certificate_finding(finding):
        return _certificate_view(finding)
    sel = finding.get("evidence_selection")
    if not isinstance(sel, dict) or not sel.get("primary"):
        view = _fallback_view(finding)
        fp = (view.get("primary") or {}).get("file")
        if _is_binary_evidence(fp, binary_files, platform):
            return _as_binary_evidence(view, is_plist=str(fp).lower().endswith(".plist"))
        return view

    primary = _proof(sel["primary"])
    # Focus manifest evidence to the EXACT triggering android:* attribute.
    if _is_manifest_file(primary["file"]):
        primary["snippet"] = _focus_manifest_snippet(primary["snippet"], finding)
        primary["language"] = "Android Manifest"
    supporting = [_proof(e) for e in (sel.get("supporting") or [])]

    # Split rejected into "hidden library evidence" (libraries/frameworks/generated)
    # and "additional references" (non-library extras worth keeping but demoted).
    hidden_items, additional = [], []
    owners: list[str] = []
    for e in sel.get("rejected") or []:
        ot = e.get("owner_type") or ""
        if _is_library(ot):
            name = e.get("owner_name") or ot
            hidden_items.append({"file": e.get("file_path") or "", "owner_type": ot,
                                 "owner_name": name, "reasons": e.get("rejected_because") or []})
            if name and name not in owners:
                owners.append(name)
        else:
            additional.append(_proof(e))

    view = {
        "primary": primary,
        "supporting": supporting,
        "additional_references": additional,
        "hidden_library_evidence": {
            "count": len(hidden_items),
            "owners": owners,
            "items": hidden_items,
        },
        "evidence_score": sel["primary"].get("score", 0),
        "selection_reason": sel.get("reason") or "",
        "evidence_confidence": _evidence_confidence(finding),
        "evidence_ownership": primary["owner_type"],
        "evidence_source": primary["source"] or (finding.get("detected_by") or [""])[0],
        "provenance": finding.get("fusion") or {},
        "detection_sources": finding.get("detected_by") or [],
        "reachability": str(finding.get("reachability") or ""),
        "in_attack_chain": bool(finding.get("in_attack_chain") or finding.get("is_attack_chain")),
        "bug_bounty_mode": sel.get("bug_bounty_mode", False),
        "framework_only": bool(sel.get("framework_only")),
        "fallback": False,
    }
    # A binary primary (iOS Mach-O / bplist, or an Android .dex/.so/.arsc) carries a strings
    # index / parse artifact, not a source line — render it as binary evidence so no consumer
    # prints file:line. RUN 26: Android is now covered too (was iOS-only, the L1 gap).
    fp = primary.get("file")
    if _is_binary_evidence(fp, binary_files, platform):
        return _as_binary_evidence(view, is_plist=str(fp).lower().endswith(".plist"))
    return view
