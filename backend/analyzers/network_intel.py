"""
Network Intelligence — IP Address Discovery (Beetle 2.0, Phase 1.99).

Restores and improves the IP-address discovery capability from the original Cortex,
as a SINGLE canonical model used identically by the Android and iOS pipelines. It
*complements* URL extraction — it never touches ``results["endpoints"]`` or any URL
logic. Output replaces ``results["ips"]`` with a richer, backward-compatible shape.

Two stages, mirroring the other intelligence engines:

* :func:`extract_ips` — the raw extractor. Runs in the analyzers' existing parallel
  scan pool. IPv4 **and** IPv6, a broad source/resource/config extension set (incl.
  Swift / Objective-C / plist for iOS parity), reusing the evidence scanner's smali /
  version-literal / binary-dump filters. Produces one raw hit per (ip, file, line).

* :func:`annotate` — the enrichment stage. Runs LATE (after the Ownership Engine), so
  it can: classify every IP into the full taxonomy; attribute an owner by reusing the
  Ownership Engine (no duplicated logic); suppress placeholder / framework-test /
  documentation IPs; MERGE repeated occurrences into one canonical entry; compute an
  explainable confidence; and tag interesting cases (hardcoded internal IP, private IP
  in a release build, loopback reference, dev environment, embedded backend, multiple
  references). It rewrites ``results["ips"]`` and emits ``results["ip_intelligence"]``.

Backward compatibility: every entry keeps ``ip`` / ``type`` / ``file_path`` / ``line``
/ ``snippet`` / ``confidence`` / ``file_evidence`` (so the existing Android public-IP
finding and the UI keep working) and ADDS ``classification`` / ``owner_type`` /
``owner_name`` / ``occurrences`` / ``merged_files`` / ``intelligence`` / ``reason`` /
``suppressed``.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re

from .evidence_scanner import (
    IP_PATTERN, _VERSION_DECL_RE, is_binary_dump_path,
    _ev_should_skip_dir, _EV_MAX_FILES, _EV_MAX_FILE_BYTES,
)
from .path_utils import relativize_path
from .source_corpus import SourceCorpus

log = logging.getLogger("cortex.network_intel")

NETWORK_INTEL_VERSION = "1.0.0"


# ════════════════════════════════════════════════════════════════════════════
# Classification taxonomy
# ════════════════════════════════════════════════════════════════════════════
class IPClass:
    PUBLIC = "public"
    PRIVATE = "private"            # RFC1918
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    BROADCAST = "broadcast"
    UNSPECIFIED = "unspecified"
    DOCUMENTATION = "documentation"   # RFC 5737 / RFC 3849 example ranges
    UNKNOWN = "unknown"


# Classes that are real, potentially-actionable endpoints (shown by default).
NOTABLE_CLASSES = frozenset((IPClass.PUBLIC, IPClass.PRIVATE))
# Classes that are decompiler / framework noise — kept for completeness + audit, but
# low-confidence and suppressed-by-default in the UI unless strong context promotes
# them (e.g. a loopback used as a real dev backend address).
NOISE_CLASSES = frozenset((
    IPClass.LINK_LOCAL, IPClass.MULTICAST, IPClass.RESERVED, IPClass.BROADCAST,
    IPClass.UNSPECIFIED, IPClass.DOCUMENTATION, IPClass.UNKNOWN,
))

# RFC 5737 (IPv4) / RFC 3849 (IPv6) documentation/example ranges.
_DOC_NETS = (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737 TEST-NET-1/2/3
    "100.64.0.0/10",                                        # RFC 6598 shared CGN space
    "2001:db8::/32",                                        # RFC 3849 IPv6 documentation
)

# Well-known placeholder / framework-test literals that are essentially never a real
# embedded endpoint. Loopback/broadcast/unspecified are classified separately; these
# are extra exact-string placeholders.
_PLACEHOLDER_IPS = frozenset((
    "0.0.0.0", "255.255.255.255", "127.0.0.1", "0:0:0:0:0:0:0:1", "::1", "::",
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "1.2.3.4", "10.0.2.2",  # 10.0.2.2 = Android emu host
    "192.168.1.1", "192.168.0.1",
))

# Placeholder / example / test HOST literals that are essentially never a real
# embedded endpoint — mirrors _PLACEHOLDER_IPS for domains so they are never DNS
# resolved or reported (e.g. `default.url`, example.com, your-api.com).
_PLACEHOLDER_DOMAINS = frozenset((
    "default.url", "example.com", "example.org", "example.net", "example.edu",
    "your-api.com", "yourapi.com", "your-domain.com", "yourdomain.com",
    "your-server.com", "api.example.com", "test.com", "test.test", "foo.com",
    "foo.bar", "bar.com", "domain.com", "mydomain.com", "myapi.com",
    "localhost", "localhost.localdomain", "changeme.com", "placeholder.com",
))
# Reserved / non-registrable TLDs (RFC 2606 / RFC 6761) — never resolvable.
_PLACEHOLDER_TLDS = frozenset((
    "invalid", "example", "test", "localhost", "local", "internal", "lan",
    "home", "corp", "onion",
))
# A registrable-looking hostname: labels of allowed chars + a 2–24 alpha TLD.
_REGISTRABLE_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def is_placeholder_domain(host: str) -> bool:
    """True for a well-known placeholder/example/test/reserved host that must never
    be DNS-resolved or reported. Mirrors the _PLACEHOLDER_IPS exact-string gate,
    plus reserved-TLD and wildcard-example checks."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or h in _PLACEHOLDER_DOMAINS:
        return True
    tld = h.rsplit(".", 1)[-1] if "." in h else h
    if tld in _PLACEHOLDER_TLDS:
        return True
    # *.example / example.* style wildcards used in docs and templates.
    labels = h.split(".")
    return "example" in labels or "invalid" in labels


def looks_like_registrable_domain(host: str) -> bool:
    """True when a host is a plausible real, registrable domain (label + real TLD),
    so a bare word / IP-shaped / malformed token is not resolved. Checked BEFORE
    any DNS resolution, alongside :func:`is_placeholder_domain`."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or is_placeholder_domain(h):
        return False
    return bool(_REGISTRABLE_RE.match(h))


def _doc_or_shared(ip) -> bool:
    for net in _DOC_NETS:
        try:
            if ip in ipaddress.ip_network(net):
                return True
        except ValueError:
            continue
    return False


def classify(ip_str: str) -> str:
    """Full classification of an IPv4/IPv6 literal. Returns an :class:`IPClass`
    value, or :data:`IPClass.UNKNOWN` if the string is not a valid IP."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return IPClass.UNKNOWN
    # Documentation/example ranges are checked first — they would otherwise look
    # like ordinary public/private addresses.
    if _doc_or_shared(ip):
        return IPClass.DOCUMENTATION
    if ip.is_unspecified:
        return IPClass.UNSPECIFIED
    if ip.is_loopback:
        return IPClass.LOOPBACK
    if ip.is_link_local:
        return IPClass.LINK_LOCAL
    if ip.is_multicast:
        return IPClass.MULTICAST
    # IPv4 limited broadcast.
    if ip.version == 4 and str(ip) == "255.255.255.255":
        return IPClass.BROADCAST
    if ip.is_private:
        return IPClass.PRIVATE
    if ip.is_reserved:
        return IPClass.RESERVED
    if ip.is_global:
        return IPClass.PUBLIC
    return IPClass.RESERVED


# Human label for the report (RFC1918 etc.).
CLASS_LABELS = {
    IPClass.PUBLIC: "Public",
    IPClass.PRIVATE: "Private (RFC1918)",
    IPClass.LOOPBACK: "Loopback",
    IPClass.LINK_LOCAL: "Link-local",
    IPClass.MULTICAST: "Multicast",
    IPClass.RESERVED: "Reserved",
    IPClass.BROADCAST: "Broadcast",
    IPClass.UNSPECIFIED: "Unspecified",
    IPClass.DOCUMENTATION: "Documentation/Example",
    IPClass.UNKNOWN: "Unknown",
}


# ════════════════════════════════════════════════════════════════════════════
# Raw extraction
# ════════════════════════════════════════════════════════════════════════════
# IPv6: a PERMISSIVE candidate (hex groups separated by colons, with empty groups so
# a mid-address ``::`` compression like 2606:4700:4700::1111 matches) bounded so it
# can't run into surrounding word/colon/dot characters — every candidate is then
# VALIDATED by ``ipaddress`` below, which rejects times ("12:30:45"), version strings
# and any malformed group. Requiring >= 2 colons keeps it off ordinary "a:b" pairs.
_IPV6_PATTERN = re.compile(
    r"(?<![:.\w])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![:.\w])"
)

# Source / resource / config extensions — Android AND iOS. Smali is deliberately
# excluded (a goldmine of hex/const false positives); jadx/Swift/ObjC source, resources
# and config carry the real endpoints.
_IP_EXTENSIONS = (
    ".java", ".kt", ".kts", ".xml", ".json", ".properties", ".txt", ".gradle",
    ".js", ".ts", ".yaml", ".yml", ".conf", ".cfg", ".config", ".ini", ".env",
    ".swift", ".m", ".mm", ".h", ".plist", ".strings", ".pbxproj", ".html",
)

# Smali / disassembly noise tokens — a snippet containing one is not a real IP literal.
_SMALI_NOISE = (
    "const-wide", "const/high16", "const-wide/high16", "const/4", "const/16",
    "const-string", "0x", ".line ", ".prologue", ".source",
)


def _dir_priority(p: str) -> int:
    pl = p.lower().replace("\\", "/")
    if "/jadx" in pl:
        return 0
    if "/apk_extract" in pl or "/ipa_extract" in pl or "/payload" in pl:
        return 1
    if "/apktool" in pl:
        return 2
    return 3


def extract_ips(base_dir: str, extra_dirs: list | None = None, *, corpus: SourceCorpus | None = None) -> list:
    """Raw IPv4 + IPv6 extraction over the decompiled tree. One hit per (ip, file,
    line); no classification/ownership yet (that is :func:`annotate`'s job). Reuses
    the evidence scanner's file caps, dir-skip, version and binary-dump filters."""
    corpus = corpus or SourceCorpus()
    dirs: list[str] = []
    if extra_dirs:
        dirs.extend(d for d in extra_dirs if d and os.path.exists(d))
    if base_dir and os.path.exists(base_dir):
        dirs.append(base_dir)
    dirs.sort(key=_dir_priority)

    hits: list[dict] = []
    seen: set = set()           # (ip, rel_path, line) — keep distinct occurrences
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
                if not fname.lower().endswith(_IP_EXTENSIONS) or is_binary_dump_path(fname):
                    continue
                fpath = os.path.join(root, fname)
                content = corpus.read_text(fpath, max_bytes=_EV_MAX_FILE_BYTES)
                if content is None:
                    continue
                files_scanned += 1
                lines = content.splitlines()
                rel_path = relativize_path(fpath, scan_dir)
                for rx in (IP_PATTERN, _IPV6_PATTERN):
                    for m in rx.finditer(content):
                        ip_str = m.group(0)
                        try:
                            ipaddress.ip_address(ip_str)
                        except ValueError:
                            continue
                        line_no = content[:m.start()].count("\n") + 1
                        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ip_str
                        snip_l = snippet.lower()
                        if any(tok in snip_l for tok in _SMALI_NOISE):
                            continue
                        if _VERSION_DECL_RE.search(snippet):
                            continue
                        key = (ip_str, rel_path, line_no)
                        if key in seen:
                            continue
                        seen.add(key)
                        hits.append({
                            "ip": ip_str, "file_path": rel_path,
                            "line": line_no, "snippet": snippet[:240],
                        })
    return hits


# ════════════════════════════════════════════════════════════════════════════
# Enrichment: classification + ownership + suppression + merge + intelligence
# ════════════════════════════════════════════════════════════════════════════
_OWNER_DISPLAY = {
    "Application": "Application",
    "GeneratedCode": "Generated Code",
}
_FRAMEWORK_OWNERS = {
    "ThirdPartySDK", "GoogleSDK", "VendorSDK", "OpenSourceLibrary",
    "AndroidFramework", "AppleFramework",
}


def _owner_display(owner_type: str) -> str:
    if owner_type in _FRAMEWORK_OWNERS:
        return "Third-party SDK" if owner_type != "AndroidFramework" \
            and owner_type != "AppleFramework" else "Framework"
    return _OWNER_DISPLAY.get(owner_type, owner_type or "Unknown")


def _is_release(results: dict) -> bool:
    """Best-effort: True when the build does not look debuggable/dev."""
    info = results.get("app_info") or {}
    if info.get("debuggable") is True:
        return False
    manifest = (results.get("manifest_xml") or "").lower()
    if 'android:debuggable="true"' in manifest:
        return False
    return True


_DEV_SNIPPET_HINTS = ("dev", "stag", "test", "qa", "uat", "debug", "internal", "local")
_BACKEND_HINTS = ("http", "url", "host", "endpoint", "base_url", "baseurl", "api",
                  "server", "://", "connect", "socket", "gateway")


def _confidence(cls: str, classification_label: str, owner_type: str,
                snippet: str, occurrences: int) -> tuple[int, str]:
    """Explainable confidence that the literal is a meaningful embedded IP. Public/
    private in application code with backend context score high; noise classes and
    framework-owned literals score low."""
    score = 50
    reasons: list[str] = []
    if cls in NOTABLE_CLASSES:
        score += 20; reasons.append("routable endpoint")
    elif cls == IPClass.LOOPBACK:
        score -= 10; reasons.append("loopback")
    else:
        score -= 30; reasons.append("non-endpoint range")
    if owner_type == "Application":
        score += 20; reasons.append("application-owned")
    elif owner_type in _FRAMEWORK_OWNERS:
        score -= 25; reasons.append("framework/SDK code")
    elif owner_type == "GeneratedCode":
        score -= 15; reasons.append("generated code")
    low = (snippet or "").lower()
    if any(h in low for h in _BACKEND_HINTS):
        score += 12; reasons.append("network-assignment context")
    if occurrences >= 3:
        score += 6; reasons.append(f"{occurrences} occurrences")
    score = max(5, min(99, score))
    return score, ", ".join(reasons)


def _intelligence_tags(ip_str: str, cls: str, owner_type: str, snippet: str,
                       occurrences: int, is_release: bool) -> list[str]:
    tags: list[str] = []
    low = (snippet or "").lower()
    app = owner_type == "Application"
    if cls == IPClass.PRIVATE and app:
        tags.append("Hardcoded Internal IP")
        if is_release:
            tags.append("Private IP in Release Build")
    if cls == IPClass.LOOPBACK:
        tags.append("Loopback Reference")
    if any(h in low for h in _DEV_SNIPPET_HINTS):
        tags.append("Development Environment")
    if cls in NOTABLE_CLASSES and app and any(h in low for h in _BACKEND_HINTS):
        tags.append("Embedded Backend Address")
    if occurrences >= 3:
        tags.append("Multiple IP References")
    return tags


def _should_suppress(cls: str, ip_str: str, owner_type: str, intelligence: list[str]) -> bool:
    """Suppress-by-default (hidden but KEPT + counted, never dropped) when the IP is
    noise — a placeholder, a documentation/framework-test range, or a non-endpoint
    class — UNLESS strong context (an intelligence tag) promotes it."""
    if intelligence:
        return False
    if ip_str in _PLACEHOLDER_IPS:
        return True
    if cls in NOISE_CLASSES:
        return True
    return False


def annotate(results: dict, *, platform: str | None = None) -> dict:
    """Classify, attribute ownership, suppress noise, MERGE duplicates and tag the
    raw IP hits in ``results["ips"]``; rewrite it as the enriched canonical list and
    emit ``results["ip_intelligence"]``. Additive w.r.t. URLs — never touched."""
    raw = results.get("ips") or []
    if not isinstance(raw, list):
        return results

    # Ownership context (app packages / bundle ids) — reuse the Ownership Engine.
    try:
        from .ownership import context_from_results
        from .evidence_selection.library import classify_file
        ctx = context_from_results(results)
        if platform and (not ctx.platform or ctx.platform == "unknown"):
            from .ownership.types import OwnershipContext
            ctx = OwnershipContext(platform=platform, app_packages=ctx.app_packages,
                                   bundle_ids=ctx.bundle_ids, app_modules=ctx.app_modules,
                                   app_name=ctx.app_name)
    except Exception:
        ctx, classify_file = None, None
        log.exception("[network_intel] ownership context unavailable; IPs left unattributed")

    is_release = _is_release(results)

    # Merge repeated occurrences: group by IP literal. The first (highest-priority
    # dir) occurrence is the canonical evidence; the rest become merged_files / count.
    merged: dict[str, dict] = {}
    order: list[str] = []
    for h in raw:
        if not isinstance(h, dict):
            continue
        ip_str = h.get("ip")
        if not ip_str:
            continue
        if ip_str not in merged:
            merged[ip_str] = {"hits": [], "files": []}
            order.append(ip_str)
        merged[ip_str]["hits"].append(h)
        fp = h.get("file_path") or ""
        if fp and fp not in merged[ip_str]["files"]:
            merged[ip_str]["files"].append(fp)

    out: list[dict] = []
    by_class: dict[str, int] = {}
    suppressed_count = 0
    for ip_str in order:
        grp = merged[ip_str]
        primary = grp["hits"][0]
        occurrences = len(grp["hits"])
        files = grp["files"]
        cls = classify(ip_str)
        snippet = primary.get("snippet") or ""

        owner_type, owner_name = "Unknown", ""
        if classify_file is not None:
            try:
                fc = classify_file(primary.get("file_path") or "", ctx)
                owner_type, owner_name = fc.owner_type, fc.owner_name
            except Exception:
                pass

        intel = _intelligence_tags(ip_str, cls, owner_type, snippet, occurrences, is_release)
        conf, conf_reason = _confidence(cls, CLASS_LABELS.get(cls, cls), owner_type,
                                        snippet, occurrences)
        suppressed = _should_suppress(cls, ip_str, owner_type, intel)
        if suppressed:
            suppressed_count += 1
        by_class[cls] = by_class.get(cls, 0) + 1

        # Backward-compatible legacy "type": public/private keep their literal class;
        # everything else collapses to "internal" so the existing Android public-IP
        # finding (reads type == "public") and the UI tag keep working unchanged.
        legacy_type = cls if cls in (IPClass.PUBLIC, IPClass.PRIVATE) else "internal"
        file_path = primary.get("file_path") or ""
        line = primary.get("line") or 0
        reason = (intel[0] if intel else conf_reason)

        out.append({
            # ── backward-compatible fields ──
            "ip": ip_str,
            "type": legacy_type,
            "priority": "high" if cls == IPClass.PUBLIC else "informational",
            "severity": "low" if cls == IPClass.PUBLIC else "info",
            "confidence": conf,
            "confidence_label": ("High Confidence" if conf >= 80
                                 else "Medium Confidence" if conf >= 55
                                 else "Low Confidence"),
            "validation_status": "validated",
            "file_path": file_path,
            "line": line,
            "snippet": snippet,
            "file_evidence": [{"path": f, "lines": [line if f == file_path else 0],
                               "snippet": snippet if f == file_path else ""} for f in files],
            # ── enriched fields (Phase 1.99) ──
            "version": ipaddress.ip_address(ip_str).version,
            "classification": cls,
            "classification_label": CLASS_LABELS.get(cls, cls),
            "owner_type": owner_type,
            "owner": _owner_display(owner_type),
            "owner_name": owner_name,
            "occurrences": occurrences,
            "merged_files": files,
            "intelligence": intel,
            "reason": reason,
            "confidence_reason": conf_reason,
            "suppressed": suppressed,
        })

    # Notable (public/private/promoted) first, then by descending confidence.
    out.sort(key=lambda x: (0 if not x["suppressed"] else 1,
                            0 if x["classification"] == IPClass.PUBLIC else 1,
                            -x["confidence"], x["ip"]))
    results["ips"] = out

    visible = [x for x in out if not x["suppressed"]]
    summary = {
        "version": NETWORK_INTEL_VERSION,
        "total": len(out),
        "visible": len(visible),
        "suppressed": suppressed_count,
        "by_classification": by_class,
        "public": by_class.get(IPClass.PUBLIC, 0),
        "private": by_class.get(IPClass.PRIVATE, 0),
        "ipv6": sum(1 for x in out if x["version"] == 6),
        "with_intelligence": sum(1 for x in out if x["intelligence"]),
        "platform": (platform or (ctx.platform if ctx else "unknown")),
    }
    results["ip_intelligence"] = summary
    log.info("[network_intel] %s | %s", summary["platform"], summary)
    return results
