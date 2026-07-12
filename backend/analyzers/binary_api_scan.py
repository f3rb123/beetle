"""Binary imported-symbol API scan (RUN 8) — insecure C APIs, logging, uncontrolled malloc.

The dynamic-import table of a Mach-O names every libc/Foundation function the binary calls.
Intersecting it with a small set of known-dangerous symbols is a cheap, EVIDENCE-BACKED check:
a hit means the symbol is genuinely imported, not that a regex guessed it.

TWO THINGS THIS MODULE IS CAREFUL ABOUT
1. It must be fed the FULL, UNCAPPED symbol list. ``lief_analyzer`` caps ``imported_syms`` at
   2000 for display, and that cap really does truncate: webview_flutter_wkwebview imports 2432
   symbols, and _fopen / _malloc / _sscanf / _strlen appear ONLY past index 2000. Scanning the
   capped field would silently miss them, so the scan runs at parse time against every symbol.
2. It emits ONE consolidated finding per class listing the matched symbols (MobSF's format),
   never one finding per symbol — a per-symbol explosion would swamp the report and inflate the
   count without adding information.

The presence of these imports is a code-quality / attack-surface signal, not proof of a
vulnerability, so the wording says "imports", not "is vulnerable to".
"""
from __future__ import annotations

# Unsafe C string/format/file APIs (unbounded copies, format-string sinks, shell-outs).
INSECURE_API_SYMS = frozenset({
    "_fopen", "_memcpy", "_printf", "_sprintf", "_sscanf", "_strlen", "_strcpy",
    "_strncpy", "_vsnprintf", "_gets", "_system", "_strcat", "_vsprintf",
})
# Console logging — leaks data to the device log.
LOGGING_SYMS = frozenset({"_NSLog"})
# Unchecked allocation.
MALLOC_SYMS = frozenset({"_malloc"})

_CLASSES = (
    ("insecure", INSECURE_API_SYMS),
    ("logging", LOGGING_SYMS),
    ("malloc", MALLOC_SYMS),
)


def match_symbols(symbol_names) -> dict:
    """{class -> sorted matched symbols} for one binary's FULL imported-symbol list."""
    syms = {str(s) for s in (symbol_names or []) if s}
    out = {}
    for label, targets in _CLASSES:
        hits = sorted(syms & targets)
        if hits:
            out[label] = hits
    return out


_FINDING_SPECS = {
    "insecure": {
        "rule_id": "ios_binary_insecure_api",
        "title": "Binary Imports Insecure C APIs",
        "severity": "medium",           # MobSF: WARNING
        "category": "Binary Analysis",
        "cwe": "CWE-676",
        "owasp": "M7",
        "masvs": "MASVS-CODE-8",
        "description": ("The binary imports C functions that are unsafe by construction — "
                        "unbounded copies, format-string sinks, or shell execution. Their "
                        "presence is an attack-surface signal: each call site must bound its "
                        "input, or a malformed input can overflow a buffer or control a format "
                        "string."),
        "recommendation": ("Replace with bounded/safe equivalents (strlcpy/strlcat, snprintf, "
                           "memcpy_s-style bounded copies) and never pass attacker-controlled "
                           "data as a format string."),
    },
    "logging": {
        "rule_id": "ios_binary_logging_api",
        "title": "Binary Imports Logging API (NSLog)",
        "severity": "info",             # MobSF: INFO
        "category": "Binary Analysis",
        "cwe": "CWE-532",
        "owasp": "M9",
        "masvs": "MASVS-STORAGE-3",
        "description": ("The binary imports NSLog. Anything logged is written to the device "
                        "log, which is readable by other processes and persists in sysdiagnose "
                        "bundles — a common route for tokens and PII to leak."),
        "recommendation": ("Strip or gate logging in release builds; never log credentials, "
                           "tokens or personal data."),
    },
    "malloc": {
        "rule_id": "ios_binary_uncontrolled_malloc",
        "title": "Binary Imports Uncontrolled Allocation (malloc)",
        "severity": "medium",           # MobSF: WARNING
        "category": "Binary Analysis",
        "cwe": "CWE-789",
        "owasp": "M7",
        "masvs": "MASVS-CODE-8",
        "description": ("The binary imports malloc. An allocation whose size derives from "
                        "untrusted input, or whose result is not NULL-checked, leads to "
                        "memory exhaustion or a NULL-deref crash."),
        "recommendation": ("Validate allocation sizes against a bound and check every "
                           "allocation result before use."),
    },
}


def _primary_binary(bins: list) -> str:
    """The binary to ATTRIBUTE a consolidated finding to.

    Prefer an APP-OWNED binary (the main executable — anything not under Frameworks/ or
    PlugIns/) over a vendor framework. This is not cosmetic: the ownership engine reads
    file_path, so attributing an app-wide finding to whichever framework sorts first
    (alphabetically a Firebase one) gets it classified as GoogleSDK and severity-downgraded
    to info — misreporting the app's own insecure imports as a third-party problem.
    """
    for b in bins:
        low = b.replace("\\", "/").lower()
        if not low.startswith(("frameworks/", "plugins/")) and "/" not in low:
            return b
    return bins[0]


def build_findings(binaries: list, platform: str = "ios", bundle_prefix: str = "") -> list:
    """Consolidate every binary's symbol matches into ONE finding per class.

    ``binaries`` are the per-binary dicts from lief_analyzer.analyze_all_macho, each carrying
    an ``api_scan`` computed from its uncapped symbol list. Returns [] when nothing matched —
    no matches, no findings.
    """
    if platform != "ios":
        return []
    # class -> {symbol -> [binaries importing it]}
    agg: dict[str, dict[str, list]] = {}
    for b in binaries or []:
        if not isinstance(b, dict):
            continue
        name = b.get("binary") or "binary"
        for label, hits in (b.get("api_scan") or {}).items():
            for sym in hits:
                agg.setdefault(label, {}).setdefault(sym, []).append(name)

    findings = []
    for label, spec in _FINDING_SPECS.items():
        by_sym = agg.get(label)
        if not by_sym:
            continue
        symbols = sorted(by_sym)
        bins = sorted({b for names in by_sym.values() for b in names})
        primary = _primary_binary(bins)
        finding = dict(spec)
        finding["description"] = (
            f"{spec['description']}\n\n"
            f"Imported symbols ({len(symbols)}): {', '.join(symbols)}\n"
            f"Binaries ({len(bins)}): {', '.join(bins[:12])}"
            + (f" (+{len(bins) - 12} more)" if len(bins) > 12 else "")
        )
        finding.update({
            "matched_symbols": symbols,
            "matched_binaries": bins,
            "symbol_evidence": {s: by_sym[s] for s in symbols},
            # Full bundle-relative path, not the bare name: ownership's iOS path stage treats a
            # bare extension-less name as a CocoaPod (it synthesises "/Pods/<name>/"), so
            # "Runner" alone would classify the app's OWN main executable as a third-party SDK.
            "file_path": f"{bundle_prefix}/{primary}" if bundle_prefix else primary,
            "snippet": ", ".join(symbols),
            "confidence": 95,           # the symbol IS in the import table — not a guess
            "evidence_type": "imported_symbol",
            "provenance": "beetle_native",
        })
        findings.append(finding)
    return findings
