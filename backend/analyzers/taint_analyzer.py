"""
Cortex Taint Analyzer
=====================
Inter-procedural data-flow analysis using Androguard's DEX engine.

Strategy
--------
1. Load the APK with androguard.misc.AnalyzeAPK to get (apk, dex_list, analysis).
2. Define *sources* — methods that return user-controlled data (intent extras,
   clipboard, contacts, microphone, location, etc.).
3. Define *sinks*   — methods that are sensitive targets (Log.*, network I/O,
   file write, crypto, SQLiteDatabase.execSQL, etc.).
4. For every source-method call site found in the DEX:
   - BFS/DFS outward over the call graph (callers → callees up to MAX_DEPTH hops)
     to find paths that reach a sink.
5. Each path becomes a taint finding with full call chain as evidence.

Graceful degradation
--------------------
- If androguard or the analysis objects are not available → return empty list.
- Hard timeout via threading: analysis capped at TIMEOUT_S seconds.
- Memory guard: skip APKs whose DEX exceeds MAX_DEX_MB.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

# ── tunables ──────────────────────────────────────────────────────────────────
MAX_DEPTH   = 6      # max call-chain hops from source to sink
MAX_PATHS   = 200    # stop collecting after this many paths (perf guard)
TIMEOUT_S   = 60     # wall-clock seconds before we abort analysis
MAX_DEX_MB  = 30     # skip APKs with >30 MB of combined DEX

# ── Source definitions ────────────────────────────────────────────────────────
# Each entry: (class_pattern, method_pattern, label, category)
# Patterns are plain substrings checked against the fully-qualified descriptor.
SOURCES: list[tuple[str, str, str, str]] = [
    # Intent / Bundle extras
    ("android/content/Intent", "getStringExtra",      "Intent.getStringExtra",      "User Input"),
    ("android/content/Intent", "getExtra",            "Intent.getExtra",            "User Input"),
    ("android/os/Bundle",      "getString",           "Bundle.getString",           "User Input"),
    ("android/os/Bundle",      "get",                 "Bundle.get",                 "User Input"),

    # EditText / UI
    ("android/widget/EditText",   "getText",           "EditText.getText",           "User Input"),
    ("android/widget/TextView",   "getText",           "TextView.getText",           "User Input"),
    ("android/widget/Spinner",    "getSelectedItem",   "Spinner.getSelectedItem",    "User Input"),

    # Clipboard
    ("android/content/ClipboardManager", "getPrimaryClip", "Clipboard.getPrimaryClip", "Clipboard"),

    # Location
    ("android/location/Location", "getLatitude",       "Location.getLatitude",       "Location"),
    ("android/location/Location", "getLongitude",      "Location.getLongitude",      "Location"),
    ("android/location/LocationManager", "getLastKnownLocation", "LocationManager.getLastKnownLocation", "Location"),

    # Camera / Microphone
    ("android/hardware/Camera",   "takePicture",       "Camera.takePicture",         "Camera"),
    ("android/media/MediaRecorder", "start",           "MediaRecorder.start",        "Microphone"),

    # SMS / Contacts / Accounts
    ("android/telephony/SmsMessage", "getMessageBody", "SmsMessage.getMessageBody", "SMS"),
    ("android/accounts/AccountManager", "getAccounts", "AccountManager.getAccounts", "Accounts"),

    # ContentResolver (generic DB query)
    ("android/content/ContentResolver", "query",        "ContentResolver.query",      "ContentProvider"),

    # Shared Preferences (values read back from prefs can propagate)
    ("android/content/SharedPreferences", "getString",  "SharedPreferences.getString","SharedPrefs"),
    ("android/content/SharedPreferences", "getInt",     "SharedPreferences.getInt",   "SharedPrefs"),
]

# ── Sink definitions ──────────────────────────────────────────────────────────
SINKS: list[tuple[str, str, str, str, str]] = [
    # (class_pattern, method_pattern, label, category, severity)

    # Logging — data leaks to logcat
    ("android/util/Log",           "d",              "Log.d",                    "Logging",     "medium"),
    ("android/util/Log",           "v",              "Log.v",                    "Logging",     "medium"),
    ("android/util/Log",           "i",              "Log.i",                    "Logging",     "medium"),
    ("android/util/Log",           "w",              "Log.w",                    "Logging",     "medium"),
    ("android/util/Log",           "e",              "Log.e",                    "Logging",     "high"),
    ("android/util/Log",           "wtf",            "Log.wtf",                  "Logging",     "high"),
    ("java/io/PrintStream",        "println",        "System.out.println",       "Logging",     "medium"),

    # Network — data sent over HTTP/socket
    ("java/net/URL",               "openConnection", "URL.openConnection",       "Network",     "high"),
    ("okhttp3/Request$Builder",    "url",            "OkHttp.url",               "Network",     "high"),
    ("okhttp3/FormBody$Builder",   "add",            "OkHttp.FormBody.add",      "Network",     "high"),
    ("retrofit2/",                 "",               "Retrofit call",            "Network",     "high"),
    ("com/android/volley",         "add",            "Volley.add",               "Network",     "high"),
    ("java/net/HttpURLConnection", "getOutputStream","HttpURLConnection.write",  "Network",     "high"),

    # SQLite — SQL injection risk
    ("android/database/sqlite/SQLiteDatabase", "execSQL",       "SQLiteDatabase.execSQL",    "SQLite",  "critical"),
    ("android/database/sqlite/SQLiteDatabase", "rawQuery",      "SQLiteDatabase.rawQuery",   "SQLite",  "critical"),
    ("android/database/sqlite/SQLiteDatabase", "insert",        "SQLiteDatabase.insert",     "SQLite",  "high"),
    ("android/database/sqlite/SQLiteDatabase", "update",        "SQLiteDatabase.update",     "SQLite",  "high"),

    # File write — arbitrary write
    ("java/io/FileOutputStream",   "write",          "FileOutputStream.write",   "FileSystem",  "high"),
    ("java/io/FileWriter",         "write",          "FileWriter.write",         "FileSystem",  "high"),
    ("java/nio/file/Files",        "write",          "Files.write",              "FileSystem",  "high"),

    # Crypto — tainted key/IV
    ("javax/crypto/Cipher",        "init",           "Cipher.init",              "Crypto",      "high"),
    ("javax/crypto/spec/SecretKeySpec", "<init>",    "SecretKeySpec.<init>",     "Crypto",      "high"),
    ("javax/crypto/spec/IvParameterSpec", "<init>",  "IvParameterSpec.<init>",   "Crypto",      "high"),

    # Process execution — command injection
    ("java/lang/Runtime",          "exec",           "Runtime.exec",             "Execution",   "critical"),
    ("java/lang/ProcessBuilder",   "command",        "ProcessBuilder.command",   "Execution",   "critical"),

    # WebView — XSS via loadUrl/evaluateJavascript
    ("android/webkit/WebView",     "loadUrl",        "WebView.loadUrl",          "WebView",     "high"),
    ("android/webkit/WebView",     "evaluateJavascript", "WebView.evaluateJavascript", "WebView", "high"),
    ("android/webkit/WebView",     "loadData",       "WebView.loadData",         "WebView",     "medium"),

    # Intent — open redirect / component hijacking
    ("android/content/Context",    "startActivity",  "Context.startActivity",    "Intent",      "medium"),
    ("android/content/Context",    "sendBroadcast",  "Context.sendBroadcast",    "Intent",      "medium"),

    # Phase 6 Task 7 — additional high-value sinks
    # WebView native bridge — tainted bridge target = potential RCE surface
    ("android/webkit/WebView",     "addJavascriptInterface", "WebView.addJavascriptInterface", "WebView", "high"),
    # Raw sockets — custom protocol exfiltration / SSRF-style
    ("java/net/Socket",            "<init>",         "Socket.<init>",            "Network",     "high"),
    ("java/net/HttpURLConnection", "setRequestProperty", "HttpURLConnection.setRequestProperty", "Network", "high"),
    # PendingIntent — mutable/implicit pending intent hijack
    ("android/app/PendingIntent",  "getActivity",    "PendingIntent.getActivity","Intent",      "high"),
    ("android/app/PendingIntent",  "getBroadcast",   "PendingIntent.getBroadcast","Intent",     "high"),
    ("android/app/PendingIntent",  "getService",     "PendingIntent.getService", "Intent",      "high"),
    # Digest of tainted input (integrity bypass / weak token derivation)
    ("java/security/MessageDigest","update",         "MessageDigest.update",     "Crypto",      "medium"),
    ("java/security/MessageDigest","digest",         "MessageDigest.digest",     "Crypto",      "medium"),

    # Shared Prefs write
    ("android/content/SharedPreferences$Editor", "putString", "SharedPrefs.putString", "Storage", "low"),
]

# Log (and similar) methods that share a substring with a sink method pattern but
# are NOT sinks — they read/format, they don't write tainted data anywhere.
# isLoggable(tag, level) -> boolean; getStackTraceString(t) -> String. Excluded
# regardless of matching mode as defence-in-depth.
_NON_SINK_METHODS = frozenset({"isLoggable", "getStackTraceString"})

# Map sink category → CWE / MASVS
_SINK_META: dict[str, dict] = {
    "Logging":    {"cwe": "CWE-532", "masvs": "MASVS-STORAGE-2",  "owasp": "M2"},
    "Network":    {"cwe": "CWE-319", "masvs": "MASVS-NETWORK-1",  "owasp": "M3"},
    "SQLite":     {"cwe": "CWE-89",  "masvs": "MASVS-CODE-4",     "owasp": "M7"},
    "FileSystem": {"cwe": "CWE-73",  "masvs": "MASVS-STORAGE-1",  "owasp": "M2"},
    "Crypto":     {"cwe": "CWE-330", "masvs": "MASVS-CRYPTO-1",   "owasp": "M5"},
    "Execution":  {"cwe": "CWE-78",  "masvs": "MASVS-CODE-4",     "owasp": "M7"},
    "WebView":    {"cwe": "CWE-79",  "masvs": "MASVS-PLATFORM-2", "owasp": "M1"},
    "Intent":     {"cwe": "CWE-926", "masvs": "MASVS-PLATFORM-1", "owasp": "M1"},
    "Storage":    {"cwe": "CWE-312", "masvs": "MASVS-STORAGE-1",  "owasp": "M2"},
}


def run_taint_analysis(apk_path: str, results: dict) -> dict:
    """
    Entry point called from android_analyzer.py.
    Writes taint flows into results['taint_flows'] and appends findings.
    Returns metrics dict.
    """
    metrics: dict = {"ran": False, "flow_count": 0, "error": None}

    try:
        _run_with_timeout(apk_path, results, metrics)
    except Exception as e:
        metrics["error"] = str(e)

    return metrics


# ── Internal implementation ───────────────────────────────────────────────────

def _run_with_timeout(apk_path: str, results: dict, metrics: dict):
    outcome: dict = {}
    exc_box: list = []

    def _worker():
        try:
            flows = _analyze(apk_path, results)
            outcome["flows"] = flows
        except Exception as e:
            exc_box.append(e)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(TIMEOUT_S)

    if t.is_alive():
        metrics["error"] = f"Taint analysis timed out after {TIMEOUT_S}s"
        results["taint_flows"] = []
        return

    if exc_box:
        raise exc_box[0]

    flows = outcome.get("flows", [])
    results["taint_flows"] = flows
    metrics["ran"]        = True
    metrics["flow_count"] = len(flows)

    # Convert flows into findings
    for flow in flows:
        results["findings"].append(_flow_to_finding(flow))


def _analyze(apk_path: str, results: dict | None = None) -> list[dict]:
    """Core analysis — loads DEX via androguard and finds source→sink paths."""
    try:
        # androguard v4.x
        from androguard.misc import AnalyzeAPK
    except ImportError:
        return []

    # Size guard
    dex_total = _total_dex_size_mb(apk_path)
    if dex_total > MAX_DEX_MB:
        raise RuntimeError(f"DEX too large ({dex_total:.1f} MB > {MAX_DEX_MB} MB limit)")

    _apk, _dex_list, dx = AnalyzeAPK(apk_path)

    # Ownership classifier (reused engine + fingerprints) so library→library flows
    # can be dropped and each kept flow can carry owner_type. Built once per scan.
    owner_lookup = _OwnershipLookup(results)

    # Build lookup: (class_substr, method_substr) → MethodAnalysis objects
    source_methods = _collect_method_refs(dx, SOURCES)
    sink_methods   = _collect_sink_refs(dx, SINKS)

    if not source_methods or not sink_methods:
        return []

    # Build a reverse-reachability set from each sink (which methods can reach it)
    sink_reachable = _build_sink_reachable(sink_methods, MAX_DEPTH)

    flows: list[dict] = []
    seen_keys: set[str] = set()

    for (src_cls, src_mth, src_label, src_cat), caller_methods in source_methods.items():
        for caller_m in caller_methods:
            # BFS from caller_m to any sink
            path = _bfs_to_sink(caller_m, sink_reachable, dx, MAX_DEPTH)
            if path is None:
                continue

            sink_entry = path[-1]
            flow_key   = f"{src_label}|{sink_entry['sink_label']}|{caller_m.get_method().get_class_name()}"
            if flow_key in seen_keys:
                continue
            seen_keys.add(flow_key)

            # Ownership filter: a flow whose ENTIRE call chain (source caller +
            # every hop + sink host) is library/framework code is framework-internal
            # logging, not an app vulnerability — drop it. Keep the flow when the app
            # owns the source or ANY intermediate hop (attacker-controlled input
            # entering app code that reaches a library logger is the real signal).
            chain_classes = _chain_class_names(caller_m, path)
            chain_owners  = [owner_lookup.owner_type(c) for c in chain_classes]
            if chain_owners and all(_is_library_owner(o) for o in chain_owners):
                continue
            # owner_type of the displayed source class (class_name below).
            source_owner = chain_owners[0] if chain_owners else "Unknown"

            flows.append({
                "source":      src_label,
                "source_cat":  src_cat,
                "sink":        sink_entry["sink_label"],
                "sink_cat":    sink_entry["sink_cat"],
                "sink_sev":    sink_entry["sink_sev"],
                "call_chain":  _format_chain(caller_m, path),
                "class_name":  caller_m.get_method().get_class_name().replace("/", ".").lstrip("L"),
                "method_name": caller_m.get_method().get_name(),
                "owner_type":  source_owner,
            })

            if len(flows) >= MAX_PATHS:
                return flows

    return flows


def _collect_method_refs(
    dx,
    source_defs: list[tuple[str, str, str, str]],
) -> dict[tuple, list]:
    """
    For each source definition return a mapping →
      (cls, mth, label, cat) → list of MethodAnalysis that *call* this source.
    """
    result: dict = {}
    for cls_pat, mth_pat, label, cat in source_defs:
        callers = []
        for cls_analysis in dx.get_classes():
            cname = cls_analysis.name  # e.g. "Landroid/content/Intent;"
            if cls_pat not in cname:
                continue
            for m in cls_analysis.get_methods():
                mn = m.name
                # EXACT method match when a name is specified (a source method
                # "get" must match Bundle.get, never "getClass"). An empty pattern
                # is an explicit class-prefix intent → match every method.
                if mth_pat and mn != mth_pat:
                    continue
                # Collect all methods that call this method
                for _, call_m, _ in m.get_xref_from():
                    callers.append(call_m)
        if callers:
            result[(cls_pat, mth_pat, label, cat)] = callers
    return result


def _collect_sink_refs(
    dx,
    sink_defs: list[tuple[str, str, str, str, str]],
) -> dict[str, dict]:
    """
    Returns { method_analysis_name: {sink_label, sink_cat, sink_sev, ma} }
    keyed by the full descriptor of sink MethodAnalysis objects.
    """
    result: dict = {}
    for cls_pat, mth_pat, label, cat, sev in sink_defs:
        for cls_analysis in dx.get_classes():
            cname = cls_analysis.name
            if cls_pat not in cname:
                continue
            for m in cls_analysis.get_methods():
                mn = m.name
                # Never treat a known non-sink (isLoggable, getStackTraceString) as
                # a sink even if it shares a substring with a sink method pattern.
                if mn in _NON_SINK_METHODS:
                    continue
                # EXACT method match when a name is specified: "e"/"i" must match
                # Log.e / Log.i, never "isLoggable". Empty pattern = class-prefix
                # intent (e.g. "retrofit2/") → match every method.
                if mth_pat and mn != mth_pat:
                    continue
                key = _ma_key(m)
                result[key] = {
                    "sink_label": label,
                    "sink_cat":   cat,
                    "sink_sev":   sev,
                    "ma":         m,
                }
    return result


def _build_sink_reachable(
    sink_methods: dict[str, dict],
    max_depth: int,
) -> dict[str, dict]:
    """
    BFS backwards from each sink: for every method that can *reach* a sink
    within max_depth hops, record which sink it eventually reaches.
    Returns { method_key → sink_info }.
    """
    reachable: dict[str, dict] = {}

    for sink_key, sink_info in sink_methods.items():
        # seed
        frontier = [sink_info["ma"]]
        reachable[sink_key] = sink_info
        visited   = {sink_key}
        depth     = 0

        while frontier and depth < max_depth:
            next_frontier = []
            for ma in frontier:
                try:
                    for _, caller_ma, _ in ma.get_xref_from():
                        k = _ma_key(caller_ma)
                        if k not in visited:
                            visited.add(k)
                            reachable[k] = sink_info
                            next_frontier.append(caller_ma)
                except Exception:
                    pass
            frontier = next_frontier
            depth += 1

    return reachable


def _bfs_to_sink(
    start_ma,
    sink_reachable: dict[str, dict],
    dx,
    max_depth: int,
) -> Optional[list[dict]]:
    """
    BFS from start_ma outward through callees to find a path that ends at a
    sink. Returns path as list of hop dicts or None.
    """
    start_key = _ma_key(start_ma)
    if start_key in sink_reachable:
        return [{"ma": start_ma, **sink_reachable[start_key]}]

    # BFS
    from collections import deque
    queue: deque = deque()
    queue.append((start_ma, []))
    visited = {start_key}

    while queue:
        current_ma, path_so_far = queue.popleft()
        if len(path_so_far) >= max_depth:
            continue
        try:
            for _, callee_ma, _ in current_ma.get_xref_to():
                k = _ma_key(callee_ma)
                if k in visited:
                    continue
                visited.add(k)
                new_path = path_so_far + [{"ma": callee_ma}]
                if k in sink_reachable:
                    # Found a path
                    new_path[-1].update(sink_reachable[k])
                    return new_path
                queue.append((callee_ma, new_path))
        except Exception:
            pass
    return None


def _ma_key(ma) -> str:
    try:
        m = ma.get_method() if hasattr(ma, "get_method") else ma
        return f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"
    except Exception:
        return str(id(ma))


def _format_chain(start_ma, path: list[dict]) -> list[str]:
    chain: list[str] = []
    try:
        m = start_ma.get_method() if hasattr(start_ma, "get_method") else start_ma
        chain.append(_fmt_method(m))
    except Exception:
        pass
    for hop in path:
        try:
            ma = hop.get("ma")
            if ma is None:
                continue
            m = ma.get_method() if hasattr(ma, "get_method") else ma
            chain.append(_fmt_method(m))
        except Exception:
            pass
    return chain


def _fmt_method(m) -> str:
    try:
        cls = m.get_class_name().replace("/", ".").lstrip("L").rstrip(";")
        return f"{cls}.{m.get_name()}"
    except Exception:
        return "?"


# ── Ownership filtering (BUG B) ───────────────────────────────────────────────
# Owner-type vocabulary that denotes library/framework/generated code (mirrors
# ownership.types.OwnerType — the values the engine emits). Application / Unknown
# are NOT here, so an app-owned or obfuscated-app class always survives the filter.
_LIBRARY_OWNER_TYPES = frozenset((
    "ThirdPartySDK", "AndroidFramework", "GoogleSDK", "AppleFramework",
    "VendorSDK", "OpenSourceLibrary", "GeneratedCode",
))


def _is_library_owner(owner_type: str) -> bool:
    return owner_type in _LIBRARY_OWNER_TYPES


def _chain_class_names(start_ma, path: list[dict]) -> list[str]:
    """Dotted class FQNs of every method in a flow (source caller + each hop)."""
    names: list[str] = []

    def _cn(ma):
        try:
            m = ma.get_method() if hasattr(ma, "get_method") else ma
            return m.get_class_name().replace("/", ".").lstrip("L").rstrip(";")
        except Exception:
            return ""

    n = _cn(start_ma)
    if n:
        names.append(n)
    for hop in path:
        ma = hop.get("ma")
        if ma is None:
            continue
        n = _cn(ma)
        if n:
            names.append(n)
    return names


class _OwnershipLookup:
    """Caches ownership classification of class FQNs for the taint pass.

    Reuses the shared Ownership Engine + fingerprints (never a hand-rolled prefix
    list) plus the scan's application namespaces, so a taint flow is classified the
    same way as every other finding. If ownership is unavailable (import failure),
    every class resolves to 'Unknown' → nothing is dropped (fail-open, never lose
    a real flow to a classification error).
    """

    def __init__(self, results: dict | None):
        self._cache: dict[str, str] = {}
        self._engine = None
        self._ctx = None
        self._ownership = None
        try:
            from . import ownership
            self._ownership = ownership
            self._engine = ownership.get_engine()
            self._ctx = ownership.context_from_results(results or {})
        except Exception:
            self._ownership = None

    def owner_type(self, fqn: str) -> str:
        if not fqn:
            return "Unknown"
        cached = self._cache.get(fqn)
        if cached is not None:
            return cached
        ot = "Unknown"
        if self._engine is not None and self._ownership is not None:
            try:
                ot = self._ownership.classify_component_class(
                    fqn, platform="android", ctx=self._ctx).owner_type
            except Exception:
                ot = "Unknown"
        self._cache[fqn] = ot
        return ot


# ── Severity calibration (Phase 5.2) ─────────────────────────────────────────
# Sources that carry inherently sensitive data — logging THESE warrants a bump.
_SENSITIVE_SOURCES = {
    "Location", "SMS", "Accounts", "Clipboard", "Camera", "Microphone",
    "ContentProvider", "SharedPrefs",
}
# Sink categories whose risk does NOT depend on data sensitivity — a tainted
# value reaching them is a real injection/exfiltration primitive.
_HIGH_VALUE_SINKS = {"WebView", "FileSystem", "Crypto", "Execution", "SQLite", "Network"}


def _calibrate_severity(sink_cat: str, source_cat: str, default_sev: str) -> str:
    """Calibrate a taint finding's severity by sink type (Phase 5.2).

    Logging sinks are LOW by default (logcat is local, API-30+ restricts read)
    and only MEDIUM when the data is inherently sensitive. Injection/exfil sinks
    (WebView.loadUrl, file writes, crypto, exec, SQL, network) keep their
    higher, sink-driven severity — those are dangerous regardless of source.
    """
    if sink_cat == "Logging":
        return "medium" if source_cat in _SENSITIVE_SOURCES else "low"
    if sink_cat in ("Intent", "Storage"):
        # Component/redirect & prefs-write risk scales with sensitivity.
        return default_sev if source_cat in _SENSITIVE_SOURCES else "low"
    if sink_cat in _HIGH_VALUE_SINKS:
        return default_sev
    return default_sev


def _flow_to_finding(flow: dict) -> dict:
    sink_cat = flow.get("sink_cat", "Unknown")
    meta     = _SINK_META.get(sink_cat, {"cwe": "CWE-200", "masvs": "MASVS-CODE-4", "owasp": "M2"})
    sev      = _calibrate_severity(sink_cat, flow.get("source_cat", ""), flow.get("sink_sev", "medium"))
    chain    = flow.get("call_chain", [])
    chain_str = " → ".join(chain) if chain else "N/A"

    return {
        "title":          f"Taint Flow: {flow['source']} → {flow['sink']}",
        "severity":       sev,
        "category":       "Taint Analysis",
        "description": (
            f"User-controlled data from **{flow['source']}** ({flow['source_cat']}) "
            f"flows into **{flow['sink']}** ({sink_cat}) without apparent sanitization.\n\n"
            f"Call chain: `{chain_str}`"
        ),
        "recommendation": (
            f"Validate and sanitize all data originating from {flow['source_cat']} "
            f"before it reaches {sink_cat} APIs. "
            "Apply input validation, output encoding, or parameterized queries as appropriate."
        ),
        "file_path":    flow.get("class_name", ""),
        "line":         0,
        "snippet":      chain_str,
        "confidence":   72,
        "exploitability": 60,
        "owner_type":   flow.get("owner_type", "Unknown"),
        "source":       "TAINT",
        "rule_id":      f"TAINT-{sink_cat.upper().replace(' ', '_')}",
        "cwe":          meta["cwe"],
        "masvs":        meta["masvs"],
        "owasp":        meta["owasp"],
        "taint_flow":   {
            "source":     flow["source"],
            "source_cat": flow["source_cat"],
            "sink":       flow["sink"],
            "sink_cat":   sink_cat,
            "chain":      chain,
        },
    }


def _total_dex_size_mb(apk_path: str) -> float:
    """Sum of all .dex file sizes inside the APK (bytes → MB)."""
    import zipfile
    total = 0
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for info in zf.infolist():
                if info.filename.endswith(".dex"):
                    total += info.file_size
    except Exception:
        pass
    return total / (1024 * 1024)
