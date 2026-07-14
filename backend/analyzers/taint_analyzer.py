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
_CONST_TRACE_DEPTH = 2  # RUN 31: nesting depth when proving a sink arg is constant

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
    const_arg_dropped = 0  # RUN 31 — Execution flows vetoed as provably non-attacker-controlled

    def _record_metrics() -> None:
        # Suppression is never silent: the count is recorded in the report itself.
        if isinstance(results, dict):
            results.setdefault("scan_metrics", {})[
                "taint_execution_flows_dropped_const_arg"] = const_arg_dropped

    for (src_cls, src_mth, src_label, src_cat), caller_methods in source_methods.items():
        for caller_m in caller_methods:
            # BFS from caller_m to any sink
            path = _bfs_to_sink(caller_m, sink_reachable, dx, MAX_DEPTH)
            if path is None:
                continue

            sink_entry = path[-1]

            # RUN 31 — constant-argument guard. An Execution sink whose arguments are
            # provably compile-time constants (root detection: exec({"/system/xbin/which",
            # "su"})) is not attacker-controlled, however reachable it is. Drop the flow
            # at birth rather than emitting a CRITICAL command-injection FP. Anything not
            # provably constant survives, so a real exec(userInput) is untouched.
            if sink_entry["sink_cat"] == "Execution" and _execution_args_all_constant(
                    sink_entry.get("ma"), caller_m, MAX_DEPTH):
                const_arg_dropped += 1
                continue

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

            # Calibrate the DISPLAYED severity ONCE, at construction, so every
            # surface (finding, Data Flow panel, PDF table) reads the same value.
            # The raw sink severity is preserved separately but is never displayed.
            raw_sink_sev = sink_entry["sink_sev"]
            flow_risk = _calibrate_severity(sink_entry["sink_cat"], src_cat, raw_sink_sev)

            flows.append({
                "source":       src_label,
                "source_cat":   src_cat,
                "sink":         sink_entry["sink_label"],
                "sink_cat":     sink_entry["sink_cat"],
                "sink_sev":     raw_sink_sev,
                "raw_sink_sev": raw_sink_sev,
                "risk":         flow_risk,
                "call_chain":   _format_chain(caller_m, path),
                "class_name":   caller_m.get_method().get_class_name().replace("/", ".").lstrip("L"),
                "method_name":  caller_m.get_method().get_name(),
                "owner_type":   source_owner,
            })

            if len(flows) >= MAX_PATHS:
                _record_metrics()
                return flows

    _record_metrics()
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


# ── RUN 31 — constant-argument guard for Execution sinks ──────────────────────
# This engine proves CALL-GRAPH REACHABILITY, not data-flow: a source-calling
# method that can reach a sink-calling method is emitted as a flow. That produces a
# CRITICAL false positive on the single most common Execution pattern in Android —
# root detection:
#
#     Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
#
# The argument is a compile-time constant array; no attacker input can reach it. It
# is a DEFENSIVE control (Beetle's own "Root Detection Present" finding flags the
# same line), yet co-occurrence with a getStringExtra elsewhere in the class was
# enough to emit "Intent → Runtime.exec (command injection)".
#
# The guard is a shallow, local def-use check at the sink CALL SITE: an Execution
# flow is dropped ONLY when every reachable call site of that sink passes arguments
# that provably originate from const* opcodes (directly, or via an array built
# entirely from const* values). Anything we cannot prove constant — a parameter, a
# move-result, a field read, an unreadable call site — KEEPS the flow. The guard can
# therefore remove a false positive but can never drop a true positive: exec(userInput)
# has a non-constant argument register and survives.
def _insn_registers(ins) -> list[int]:
    """Register operands of an instruction, in order (receiver first for invokes)."""
    regs: list[int] = []
    try:
        for op in ins.get_operands():
            # androguard operand: (Operand.REGISTER == 0, index)
            if isinstance(op, tuple) and len(op) >= 2 and int(op[0]) == 0:
                regs.append(int(op[1]))
    except Exception:
        return []
    return regs


def _method_instructions(em) -> list[tuple[int, object]]:
    """[(byte_offset, instruction)] — offsets match those in MethodAnalysis xrefs."""
    out: list[tuple[int, object]] = []
    try:
        off = 0
        for ins in em.get_instructions():
            out.append((off, ins))
            off += ins.get_length()
    except Exception:
        return []
    return out


def _reg_is_constant(insns: list, idx: int, reg: int, depth: int = 0) -> bool:
    """True only when `reg`, as of instruction `idx`, provably holds a compile-time
    constant. Unknown provenance ⇒ False (fail-open: the flow is kept)."""
    if depth > _CONST_TRACE_DEPTH:
        return False
    for j in range(idx - 1, -1, -1):
        ins = insns[j][1]
        name = ins.get_name()
        regs = _insn_registers(ins)
        if not regs:
            continue
        # aput* writes an ARRAY ELEMENT (regs[1] is the array), it does not define `reg`.
        if name.startswith("aput"):
            continue
        if regs[0] != reg:
            continue

        # ── the nearest instruction that DEFINES reg ──
        if name.startswith("const"):
            return True  # const / const-string / const-class / const-wide …
        if name == "new-array":
            # Constant only if every element stored into it before the call is constant.
            for k in range(j + 1, idx):
                el = insns[k][1]
                if not el.get_name().startswith("aput"):
                    continue
                el_regs = _insn_registers(el)
                if len(el_regs) >= 2 and el_regs[1] == reg:
                    if not _reg_is_constant(insns, k, el_regs[0], depth + 1):
                        return False
            return True
        if name.startswith("filled-new-array"):
            return all(_reg_is_constant(insns, j, r, depth + 1) for r in regs)
        # move-result*, iget*, sget*, move*, invoke* … → not provably constant.
        return False

    # No defining write in this method ⇒ it is an incoming parameter ⇒ NOT constant.
    return False


def _call_site_args_constant(em, off: int) -> bool:
    """True when the invoke at byte offset `off` passes only constant arguments."""
    insns = _method_instructions(em)
    for i, (o, ins) in enumerate(insns):
        if o != off:
            continue
        name = ins.get_name()
        regs = _insn_registers(ins)
        if not name.startswith("invoke") or not regs:
            return False
        # An instance invoke passes the receiver first — it is not an argument.
        args = regs if name.startswith("invoke-static") else regs[1:]
        if not args:
            return False  # nothing to judge ⇒ cannot prove constant ⇒ keep the flow
        return all(_reg_is_constant(insns, i, r) for r in args)
    return False  # offset not found ⇒ cannot prove ⇒ keep the flow


def _forward_reachable_keys(start_ma, max_depth: int) -> set[str]:
    """Method keys reachable FROM start_ma within max_depth call hops."""
    from collections import deque
    seen: set[str] = {_ma_key(start_ma)}
    queue: deque = deque([(start_ma, 0)])
    while queue:
        ma, depth = queue.popleft()
        if depth >= max_depth:
            continue
        try:
            for _, callee_ma, _ in ma.get_xref_to():
                k = _ma_key(callee_ma)
                if k not in seen:
                    seen.add(k)
                    queue.append((callee_ma, depth + 1))
        except Exception:
            continue
    return seen


def _execution_args_all_constant(sink_ma, caller_m, max_depth: int) -> bool:
    """True when EVERY call site of this Execution sink reachable from caller_m passes
    provably-constant arguments. False whenever anything cannot be proven."""
    if sink_ma is None:
        return False
    try:
        xrefs = list(sink_ma.get_xref_from())
    except Exception:
        return False

    reachable = _forward_reachable_keys(caller_m, max_depth)
    sites: list[tuple] = []
    for xref in xrefs:
        try:
            _cls, caller_ma, off = xref
        except Exception:
            continue
        if _ma_key(caller_ma) not in reachable:
            continue  # a call site the flow's caller cannot reach — not this flow's sink
        em = caller_ma.get_method() if hasattr(caller_ma, "get_method") else caller_ma
        sites.append((em, off))

    if not sites:
        return False  # could not locate the call site ⇒ cannot prove ⇒ keep the flow
    return all(_call_site_args_constant(em, off) for em, off in sites)


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
    if sink_cat == "Crypto":
        # RUN 35 T1: encrypting/hashing user-controlled data is the NORMAL use of a crypto API —
        # "user data reaches a crypto call" is not itself a weakness (a user-controlled IV is public;
        # a user-controlled plaintext is the point of encryption). The genuine crypto weaknesses —
        # hardcoded key/IV, ECB/CBC, Base64-as-encryption — are detected STRUCTURALLY by code_rules
        # and reported at their real severity. So this flow is LOW context, not a HIGH finding.
        return "low"
    if sink_cat in _HIGH_VALUE_SINKS:
        return default_sev
    return default_sev


def calibrate_flow_severity(flow: dict) -> str:
    """Single source of truth for a taint flow's DISPLAYED severity.

    Every consumer (the promoted finding, the Data Flow panel, the PDF taint table)
    must read ``flow["risk"]`` — this recomputes it from the flow's own fields when a
    flow (e.g. from an older scan) lacks it, so no surface ever falls back to the raw
    sink severity or a hardcoded default.
    """
    return flow.get("risk") or _calibrate_severity(
        flow.get("sink_cat", "Unknown"),
        flow.get("source_cat", ""),
        flow.get("sink_sev") or flow.get("raw_sink_sev") or "medium",
    )


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def reconcile_taint_flows(results: dict) -> list[dict]:
    """Canonical taint-flow list, deduped by (source → sink), shared by EVERY surface.

    Multiple call sites of the same source→sink pair collapse into ONE entry that
    carries ``call_site_count`` and the individual ``call_sites`` — so the Data Flow
    panel, its metrics and the PDF taint table always report the SAME number of
    flows. Deterministic: first-occurrence order is preserved. Prefers the raw
    per-call-site ``results['taint_flows']``; falls back to reconstructing sites from
    TAINT findings for older scans that lack it.
    """
    raw = results.get("taint_flows")
    if not raw:
        raw = []
        for f in results.get("findings") or []:
            if f.get("source") == "TAINT" and isinstance(f.get("taint_flow"), dict):
                tf = f["taint_flow"]
                raw.append({
                    "source": tf.get("source"), "source_cat": tf.get("source_cat"),
                    "sink": tf.get("sink"), "sink_cat": tf.get("sink_cat"),
                    "risk": f.get("severity") or tf.get("risk"),
                    "call_chain": tf.get("chain") or [],
                    "class_name": f.get("file_path") or "", "line": f.get("line") or 0,
                    "owner_type": f.get("owner_type"),
                })

    pairs: dict = {}
    order: list = []
    for flow in raw or []:
        if not isinstance(flow, dict) or not flow.get("source") or not flow.get("sink"):
            continue
        key = (flow.get("source"), flow.get("sink"))
        site = {
            "file": flow.get("file") or flow.get("class_name") or "",
            "line": flow.get("line") or 0,
            "call_chain": flow.get("call_chain") or flow.get("chain") or [],
            "method_name": flow.get("method_name") or "",
            "owner_type": flow.get("owner_type") or "",
        }
        risk = calibrate_flow_severity(flow)
        if key not in pairs:
            pairs[key] = {
                "source": flow.get("source"), "source_cat": flow.get("source_cat"),
                "sink": flow.get("sink"), "sink_cat": flow.get("sink_cat"),
                "risk": risk, "call_sites": [site],
            }
            order.append(key)
        else:
            e = pairs[key]
            e["call_sites"].append(site)
            # Highest severity across the pair's sites wins (they share source/sink
            # categories, so this is normally identical — defensive + deterministic).
            if _SEV_RANK.get(risk, 4) < _SEV_RANK.get(e["risk"], 4):
                e["risk"] = risk

    out: list[dict] = []
    for key in order:
        e = pairs[key]
        first = e["call_sites"][0]
        e["call_site_count"] = len(e["call_sites"])
        # Representative fields kept flat for existing readers (panel/graph).
        e["call_chain"] = first["call_chain"]
        e["file"] = first["file"]
        e["line"] = first["line"]
        e["method_name"] = first["method_name"]
        e["owner_type"] = first["owner_type"]
        out.append(e)
    return out


# ── Human copy (plain-English explainers for the Data Flow panel) ────────────
# Keep every string ≤160 chars, natural and non-alarmist. Specific (source_cat,
# sink_cat) pairs win; otherwise a generic per-sink-category fallback is used.
_FLOW_EXPLAINERS: dict[tuple, dict] = {
    ("Location", "Logging"): {
        "plain_summary": "The app reads the device's GPS location and writes it to the Android system log (logcat).",
        "why_it_matters": "Logs are readable by crash-reporting SDKs, bug-report captures, and — on Android 10 and older — other apps. Precise location in logs is a privacy leak.",
    },
    ("SharedPrefs", "Logging"): {
        "plain_summary": "A value read from local preferences is written to the system log.",
        "why_it_matters": "If that value is sensitive (a token, ID, or PII), it leaks to anything that can read logcat.",
    },
    ("User Input", "Logging"): {
        "plain_summary": "A value the user typed (or that arrived from another app) is written to the system log.",
        "why_it_matters": "If the input is sensitive it leaks to anything that can read logcat, and logged input can aid other attacks.",
    },
    ("Clipboard", "Logging"): {
        "plain_summary": "Clipboard contents are written to the system log.",
        "why_it_matters": "The clipboard can hold passwords or copied secrets; logging them exposes them to log readers.",
    },
    ("SharedPrefs", "Storage"): {
        "plain_summary": "A value from local preferences is written back to on-device storage.",
        "why_it_matters": "On-device storage isn't encrypted by default — sensitive values there are readable on a rooted or backed-up device.",
    },
    ("SharedPrefs", "Crypto"): {
        "plain_summary": "A value from local preferences flows into a cryptographic call (hashing/encryption).",
        "why_it_matters": "Only a concern if the algorithm is weak or a key/IV is misused — check the crypto findings.",
    },
}

# Generic fallback keyed by SINK category (used when no specific pair matches).
_SINK_CAT_EXPLAINERS: dict[str, dict] = {
    "Logging": {
        "plain_summary": "User-controlled data is written to the Android system log (logcat).",
        "why_it_matters": "If the data is sensitive, logs are readable by crash SDKs, bug reports, and older Android versions.",
    },
    "Crypto": {
        "plain_summary": "Data flows into a cryptographic call (hashing/encryption).",
        "why_it_matters": "Only a concern if the algorithm is weak or a key/IV is misused — check the crypto findings.",
    },
    "Network": {
        "plain_summary": "User-controlled data is sent over the network.",
        "why_it_matters": "If it's sensitive or unvalidated, it can leak to third parties or enable request tampering.",
    },
    "SQLite": {
        "plain_summary": "User-controlled data is used to build a database query.",
        "why_it_matters": "Unsanitized input here can mean SQL injection — data theft or tampering.",
    },
    "FileSystem": {
        "plain_summary": "User-controlled data is written to a file on the device.",
        "why_it_matters": "Depending on the path and permissions, this can expose data or allow file tampering.",
    },
    "Execution": {
        "plain_summary": "User-controlled data flows into an OS command execution.",
        "why_it_matters": "Unsanitized input here can mean command injection — arbitrary code execution.",
    },
    "WebView": {
        "plain_summary": "User-controlled data is loaded into a WebView.",
        "why_it_matters": "Tainted input here can mean script injection (XSS) inside the app's web view.",
    },
    "Intent": {
        "plain_summary": "User-controlled data flows into an Android component launch (intent).",
        "why_it_matters": "Can redirect to unintended components or leak data to other apps.",
    },
    "Storage": {
        "plain_summary": "User-controlled data is written to on-device storage.",
        "why_it_matters": "On-device storage isn't encrypted by default — sensitive values are readable on a rooted or backed-up device.",
    },
}
_FLOW_EXPLAINER_DEFAULT = {
    "plain_summary": "User-controlled data flows into a sensitive operation without visible sanitization.",
    "why_it_matters": "Review whether the data is sensitive and whether the sink can be abused.",
}

# One-line glossary for the SINK, keyed by label prefix then sink category.
_SINK_GLOSSARY_BY_LABEL: tuple = (
    ("Log.", "Android logcat — the device's local debug log. Writing sensitive data here exposes it to log readers."),
    ("System.out", "Android logcat — the device's local debug log. Writing sensitive data here exposes it to log readers."),
    ("SharedPrefs.put", "An unencrypted on-device preferences file (XML). Not safe for secrets."),
    ("MessageDigest.", "A hashing call. Weak hashes (MD5/SHA-1) don't protect data."),
    ("Cipher.", "A cryptographic call — weak algorithms or misused keys don't protect data."),
    ("SecretKeySpec", "A cryptographic key is constructed here — weak or hardcoded keys don't protect data."),
    ("IvParameterSpec", "A cryptographic IV is constructed here — a reused/predictable IV weakens encryption."),
    ("WebView.loadUrl", "Loads content into a WebView — tainted input here can mean navigation to attacker content."),
    ("WebView.evaluateJavascript", "Runs JavaScript in a WebView — tainted input here can mean script injection."),
    ("WebView.loadData", "Loads content/HTML into a WebView — tainted input here can mean script injection."),
    ("WebView.addJavascriptInterface", "Bridges native code to WebView JS — a tainted bridge is a remote-code-execution surface."),
    ("Runtime.exec", "Runs an OS command — tainted input here can mean command injection."),
    ("ProcessBuilder", "Runs an OS command — tainted input here can mean command injection."),
    ("SQLiteDatabase.exec", "Executes a raw SQL statement — unsanitized input here can mean SQL injection."),
    ("SQLiteDatabase.rawQuery", "Runs a raw SQL query — unsanitized input here can mean SQL injection."),
    ("SQLiteDatabase.", "A database operation — unsanitized input here can mean SQL injection."),
    ("FileOutputStream", "Writes bytes to a file on the device."),
    ("FileWriter", "Writes text to a file on the device."),
    ("Files.write", "Writes to a file on the device."),
    ("Socket", "Opens a raw network connection — data sent here leaves the device."),
    ("HttpURLConnection", "Sends data over an HTTP connection — data sent here leaves the device."),
    ("OkHttp", "Sends data over the network via OkHttp."),
    ("URL.openConnection", "Opens a network connection — data sent here leaves the device."),
    ("PendingIntent", "Creates a deferred intent — a mutable/implicit one can be hijacked by another app."),
    ("Context.startActivity", "Launches an Android component — tainted input can redirect to unintended screens."),
    ("Context.sendBroadcast", "Broadcasts an intent — any app can receive it unless it's permission-protected."),
)
_SINK_GLOSSARY_BY_CAT: dict[str, str] = {
    "Logging": "Android logcat — the device's local debug log. Sensitive data here is exposed to log readers.",
    "Network": "A network destination — data sent here leaves the device.",
    "SQLite": "A local database — unsanitized input can mean SQL injection.",
    "FileSystem": "A file on the device.",
    "Crypto": "A cryptographic call — weak algorithms or misused keys don't protect data.",
    "Execution": "An OS command — tainted input can mean command injection.",
    "WebView": "An in-app web view — tainted input can mean script injection.",
    "Intent": "An Android component launch — can redirect or leak data to other apps.",
    "Storage": "On-device storage — not encrypted by default; not safe for secrets.",
}

# One-line glossary for the SOURCE, keyed by source category.
_SOURCE_GLOSSARY_BY_CAT: dict[str, str] = {
    "Location": "The device's GPS / network location.",
    "SharedPrefs": "A value read from the app's local preferences file.",
    "User Input": "Data the user typed or that arrived from another app via an intent.",
    "Clipboard": "The device clipboard — may contain copied passwords or secrets.",
    "SMS": "The contents of an SMS message.",
    "Accounts": "Account identifiers registered on the device.",
    "Camera": "Data captured from the camera.",
    "Microphone": "Audio captured from the microphone.",
    "ContentProvider": "Data queried from a content provider (shared app data).",
}


def _sink_explainer(sink_label: str, sink_cat: str) -> str:
    label = sink_label or ""
    for prefix, text in _SINK_GLOSSARY_BY_LABEL:
        if label.startswith(prefix):
            return text
    return _SINK_GLOSSARY_BY_CAT.get(sink_cat, "A sensitive operation the tainted data reaches.")


def explain_flow(source_cat: str, sink_cat: str,
                 source_label: str = "", sink_label: str = "") -> dict:
    """Plain-English copy for one taint flow: what happens, why it matters, and what
    the source and sink actually ARE — for a reader who doesn't know Android APIs.

    Specific (source_cat, sink_cat) pairs win; otherwise a per-sink-category fallback.
    All strings are short (≤160 chars). Deterministic, data-driven."""
    pair = _FLOW_EXPLAINERS.get((source_cat, sink_cat))
    base = pair or _SINK_CAT_EXPLAINERS.get(sink_cat) or _FLOW_EXPLAINER_DEFAULT
    return {
        "plain_summary": base["plain_summary"],
        "why_it_matters": base["why_it_matters"],
        "source_explainer": _SOURCE_GLOSSARY_BY_CAT.get(
            source_cat, "A value read by the app."),
        "sink_explainer": _sink_explainer(sink_label, sink_cat),
    }


def _flow_to_finding(flow: dict) -> dict:
    sink_cat = flow.get("sink_cat", "Unknown")
    meta     = _SINK_META.get(sink_cat, {"cwe": "CWE-200", "masvs": "MASVS-CODE-4", "owasp": "M2"})
    # Reuse the calibrated risk already on the flow so the finding severity is
    # identical to what the panel and PDF show.
    sev      = calibrate_flow_severity(flow)
    chain    = flow.get("call_chain", [])
    chain_str = " → ".join(chain) if chain else "N/A"

    # RUN 35 T1: a Crypto-sink flow is reframed as CONTEXT — reaching a crypto API with user data
    # is normal, not a weakness. Point the reader at the structural crypto findings for the real risk.
    if sink_cat == "Crypto":
        description = (
            f"User-controlled data from **{flow['source']}** ({flow['source_cat']}) reaches the "
            f"crypto API **{flow['sink']}**. This is CONTEXT, not a weakness by itself — encrypting or "
            "hashing user input is the normal use of cryptography. Any actual crypto weakness "
            "(hardcoded key/IV, ECB/CBC mode, Base64-as-encryption) is reported separately as its own "
            f"structural finding.\n\nCall chain: `{chain_str}`"
        )
        recommendation = (
            "No action for the data-flow itself. Address the structural crypto findings for this class "
            "(remove hardcoded keys/IVs, use an authenticated cipher mode)."
        )
    else:
        description = (
            f"User-controlled data from **{flow['source']}** ({flow['source_cat']}) "
            f"flows into **{flow['sink']}** ({sink_cat}) without apparent sanitization.\n\n"
            f"Call chain: `{chain_str}`"
        )
        recommendation = (
            f"Validate and sanitize all data originating from {flow['source_cat']} "
            f"before it reaches {sink_cat} APIs. "
            "Apply input validation, output encoding, or parameterized queries as appropriate."
        )

    return {
        "title":          f"Taint Flow: {flow['source']} → {flow['sink']}",
        "severity":       sev,
        "category":       "Taint Analysis",
        "description":    description,
        "recommendation": recommendation,
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
            # Calibrated severity carried on the sub-dict too, so any consumer
            # reading finding["taint_flow"] gets the same value as finding["severity"].
            "risk":       sev,
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
