"""
Flutter Security Intelligence (Beetle 2.0, Phase 2.1).

Makes Flutter a first-class Beetle platform WITHOUT a parallel pipeline. A Flutter
app is just an Android APK (``libflutter.so`` + ``libapp.so`` + ``flutter_assets``) or
an iOS IPA (``Flutter.framework`` + ``flutter_assets``), so this is a SUB-ANALYZER
that runs inside the existing Android / iOS flow when ``framework == "flutter"`` —
exactly like the React Native bundle analyzer. It contributes plain, canonical-shaped
detections to the EXISTING result streams and then gets out of the way:

* ``results["findings"]``  ← canonical finding dicts (tagged ``Flutter Intelligence``)
* ``results["secrets"]``   ← candidate secrets via the reused ``scan_text_for_secrets``
* ``results["endpoints"]`` ← URLs via the reused ``extract_urls``

It calls NO intelligence engine itself. The unchanged finalize phase then runs over
those streams — Ownership → Confidence → Evidence → Evidence Selection → Finding
Fusion → Triage → Attack Chains → Bug Bounty → Network Intelligence → Reports — so
Flutter findings receive identical treatment to Android/iOS findings (Detected By,
Owner, Confidence, Evidence, Attack Chain, Bug Bounty, Source).

Analysis sources (whichever are present): ``pubspec.yaml`` / ``pubspec.lock``, ``.dart``
source (source-dir / debug builds), ``flutter_assets`` (AssetManifest, ``kernel_blob``)
and the printable strings of ``libapp.so`` / the App snapshot (release AOT Dart). The
public entry point ``analyze(roots, results, platform=…)`` accepts ARBITRARY roots, so
a future "Flutter project source directory" input is a thin add-on, not a rewrite.

It also emits ``results["flutter"]`` metadata (detection, dependencies, project
structure) — the data a future Source Explorer tree-view needs; the explorer itself is
intentionally NOT built here.
"""
from __future__ import annotations

import logging
import os
import re

from .common import extract_urls, rule_slug, scan_text_for_secrets
from .path_utils import make_file_evidence, relativize_path

log = logging.getLogger("cortex.flutter")

FLUTTER_VERSION = "1.0.0"
SOURCE = "Flutter Intelligence"

# Canonical Flutter project directories — preserved as metadata for the future Source
# Explorer (this phase exposes them, it does not render a tree).
PROJECT_DIRS = ("lib", "assets", "android", "ios", "test", "windows", "linux", "macos", "web")

# Harvest budget (defensive: a pathological app must never stall the scan).
_MAX_DART_FILES = 4000
_MAX_TEXT_BYTES = 4 * 1024 * 1024
_SNIPPET_CAP = 240


# ════════════════════════════════════════════════════════════════════════════
# Detection
# ════════════════════════════════════════════════════════════════════════════
_FLUTTER_MARKERS = ("libflutter.so", "libapp.so", "flutter_assets", "isolate_snapshot_data")


def detect(roots: list[str]) -> bool:
    """True when any root contains a Flutter artifact. The live pipeline gates on the
    analyzers' existing ``framework == "flutter"`` flag; this exists for the source-dir
    path and the tests."""
    for root in roots or []:
        if not root or not os.path.exists(root):
            continue
        # A source project is unambiguous: a pubspec.yaml declaring the flutter SDK.
        pub = os.path.join(root, "pubspec.yaml")
        if os.path.isfile(pub):
            try:
                with open(pub, "r", errors="replace") as f:
                    if "flutter" in f.read().lower():
                        return True
            except OSError:
                pass
        for cur, dirs, files in os.walk(root):
            base = os.path.basename(cur).lower()
            if base in _FLUTTER_MARKERS or "flutter_assets" in [d.lower() for d in dirs]:
                return True
            for fn in files:
                low = fn.lower()
                if low in _FLUTTER_MARKERS or low.startswith("libapp") or low.startswith("libflutter"):
                    return True
    return False


# ════════════════════════════════════════════════════════════════════════════
# Pattern catalogs — each rule maps a Dart/Flutter signature to a canonical finding.
# Data, not logic: add a rule = add a tuple. (regex, title, severity, category, desc,
# recommendation, cwe, masvs)
# ════════════════════════════════════════════════════════════════════════════
def _r(p):
    return re.compile(p)


# ── Platform channels (native bridge surface) ─────────────────────────────────
_CHANNEL_RULES = [
    (_r(r'MethodChannel\s*\(\s*[\'"]([^\'"]+)[\'"]'), "MethodChannel",
     "Flutter MethodChannel (native bridge)", "info", "Platform Channel",
     "A Flutter MethodChannel '{m}' bridges Dart to native code. Method names and "
     "arguments cross the platform boundary and define part of the app's attack surface.",
     "Validate and authorize all channel arguments on the native side; treat channel "
     "input as untrusted.", "CWE-749", "MASVS-PLATFORM-1"),
    (_r(r'EventChannel\s*\(\s*[\'"]([^\'"]+)[\'"]'), "EventChannel",
     "Flutter EventChannel (native event stream)", "info", "Platform Channel",
     "A Flutter EventChannel '{m}' streams native events to Dart.",
     "Ensure the native event source cannot leak sensitive data to the Dart layer.",
     "CWE-749", "MASVS-PLATFORM-1"),
    (_r(r'BasicMessageChannel\s*\(\s*[\'"]([^\'"]+)[\'"]'), "BasicMessageChannel",
     "Flutter BasicMessageChannel (native messaging)", "info", "Platform Channel",
     "A Flutter BasicMessageChannel '{m}' exchanges arbitrary messages with native code.",
     "Validate message payloads on both sides of the bridge.",
     "CWE-749", "MASVS-PLATFORM-1"),
]

# ── Storage ───────────────────────────────────────────────────────────────────
_STORAGE_RULES = [
    (_r(r'FlutterSecureStorage|flutter_secure_storage'),
     "Flutter Secure Storage in use", "info", "Insecure Storage",
     "App uses flutter_secure_storage (Keychain/Keystore-backed). This is the "
     "recommended store for sensitive values.",
     "Confirm sensitive values use secure storage rather than SharedPreferences/Hive.",
     "CWE-312", "MASVS-STORAGE-1"),
    (_r(r'SharedPreferences|shared_preferences'),
     "SharedPreferences storage (plaintext)", "low", "Insecure Storage",
     "App uses SharedPreferences, which stores values in plaintext XML/plist. Sensitive "
     "data here is readable on a rooted/jailbroken device or via backup.",
     "Store secrets in flutter_secure_storage; never keep tokens/keys in SharedPreferences.",
     "CWE-312", "MASVS-STORAGE-1"),
    (_r(r'Hive\.openBox\s*\((?![^)]*encryptionCipher)'),
     "Unencrypted Hive box", "medium", "Insecure Storage",
     "A Hive box is opened without an encryptionCipher, so its contents are stored "
     "unencrypted on disk.",
     "Open Hive boxes with HiveAesCipher (openBox(..., encryptionCipher: ...)).",
     "CWE-312", "MASVS-STORAGE-1"),
    (_r(r'openDatabase\s*\(|sqflite'),
     "SQLite (sqflite) local database", "info", "Insecure Storage",
     "App uses a local SQLite database via sqflite. Data is unencrypted unless an "
     "encrypted SQLite implementation is used.",
     "Avoid storing secrets in SQLite; use sqlcipher or secure storage for sensitive rows.",
     "CWE-312", "MASVS-STORAGE-1"),
]

# ── Network ───────────────────────────────────────────────────────────────────
_NETWORK_RULES = [
    (_r(r'badCertificateCallback\s*=\s*\(?[^;]*=>\s*true|onBadCertificate\s*:\s*\(?[^;]*=>\s*true'),
     "TLS certificate validation disabled", "high", "Network Security",
     "A Dio/HttpClient bad-certificate callback unconditionally returns true, disabling "
     "TLS certificate validation and enabling trivial man-in-the-middle interception.",
     "Never return true from badCertificateCallback/onBadCertificate. Implement proper "
     "certificate or public-key pinning instead.",
     "CWE-295", "MASVS-NETWORK-1"),
    (_r(r'\bDio\s*\('), "Dio HTTP client", "info", "Network Security",
     "App uses the Dio HTTP client. Review interceptors and certificate handling for "
     "secure transport.",
     "Add a certificate-pinning interceptor; ensure all base URLs are HTTPS.",
     "CWE-295", "MASVS-NETWORK-1"),
    (_r(r'WebSocket(?:Channel)?\s*[.(]|web_socket_channel|ws://'),
     "WebSocket usage", "info", "Network Security",
     "App establishes WebSocket connections. Cleartext ws:// connections are unencrypted.",
     "Use wss:// (TLS) for all WebSocket connections; never ws:// in production.",
     "CWE-319", "MASVS-NETWORK-1"),
]

# ── Build / debug ─────────────────────────────────────────────────────────────
_BUILD_RULES = [
    (_r(r'\bkDebugMode\b'), "Flutter debug-mode flag referenced", "info", "Configuration",
     "Code branches on kDebugMode. Ensure debug-only logic (verbose logging, test "
     "endpoints, disabled checks) cannot execute in a release build.",
     "Confirm kDebugMode-gated code is excluded from release; never ship debug endpoints.",
     "CWE-489", "MASVS-CODE-2"),
    (_r(r'debugPrint\s*\(|print\s*\([^)]*token|print\s*\([^)]*password', ),
     "Potential sensitive logging", "low", "Configuration",
     "A print/debugPrint call may log sensitive data. Logs are readable via logcat / "
     "device console.",
     "Strip debug logging from release builds; never log tokens, passwords or PII.",
     "CWE-532", "MASVS-STORAGE-2"),
]

_ALL_RULES = _CHANNEL_RULES + _STORAGE_RULES + _NETWORK_RULES + _BUILD_RULES

# ── AOT capability signals ────────────────────────────────────────────────────
# A code-pattern rule (call site + line) is meaningless against a COMPILED AOT
# snapshot: a token like "SharedPreferences" in libapp.so's string table is just a
# linked symbol, not a call site. Instead of emitting per-offset "findings" with a
# fake libapp.so:NNNN line (a false attribution + duplicate explosion), we surface
# ONE deduped, NON-CHAINABLE INFO capability note per capability. (capability_key,
# regex, title, description, cwe, masvs).
_AOT_CAPABILITY_SIGNALS = [
    ("shared_preferences", _r(r'SharedPreferences|shared_preferences'),
     "SharedPreferences dependency present (AOT symbol)",
     "The AOT snapshot links against shared_preferences. This is a capability signal "
     "from a compiled symbol — NOT evidence of a specific insecure call site (the "
     "snapshot has no source location). Confirm in source whether sensitive values are "
     "stored in SharedPreferences rather than flutter_secure_storage.",
     "CWE-312", "MASVS-STORAGE-1"),
    ("hive", _r(r'\bHive\b|hive_flutter'),
     "Hive local-DB dependency present (AOT symbol)",
     "The AOT snapshot links against Hive. Capability signal from a compiled symbol — "
     "not a call site. Confirm whether boxes are opened with an encryptionCipher.",
     "CWE-312", "MASVS-STORAGE-1"),
    ("sqflite", _r(r'\bsqflite\b'),
     "SQLite (sqflite) dependency present (AOT symbol)",
     "The AOT snapshot links against sqflite. Capability signal from a compiled symbol "
     "— not a call site. Confirm sensitive rows are not stored unencrypted.",
     "CWE-312", "MASVS-STORAGE-1"),
    ("secure_storage", _r(r'FlutterSecureStorage|flutter_secure_storage'),
     "flutter_secure_storage present (AOT symbol)",
     "The AOT snapshot links against flutter_secure_storage (Keychain/Keystore-backed) "
     "— the recommended secure store. Capability signal from a compiled symbol.",
     "CWE-312", "MASVS-STORAGE-1"),
]

# Known Flutter dependencies → a short capability label (for the metadata inventory).
_KNOWN_DEPS = {
    "dio": "HTTP client", "http": "HTTP client", "chopper": "HTTP client",
    "web_socket_channel": "WebSocket", "flutter_secure_storage": "Secure storage",
    "hive": "Local DB", "hive_flutter": "Local DB", "sqflite": "SQLite",
    "shared_preferences": "Key-value storage", "firebase_core": "Firebase",
    "firebase_auth": "Firebase", "cloud_firestore": "Firebase", "firebase_messaging": "Firebase",
    "encrypt": "Crypto", "crypto": "Crypto", "pointycastle": "Crypto",
}


# ════════════════════════════════════════════════════════════════════════════
# Finding builder
# ════════════════════════════════════════════════════════════════════════════
def _finding(title, severity, category, desc, *, file_path="", line=0, snippet="",
             rec="", cwe="", masvs="", owasp="M1") -> dict:
    return {
        # Stable per-RULE id derived from the rule's static title.
        "rule_id": rule_slug("flutter", title),
        "evidence_type": "regex_match",
        "title": title, "severity": severity, "category": category,
        "description": desc, "recommendation": rec,
        "file_path": file_path, "line": line, "line_number": line,
        "snippet": snippet, "code_context": snippet,
        "cwe": cwe, "masvs": masvs, "owasp": owasp,
        "confidence": 80, "exploitability": 40, "validation_status": "detected",
        # Attribution so Finding Fusion shows "Detected By: Flutter Intelligence".
        "source": SOURCE, "source_module": SOURCE, "detected_by": [SOURCE],
        "discovery_method": "flutter_analysis",
        "file_evidence": [make_file_evidence(file_path, line, snippet)] if file_path else [],
    }


def _emit_aot_capability_notes(text: str, rel: str, findings: list, seen_cap: set) -> int:
    """Emit ONE deduped, non-chainable INFO note per capability found in an AOT blob.

    A capability is recorded at most once per scan (``seen_cap``), carries NO line
    number (no bogus ``libapp.so:NNNN`` anchor) and is flagged ``do_not_chain`` so the
    attack-chain engine never pulls an AOT symbol as a required/supporting step.
    Returns the number of notes emitted."""
    emitted = 0
    for cap_key, rx, title, desc, cwe, masvs in _AOT_CAPABILITY_SIGNALS:
        if cap_key in seen_cap:
            continue
        if not rx.search(text):
            continue
        seen_cap.add(cap_key)
        f = _finding(title, "info", "Insecure Storage", desc,
                     file_path=rel, line=0, snippet="", rec="", cwe=cwe, masvs=masvs)
        # AOT symbol presence is a capability signal, not a call site: no evidence
        # line, and explicitly ineligible as attack-chain evidence.
        f["evidence_type"] = "aot_symbol"
        f["do_not_chain"] = True
        f["validation_status"] = "capability"
        f["confidence"] = 40
        f["file_evidence"] = []
        findings.append(f)
        emitted += 1
    return emitted


def _line_of(text: str, pos: int) -> tuple[int, str]:
    line_no = text.count("\n", 0, pos) + 1
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    snippet = text[start:(end if end != -1 else len(text))].strip()[:_SNIPPET_CAP]
    return line_no, snippet


# ════════════════════════════════════════════════════════════════════════════
# Harvest — collect (rel_path, text, is_source) tuples from the roots
# ════════════════════════════════════════════════════════════════════════════
def _printable(path: str) -> str:
    """Printable strings of a binary (libapp.so / kernel_blob) — release AOT Dart."""
    try:
        from .scan_storage import _printable_strings
        with open(path, "rb") as f:
            return _printable_strings(f.read(_MAX_TEXT_BYTES))
    except Exception:
        return ""


def _harvest(roots: list[str]) -> tuple[list[tuple[str, str, str]], dict]:
    """Return (sources, artifacts). Each source = (rel_path, text, kind).

    ``kind`` is ``"dart"`` (real Dart source), ``"asset"`` (human-readable asset
    text) or ``"blob"`` (printable strings of a COMPILED AOT artifact — libapp.so /
    kernel_blob / *.aotsnapshot). Only ``dart``/``asset`` are real source locations
    where a code-pattern regex hit means a call site; a hit in a ``blob`` is just a
    class-name symbol in the snapshot, not evidence of a call site.
    ``artifacts`` records what was found (for metadata + pubspec parsing)."""
    sources: list[tuple[str, str, str]] = []
    artifacts = {"pubspec": "", "pubspec_lock": "", "has_libapp": False,
                 "has_flutter_assets": False, "dart_files": 0, "dirs_present": {}}
    seen_files: set = set()
    dart_count = 0

    for root in roots or []:
        if not root or not os.path.exists(root):
            continue
        for cur, dirs, files in os.walk(root):
            rel_cur = os.path.relpath(cur, root).replace("\\", "/")
            top = rel_cur.split("/", 1)[0] if rel_cur != "." else ""
            if top in PROJECT_DIRS:
                artifacts["dirs_present"][top] = True
            for fn in files:
                low = fn.lower()
                fpath = os.path.join(cur, fn)
                rel = relativize_path(fpath, root)
                if rel in seen_files:
                    continue
                try:
                    if low.endswith(".dart") and dart_count < _MAX_DART_FILES:
                        with open(fpath, "r", errors="replace") as f:
                            sources.append((rel, f.read(_MAX_TEXT_BYTES), "dart"))
                        seen_files.add(rel); dart_count += 1
                    elif low == "pubspec.yaml":
                        with open(fpath, "r", errors="replace") as f:
                            artifacts["pubspec"] = f.read(_MAX_TEXT_BYTES)
                    elif low == "pubspec.lock":
                        with open(fpath, "r", errors="replace") as f:
                            artifacts["pubspec_lock"] = f.read(_MAX_TEXT_BYTES)
                    elif low.startswith("libapp") and low.endswith(".so"):
                        artifacts["has_libapp"] = True
                        txt = _printable(fpath)
                        if txt:
                            sources.append((rel, txt, "blob"))
                            seen_files.add(rel)
                    elif low in ("kernel_blob.bin", "app.framework", "isolate_snapshot_data") \
                            or low.endswith(".aotsnapshot"):
                        txt = _printable(fpath)
                        if txt:
                            sources.append((rel, txt, "blob"))
                            seen_files.add(rel)
                    elif low == "assetmanifest.json":
                        artifacts["has_flutter_assets"] = True
                        with open(fpath, "r", errors="replace") as f:
                            sources.append((rel, f.read(_MAX_TEXT_BYTES), "asset"))
                        seen_files.add(rel)
                except OSError:
                    continue
            if "flutter_assets" in [d.lower() for d in dirs]:
                artifacts["has_flutter_assets"] = True
    artifacts["dart_files"] = dart_count
    return sources, artifacts


# ════════════════════════════════════════════════════════════════════════════
# pubspec parsing (dependency inventory — no yaml dependency, line-based)
# ════════════════════════════════════════════════════════════════════════════
# Structural pubspec sub-keys that are NOT dependency names (they appear nested
# under a dependency, e.g. `flutter:\n    sdk: flutter`).
_PUBSPEC_NON_DEPS = {"sdk", "path", "git", "url", "ref", "version", "hosted", "name"}


def _parse_pubspec(text: str) -> list[str]:
    """Extract declared dependency names from pubspec.yaml (dependencies / dev_).

    A dependency is a key at the FIRST indent level (canonical 2 spaces) under a
    ``dependencies:`` block; deeper-nested structural keys (``sdk:``/``git:``…) are
    excluded so e.g. the Flutter SDK pseudo-dependency is never mistaken for a package.
    """
    deps: list[str] = []
    in_deps = False
    for raw in (text or "").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if re.match(r'^[A-Za-z_]+:', raw):  # a top-level key resets the section
            in_deps = raw.split(":", 1)[0] in ("dependencies", "dev_dependencies", "dependency_overrides")
            continue
        if in_deps:
            m = re.match(r'^( +)([A-Za-z0-9_]+)\s*:', raw)
            if m and len(m.group(1)) == 2:  # first indent level = a real dependency
                name = m.group(2)
                if name != "flutter" and name not in _PUBSPEC_NON_DEPS:
                    deps.append(name)
    return sorted(set(deps))


# ════════════════════════════════════════════════════════════════════════════
# Public entry point
# ════════════════════════════════════════════════════════════════════════════
def analyze(roots, results: dict, *, platform: str = "android") -> dict:
    """Run Flutter analysis over ``roots`` and fold canonical detections into the
    existing ``results`` streams. Additive and defensive — never raises into the
    caller. Returns the ``results["flutter"]`` metadata block."""
    if isinstance(roots, str):
        roots = [roots]
    roots = [r for r in (roots or []) if r]

    sources, artifacts = _harvest(roots)
    findings = results.setdefault("findings", [])
    secrets = results.setdefault("secrets", [])
    endpoints = results.setdefault("endpoints", [])

    seen_find: set = set()
    seen_secret = {f"{s.get('name')}:{s.get('value')}" for s in secrets if isinstance(s, dict)}
    seen_url = set(endpoints)
    seen_cap: set = set()
    channels: list[str] = []
    n_find = n_secret = n_url = 0

    for rel, text, kind in sources:
        if not text:
            continue
        if kind == "blob":
            # Compiled AOT snapshot — code-pattern/call-site rules are NOT valid here
            # (a symbol string is not a call site). Emit deduped, non-chainable INFO
            # capability notes instead; secrets/URLs below still run over the strings.
            n_find += _emit_aot_capability_notes(text, rel, findings, seen_cap)
        else:
            # ── Pattern findings — real source (.dart) or asset text only ──────
            for rule in _ALL_RULES:
                rx, *meta = rule
                # Channel rules carry an extra "kind" element first; normalize both
                # shapes to (title, sev, cat, desc, rec, cwe, masvs).
                if len(meta) == 8:   # channel rule: (kind, title, sev, cat, desc, rec, cwe, masvs)
                    _kind, title, sev, cat, desc, rec, cwe, masvs = meta
                else:                # 7: (title, sev, cat, desc, rec, cwe, masvs)
                    title, sev, cat, desc, rec, cwe, masvs = meta
                for m in rx.finditer(text):
                    line_no, snippet = _line_of(text, m.start())
                    cap = m.group(1) if m.groups() else ""
                    key = (title, rel, cap or line_no)
                    if key in seen_find:
                        continue
                    seen_find.add(key)
                    if cap and "{m}" in desc:
                        if cap not in channels:
                            channels.append(cap)
                    findings.append(_finding(
                        title, sev, cat, desc.format(m=cap) if "{m}" in desc else desc,
                        file_path=rel, line=line_no, snippet=snippet, rec=rec, cwe=cwe, masvs=masvs))
                    n_find += 1

        # ── Secrets — REUSE the Secret Intelligence pipeline (no Flutter detector) ──
        for s in scan_text_for_secrets(text, rel):
            k = f"{s.get('name')}:{s.get('value')}"
            if k not in seen_secret:
                seen_secret.add(k)
                s.setdefault("source", SOURCE)
                s.setdefault("detected_by", [SOURCE])
                secrets.append(s)
                n_secret += 1

        # ── Network — REUSE extract_urls → endpoints (Network Intelligence) ──
        for url in extract_urls(text):
            if url not in seen_url:
                seen_url.add(url)
                endpoints.append(url)
                n_url += 1

    # ── Dependencies (capability inventory + a note when risky combos appear) ──
    deps = _parse_pubspec(artifacts["pubspec"])
    dep_caps = {d: _KNOWN_DEPS[d] for d in deps if d in _KNOWN_DEPS}

    # ── Source Explorer metadata (exposed, not rendered) ──────────────────────
    project_structure = {
        d: bool(artifacts["dirs_present"].get(d, False)) for d in PROJECT_DIRS
    }
    meta = {
        "version": FLUTTER_VERSION,
        "detected": True,
        "platform": platform,
        "build_mode": "debug" if artifacts["dart_files"] else "release",
        "has_libapp_snapshot": artifacts["has_libapp"],
        "has_flutter_assets": artifacts["has_flutter_assets"],
        "dart_source_files": artifacts["dart_files"],
        "dependencies": deps,
        "dependency_capabilities": dep_caps,
        "platform_channels": channels,
        "has_pubspec": bool(artifacts["pubspec"]),
        "has_pubspec_lock": bool(artifacts["pubspec_lock"]),
        # Source Explorer preparation: canonical project dirs + key files (metadata
        # only — the tree-view itself is a future phase).
        "project_structure": project_structure,
        "key_files": {
            "pubspec.yaml": bool(artifacts["pubspec"]),
            "pubspec.lock": bool(artifacts["pubspec_lock"]),
        },
        "stats": {"findings": n_find, "secrets": n_secret, "endpoints": n_url},
    }
    results["flutter"] = meta
    log.info("[flutter] %s | findings=%d secrets=%d endpoints=%d channels=%d deps=%d",
             platform, n_find, n_secret, n_url, len(channels), len(deps))
    return meta
