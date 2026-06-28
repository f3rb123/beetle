"""
React Native Security Intelligence (Beetle 2.0, Phase 2.2).

Makes React Native a first-class Beetle platform the SAME way Flutter is — a
SUB-ANALYZER inside the existing Android / iOS flow, gated on the pre-existing
``framework == "react_native"`` detection, contributing canonical detections to the
EXISTING result streams and then getting out of the way:

* ``results["findings"]``  ← canonical finding dicts (tagged ``React Native Intelligence``)
* ``results["secrets"]``   ← candidate secrets via the reused ``scan_text_for_secrets``
* ``results["endpoints"]`` ← URLs via the reused ``extract_urls``

It calls NO intelligence engine itself. The unchanged finalize phase then runs over
those streams — Ownership → Confidence → Evidence → Evidence Selection → Finding
Fusion → Triage → Attack Chains → Bug Bounty → Network Intelligence → Reports — so RN
findings get identical treatment to Android / iOS / Flutter findings.

Relationship to the existing JS modules (no duplication):
* Bundle DISCOVERY is reused from ``js_bundle_analyzer.find_js_bundles`` — not
  re-implemented.
* Generic JS dangerous sinks (``eval`` / ``Function`` / ``dangerouslySetInnerHTML``)
  remain ``js_bundle_analyzer``'s job (it runs for every app). THIS module adds the
  RN-IDIOMATIC security analysis: the native bridge (NativeModules / TurboModules /
  Fabric), RN storage libs (AsyncStorage / MMKV / Realm / SecureStore / Encrypted
  Storage), network (axios / fetch / WebSocket / certificate pinning), deep links,
  Firebase and environment configuration. It replaces the weak inline
  ``_analyze_rn_bundle``.

Analysis sources (whichever are present): JS/Hermes bundles, ``package.json``,
``metro.config.js`` / ``babel.config.js``, ``.env``, and ``.js`` / ``.jsx`` / ``.ts``
/ ``.tsx`` source (source-dir / future input). The public entry ``analyze(roots,
results, platform=…)`` accepts ARBITRARY roots, so a future "RN project source
directory" input is a thin add-on. It also emits ``results["react_native"]`` metadata
(detection, dependencies, project structure) for the future Source Explorer — the
explorer itself is NOT built here.
"""
from __future__ import annotations

import json
import logging
import os
import re

from .common import extract_urls, scan_text_for_secrets
from .path_utils import make_file_evidence, relativize_path

log = logging.getLogger("cortex.react_native")

RN_VERSION = "1.0.0"
SOURCE = "React Native Intelligence"

# Canonical RN project directories / files — preserved as metadata for the future
# Source Explorer (this phase exposes them, it does not render a tree).
PROJECT_DIRS = ("android", "ios", "src", "app", "assets", "node_modules")
PROJECT_FILES = ("package.json", "metro.config.js", "babel.config.js")

_MAX_SRC_FILES = 4000
_MAX_TEXT_BYTES = 12 * 1024 * 1024   # JS bundles are large
_SNIPPET_CAP = 240


# ════════════════════════════════════════════════════════════════════════════
# Detection
# ════════════════════════════════════════════════════════════════════════════
_RN_MARKERS = ("index.android.bundle", "index.ios.bundle", "main.jsbundle",
               "libreactnativejni.so", "libhermes.so", "libjsc.so")


def detect(roots: list[str]) -> bool:
    """True when any root contains a React Native artifact. The live pipeline gates on
    the analyzers' existing ``framework == "react_native"`` flag; this exists for the
    source-dir path and the tests."""
    for root in roots or []:
        if not root or not os.path.exists(root):
            continue
        # A source project is unambiguous: package.json depending on react-native.
        pkg = os.path.join(root, "package.json")
        if os.path.isfile(pkg):
            try:
                with open(pkg, "r", errors="replace") as f:
                    if "react-native" in f.read().lower():
                        return True
            except OSError:
                pass
        for cur, dirs, files in os.walk(root):
            for fn in files:
                low = fn.lower()
                if low in _RN_MARKERS or (low.endswith(".bundle") and "index" in low):
                    return True
    return False


# ════════════════════════════════════════════════════════════════════════════
# Pattern catalogs — Dart-style: (regex, [kind,] title, sev, cat, desc, rec, cwe, masvs)
# ════════════════════════════════════════════════════════════════════════════
def _r(p):
    return re.compile(p)


# ── Native bridge (NativeModules / TurboModules / Fabric) ─────────────────────
_BRIDGE_RULES = [
    (_r(r'NativeModules\.([A-Za-z_][A-Za-z0-9_]*)'), "NativeModule",
     "React Native bridge call (NativeModules.{m})", "info", "Native Bridge",
     "JavaScript invokes the native module '{m}' over the React Native bridge. Bridge "
     "methods and their arguments cross into native code and form part of the attack surface.",
     "Validate and authorize all bridge arguments on the native side; treat JS input as untrusted.",
     "CWE-749", "MASVS-PLATFORM-1"),
    (_r(r'TurboModuleRegistry|TurboModules\.|getEnforcing\s*<'), "TurboModule",
     "React Native TurboModule (new architecture bridge)", "info", "Native Bridge",
     "App uses TurboModules (the new RN architecture JSI bridge). Native methods are "
     "exposed synchronously to JavaScript.",
     "Validate all TurboModule inputs natively; do not expose sensitive native APIs to JS.",
     "CWE-749", "MASVS-PLATFORM-1"),
    (_r(r'requireNativeComponent|codegenNativeComponent'), "Fabric",
     "React Native Fabric native component", "info", "Native Bridge",
     "App registers a native UI component (Fabric/legacy). Native view props cross the bridge.",
     "Validate component props natively; avoid passing sensitive data through view props.",
     "CWE-749", "MASVS-PLATFORM-1"),
    (_r(r'NativeEventEmitter'), "EventEmitter",
     "React Native NativeEventEmitter (native→JS events)", "info", "Native Bridge",
     "Native code streams events to JavaScript via NativeEventEmitter.",
     "Ensure the native event source cannot leak sensitive data to the JS layer.",
     "CWE-749", "MASVS-PLATFORM-1"),
]

# ── Storage ───────────────────────────────────────────────────────────────────
_STORAGE_RULES = [
    (_r(r'AsyncStorage|@react-native-async-storage'),
     "AsyncStorage (plaintext)", "low", "Insecure Storage",
     "App uses AsyncStorage, which persists data UNENCRYPTED. Sensitive values here are "
     "readable on a rooted/jailbroken device or via backup.",
     "Never store secrets/tokens in AsyncStorage; use EncryptedStorage / SecureStore / Keychain.",
     "CWE-312", "MASVS-STORAGE-1"),
    (_r(r'new\s+MMKV\s*\((?![^)]*encryptionKey)|react-native-mmkv'),
     "MMKV storage without encryption", "medium", "Insecure Storage",
     "App uses react-native-mmkv without an encryptionKey, so values are stored unencrypted.",
     "Construct MMKV with an encryptionKey, or store secrets in Keychain/SecureStore.",
     "CWE-312", "MASVS-STORAGE-1"),
    (_r(r'new\s+Realm\s*\((?![^)]*encryptionKey)|realm'),
     "Realm database (encryption unverified)", "medium", "Insecure Storage",
     "App uses a Realm database. Realm is unencrypted unless opened with an encryptionKey.",
     "Open Realm with an encryptionKey; keep the key in Keychain/SecureStore.",
     "CWE-312", "MASVS-STORAGE-1"),
    (_r(r'react-native-sqlite-storage|SQLite\.openDatabase|WatermelonDB'),
     "SQLite local database", "info", "Insecure Storage",
     "App uses a local SQLite database. Data is unencrypted unless SQLCipher is used.",
     "Avoid storing secrets in SQLite; use an encrypted store for sensitive rows.",
     "CWE-312", "MASVS-STORAGE-1"),
    (_r(r'EncryptedStorage|react-native-encrypted-storage|SecureStore|expo-secure-store|react-native-keychain|Keychain\.set'),
     "Encrypted/secure storage in use", "info", "Insecure Storage",
     "App uses an encrypted store (EncryptedStorage / SecureStore / Keychain). This is the "
     "recommended location for sensitive values.",
     "Confirm all secrets/tokens use secure storage rather than AsyncStorage/MMKV.",
     "CWE-312", "MASVS-STORAGE-1"),
]

# ── Network ───────────────────────────────────────────────────────────────────
_NETWORK_RULES = [
    (_r(r'rejectUnauthorized\s*:\s*false|sslPinning\s*:\s*false|trustAllCerts\s*:\s*true|allowsArbitraryLoads'),
     "TLS certificate validation disabled", "high", "Network Security",
     "A network client disables certificate validation (rejectUnauthorized:false / "
     "trustAllCerts / arbitrary loads), enabling trivial man-in-the-middle interception.",
     "Never disable TLS validation. Use certificate or public-key pinning "
     "(react-native-ssl-pinning) instead.",
     "CWE-295", "MASVS-NETWORK-1"),
    (_r(r'react-native-ssl-pinning|react-native-cert-pinner|public-key-pinning|sslPinning\s*:\s*\{'),
     "Certificate pinning configured", "info", "Network Security",
     "App configures certificate/public-key pinning for network requests (good).",
     "Verify pins cover all sensitive hosts and have a rotation plan.",
     "CWE-295", "MASVS-NETWORK-1"),
    (_r(r'axios\.create\s*\(|\baxios\s*\(|from\s+[\'"]axios[\'"]'),
     "axios HTTP client", "info", "Network Security",
     "App uses the axios HTTP client. Review interceptors and TLS handling for secure transport.",
     "Ensure all base URLs are HTTPS; add a pinning interceptor for sensitive APIs.",
     "CWE-319", "MASVS-NETWORK-1"),
    (_r(r'new\s+WebSocket\s*\(|ws://'),
     "WebSocket usage", "info", "Network Security",
     "App establishes WebSocket connections. Cleartext ws:// connections are unencrypted.",
     "Use wss:// (TLS) for all WebSocket connections; never ws:// in production.",
     "CWE-319", "MASVS-NETWORK-1"),
]

# ── Deep links / Firebase / env / build ───────────────────────────────────────
_PLATFORM_RULES = [
    (_r(r'Linking\.(?:getInitialURL|addEventListener|openURL)'),
     "Deep link handling", "info", "Platform Interaction",
     "App handles deep links via the Linking API. Deep-link parameters are attacker-"
     "controllable input into the app.",
     "Validate and sanitize all deep-link URLs/params; never auto-execute actions from them.",
     "CWE-939", "MASVS-PLATFORM-3"),
    (_r(r'@react-native-firebase|firebase\.initializeApp|getFirestore\s*\('),
     "Firebase integration", "info", "Configuration",
     "App integrates Firebase. Client Firebase config (apiKey/projectId) is shippable, but "
     "Firestore/RTDB security rules and exposed services must be reviewed.",
     "Audit Firebase security rules; never rely on client-side checks for authorization.",
     "CWE-200", "MASVS-PLATFORM-1"),
    (_r(r'react-native-config|react-native-dotenv|process\.env\.[A-Z][A-Z0-9_]+'),
     "Environment configuration in bundle", "low", "Configuration",
     "App reads environment configuration (react-native-config / process.env). These values "
     "are COMPILED INTO the JS bundle and are not secret — anyone can extract them.",
     "Never put real secrets in RN env config; resolve sensitive values server-side at runtime.",
     "CWE-312", "MASVS-STORAGE-1"),
    (_r(r'__DEV__'),
     "Development-mode flag (__DEV__) referenced", "info", "Configuration",
     "Code branches on __DEV__. Ensure debug-only logic (verbose logging, test endpoints, "
     "disabled checks) is stripped from release bundles.",
     "Confirm __DEV__-gated code is excluded from release; never ship debug endpoints.",
     "CWE-489", "MASVS-CODE-2"),
]

_ALL_RULES = _BRIDGE_RULES + _STORAGE_RULES + _NETWORK_RULES + _PLATFORM_RULES

# Known RN dependencies → capability label (for the metadata inventory).
_KNOWN_DEPS = {
    "axios": "HTTP client", "react-native-ssl-pinning": "Cert pinning",
    "@react-native-async-storage/async-storage": "Key-value storage",
    "react-native-mmkv": "Key-value storage", "realm": "Local DB",
    "react-native-sqlite-storage": "SQLite", "@nozbe/watermelondb": "Local DB",
    "react-native-encrypted-storage": "Secure storage",
    "expo-secure-store": "Secure storage", "react-native-keychain": "Secure storage",
    "@react-native-firebase/app": "Firebase", "firebase": "Firebase",
    "react-native-config": "Env config", "react-native-webview": "WebView",
}


# ════════════════════════════════════════════════════════════════════════════
# Finding builder (identical canonical shape to flutter_analyzer)
# ════════════════════════════════════════════════════════════════════════════
def _finding(title, severity, category, desc, *, file_path="", line=0, snippet="",
             rec="", cwe="", masvs="", owasp="M1") -> dict:
    return {
        "title": title, "severity": severity, "category": category,
        "description": desc, "recommendation": rec,
        "file_path": file_path, "line": line, "line_number": line,
        "snippet": snippet, "code_context": snippet,
        "cwe": cwe, "masvs": masvs, "owasp": owasp,
        "confidence": 80, "exploitability": 40, "validation_status": "detected",
        "source": SOURCE, "source_module": SOURCE, "detected_by": [SOURCE],
        "discovery_method": "react_native_analysis",
        "file_evidence": [make_file_evidence(file_path, line, snippet)] if file_path else [],
    }


def _line_of(text: str, pos: int) -> tuple[int, str]:
    line_no = text.count("\n", 0, pos) + 1
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    snippet = text[start:(end if end != -1 else len(text))].strip()[:_SNIPPET_CAP]
    # Minified bundles are one giant line; clamp the snippet around the match instead.
    if len(snippet) >= _SNIPPET_CAP and end - start > _SNIPPET_CAP:
        s = max(0, pos - 80)
        snippet = text[s:pos + 80].strip()[:_SNIPPET_CAP]
    return line_no, snippet


# ════════════════════════════════════════════════════════════════════════════
# Harvest
# ════════════════════════════════════════════════════════════════════════════
_SRC_EXTS = (".js", ".jsx", ".ts", ".tsx", ".cjs", ".mjs")


def _harvest(roots: list[str]) -> tuple[list[tuple[str, str, bool]], dict]:
    """Return (sources, artifacts). Each source = (rel_path, text, is_source_file)."""
    from .js_bundle_analyzer import find_js_bundles  # reuse bundle discovery (no dup)

    sources: list[tuple[str, str, bool]] = []
    artifacts = {"package_json": "", "metro": False, "babel": False, "hermes": False,
                 "bundles": [], "dirs_present": {}, "files_present": {}, "src_files": 0}
    seen: set = set()
    src_count = 0

    for root in roots or []:
        if not root or not os.path.exists(root):
            continue
        # Project structure metadata (canonical dirs/files).
        for d in PROJECT_DIRS:
            if os.path.isdir(os.path.join(root, d)):
                artifacts["dirs_present"][d] = True
        for fn in PROJECT_FILES:
            if os.path.isfile(os.path.join(root, fn)):
                artifacts["files_present"][fn] = True

        # JS / Hermes bundles (reused discovery).
        for bpath in find_js_bundles(root):
            rel = relativize_path(bpath, root)
            if rel in seen:
                continue
            seen.add(rel)
            try:
                with open(bpath, "rb") as f:
                    raw = f.read(_MAX_TEXT_BYTES)
                if raw[:8].find(b"Hermes") != -1 or b"\x00\x00\x00Hermes" in raw[:64]:
                    artifacts["hermes"] = True
                sources.append((rel, raw.decode("utf-8", "replace"), False))
                artifacts["bundles"].append(rel)
            except OSError:
                continue

        # Config + package.json + source files.
        for cur, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__MACOSX", "META-INF")]
            for fn in files:
                low = fn.lower()
                fpath = os.path.join(cur, fn)
                rel = relativize_path(fpath, root)
                try:
                    if low == "package.json" and not artifacts["package_json"]:
                        with open(fpath, "r", errors="replace") as f:
                            artifacts["package_json"] = f.read(_MAX_TEXT_BYTES)
                    elif low == "metro.config.js":
                        artifacts["metro"] = True
                    elif low == "babel.config.js":
                        artifacts["babel"] = True
                    elif low.endswith(_SRC_EXTS) and rel not in seen and src_count < _MAX_SRC_FILES:
                        with open(fpath, "r", errors="replace") as f:
                            sources.append((rel, f.read(_MAX_TEXT_BYTES), True))
                        seen.add(rel); src_count += 1
                except OSError:
                    continue
    artifacts["src_files"] = src_count
    return sources, artifacts


def _parse_package_json(text: str) -> list[str]:
    """Dependency names from package.json (dependencies + devDependencies)."""
    try:
        data = json.loads(text or "{}")
    except (ValueError, TypeError):
        return []
    deps: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            deps.update(block.keys())
    return sorted(deps)


# ════════════════════════════════════════════════════════════════════════════
# Public entry point
# ════════════════════════════════════════════════════════════════════════════
def analyze(roots, results: dict, *, platform: str = "android") -> dict:
    """Run React Native analysis over ``roots`` and fold canonical detections into the
    existing ``results`` streams. Additive and defensive — never raises into the
    caller. Returns the ``results["react_native"]`` metadata block."""
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
    bridges: list[str] = []
    n_find = n_secret = n_url = 0

    for rel, text, _is_source in sources:
        if not text:
            continue
        for rule in _ALL_RULES:
            rx, *meta = rule
            if len(meta) == 8:   # bridge rule: (kind, title, sev, cat, desc, rec, cwe, masvs)
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
                if cap and "{m}" in desc and cap not in bridges:
                    bridges.append(cap)
                findings.append(_finding(
                    title.format(m=cap) if "{m}" in title else title, sev, cat,
                    desc.format(m=cap) if "{m}" in desc else desc,
                    file_path=rel, line=line_no, snippet=snippet, rec=rec, cwe=cwe, masvs=masvs))
                n_find += 1

        # Secrets — REUSE the Secret Intelligence pipeline (no RN-specific detector).
        for s in scan_text_for_secrets(text, rel):
            k = f"{s.get('name')}:{s.get('value')}"
            if k not in seen_secret:
                seen_secret.add(k)
                s.setdefault("source", SOURCE)
                s.setdefault("detected_by", [SOURCE])
                secrets.append(s)
                n_secret += 1

        # Network — REUSE extract_urls → endpoints (Network Intelligence).
        for url in extract_urls(text):
            if url not in seen_url:
                seen_url.add(url)
                endpoints.append(url)
                n_url += 1

    deps = _parse_package_json(artifacts["package_json"])
    dep_caps = {d: _KNOWN_DEPS[d] for d in deps if d in _KNOWN_DEPS}

    project_structure = {d: bool(artifacts["dirs_present"].get(d, False)) for d in PROJECT_DIRS}
    key_files = {
        "package.json": bool(artifacts["files_present"].get("package.json") or artifacts["package_json"]),
        "metro.config.js": bool(artifacts["metro"] or artifacts["files_present"].get("metro.config.js")),
        "babel.config.js": bool(artifacts["babel"] or artifacts["files_present"].get("babel.config.js")),
    }
    meta = {
        "version": RN_VERSION,
        "detected": True,
        "platform": platform,
        "hermes": artifacts["hermes"],
        "bundles": artifacts["bundles"],
        "src_files": artifacts["src_files"],
        "dependencies": deps,
        "dependency_capabilities": dep_caps,
        "native_modules": bridges,
        "has_package_json": bool(artifacts["package_json"]),
        # Source Explorer preparation: canonical project dirs + key files (metadata only).
        "project_structure": project_structure,
        "key_files": key_files,
        "stats": {"findings": n_find, "secrets": n_secret, "endpoints": n_url},
    }
    results["react_native"] = meta
    log.info("[react_native] %s | findings=%d secrets=%d endpoints=%d bridges=%d deps=%d hermes=%s",
             platform, n_find, n_secret, n_url, len(bridges), len(deps), artifacts["hermes"])
    return meta
