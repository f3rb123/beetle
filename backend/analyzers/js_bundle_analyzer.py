"""
JavaScript bundle scanner — React Native (index.*.bundle / main.jsbundle),
Cordova / Capacitor / Ionic (www/), and generic minified JS/TS shipped in APKs
and IPAs.

These files commonly hold the real application logic and most secrets, yet
MobSF and similar tools rarely touch them. This analyzer:
  • finds bundle files under a scan root
  • scans them for hardcoded URLs, API keys, Firebase/S3 endpoints, JWTs
  • flags dangerous sinks (eval, Function ctor, dangerouslySetInnerHTML)
  • records framework detection (React Native / Cordova / Capacitor / Ionic)
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .common import normalize_severity

# ── Detection patterns ───────────────────────────────────────────────────────
_BUNDLE_NAME_RE = re.compile(
    r"(?:^|/)(?:index\.(?:android|ios)\.bundle|main\.jsbundle|"
    r"app\.bundle\.js|bundle\.js|index\.bundle|main-es\d+\.js)$",
    re.IGNORECASE,
)

_JS_DANGEROUS_RULES = [
    (r"\beval\s*\(",
     "high", "CWE-95", "MASVS-CODE-1",
     "JavaScript eval() Usage",
     "eval() executes arbitrary strings as code. If any user input reaches eval, RCE in the JS VM is possible.",
     "Remove eval. Parse JSON with JSON.parse. Use Function constructor only with trusted static code."),

    (r"new\s+Function\s*\(",
     "high", "CWE-95", "MASVS-CODE-1",
     "JavaScript Function Constructor Usage",
     "new Function(...) compiles runtime strings to code — same risk profile as eval.",
     "Avoid dynamic code generation. Use static functions and data-driven dispatch."),

    (r"dangerouslySetInnerHTML",
     "medium", "CWE-79", "MASVS-PLATFORM-2",
     "React dangerouslySetInnerHTML Usage",
     "dangerouslySetInnerHTML bypasses React's XSS protection. Unsanitized input leads to DOM XSS inside WebViews.",
     "Sanitize HTML with DOMPurify before injecting, or render React components instead of raw HTML."),

    (r"document\.write\s*\(",
     "medium", "CWE-79", "MASVS-PLATFORM-2",
     "document.write() Usage",
     "document.write with dynamic content is a classic XSS sink.",
     "Replace with safe DOM APIs (textContent, createElement)."),

    (r"XMLHttpRequest\s*\([^)]*\)|fetch\(['\"]http://",
     "medium", "CWE-319", "MASVS-NETWORK-1",
     "Cleartext HTTP Request in JS Bundle",
     "Bundle contains a cleartext http:// endpoint — data is transmitted unencrypted.",
     "Use https:// endpoints. Verify network security config permits no cleartext."),

    (r"window\.(?:localStorage|sessionStorage)\.setItem\([^,]*(?:password|token|secret)",
     "high", "CWE-312", "MASVS-STORAGE-1",
     "Sensitive Data Stored In Web Storage",
     "localStorage/sessionStorage is readable by any script in the same origin. Storing tokens there enables XSS-based account takeover.",
     "Store tokens in HTTP-only cookies or native secure storage (Keychain / EncryptedSharedPreferences)."),
]

_JS_SECRET_RULES = [
    (r"AIza[0-9A-Za-z\-_]{35}",
     "high", "Google API Key"),
    (r"AKIA[0-9A-Z]{16}",
     "critical", "AWS Access Key ID"),
    (r"sk_live_[0-9a-zA-Z]{24,}",
     "critical", "Stripe Live Secret Key"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,48}",
     "high", "Slack Token"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     "medium", "JSON Web Token (JWT)"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "critical", "Private Key Material"),
    (r"ghp_[A-Za-z0-9]{36}",
     "critical", "GitHub Personal Access Token"),
    (r"(?:firebaseio\.com|firebase\.googleapis\.com)",
     "info", "Firebase Endpoint Reference"),
    (r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com",
     "info", "S3 Bucket Endpoint"),
]

_COMPILED_DANGEROUS = None
_COMPILED_SECRETS   = None


def _compile_once():
    global _COMPILED_DANGEROUS, _COMPILED_SECRETS
    if _COMPILED_DANGEROUS is None:
        _COMPILED_DANGEROUS = [
            (re.compile(p, re.IGNORECASE), *rest) for p, *rest in _JS_DANGEROUS_RULES
        ]
    if _COMPILED_SECRETS is None:
        _COMPILED_SECRETS = [(re.compile(p), sev, label) for p, sev, label in _JS_SECRET_RULES]
    return _COMPILED_DANGEROUS, _COMPILED_SECRETS


def find_js_bundles(root: str, max_files: int = 200) -> list:
    """Return absolute paths of likely JS bundles under `root`."""
    hits = []
    root_p = Path(root)
    if not root_p.exists():
        return hits
    for dirpath, dirnames, filenames in os.walk(root_p):
        # Skip vendor/noise
        dirnames[:] = [d for d in dirnames if d not in (
            "__MACOSX", "META-INF", ".git", "node_modules",
        )]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if _BUNDLE_NAME_RE.search(full.replace("\\", "/")):
                hits.append(full)
            elif name.endswith(".js") and "assets" in dirpath.replace("\\", "/"):
                # Cordova / Capacitor / Ionic shipped JS
                try:
                    if os.path.getsize(full) > 5_000:
                        hits.append(full)
                except OSError:
                    pass
            if len(hits) >= max_files:
                return hits
    return hits


def detect_framework(bundle_paths: list) -> dict:
    """Return {type, confidence, evidence} based on bundle contents/names."""
    framework = {"type": None, "confidence": "low", "evidence": []}
    for p in bundle_paths[:10]:
        lp = p.replace("\\", "/").lower()
        if "index.android.bundle" in lp or "main.jsbundle" in lp:
            framework = {"type": "React Native", "confidence": "high", "evidence": [p]}
            break
    if framework["type"]:
        return framework
    for p in bundle_paths[:20]:
        try:
            head = Path(p).read_bytes()[:65536].decode("utf-8", errors="ignore")
        except Exception:
            continue
        if "capacitor" in head.lower():
            return {"type": "Capacitor", "confidence": "medium", "evidence": [p]}
        if "cordova" in head.lower():
            return {"type": "Cordova", "confidence": "medium", "evidence": [p]}
        if "__REACT_DEVTOOLS_GLOBAL_HOOK__" in head or '"react-native"' in head:
            return {"type": "React Native", "confidence": "medium", "evidence": [p]}
    return framework


def analyze_js_bundles(root: str, max_file_bytes: int = 15_000_000) -> dict:
    """
    Scan all JS bundles under `root` for dangerous APIs and secrets.
    Returns {framework, findings, secrets, bundles}.
    """
    bundles = find_js_bundles(root)
    dangerous, secrets_rules = _compile_once()
    findings = []
    secrets = []

    for bp in bundles:
        try:
            size = os.path.getsize(bp)
        except OSError:
            continue
        if size > max_file_bytes:
            continue
        try:
            with open(bp, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        rel = os.path.relpath(bp, root)

        # Dangerous APIs
        for regex, sev, cwe, masvs, title, desc, rec in dangerous:
            for m in regex.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                findings.append({
                    "rule_id":        f"js_{title.lower().replace(' ', '_')[:40]}",
                    "title":          title,
                    "severity":       normalize_severity(sev),
                    "source":         "js_bundle",
                    "category":       "JavaScript",
                    "cwe":            cwe,
                    "masvs":          masvs,
                    "file_path":      rel,
                    "line_number":    line_no,
                    "snippet":        content[max(0, m.start() - 40): m.end() + 40].strip()[:240],
                    "description":    desc,
                    "recommendation": rec,
                    "confidence":     "high",
                })

        # Secrets
        for regex, sev, label in secrets_rules:
            for m in regex.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                secrets.append({
                    "type":       label,
                    "severity":   normalize_severity(sev),
                    "file_path":  rel,
                    "line":       line_no,
                    "match":      m.group(0)[:120],
                    "source":     "js_bundle",
                })

    framework = detect_framework(bundles)
    return {
        "framework": framework,
        "findings":  findings,
        "secrets":   secrets,
        "bundles":   [os.path.relpath(b, root) for b in bundles],
    }
