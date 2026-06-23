"""
Cortex Evidence Scanner
Provides file+line+snippet attribution for all findings.
Fixes JWT detection, IP detection, and secret scanning regressions.
"""
import re
import os
import ipaddress
from functools import lru_cache
from pathlib import Path
from .path_utils import relativize_path


# ─── Performance bounds ───────────────────────────────────────────────────────
# These bound the secrets / IP / evidence walks so a large APK (tens of
# thousands of smali files) does not spend minutes slurping framework code.
_EV_MAX_FILES      = int(os.environ.get("CORTEX_EVIDENCE_MAX_FILES", "15000"))
_EV_MAX_FILE_BYTES = int(os.environ.get("CORTEX_EVIDENCE_MAX_FILE_BYTES", str(2 * 1024 * 1024)))
# Only skip Kotlin/androidx *standard-library* trees — these are known noise.
# GMS / Firebase / material stay IN because app secrets occasionally hide in
# embedded config of those SDKs.
# Narrowed to stdlib shells only. `androidx/*` stays IN — real app code ships
# under `androidx/work`, `androidx/security`, etc., and secrets have been found
# there. Must match the list in code_analyzer.py.
_EV_SKIP_PREFIXES  = (
    "smali/android/support/v4/",
    "smali/android/support/v7/",
    "smali/kotlin/",
    "smali/kotlinx/",
    "smali_classes2/kotlin/",
    "smali_classes2/kotlinx/",
    "smali_classes3/kotlin/",
    "smali_classes3/kotlinx/",
    "original/",
    "unknown/",
)


def _ev_should_skip_dir(rel_root: str) -> bool:
    rel = rel_root.replace("\\", "/").strip("/") + "/"
    return any(rel.startswith(p) for p in _EV_SKIP_PREFIXES)


# ─── Evidence Finding Model ───────────────────────────────────────────────────
def make_finding(
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    file_path: str = "",
    line: int = 0,
    snippet: str = "",
    code_context: str = "",
    confidence: int = 70,
    exploitability: int = 50,
    validation_status: str = "detected",
    **kwargs
) -> dict:
    """Standard finding model with full evidence."""
    f = {
        "title":             title,
        "severity":          severity,
        "category":          category,
        "description":       description,
        "recommendation":    recommendation,
        "file_path":         file_path,
        "line":              line,
        "snippet":           snippet,
        "code_context":      code_context,
        "confidence":        confidence,
        "exploitability":    exploitability,
        "validation_status": validation_status,
    }
    f.update(kwargs)
    return f


# ─── JWT Detection (fixed regex) ─────────────────────────────────────────────
JWT_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9\-_*]+\.[A-Za-z0-9\-_*]+\.[A-Za-z0-9\-_]+',
    re.MULTILINE
)

# ─── IP Detection ─────────────────────────────────────────────────────────────
IP_PATTERN = re.compile(
    r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])'
)

# IPs to skip — loopback, broadcast, obvious test values. Classification via
# `classify_ip()` (ipaddress stdlib) is authoritative; this list is a fast-path
# hint only. Note: the old `^\.` regex was a bug — it can never match a real
# IP string since the IP_PATTERN capture never starts with a dot.
IP_SKIP_PATTERNS = [
    re.compile(r'^0\.0\.0\.0$'),
    re.compile(r'^255\.'),
    re.compile(r'^127\.'),
]

# A snippet is treated as a version declaration only when it actually says so.
# Matches: `version = "1.2.3.4"`, `versionName "..."`, `"version": "..."`,
# `compileSdkVersion 34`, `implementation 'foo:bar:1.2.3.4'`, etc.
_VERSION_DECL_RE = re.compile(
    r'(?i)(?:^|[\s,;({\[])(?:'
    r'version[_\-]?name|version[_\-]?code|version|'
    r'compile[_\-]?sdk[_\-]?version|min[_\-]?sdk[_\-]?version|target[_\-]?sdk[_\-]?version'
    r')\s*(?:[:=]|\s+["\']|\s+\d)|'
    r'implementation\s+["\'][\w.\-]+:[\w.\-]+:|'
    r'["\']version["\']\s*:'
)

def classify_ip(ip_str: str) -> str | None:
    """Returns 'private', 'public', or None if invalid/skip.

    Rejects non-routable / reserved / documentation ranges that are pure noise
    in a decompiled app (link-local, reserved, TEST-NET, multicast, etc.).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast
            or ip.is_link_local or ip.is_reserved):
        return None
    # RFC 5737 / RFC 6598 documentation & shared-address ranges are not real
    # endpoints — they only appear as examples/placeholders in code.
    if any(ip in ipaddress.ip_network(net) for net in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10",
    )):
        return None
    if ip.is_private:
        return "private"
    return "public"


# Binary string-dump artifacts: a finding/IP attributed here is never a real
# source location (it's a printable-strings dump of a binary). We refuse to
# surface evidence from these — the decompiled Java/Kotlin source is the truth.
_BINARY_DUMP_SUFFIXES = (
    ".dex", ".so", ".dylib", ".arsc", ".odex", ".vdex", ".oat",
    ".dex.txt", ".so.txt", ".dylib.txt", ".arsc.txt",
)


def is_binary_dump_path(path: str) -> bool:
    p = (path or "").replace("\\", "/").lower()
    return p.endswith(_BINARY_DUMP_SUFFIXES)


@lru_cache(maxsize=256)
def _compile_pattern(pattern: str):
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


# ─── Core file scanner with evidence ─────────────────────────────────────────
def scan_file_for_patterns(
    fpath: str,
    content: str,
    patterns: list,
) -> list:
    """
    Scan a single file's content with a list of pattern dicts.
    Each pattern: {name, regex, severity, category, description, recommendation,
                   confidence, exploitability, check_entropy?, max_len?}
    Returns list of evidence findings.
    """
    lines   = content.splitlines()
    results = []
    seen    = set()

    for pat in patterns:
        try:
            compiled = _compile_pattern(pat["pattern"])
        except re.error:
            continue

        for match in compiled.finditer(content):
            value = match.group(0)
            if isinstance(match.groups(), tuple) and match.groups():
                value = match.group(1) if match.group(1) else value

            # Dedup
            key = f"{pat['name']}:{value[:40]}"
            if key in seen:
                continue
            seen.add(key)

            # Length cap
            max_len = pat.get("max_len", 300)
            if len(value) > max_len:
                continue

            # Skip pure long hex (crypto constants)
            if len(value) > 40 and re.fullmatch(r'[0-9a-fA-F]+', value):
                continue

            # Entropy check
            if pat.get("check_entropy"):
                entropy = _shannon_entropy(value)
                if entropy < 3.0:
                    continue

            # Get line number + context
            start = content[:match.start()].count("\n")
            line_no = start + 1
            snippet = lines[start].strip() if start < len(lines) else value
            ctx_start = max(0, start - 2)
            ctx_end   = min(len(lines), start + 3)
            code_ctx  = "\n".join(lines[ctx_start:ctx_end])

            results.append(make_finding(
                title             = pat["name"],
                severity          = pat["severity"],
                category          = pat["category"],
                description       = pat["description"],
                recommendation    = pat["recommendation"],
                file_path         = fpath,
                line              = line_no,
                snippet           = snippet,
                code_context      = code_ctx,
                confidence        = pat.get("confidence", 75),
                exploitability    = pat.get("exploitability", 50),
                validation_status = "detected",
                value             = value,
                source            = pat.get("source", "pattern"),
                name              = pat["name"],
                cwe               = pat.get("cwe", ""),
                masvs             = pat.get("masvs", ""),
                owasp             = pat.get("owasp", ""),
            ))

    return results


def scan_directory_for_secrets(
    base_dir: str,
    extra_dirs: list = None,
    extensions: list = None,
) -> list:
    """
    Walk base_dir (and extra_dirs) scanning text files for secrets.
    Returns deduplicated list of findings with full evidence.
    """
    if extensions is None:
        extensions = [
            ".java", ".kt", ".xml", ".json", ".properties", ".txt",
            ".js", ".ts", ".html", ".plist", ".yaml", ".yml",
            ".gradle", ".swift", ".m", ".h", ".cfg", ".config",
            ".env", ".strings", ".smali",
        ]

    dirs = []
    if extra_dirs:
        dirs.extend(d for d in extra_dirs if d and os.path.exists(d))
    if base_dir and os.path.exists(base_dir):
        dirs.append(base_dir)

    # Prioritise jadx (Java source) — secrets/JWTs are almost always found as
    # string literals in decompiled Java, not in smali. This guarantees we
    # never hit the file cap before scanning the highest-value tree.
    def _dir_priority(p: str) -> int:
        pl = p.lower().replace("\\", "/")
        if "/jadx" in pl:        return 0
        if "/apk_extract" in pl: return 1
        if "/apktool" in pl:     return 2
        return 3
    dirs.sort(key=_dir_priority)

    all_findings = []
    seen_global  = set()

    files_scanned = 0
    for scan_dir in dirs:
        if files_scanned >= _EV_MAX_FILES:
            break
        for root, subdirs, files in os.walk(scan_dir):
            rel_root = os.path.relpath(root, scan_dir)
            if rel_root != "." and _ev_should_skip_dir(rel_root):
                subdirs[:] = []
                continue
            for fname in files:
                if files_scanned >= _EV_MAX_FILES:
                    break
                if not any(fname.lower().endswith(ext) for ext in extensions):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > _EV_MAX_FILE_BYTES:
                        continue
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                    files_scanned += 1
                    rel_path = relativize_path(fpath, scan_dir)
                    file_findings = scan_file_for_patterns(rel_path, content, SECRET_PATTERNS_EVIDENCE)
                    for finding in file_findings:
                        key = f"{finding['name']}:{finding.get('value','')[:30]}"
                        if key not in seen_global:
                            seen_global.add(key)
                            all_findings.append(finding)
                except Exception:
                    continue

    return all_findings


def scan_directory_for_ips(
    base_dir: str,
    extra_dirs: list = None,
) -> list:
    """Extract and classify IP addresses from source files."""
    dirs = []
    if extra_dirs:
        dirs.extend(d for d in extra_dirs if d and os.path.exists(d))
    if base_dir and os.path.exists(base_dir):
        dirs.append(base_dir)

    # Prioritise jadx (Java) → apk_extract → apktool (smali last)
    def _dir_priority(p: str) -> int:
        pl = p.lower().replace("\\", "/")
        if "/jadx" in pl:        return 0
        if "/apk_extract" in pl: return 1
        if "/apktool" in pl:     return 2
        return 3
    dirs.sort(key=_dir_priority)

    results = []
    seen    = set()

    # Smali is a goldmine of false-positive IPs: hex literals, const-wide
    # opcodes, version numbers in comments. Legitimate production IPs live in
    # Java source, resources/strings.xml, or config JSON — never in smali.
    IP_EXTENSIONS = [
        ".java", ".kt", ".xml", ".json", ".properties",
        ".txt", ".gradle", ".js", ".yaml", ".yml", ".conf", ".cfg",
    ]
    files_scanned = 0
    for scan_dir in dirs:
        if files_scanned >= _EV_MAX_FILES:
            break
        for root, subdirs, files in os.walk(scan_dir):
            rel_root = os.path.relpath(root, scan_dir)
            if rel_root != "." and _ev_should_skip_dir(rel_root):
                subdirs[:] = []
                continue
            for fname in files:
                if files_scanned >= _EV_MAX_FILES:
                    break
                if not any(fname.lower().endswith(ext) for ext in IP_EXTENSIONS):
                    continue
                # Never scan binary string-dumps (classes.dex.txt, *.so.txt …):
                # they are a goldmine of emulator/version false-positive IPs and
                # can't be opened as real source.
                if is_binary_dump_path(fname):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > _EV_MAX_FILE_BYTES:
                        continue
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                    files_scanned += 1
                    lines = content.splitlines()
                    for match in IP_PATTERN.finditer(content):
                        ip_str = match.group(0)
                        if ip_str in seen:
                            continue
                        ip_type = classify_ip(ip_str)
                        if ip_type is None:
                            continue
                        line_no = content[:match.start()].count("\n") + 1
                        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ip_str
                        # Filter out smali-style literal lines that slip through
                        # (hex constants, const-wide opcodes, float literals).
                        snip_l = snippet.lower()
                        if any(tok in snip_l for tok in (
                            "const-wide", "const/high16", "const-wide/high16",
                            "const/4", "const/16", "const-string",
                            "0x", ".line ", ".prologue", ".source",
                        )):
                            continue
                        # Reject version-like matches (e.g. "1.2.3.4" inside a
                        # gradle dep). Old heuristic was a blanket "version"
                        # substring check which wrongly discarded any line
                        # mentioning an API version. Now only reject when the
                        # snippet is a clear version declaration.
                        if ip_type == "public" and _VERSION_DECL_RE.search(snippet):
                            continue
                        seen.add(ip_str)
                        rel_path = relativize_path(fpath, scan_dir)
                        results.append({
                            "ip":        ip_str,
                            "type":      ip_type,
                            "priority":  "high" if ip_type == "public" else "informational",
                            "severity":  "low" if ip_type == "public" else "info",
                            "confidence": 92,
                            "confidence_label": "High Confidence",
                            "validation_status": "validated",
                            "file_path": rel_path,
                            "line":      line_no,
                            "snippet":   snippet,
                            "file_evidence": [{"path": rel_path, "lines": [line_no], "snippet": snippet}],
                        })
                except Exception:
                    continue

    # Separate internal vs public
    return sorted(results, key=lambda x: (0 if x["type"] == "public" else 1, x["ip"]))


def scan_directory_for_jwts(base_dir: str, extra_dirs: list = None) -> list:
    """Find hardcoded JWT tokens with file+line evidence."""
    dirs = []
    if extra_dirs:
        dirs.extend(d for d in extra_dirs if d and os.path.exists(d))
    if base_dir and os.path.exists(base_dir):
        dirs.append(base_dir)

    # Prioritise high-value source trees (same as secrets scanner)
    def _dir_priority(p: str) -> int:
        pl = p.lower().replace("\\", "/")
        if "/jadx" in pl:        return 0
        if "/apk_extract" in pl: return 1
        if "/apktool" in pl:     return 2
        return 3
    dirs.sort(key=_dir_priority)

    JWT_EXTENSIONS = {
        ".java", ".kt", ".xml", ".json", ".properties",
        ".txt", ".gradle", ".smali", ".js", ".ts",
        ".swift", ".m", ".h", ".plist", ".yaml", ".yml",
    }

    results = []
    seen    = set()
    files_scanned = 0

    for scan_dir in dirs:
        if files_scanned >= _EV_MAX_FILES:
            break
        for root, subdirs, files in os.walk(scan_dir):
            rel_root = os.path.relpath(root, scan_dir)
            if rel_root != "." and _ev_should_skip_dir(rel_root):
                subdirs[:] = []
                continue
            for fname in files:
                if files_scanned >= _EV_MAX_FILES:
                    break
                if os.path.splitext(fname)[1].lower() not in JWT_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > _EV_MAX_FILE_BYTES:
                        continue
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                    files_scanned += 1
                    lines = content.splitlines()
                    for match in JWT_PATTERN.finditer(content):
                        value = match.group(0)
                        if value in seen:
                            continue
                        seen.add(value)
                        line_no = content[:match.start()].count("\n") + 1
                        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else value
                        ctx_start = max(0, line_no - 3)
                        ctx_end   = min(len(lines), line_no + 2)
                        code_ctx  = "\n".join(lines[ctx_start:ctx_end])
                        rel_path = relativize_path(fpath, scan_dir)
                        results.append({
                            "value":       value,
                            "file_path":   rel_path,
                            "line":        line_no,
                            "snippet":     snippet,
                            "code_context": code_ctx,
                            "file_evidence": [{"path": rel_path, "lines": [line_no], "snippet": snippet}],
                        })
                except Exception:
                    continue

    return results


# ─── Secret patterns with full evidence metadata ───────────────────────────
# NOTE: "JWT Token (Hardcoded)" is intentionally absent here.
# JWTs are detected by the dedicated scan_directory_for_jwts() scanner which
# produces results["jwts"]. Including them here would cause double-reporting in
# both the Secrets and JWTs sections of the UI.
SECRET_PATTERNS_EVIDENCE = [
    {
        "name":    "AWS Access Key ID",
        "pattern": r'AKIA[0-9A-Z]{16}',
        "severity":"critical",
        "category":"Cloud Credentials",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    95,
        "exploitability":90,
        "description":   "AWS Access Key ID found. Combined with secret key gives AWS API access.",
        "recommendation":"Rotate immediately. Use IAM roles instead of hardcoded credentials.",
    },
    {
        "name":    "Google API Key",
        "pattern": r'AIza[0-9A-Za-z\-_]{35}',
        "severity":"high",
        "category":"API Key",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    90,
        "exploitability":70,
        "description":   "Google API Key detected. May allow unauthorized API quota usage.",
        "recommendation":"Restrict key to specific APIs and fingerprints in Google Cloud Console.",
    },
    {
        "name":    "Firebase Realtime Database URL",
        "pattern": r'https://[a-z0-9\-]+\.firebaseio\.com',
        "severity":"medium",
        "category":"Cloud Config",
        "cwe":     "CWE-200",
        "masvs":   "MASVS-NETWORK-1",
        "owasp":   "M8",
        "confidence":    85,
        "exploitability":60,
        "description":   "Firebase DB URL found. Check for unauthenticated read/write access.",
        "recommendation":"Audit Firebase security rules. Test: curl https://<db>.firebaseio.com/.json",
        "poc":           "curl https://<project>.firebaseio.com/.json",
    },
    {
        "name":    "Stripe Live Secret Key",
        "pattern": r'sk_live_[0-9a-zA-Z]{24,}',
        "severity":"critical",
        "category":"Payment Credentials",
        "cwe":     "CWE-798",
        "confidence":    99,
        "exploitability":95,
        "check_entropy": True,
        "description":   "Stripe live secret key detected. Full payment API access.",
        "recommendation":"Rotate immediately in Stripe dashboard. Never embed payment keys in apps.",
    },
    {
        "name":    "Stripe Test Key",
        "pattern": r'sk_test_[0-9a-zA-Z]{24,}',
        "severity":"medium",
        "category":"Payment Credentials",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    95,
        "exploitability":40,
        "description":   "Stripe test secret key in production code.",
        "recommendation":"Remove test keys from production builds.",
    },
    {
        "name":    "GitHub Personal Access Token",
        "pattern": r'gh[pousr]_[A-Za-z0-9_]{36,}',
        "severity":"critical",
        "category":"Source Control",
        "cwe":     "CWE-798",
        "confidence":    95,
        "exploitability":90,
        "check_entropy": True,
        "description":   "GitHub PAT detected. May allow repository access or code exfiltration.",
        "recommendation":"Revoke immediately via GitHub Settings > Developer settings.",
    },
    {
        "name":    "Slack OAuth Token",
        "pattern": r'xox[baprs]-(?:[0-9]{10,}|[a-zA-Z0-9\-]{24,})',
        "severity":"high",
        "category":"Communication",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    90,
        "exploitability":70,
        "description":   "Slack OAuth token found. May allow reading messages or posting.",
        "recommendation":"Revoke token in Slack app settings.",
    },
    {
        "name":    "FCM Server Key",
        "pattern": r'AAAA[A-Za-z0-9\-_]{7}:[A-Za-z0-9\-_]{140}',
        "severity":"high",
        "category":"Push Notifications",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    95,
        "exploitability":75,
        "description":   "Firebase Cloud Messaging server key. Allows sending push to all users.",
        "recommendation":"Move to server-side only. Rotate in Firebase console.",
    },
    {
        "name":    "SendGrid API Key",
        "pattern": r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        "severity":"high",
        "category":"Email Service",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    95,
        "exploitability":70,
        "description":   "SendGrid API key found. Allows sending emails from your domain.",
        "recommendation":"Rotate in SendGrid dashboard. Move to server-side.",
    },
    {
        "name":    "Braze SDK Key",
        "pattern": r'(?i)(?:braze|appboy)[_\-]?(?:api[_\-]?)?key[\'"\s:=]+["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?',
        "severity":"medium",
        "category":"Marketing SDK",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    80,
        "exploitability":40,
        "description":   "Braze API key detected. Limited scope but confirms marketing SDK usage.",
        "recommendation":"Verify key has minimal permissions.",
    },
    {
        "name":    "Auth0 Client ID / Secret",
        "pattern": r'(?i)(?:auth0)[_\-]?(?:client[_\-]?(?:id|secret)|domain)[\'"\s:=]+["\']([a-zA-Z0-9_\-\.]{10,})["\']',
        "severity":"medium",
        "category":"Auth Config",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-AUTH-1",
        "owasp":   "M1",
        "confidence":    80,
        "exploitability":50,
        "description":   "Auth0 configuration value detected. Verify this is a public client ID only.",
        "recommendation":"Client secrets must never be in mobile apps. Client IDs are generally safe.",
    },
    {
        "name":    "PEM Private Key",
        "pattern": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        "severity":"critical",
        "category":"Cryptographic Key",
        "cwe":     "CWE-321",
        "confidence":    99,
        "exploitability":90,
        "description":   "PEM-encoded private key embedded in the app.",
        "recommendation":"Remove immediately. Revoke and reissue any associated certificates.",
    },
    {
        "name":    "Hardcoded Password",
        # Require = assignment (not : which is XML attribute), value min 8 chars,
        # not a UI hint/placeholder word. Uses negative lookahead to exclude common FP values.
        "pattern": r'(?i)(?:password|passwd|pwd)\s*=\s*["\'](?!(password|passwd|hint|placeholder|visible|invisible|textPassword|newPassword|confirm|change|enter|your|the|a |an |this|example|sample|test|dummy|none|null|empty|false|true|default|required|forgot|reset|update|new|old|current|repeat|retype|again)["\'\s])["\']?([^\s"\'\\]{8,})["\']',
        "severity":"high",
        "category":"Credentials",
        "cwe":     "CWE-798",
        "confidence":    70,
        "exploitability":65,
        "description":   "Hardcoded password string detected.",
        "recommendation":"Remove hardcoded credentials. Use secure storage or server-side auth.",
    },
    {
        "name":    "Hardcoded Credential Pair",
        # Catches credentials stored in map/dict entries where the key signals an
        # identity or secret (e.g. hashMap.put("shopuser", "!ns3csh0p"), Kotlin
        # mapOf("apiKey" to "…")). The value char-class excludes / : . and the
        # lookahead requires a digit or symbol, so URLs, user-agents, version
        # strings and plain display names ("John Doe", "Mozilla/5.0") are skipped.
        # No entropy gate — short real passwords (e.g. "!ns3csh0p", entropy 2.95)
        # fall below the 3.0 bar; the key-hint + value-shape constraints are the
        # filter instead. The key must not contain "/" (excludes error-code paths
        # like "auth/invalid-provider-id"), and the value must contain a digit or
        # a true symbol — NOT merely an underscore — so SCREAMING_SNAKE_CASE enum
        # constants (e.g. "INVALID_PROVIDER_ID") are not mistaken for secrets.
        "pattern": r'(?:\.put|Pair|mapOf|hashMapOf|\bput)\s*\(?\s*["\'][^"\'/]*?(?:user|login|account|cred|passw|pwd|secret|token|api[_\-]?key|auth)[^"\'/]*["\']\s*(?:,|\sto\s)\s*["\'](?=[^"\']*[0-9!@#$%^&*])([^"\'\s/:.,;]{6,40})["\']',
        "severity":"high",
        "category":"Credentials",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-STORAGE-2",
        "owasp":   "M1",
        "confidence":    75,
        "exploitability":70,
        "description":   "Hardcoded credential stored as a map/dictionary value under an identity or secret key.",
        "recommendation":"Remove the embedded credential. Authenticate server-side or use the Android Keystore / EncryptedSharedPreferences.",
    },
    {
        "name":    "Generic API Key",
        "pattern": r'(?i)(?:api[_\-]?key|api[_\-]?secret|client[_\-]?secret)[\'"\s:=]+["\']([a-zA-Z0-9\-_\.]{20,})["\']',
        "severity":"medium",
        "category":"API Key",
        "cwe":     "CWE-798",
        "confidence":    60,
        "exploitability":45,
        "check_entropy": True,
        "description":   "Generic API key or secret string detected.",
        "recommendation":"Validate if key is active. Consider server-side credential management.",
    },
    {
        "name":    "Basic Auth in URL",
        "pattern": r'https?://[^\s:@/]+:[^\s:@/]+@[^\s/]+',
        "severity":"high",
        "category":"Credentials",
        "cwe":     "CWE-522",
        "confidence":    90,
        "exploitability":80,
        "description":   "Credentials embedded directly in a URL.",
        "recommendation":"Remove credentials from URLs. Use Authorization headers.",
    },
    {
        "name":    "GCP Service Account Key",
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity":"critical",
        "category":"Cloud Credentials",
        "cwe":     "CWE-798",
        "confidence":    98,
        "exploitability":95,
        "description":   "GCP service account key embedded in app.",
        "recommendation":"Remove immediately. Revoke in GCP IAM console.",
    },
    {
        "name":    "Mixpanel Token",
        "pattern": r'(?i)mixpanel[_\-]?token[\'"\s:=]+["\']([a-f0-9]{32})["\']',
        "severity":"low",
        "category":"Analytics",
        "cwe":     "CWE-200",
        "masvs":   "MASVS-STORAGE-2",
        "owasp":   "M8",
        "confidence":    85,
        "exploitability":20,
        "description":   "Mixpanel project token found. Low risk — client-side token.",
        "recommendation":"Expected in client apps. Verify token scoping in Mixpanel settings.",
    },
    {
        "name":    "Crashlytics Mapping File ID",
        "pattern": r'(?i)crashlytics[_\-]?mapping[_\-]?file[_\-]?id[\'"\s:=]+["\']([a-f0-9\-]{30,})["\']',
        "severity":"info",
        "category":"Crash Reporting",
        "cwe":     "CWE-200",
        "masvs":   "MASVS-CODE-4",
        "owasp":   "M8",
        "confidence":    95,
        "exploitability":5,
        "description":   "Crashlytics mapping file ID — confirms crash reporting integration.",
        "recommendation":"Informational only. No action required.",
    },
    # ── Newly added patterns ─────────────────────────────────────────────────
    {
        "name":    "Slack Webhook URL",
        "pattern": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
        "severity":"high",
        "category":"Communication",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    97,
        "exploitability":70,
        "description":   "Slack Incoming Webhook URL. Allows posting arbitrary messages to a Slack channel without authentication.",
        "recommendation":"Revoke in Slack app settings. Move webhook delivery to server-side.",
    },
    {
        "name":    "Twilio Account SID",
        "pattern": r'AC[a-f0-9]{32}',
        "severity":"high",
        "category":"Telephony",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    85,
        "exploitability":65,
        "check_entropy": True,
        "description":   "Twilio Account SID. Combined with Auth Token enables SMS sending, call initiation, and account enumeration.",
        "recommendation":"Rotate credentials in Twilio console. Move to server-side.",
    },
    {
        "name":    "Twilio Auth Token",
        "pattern": r'(?i)twilio[_\-]?auth[_\-]?token[\'"\s:=]+["\']([a-f0-9]{32})["\']',
        "severity":"critical",
        "category":"Telephony",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    93,
        "exploitability":85,
        "description":   "Twilio Auth Token detected. Full account takeover risk — can send SMS, make calls, and enumerate account data.",
        "recommendation":"Rotate immediately in Twilio console. Never embed in mobile apps.",
    },
    {
        "name":    "OpenAI API Key",
        "pattern": r'sk-[A-Za-z0-9]{48}',
        "severity":"critical",
        "category":"AI Service",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    90,
        "exploitability":85,
        "check_entropy": True,
        "description":   "OpenAI API key detected. Allows model invocations at your expense and potential data exfiltration via prompts.",
        "recommendation":"Rotate immediately at platform.openai.com. Add usage limits and IP restrictions.",
    },
    {
        "name":    "Anthropic API Key",
        "pattern": r'sk-ant-[A-Za-z0-9\-_]{40,}',
        "severity":"critical",
        "category":"AI Service",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    95,
        "exploitability":85,
        "description":   "Anthropic API key detected. Enables Claude model access at your billing cost.",
        "recommendation":"Rotate immediately in Anthropic console.",
    },
    {
        "name":    "HuggingFace API Token",
        "pattern": r'hf_[A-Za-z0-9]{34,}',
        "severity":"high",
        "category":"AI Service",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    93,
        "exploitability":70,
        "description":   "HuggingFace API token. Allows model inference, dataset access, and private repo access.",
        "recommendation":"Rotate in HuggingFace account settings.",
    },
    {
        "name":    "Mailgun API Key",
        "pattern": r'key-[a-f0-9]{32}',
        "severity":"high",
        "category":"Email Service",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    85,
        "exploitability":70,
        "description":   "Mailgun API key. Allows sending emails, reading domain settings, and enumerating mailing lists.",
        "recommendation":"Rotate in Mailgun dashboard. Restrict to server-side only.",
    },
    {
        "name":    "Mailchimp API Key",
        "pattern": r'[a-f0-9]{32}-us[0-9]{1,2}',
        "severity":"high",
        "category":"Email Marketing",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    90,
        "exploitability":65,
        "description":   "Mailchimp API key with datacenter suffix. Allows reading/sending campaigns and accessing subscriber lists.",
        "recommendation":"Rotate in Mailchimp account settings.",
    },
    {
        "name":    "Shopify Access Token",
        "pattern": r'shpat_[a-fA-F0-9]{32}',
        "severity":"critical",
        "category":"E-Commerce",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    97,
        "exploitability":90,
        "description":   "Shopify Admin API access token. Grants full store management — orders, customers, products.",
        "recommendation":"Rotate in Shopify Partners dashboard. Use scoped tokens.",
    },
    {
        "name":    "Shopify Storefront Token",
        "pattern": r'shpss_[a-fA-F0-9]{32}',
        "severity":"medium",
        "category":"E-Commerce",
        "cwe":     "CWE-200",
        "masvs":   "MASVS-STORAGE-2",
        "owasp":   "M8",
        "confidence":    95,
        "exploitability":40,
        "description":   "Shopify Storefront API token. Limited public read access but confirms store details.",
        "recommendation":"Review storefront token scopes. Acceptable for client apps if read-only.",
    },
    {
        "name":    "Cloudflare API Token",
        "pattern": r'(?i)cloudflare[_\-]?(?:api[_\-]?)?token[\'"\s:=]+["\']([A-Za-z0-9\-_]{40,})["\']',
        "severity":"critical",
        "category":"CDN / DNS",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    85,
        "exploitability":90,
        "description":   "Cloudflare API token. Can modify DNS records, firewall rules, and SSL certificates.",
        "recommendation":"Rotate in Cloudflare dashboard. Scope tokens to minimum required zones.",
    },
    {
        "name":    "Cloudflare Global API Key",
        "pattern": r'(?i)cloudflare[_\-]?(?:global[_\-]?)?(?:api[_\-]?)?key[\'"\s:=]+["\']([a-f0-9]{37})["\']',
        "severity":"critical",
        "category":"CDN / DNS",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    88,
        "exploitability":95,
        "description":   "Cloudflare Global API Key — full account access. More dangerous than a scoped token.",
        "recommendation":"Rotate immediately. Replace with scoped API tokens.",
    },
    {
        "name":    "PagerDuty API Key",
        "pattern": r'(?i)pagerduty[_\-]?(?:api[_\-]?)?(?:key|token)[\'"\s:=]+["\']([A-Za-z0-9_\-+]{20,})["\']',
        "severity":"high",
        "category":"Incident Management",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    80,
        "exploitability":65,
        "description":   "PagerDuty API key. Allows incident manipulation and alert suppression — a risk to on-call operations.",
        "recommendation":"Rotate in PagerDuty account settings.",
    },
    {
        "name":    "npm Publish Token",
        "pattern": r'npm_[A-Za-z0-9]{36}',
        "severity":"critical",
        "category":"Supply Chain",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CODE-2",
        "owasp":   "M8",
        "confidence":    95,
        "exploitability":90,
        "description":   "npm publish token. Allows publishing packages to npm — direct supply chain attack vector.",
        "recommendation":"Rotate immediately via npm account settings. Audit recent publishes.",
    },
    {
        "name":    "Docker Hub Token",
        "pattern": r'dckr_pat_[A-Za-z0-9_\-]{28,}',
        "severity":"high",
        "category":"Container Registry",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CODE-2",
        "owasp":   "M8",
        "confidence":    95,
        "exploitability":75,
        "description":   "Docker Hub personal access token. Can push malicious images to public/private repositories.",
        "recommendation":"Rotate in Docker Hub account settings.",
    },
    {
        "name":    "Linear API Key",
        "pattern": r'lin_api_[A-Za-z0-9]{40}',
        "severity":"medium",
        "category":"Project Management",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    95,
        "exploitability":45,
        "description":   "Linear API key. Allows reading issues, projects, and team information.",
        "recommendation":"Rotate in Linear account settings. Do not embed in client apps.",
    },
    {
        "name":    "Notion Integration Token",
        "pattern": r'secret_[A-Za-z0-9]{43}',
        "severity":"medium",
        "category":"Productivity",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    85,
        "exploitability":50,
        "description":   "Notion integration token. Access to connected pages and databases.",
        "recommendation":"Revoke in Notion integration settings.",
    },
    {
        "name":    "Zoom JWT Token / App Credential",
        "pattern": r'(?i)zoom[_\-]?(?:jwt|api[_\-]?(?:key|secret))[\'"\s:=]+["\']([A-Za-z0-9_\-\.]{20,})["\']',
        "severity":"high",
        "category":"Video Conferencing",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-AUTH-1",
        "owasp":   "M1",
        "confidence":    80,
        "exploitability":65,
        "description":   "Zoom API credential. Allows creating meetings, accessing recordings, and impersonating users.",
        "recommendation":"Rotate in Zoom marketplace app settings.",
    },
    {
        "name":    "Databricks Token",
        "pattern": r'dapi[a-f0-9]{32}',
        "severity":"critical",
        "category":"Data Platform",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    95,
        "exploitability":85,
        "description":   "Databricks personal access token. Full workspace access — clusters, notebooks, and job execution.",
        "recommendation":"Rotate in Databricks user settings.",
    },
    {
        "name":    "Sentry Auth Token",
        "pattern": r'(?i)sentry[_\-]?(?:auth[_\-]?)?token[\'"\s:=]+["\']([a-f0-9]{64})["\']',
        "severity":"high",
        "category":"Error Monitoring",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    85,
        "exploitability":60,
        "description":   "Sentry auth token. Access to error events, source maps, and project configuration.",
        "recommendation":"Rotate in Sentry account settings.",
    },
    {
        "name":    "Intercom Access Token",
        "pattern": r'(?i)intercom[_\-]?(?:access[_\-]?)?token[\'"\s:=]+["\']([A-Za-z0-9_\-]{30,})["\']',
        "severity":"high",
        "category":"Customer Support",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    80,
        "exploitability":65,
        "description":   "Intercom access token. Exposes customer conversations, contact data, and support tickets.",
        "recommendation":"Rotate in Intercom developer settings.",
    },
    {
        "name":    "Amplitude API Key",
        "pattern": r'(?i)amplitude[_\-]?(?:api[_\-]?)?key[\'"\s:=]+["\']([a-f0-9]{32})["\']',
        "severity":"low",
        "category":"Analytics",
        "cwe":     "CWE-200",
        "masvs":   "MASVS-STORAGE-2",
        "owasp":   "M8",
        "confidence":    85,
        "exploitability":20,
        "description":   "Amplitude analytics API key. Generally a client-side key with limited risk.",
        "recommendation":"Verify this is the project API key (public) and not the secret key.",
    },
    {
        "name":    "Square Access Token",
        "pattern": r'(?:EAAA|sq0atp-)[A-Za-z0-9\-_]{22,}',
        "severity":"critical",
        "category":"Payment Credentials",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    90,
        "exploitability":90,
        "description":   "Square access token. Full payment processing and customer data access.",
        "recommendation":"Rotate immediately in Square Developer portal.",
    },
    {
        "name":    "Okta API Token",
        "pattern": r'(?i)(?:okta[_\-]?(?:api[_\-]?)?(?:token|key|secret)|ssws\s+)(00[A-Za-z0-9\-_]{38,42})',
        "severity":"critical",
        "category":"Identity Provider",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-AUTH-1",
        "owasp":   "M1",
        "confidence":    80,
        "exploitability":90,
        "check_entropy": True,
        "description":   "Possible Okta API token. Full identity management access — user provisioning, SSO configuration.",
        "recommendation":"Rotate in Okta admin console.",
    },
    {
        "name":    "Supabase Service Role Key",
        # Full Supabase HS256 header prefix — identifies service role JWTs specifically
        "pattern": r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
        "severity":"high",
        "category":"Database / Backend",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-AUTH-1",
        "owasp":   "M1",
        "confidence":    70,
        "exploitability":75,
        "description":   "JWT token matching Supabase service role key pattern. Bypasses Row Level Security — full database access.",
        "recommendation":"Never embed service role keys in client apps. Use anon key for client-side.",
    },
    {
        "name":    "Mapbox Access Token",
        "pattern": r'pk\.[A-Za-z0-9\-_]{60,}',
        "severity":"low",
        "category":"Maps / Location",
        "cwe":     "CWE-200",
        "masvs":   "MASVS-STORAGE-2",
        "owasp":   "M8",
        "confidence":    88,
        "exploitability":20,
        "description":   "Mapbox public access token. Can be abused for quota exhaustion if unscoped.",
        "recommendation":"Restrict token to specific URLs and token scopes in Mapbox account.",
    },
    {
        "name":    "Algolia Admin API Key",
        "pattern": r'(?i)algolia[_\-]?admin[_\-]?(?:api[_\-]?)?key[\'"\s:=]+["\']([A-Za-z0-9]{32})["\']',
        "severity":"high",
        "category":"Search Service",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    85,
        "exploitability":70,
        "description":   "Algolia admin API key. Full index management — can delete indices or expose all indexed data.",
        "recommendation":"Use Search-Only API keys in client apps. Rotate admin key.",
    },
    {
        "name":    "Pusher App Key / Secret",
        "pattern": r'(?i)pusher[_\-]?(?:app[_\-]?)?secret[\'"\s:=]+["\']([a-f0-9]{20,})["\']',
        "severity":"high",
        "category":"Real-time Messaging",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    80,
        "exploitability":65,
        "description":   "Pusher app secret. Allows publishing events to any channel and authenticating users.",
        "recommendation":"Move to server-side. Rotate in Pusher dashboard.",
    },
    {
        "name":    "Apple Push Notification Key",
        "pattern": r'-----BEGIN PRIVATE KEY-----[\s\S]{50,}-----END PRIVATE KEY-----',
        "severity":"critical",
        "category":"Push Notifications",
        "cwe":     "CWE-321",
        "masvs":   "MASVS-CRYPTO-1",
        "owasp":   "M10",
        "confidence":    92,
        "exploitability":85,
        "description":   "PKCS#8 private key embedded. If an APNs p8 key, allows sending push notifications to all app users.",
        "recommendation":"Remove immediately. Revoke key in Apple Developer portal.",
    },
    {
        "name":    "Azure Storage Account Key",
        "pattern": r'(?i)(?:azure|storage)[_\-]?(?:account[_\-]?)?key[\'"\s:=]+["\']([A-Za-z0-9/+=]{86,88}==)["\']',
        "severity":"critical",
        "category":"Cloud Credentials",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    88,
        "exploitability":90,
        "description":   "Azure Storage Account key. Full read/write/delete access to all blobs and queues.",
        "recommendation":"Rotate in Azure portal. Use managed identities instead.",
    },
    {
        "name":    "AWS Secret Access Key",
        "pattern": r'(?i)(?:aws[_\-]?secret[_\-]?access[_\-]?key|aws[_\-]?secret)[\'"\s:=]+["\']([A-Za-z0-9/+=]{40})["\']',
        "severity":"critical",
        "category":"Cloud Credentials",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    88,
        "exploitability":92,
        "check_entropy": True,
        "description":   "AWS Secret Access Key. Combined with an Access Key ID gives programmatic AWS API access.",
        "recommendation":"Rotate immediately. Use IAM roles and instance profiles.",
    },
    {
        "name":    "Facebook App Secret",
        "pattern": r'(?i)(?:facebook|fb)[_\-]?(?:app[_\-]?)?secret[\'"\s:=]+["\']([a-f0-9]{32})["\']',
        "severity":"critical",
        "category":"Social",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-CRYPTO-2",
        "owasp":   "M1",
        "confidence":    88,
        "exploitability":85,
        "description":   "Facebook App Secret found. Allows server-side API calls on behalf of your app including user data access.",
        "recommendation":"Rotate in Meta Developer portal. Never embed app secrets in client apps.",
    },
    {
        "name":    "Hardcoded Username",
        # Require explicit credential-context key (not bare "user"), = assignment only,
        # value must look like an actual identifier (not a UI label word).
        "pattern": r'(?i)(?:username|user_name|login_user|default_user|admin_user|hardcoded_user)\s*=\s*["\'](?!(user|admin|username|login|name|enter|your|example|test|dummy|null|none|default|anonymous|guest|placeholder)["\'\s])([^\s"\'\\]{4,})["\']',
        "severity":"low",
        "category":"Credentials",
        "cwe":     "CWE-798",
        "masvs":   "MASVS-AUTH-1",
        "owasp":   "M1",
        "confidence":    55,
        "exploitability":30,
        "description":   "Possible hardcoded username string detected.",
        "recommendation":"Remove hardcoded credentials from source. Use configuration or secure storage.",
    },
]


# ─── URL extraction ────────────────────────────────────────────────────────────
URL_PATTERN = re.compile(
    r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
    re.IGNORECASE
)

# XML namespace / schema / spec hosts. These are URIs used as identifiers in
# XML, manifests and licenses — never network endpoints. Matched as substrings.
NAMESPACE_URL_HOSTS = (
    "schemas.android.com", "schemas.microsoft.com", "schemas.openxmlformats.org",
    "schemas.xmlsoap.org", "www.w3.org", "/www.w3.org", "xmlns",
    "ns.adobe.com", "java.sun.com", "xml.org", "purl.org", "iana.org",
    "apache.org/licenses", "apache.org/xml", "specs.openid.net",
    "openid.net/specs", "docbook.org", "relaxng.org", "oasis-open.org",
    "w3.org/2000", "w3.org/2001", "w3.org/1999", "w3.org/XML",
)

URL_SKIP = {
    "example.com", "test.com", "localhost",
    "developer.android.com", "play.google.com/store",
    *NAMESPACE_URL_HOSTS,
}


def is_namespace_url(url: str) -> bool:
    """True for XML-namespace / schema / spec URIs that are not endpoints."""
    u = (url or "").lower()
    return any(host in u for host in NAMESPACE_URL_HOSTS)


def extract_urls(text: str) -> list:
    urls = set()
    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip("\"',;)")
        if any(skip in url for skip in URL_SKIP):
            continue
        if len(url) > 20:
            urls.add(url)
    return sorted(list(urls))


# ─── Shannon entropy ──────────────────────────────────────────────────────────
def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    import math
    return -sum((count / length) * math.log2(count / length) for count in freq.values())
