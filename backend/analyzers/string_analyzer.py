import re
import os
import ipaddress
from .path_utils import normalize_relative_path
from .source_corpus import SourceCorpus, printable_text
from . import regex_prefilter


def _is_real_ip(val: str) -> bool:
    """Accept only routable IPv4 literals — reject version numbers, reserved,
    link-local, documentation and loopback ranges (the bulk of IP-shaped noise).
    """
    try:
        ip = ipaddress.ip_address(val)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast
            or ip.is_link_local or ip.is_reserved):
        return False
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10"):
        if ip in ipaddress.ip_network(net):
            return False
    return True


def _is_namespace_url(val: str) -> bool:
    u = (val or "").lower()
    return any(h in u for h in (
        "schemas.android.com", "schemas.microsoft.com", "schemas.xmlsoap.org",
        "schemas.openxmlformats.org", "www.w3.org", "/w3.org", "xmlns",
        "ns.adobe.com", "java.sun.com", "xml.org", "purl.org",
        "apache.org/licenses", "apache.org/xml", "openid.net/specs",
        "specs.openid.net", "oasis-open.org", "relaxng.org", "docbook.org",
    ))


# Category -> value validator. A match is dropped when the validator returns False.
_VALUE_VALIDATORS = {
    "Hardcoded IP Address": _is_real_ip,
    "Hidden URL / API Endpoint": lambda v: not _is_namespace_url(v),
}

# ─── String Categories ────────────────────────────────────────────────────────
STRING_PATTERNS = [
    {
        "category":    "Hardcoded IP Address",
        "pattern":     r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        "severity":    "low",
        "description": "Hardcoded IP address found. May indicate dev/test server endpoints left in production.",
        "exclude":     [r'^0\.0\.0\.0$', r'^127\.0\.0\.1$', r'^255\.255\.255\.\d+$'],
    },
    {
        "category":    "Email Address",
        "pattern":     r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
        "severity":    "info",
        "description": "Email address embedded in app. May expose developer or internal contact details.",
        "exclude":     [r'example\.com$', r'test\.com$', r'@android\.com$', r'@google\.com$'],
    },
    {
        "category":    "Weak Crypto — MD5",
        "pattern":     r'\bMD5\b|MessageDigest\.getInstance\("MD5"\)',
        "severity":    "high",
        "description": "MD5 usage detected in code. Cryptographically broken.",
    },
    {
        "category":    "Weak Crypto — SHA1",
        "pattern":     r'\bSHA-1\b|\bSHA1\b|MessageDigest\.getInstance\("SHA-1"\)',
        "severity":    "medium",
        "description": "SHA-1 usage detected. Deprecated for security use.",
    },
    {
        "category":    "Weak Cipher — DES",
        "pattern":     r'Cipher\.getInstance\("DES|DESede|TripleDES',
        "severity":    "high",
        "description": "DES or 3DES cipher usage detected.",
    },
    {
        "category":    "Weak Cipher — ECB Mode",
        "pattern":     r'Cipher\.getInstance\("[^"]+/ECB/',
        "severity":    "high",
        "description": "ECB cipher mode detected — deterministic, pattern-leaking.",
    },
    {
        "category":    "Debug/Logging — Log.d/e/i/v/w",
        "pattern":     r'\bLog\.(d|e|i|v|w|wtf)\s*\(',
        "severity":    "low",
        "description": "Android logging calls detected. May log sensitive data in production.",
    },
    {
        "category":    "SQLite Query",
        "pattern":     r'(?i)SELECT.{1,50}FROM\s+\w+|rawQuery\s*\(|execSQL\s*\(',
        "severity":    "info",
        "description": "SQLite query patterns detected. Review for SQL injection via user input.",
    },
    {
        "category":    "Hidden URL / API Endpoint",
        "pattern":     r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,}',
        "severity":    "info",
        "description": "URL found in code. May reveal API endpoints, internal services, or third-party integrations.",
        "exclude":     [r'schemas\.android\.com', r'www\.w3\.org', r'xmlns', r'example\.com'],
    },
    {
        "category":    "Base64 Encoded String (Potential Secret)",
        "pattern":     r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']',
        "severity":    "low",
        "description": "Long Base64-encoded string found. May be an obfuscated secret, key, or certificate.",
    },
    {
        "category":    "World-Readable / World-Writable File Mode",
        "pattern":     r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|openFileOutput.*,\s*[12]\b',
        "severity":    "high",
        "description": "World-readable or world-writable file mode usage detected.",
    },
    {
        "category":    "External Storage Access",
        "pattern":     r'getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir',
        "severity":    "medium",
        "description": "External storage access detected. Data stored here is accessible to any app.",
    },
    {
        "category":    "Dynamic Code Loading",
        "pattern":     r'DexClassLoader|PathClassLoader|InMemoryDexClassLoader',
        "severity":    "high",
        "description": "Dynamic DEX/code loading detected. Used in some malware and evasion techniques.",
    },
    {
        "category":    "Runtime Command Execution",
        "pattern":     r'Runtime\.getRuntime\(\)\.exec|Runtime\.exec\(',
        "severity":    "high",
        "description": "Runtime OS command execution detected.",
    },
    {
        "category":    "Reflection",
        "pattern":     r'java\.lang\.reflect\.|Class\.forName\(|\.getDeclaredMethod\(|\.invoke\(',
        "severity":    "low",
        "description": "Java reflection usage detected. Can be used to access private APIs and evade static analysis.",
    },
    {
        "category":    "Pending Intent",
        "pattern":     r'PendingIntent\.(getActivity|getService|getBroadcast)\(',
        "severity":    "medium",
        "description": "PendingIntent usage detected. Review for intent hijacking risk.",
    },
    {
        "category":    "SSL/TLS Bypass Pattern",
        "pattern":     r'AllowAllHostnameVerifier|TrustAllCerts|X509TrustManager|checkServerTrusted',
        "severity":    "critical",
        "description": "Potential SSL/TLS certificate validation bypass detected.",
    },
    {
        "category":    "Hardcoded Password / Key",
        "pattern":     r'(?i)(?:password|passwd|secret|private.?key)\s*=\s*"[^"]{6,}"',
        "severity":    "high",
        "description": "Hardcoded credential or key string detected.",
    },
    {
        "category":    "Broadcast Without Permission",
        "pattern":     r'sendBroadcast\(|sendOrderedBroadcast\(',
        "severity":    "low",
        "description": "Broadcast sent without explicit permission. Any app can receive it.",
    },
    {
        "category":    "AES Encryption Detected",
        "pattern":     r'AES/GCM|AES/CBC|AES/CTR|Cipher\.getInstance\("AES',
        "severity":    "info",
        "description": "AES encryption usage detected. Review mode and key management.",
    },
    {
        "category":    "Obfuscation — ProGuard/R8",
        "pattern":     r'-keep class|-dontwarn|proguard-rules|minifyEnabled\s*=\s*true',
        "severity":    "info",
        "description": "ProGuard/R8 obfuscation configuration detected.",
    },
    {
        "category":    "Root Detection",
        "pattern":     r'isRooted|RootBeer|su\b|/system/bin/su|/system/xbin/su',
        "severity":    "info",
        "description": "Root detection logic detected.",
    },
    {
        "category":    "Firebase Cloud Messaging Token",
        "pattern":     r'getToken\(\)|FirebaseInstanceId|FirebaseMessaging\.getInstance\(\)',
        "severity":    "info",
        "description": "FCM token retrieval detected. Ensure tokens are stored securely.",
    },
    {
        "category":    "Clipboard Access",
        "pattern":     r'ClipboardManager|getPrimaryClip\(|setPrimaryClip\(',
        "severity":    "low",
        "description": "Clipboard access detected.",
    },
    {
        "category":    "Screenshot Capture",
        "pattern":     r'FLAG_SECURE|getWindow\(\)\.setFlags|WindowManager\.LayoutParams\.FLAG_SECURE',
        "severity":    "info",
        "description": "Screenshot protection (FLAG_SECURE) detected.",
    },
    {
        "category":    "Insecure Deserialization",
        "pattern":     r'ObjectInputStream|readObject\(\)|Serializable',
        "severity":    "medium",
        "description": "Java deserialization detected. Potentially vulnerable to deserialization attacks.",
    },
    {
        "category":    "Biometric Authentication",
        "pattern":     r'BiometricPrompt|BiometricManager|FingerprintManager|USE_BIOMETRIC',
        "severity":    "info",
        "description": "Biometric authentication implementation detected.",
    },
    {
        "category":    "Intent Scheme URL",
        "pattern":     r'intent://|Intent\.parseUri',
        "severity":    "high",
        "description": "Intent scheme URL processing detected — potential intent hijacking.",
    },
]


def analyze_strings(tmpdir: str, platform: str, *, corpus: SourceCorpus | None = None) -> dict:
    """
    Scan extracted app content for categorized sensitive strings.
    Returns dict with categories, each match includes value + source files.
    """
    # Collect per-file content
    file_map = _collect_files(tmpdir, platform, corpus=corpus or SourceCorpus())

    # Compile once; iterate files OUTER so the casefolded content used by the
    # necessary-literal prefilter is built once per file, not once per pattern.
    compiled = []
    for pat_info in STRING_PATTERNS:
        try:
            pattern = re.compile(pat_info["pattern"], re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        compiled.append((
            pat_info, pattern,
            pat_info.get("exclude", []),
            _VALUE_VALIDATORS.get(pat_info["category"]),
            {},  # value -> list of rel paths (accumulated across files)
        ))

    for rel_path, content in file_map.items():
        folded = regex_prefilter.fold(content)
        for pat_info, pattern, exclusions, validator, value_files in compiled:
            if not regex_prefilter.may_match(pat_info["pattern"], folded):
                continue
            for m in pattern.findall(content):
                val = m if isinstance(m, str) else (m[0] if m else "")
                if not val or len(val) < 3:
                    continue
                # Length cap — skip crypto constants
                if len(val) > 200:
                    continue
                # Skip pure long hex
                if len(val) > 40 and re.fullmatch(r'[0-9a-fA-F]+', val):
                    continue
                if any(re.search(excl, val, re.IGNORECASE) for excl in exclusions):
                    continue
                # Category-specific semantic validation (real IP, not a
                # namespace URL, …). Drops shape-matches that aren't real.
                if validator and not validator(val):
                    continue

                # Truncate display value but keep it readable
                display = val if len(val) <= 80 else val[:40] + "..." + val[-15:]

                if display not in value_files:
                    value_files[display] = []
                if rel_path not in value_files[display]:
                    value_files[display].append(rel_path)

    # Emit in STRING_PATTERNS order — identical to the historical pattern-outer
    # loop, so category ordering and content are unchanged.
    categories = {}
    for pat_info, _pattern, _ex, _v, value_files in compiled:
        if value_files:
            matches = [
                {"value": v, "files": fs}
                for v, fs in list(value_files.items())[:20]
            ]
            categories[pat_info["category"]] = {
                "severity":    pat_info["severity"],
                "description": pat_info["description"],
                "matches":     matches,
                "count":       len(value_files),
            }

    return categories


def _collect_files(tmpdir: str, platform: str, *, corpus: SourceCorpus | None = None) -> dict:
    """Return {rel_path -> content} for all scannable files.

    Raw .dex/.so binaries are only string-dumped as a LAST RESORT — when no
    decompiled Java/Kotlin source exists. Otherwise their printable-strings
    dump just duplicates the real source while attributing findings to a binary
    file (classes.dex) that can't be opened in the source viewer.
    """
    corpus = corpus or SourceCorpus()
    result = {}
    binary_blobs = {}  # rel_path -> dumped strings (only used if no source)
    has_source = False
    text_exts = {
        ".xml", ".json", ".properties", ".txt", ".gradle",
        ".java", ".kt", ".smali", ".js", ".ts", ".html",
        ".swift", ".m", ".h", ".plist", ".strings",
        ".yaml", ".yml", ".cfg", ".config", ".env",
    }

    for root, _, files in corpus.walk(tmpdir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = normalize_relative_path(os.path.relpath(fpath, tmpdir))
            ext = os.path.splitext(fname)[1].lower()

            if ext in text_exts:
                content = corpus.read_text(fpath)
                if content is None:
                    continue
                result[rel] = content
                if ext in (".java", ".kt", ".smali"):
                    has_source = True
            elif ext in (".dex", ".so"):
                raw = corpus.read_bytes(fpath, max_bytes=8 * 1024 * 1024)
                if raw is None:
                    continue
                binary_blobs[rel] = printable_text(raw)

    # Fallback only: surface dex/so strings when decompilation produced nothing.
    if not has_source:
        result.update(binary_blobs)

    return result
