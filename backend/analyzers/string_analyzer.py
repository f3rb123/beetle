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


def _is_real_email(val: str) -> bool:
    """Reject code-identifier noise the loose regex matches as an email.

    Kills FPs like ``_Double@0150898.fromInteger`` (leading-underscore local,
    all-digit domain label, camelCase pseudo-TLD) and ``n@d.Ce`` (1-char domain
    label, mixed-case pseudo-TLD). A real TLD is 2-24 letters in a single case
    (``com`` / ``COM``, never ``fromInteger`` / ``Ce``).
    """
    v = (val or "").strip()
    if v.count("@") != 1:
        return False
    local, domain = v.split("@", 1)
    if not local or local[0] == "_":       # code identifiers, not addresses
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if not (2 <= len(tld) <= 24 and tld.isalpha()):
        return False
    if not (tld.islower() or tld.isupper()):  # camelCase → a method call, not a TLD
        return False
    if any(lbl.isdigit() for lbl in labels[:-1]):  # all-digit domain label
        return False
    if len(labels[-2]) < 2:                 # 1-char registrable label ("d.Ce")
        return False
    return True


# Category -> value validator. A match is dropped when the validator returns False.
_VALUE_VALIDATORS = {
    "Hardcoded IP Address": _is_real_ip,
    "Email Address": _is_real_email,
    "Hidden URL / API Endpoint": lambda v: not _is_namespace_url(v),
}

# ─── String Categories ────────────────────────────────────────────────────────
STRING_PATTERNS = [
    {
        "category":    "Hardcoded IP Address",
        "pattern":     r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        "severity":    "info",
        "description": "Dotted-quad string found. Detection is HEURISTIC — many dotted-quads are "
                       "version numbers or byte sequences, not IPs. Reserved/test/documentation ranges "
                       "are filtered; confirm the value is a real endpoint before acting on it.",
        "exclude":     [r'^0\.0\.0\.0$', r'^127\.0\.0\.1$', r'^255\.255\.255\.\d+$'],
    },
    {
        "category":    "Email Address",
        "pattern":     r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
        "severity":    "info",
        "description": "Email address embedded in app. May expose developer or internal contact details.",
        "exclude":     [r'example\.com$', r'test\.com$', r'@android\.com$', r'@google\.com$'],
    },
    # ── Crypto ALGORITHM STRING presence (INFO only) ──────────────────────────
    # These match a bare algorithm token anywhere (a string constant, class name,
    # comment). Token presence is NOT proof of insecure USAGE, so they are INFO
    # signals only. The authoritative weak-crypto findings come from code_rules.py
    # (android_weak_hash_md5 etc., which match MessageDigest.getInstance("MD5")) and
    # keep their real severity; the string-presence copy for the same file is
    # suppressed downstream to avoid double-counting.
    {
        "category":    "Crypto Algorithm String Present — MD5",
        "pattern":     r'\bMD5\b',
        "severity":    "info",
        "description": "The token 'MD5' appears in app strings/code. String-presence signal only — "
                       "not proof MD5 is used for a security purpose. Confirm actual usage "
                       "(e.g. MessageDigest.getInstance(\"MD5\")); the authoritative weak-hash finding "
                       "comes from code analysis.",
    },
    {
        "category":    "Crypto Algorithm String Present — SHA-1",
        "pattern":     r'\bSHA-1\b|\bSHA1\b',
        "severity":    "info",
        "description": "The token 'SHA-1' appears in app strings/code. String-presence signal only — "
                       "not proof SHA-1 is used for a security purpose. Confirm actual usage; the "
                       "authoritative weak-hash finding comes from code analysis.",
    },
    {
        "category":    "Crypto Algorithm String Present — DES",
        "pattern":     r'\bDES\b',
        "severity":    "info",
        "description": "The token 'DES' (single DES) appears in app strings/code. String-presence "
                       "signal only — not proof single-DES is used. Distinct from 3DES/TripleDES. "
                       "Confirm actual usage; the authoritative weak-cipher finding comes from code analysis.",
    },
    {
        "category":    "Crypto Algorithm String Present — 3DES/TripleDES",
        "pattern":     r'\bDESede\b|\bTripleDES\b|\b3DES\b',
        "severity":    "info",
        "description": "The token '3DES/TripleDES' appears in app strings/code. String-presence signal "
                       "only. 3DES is weak-but-distinct from single DES. Confirm actual usage; the "
                       "authoritative weak-cipher finding comes from code analysis.",
    },
    {
        "category":    "Crypto Algorithm String Present — ECB Mode",
        "pattern":     r'\bECB\b',
        "severity":    "info",
        "description": "The token 'ECB' appears in app strings/code. String-presence signal only — "
                       "ECB is deterministic/pattern-leaking WHEN used as a cipher mode. Confirm actual "
                       "usage (e.g. Cipher.getInstance(\".../ECB/...\")); the authoritative finding comes "
                       "from code analysis.",
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


# A string-presence crypto category is redundant once an authoritative code_rules
# finding (matching MessageDigest.getInstance("MD5") etc.) exists for the SAME file.
# Maps the category to the substring(s) that identify the covering code rule_id.
_CRYPTO_PRESENCE_TO_RULE_TOKENS = {
    "Crypto Algorithm String Present — MD5":              ("md5",),
    "Crypto Algorithm String Present — SHA-1":            ("sha1",),
    "Crypto Algorithm String Present — DES":              ("cipher_des",),
    "Crypto Algorithm String Present — 3DES/TripleDES":   ("cipher_des",),
    "Crypto Algorithm String Present — ECB Mode":         ("ecb",),
}


def _finding_files(f: dict) -> set:
    files = set()
    if f.get("file_path"):
        files.add(f["file_path"])
    for p in (f.get("files") or []):
        if p:
            files.add(p)
    for e in (f.get("file_evidence") or []):
        if isinstance(e, dict) and e.get("path"):
            files.add(e["path"])
    return files


def suppress_crypto_string_presence_duplicates(results: dict) -> int:
    """Drop string-presence crypto matches for files that already have an
    authoritative code_rules crypto finding for the same algorithm — no double count.

    Additive/non-destructive: only prunes results["string_analysis"] entries whose
    file is covered by a real code finding; leaves everything else untouched.
    """
    sa = results.get("string_analysis") or {}
    if not sa:
        return 0
    covered: dict = {}  # rule token -> set(files)
    for f in results.get("findings") or []:
        if not isinstance(f, dict):
            continue
        rid = str(f.get("rule_id") or f.get("id") or "").lower()
        if not rid:
            continue
        files = _finding_files(f)
        for tok in ("md5", "sha1", "cipher_des", "ecb"):
            if tok in rid and files:
                covered.setdefault(tok, set()).update(files)

    removed = 0
    for cat, tokens in _CRYPTO_PRESENCE_TO_RULE_TOKENS.items():
        entry = sa.get(cat)
        if not entry:
            continue
        covered_files = set()
        for t in tokens:
            covered_files |= covered.get(t, set())
        if not covered_files:
            continue
        new_matches = []
        for m in entry.get("matches", []):
            kept = [p for p in (m.get("files") or []) if p not in covered_files]
            if kept:
                m["files"] = kept
                new_matches.append(m)
            else:
                removed += 1
        if new_matches:
            entry["matches"] = new_matches
            entry["count"] = len(new_matches)
        else:
            sa.pop(cat, None)
    return removed


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
