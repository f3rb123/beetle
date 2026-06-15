import re
import os
from .tracker_db import ANDROID_API_CATEGORIES
from .path_utils import normalize_relative_path


EMAIL_PATTERN = re.compile(
    r'(?<![\w.-])[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+'
)

EXCLUDE_DOMAINS = {
    'android.com', 'google.com', 'example.com', 'test.com',
    'w3.org', 'schema.org', 'apache.org', 'junit.org',
    'spdx.org', 'iana.org', 'whatwg.org', 'jcp.org',
    'eclipse.org', 'xmlpull.org',
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com",
    "sharklasers.com", "discard.email",
}

FILE_LIKE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "pdf", "json", "xml", "kt", "java"}


def _is_valid_email_candidate(email: str) -> bool:
    if email.count("@") != 1:
        return False
    local, domain = email.rsplit("@", 1)
    labels = domain.split(".")
    tld = labels[-1].lower() if labels else ""
    if len(local) < 2 or len(tld) < 2:
        return False
    if tld in FILE_LIKE_TLDS:
        return False
    if domain.lower() in DISPOSABLE_DOMAINS:
        return False
    if any(domain.lower().endswith("." + excluded) or domain.lower() == excluded for excluded in EXCLUDE_DOMAINS):
        return False
    if ".." in email or any(part.startswith("-") or part.endswith("-") for part in labels):
        return False
    return True


def analyze_android_apis(tmpdir: str, results: dict):
    """
    Scan extracted APK content for Android API usage categories.
    Returns grouped API findings with file references.
    """
    # Collect all text content
    content_map = {}  # file_path -> content
    seen_hashes = set()
    duplicate_skips = 0
    for root, _, files in os.walk(tmpdir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in ('.smali', '.java', '.kt', '.js', '.bundle'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='replace') as f:
                        content = f.read()
                    content_hash = hash(content)
                    if content_hash in seen_hashes:
                        duplicate_skips += 1
                        continue
                    seen_hashes.add(content_hash)
                    content_map[fpath] = content
                except Exception:
                    continue
            elif ext == '.dex':
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        raw = f.read()
                    text = "".join(chr(b) if 32 <= b < 127 else " " for b in raw)
                    content_hash = hash(text)
                    if content_hash in seen_hashes:
                        duplicate_skips += 1
                        continue
                    seen_hashes.add(content_hash)
                    content_map[fpath] = text
                except Exception:
                    continue

    api_results = {}

    for category, patterns in ANDROID_API_CATEGORIES.items():
        matching_files = []
        seen_files = set()

        for fpath, content in content_map.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, content, re.IGNORECASE):
                        rel = normalize_relative_path(os.path.relpath(fpath, tmpdir))
                        if rel not in seen_files:
                            seen_files.add(rel)
                            matching_files.append(rel)
                        break
                except re.error:
                    continue

        if matching_files:
            api_results[category] = sorted(matching_files)

    results["android_api"] = api_results
    results["android_api_stats"] = {
        "unique_inputs": len(content_map),
        "duplicate_content_skips": duplicate_skips,
    }


def extract_emails_from_app(tmpdir: str, apk_path: str) -> list:
    """Extract email addresses from all app files with their source paths."""
    found = {}  # email -> list of file paths
    seen_hashes = set()

    for root, _, files in os.walk(tmpdir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in ('.java', '.kt', '.smali', '.xml', '.json',
                           '.properties', '.gradle', '.strings', '.plist',
                           '.swift', '.m', '.h', '.txt', '.js', '.bundle'):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', errors='replace') as f:
                    content = f.read()
                content_hash = hash(content)
                if content_hash in seen_hashes:
                    continue
                seen_hashes.add(content_hash)
                for match in EMAIL_PATTERN.findall(content):
                    if not _is_valid_email_candidate(match):
                        continue
                    rel = normalize_relative_path(os.path.relpath(fpath, tmpdir))
                    if match not in found:
                        found[match] = []
                    if rel not in found[match]:
                        found[match].append(rel)
            except Exception:
                continue

    # Scan SO binaries
    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if not fname.endswith('.so'):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'rb') as f:
                    raw = f.read()
                text = "".join(chr(b) if 32 <= b < 127 else " " for b in raw)
                content_hash = hash(text)
                if content_hash in seen_hashes:
                    continue
                seen_hashes.add(content_hash)
                for match in EMAIL_PATTERN.findall(text):
                    if not _is_valid_email_candidate(match):
                        continue
                    rel = normalize_relative_path(os.path.relpath(fpath, tmpdir))
                    if match not in found:
                        found[match] = []
                    if rel not in found[match]:
                        found[match].append(rel)
            except Exception:
                continue

    return [{"email": email, "files": paths} for email, paths in found.items()]


def detect_apkid_features(tmpdir: str) -> dict:
    """
    Detect anti-VM, anti-debug, compiler, packer features from DEX strings.
    Mimics APKiD behaviour without requiring the tool.
    """
    APKID_PATTERNS = {
        "Anti-VM": {
            "Build.FINGERPRINT check":     r"Build\.FINGERPRINT",
            "Build.MODEL check":           r"Build\.MODEL",
            "Build.MANUFACTURER check":    r"Build\.MANUFACTURER",
            "Build.PRODUCT check":         r"Build\.PRODUCT",
            "Build.HARDWARE check":        r"Build\.HARDWARE",
            "Build.BOARD check":           r"Build\.BOARD",
            "Build.TAGS check":            r"Build\.TAGS",
            "Build.SERIAL check":          r"Build\.SERIAL",
            "SIM operator check":          r"getSimOperator\(\)",
            "Network operator check":      r"getNetworkOperatorName\(\)",
            "Emulator property check":     r"ro\.product\.model|ro\.kernel|init\.svc\.qemud",
        },
        "Anti-Debug": {
            "Debug.isDebuggerConnected()": r"isDebuggerConnected\(\)",
            "TracerPid check":             r"TracerPid",
            "ptrace detection":            r"ptrace",
            "Debug flag check":            r"ApplicationInfo\.FLAG_DEBUGGABLE",
        },
        "Obfuscation": {
            "ProGuard/R8 compiled":        r"Compiled by r8|compiled with r8",
            "DexGuard":                    r"com\.saikoa\.dexguard",
            "Obfuscation patterns":        r"^[a-z]\.[a-z]$",
        },
        "Packer/Protector": {
            "Custom class loader":         r"DexClassLoader|InMemoryDexClassLoader",
            "Dynamic DEX loading":         r"loadDex\(|loadClass\(",
            "Reflection usage":            r"getDeclaredMethod\(|getDeclaredField\(",
        },
    }

    dex_files = {}
    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if fname.endswith('.dex'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        raw = f.read()
                    text = "".join(chr(b) if 32 <= b < 127 else " " for b in raw)
                    dex_files[fname] = text
                except Exception:
                    continue

    results = {}
    for dex_name, content in dex_files.items():
        findings = {}
        for category, patterns in APKID_PATTERNS.items():
            matched = []
            for label, pattern in patterns.items():
                try:
                    if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                        matched.append(label)
                except re.error:
                    continue
            if matched:
                findings[category] = matched

        # Detect compiler
        if "r8" in content.lower() or "R8" in content:
            findings.setdefault("Compiler", []).append("R8 (Google)")
        elif "proguard" in content.lower():
            findings.setdefault("Compiler", []).append("ProGuard")
        else:
            findings.setdefault("Compiler", []).append("javac/kotlinc (unobfuscated)")

        if findings:
            results[dex_name] = findings

    return results
