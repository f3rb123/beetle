import re
import os
from .tracker_db import ANDROID_API_CATEGORIES
from .path_utils import normalize_relative_path
from .source_corpus import SourceCorpus, printable_text
from . import regex_prefilter


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


def analyze_android_apis(tmpdir: str, results: dict, source_dirs=None, *, corpus: SourceCorpus | None = None):
    """
    Scan extracted APK content for Android API usage categories.
    Returns grouped API findings with file references.

    Phase 4 (P4): when decompiled source dirs (jadx/apktool) are available they
    are scanned in preference to the raw APK, so behaviour/API findings attribute
    to real .java/.smali source paths instead of the binary classes.dex.
    """
    # Prefer decompiled source roots; fall back to the raw extraction.
    corpus = corpus or SourceCorpus()
    roots = [d for d in (source_dirs or []) if d and os.path.exists(d)] or [tmpdir]

    # Collect all text content, keyed by source-root-relative path so the code
    # viewer can resolve it later.
    content_map = {}  # rel_path -> content
    dex_blobs = {}    # rel_path -> dumped strings (fallback only)
    has_source = False
    seen_hashes = set()
    duplicate_skips = 0
    for base in roots:
        for root, _, files in corpus.walk(base):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                fpath = os.path.join(root, fname)
                rel = normalize_relative_path(os.path.relpath(fpath, base))
                if ext in ('.smali', '.java', '.kt', '.js', '.bundle'):
                    content = corpus.read_text(fpath)
                    if content is None:
                        continue
                    content_hash = hash(content)
                    if content_hash in seen_hashes:
                        duplicate_skips += 1
                        continue
                    seen_hashes.add(content_hash)
                    content_map[rel] = content
                    if ext in ('.java', '.kt', '.smali'):
                        has_source = True
                elif ext == '.dex':
                    raw = corpus.read_bytes(fpath)
                    if raw is None:
                        continue
                    text = printable_text(raw)
                    dex_blobs[rel] = text

    # Only fall back to raw classes.dex strings when no real source was found —
    # otherwise classes.dex pollutes the API file lists with a binary path.
    if not has_source:
        for rel, text in dex_blobs.items():
            content_hash = hash(text)
            if content_hash in seen_hashes:
                duplicate_skips += 1
                continue
            seen_hashes.add(content_hash)
            content_map[rel] = text

    # Source roots only — never attribute behaviour evidence to a binary dump.
    def _is_source(rel):
        return not str(rel).lower().endswith((".dex", ".so", ".dylib", ".arsc"))

    # Compile every category pattern once (invalid patterns can never match —
    # same effect as the historical per-search re.error skip).
    compiled_cats = []
    for category, patterns in ANDROID_API_CATEGORIES.items():
        plist = []
        for pattern in patterns:
            try:
                plist.append((pattern, re.compile(pattern, re.IGNORECASE)))
            except re.error:
                continue
        compiled_cats.append((category, plist, [], set(), []))  # files, seen, evidence

    # Files OUTER so the prefilter's casefolded content and the splitlines()
    # used for evidence snippets are built once per file, not once per
    # (category, file) — profiling showed 2.4M re.search calls here.
    for rel, content in content_map.items():
        folded = regex_prefilter.fold(content)
        src_lines = None
        is_src = _is_source(rel)
        for category, plist, matching_files, seen_files, evidence in compiled_cats:
            for pattern, cre in plist:
                if not regex_prefilter.may_match(pattern, folded):
                    continue
                m = cre.search(content)
                if not m:
                    continue
                if rel not in seen_files:
                    seen_files.add(rel)
                    matching_files.append(rel)
                # Record exact line + snippet for the first source-file match.
                if is_src and len(evidence) < 10:
                    line_no = content[:m.start()].count("\n") + 1
                    if src_lines is None:
                        src_lines = content.splitlines()
                    snippet = src_lines[line_no - 1].strip()[:240] if line_no <= len(src_lines) else m.group(0)
                    evidence.append({"path": rel, "line": line_no, "snippet": snippet})
                break

    # Emit in ANDROID_API_CATEGORIES order — identical to the historical
    # category-outer loop.
    api_results = {}
    api_evidence = {}  # category -> [{path, line, snippet}]  (Phase 6 Task 4)
    for category, _plist, matching_files, _seen, evidence in compiled_cats:
        if matching_files:
            api_results[category] = sorted(matching_files)
        if evidence:
            api_evidence[category] = evidence

    results["android_api"] = api_results
    results["android_api_evidence"] = api_evidence
    results["android_api_stats"] = {
        "unique_inputs": len(content_map),
        "duplicate_content_skips": duplicate_skips,
    }


def extract_emails_from_app(tmpdir: str, apk_path: str, *, corpus: SourceCorpus | None = None) -> list:
    """Extract email addresses from all app files with their source paths."""
    corpus = corpus or SourceCorpus()
    found = {}  # email -> list of file paths
    seen_hashes = set()

    for root, _, files in corpus.walk(tmpdir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in ('.java', '.kt', '.smali', '.xml', '.json',
                           '.properties', '.gradle', '.strings', '.plist',
                           '.swift', '.m', '.h', '.txt', '.js', '.bundle'):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = corpus.read_text(fpath)
                if content is None:
                    continue
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
    for root, _, files in corpus.walk(tmpdir):
        for fname in files:
            if not fname.endswith('.so'):
                continue
            fpath = os.path.join(root, fname)
            try:
                raw = corpus.read_bytes(fpath)
                if raw is None:
                    continue
                text = printable_text(raw)
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


def detect_apkid_features(tmpdir: str, *, corpus: SourceCorpus | None = None) -> dict:
    """
    Detect anti-VM, anti-debug, compiler, packer features from DEX strings.
    Mimics APKiD behaviour without requiring the tool.
    """
    corpus = corpus or SourceCorpus()
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
    for root, _, files in corpus.walk(tmpdir):
        for fname in files:
            if fname.endswith('.dex'):
                fpath = os.path.join(root, fname)
                raw = corpus.read_bytes(fpath)
                if raw is None:
                    continue
                text = printable_text(raw)
                dex_files[fname] = text

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
