"""
CVE mapping for bundled native libraries (Android .so / iOS Mach-O).

Pipeline:
  1. Read printable strings + symbols from the binary (LIEF if available, else
     raw byte scan) and regex-match common version markers for well-known
     OSS libraries (OpenSSL, BoringSSL, libcurl, zlib, libpng, SQLite, ...).
  2. For each (product, version) pair, query OSV.dev for known vulnerabilities.
  3. Cache every OSV response in SQLite for 24h to keep repeat scans fast and
     offline-friendly.
  4. Emit one finding per CVE, mapped to severity from CVSS, plus a flat
     `components` list for a future "Vulnerable Components" UI section.

All I/O is best-effort: no network, no cache, or no LIEF → we degrade to
"return empty" rather than crash the scan.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

try:
    import httpx
    _HTTPX_OK = True
except Exception:
    _HTTPX_OK = False

try:
    import lief
    try:
        lief.logging.disable()
    except Exception:
        pass
    _LIEF_OK = True
except Exception:
    _LIEF_OK = False

log = logging.getLogger("cortex.cve_mapper")

# ── Config ───────────────────────────────────────────────────────────────────
OSV_URL        = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_S  = 5
CACHE_TTL_S    = 24 * 3600          # 24h
NEG_CACHE_TTL_S = 6 * 3600          # re-try empty results after 6h
KEV_TTL_S      = 24 * 3600          # CISA KEV refresh cadence
KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BINARIES   = 40                  # cap work per scan
MAX_STRINGS_MB = 6                   # don't read huge binaries whole
MAX_PACKAGES   = 200                 # cap pkg lookups per scan
OSV_CONCURRENCY = 10                 # parallel OSV HTTP calls
OSV_BUDGET_S    = 45                 # overall wall-clock budget for all OSV calls

# Cache lives next to the main cortex.db.
_DATA_DIR = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
_CACHE_DB = _DATA_DIR / "cortex.db"

# ── Symbol-based cross-checks ────────────────────────────────────────────────
# For products whose version strings are commonly quoted in unrelated code
# (e.g. analytics SDKs embedding the text "OpenSSL 1.0.2k" in telemetry), we
# additionally require at least one matching imported/exported symbol in the
# binary. Products not listed here skip the check and accept the string match.
_REQUIRED_SYMBOLS: dict[str, tuple[str, ...]] = {
    "openssl":       ("SSL_CTX_", "SSL_read", "SSL_write", "OPENSSL_init", "EVP_"),
    "curl":          ("curl_easy_", "curl_multi_", "curl_global_"),
    "zlib":          ("inflate", "deflate", "compress", "zlibVersion"),
    "libpng":        ("png_create_", "png_write_", "png_read_", "png_get_"),
    "sqlite":        ("sqlite3_", "sqlite3_prepare", "sqlite3_exec"),
    "libsodium":     ("crypto_", "sodium_init", "randombytes_"),
    "freetype":      ("FT_Init_", "FT_Load_", "FT_New_"),
    "libxml2":       ("xmlParse", "xmlNew", "xmlFree"),
    "protobuf":      ("google::protobuf", "protobuf_", "_ZN6google8protobuf"),
    "sqlcipher":     ("sqlcipher_", "sqlite3_key"),
    "grpc":          ("grpc_", "grpc_completion_queue"),
    "conscrypt":     ("Conscrypt_", "NativeCrypto_"),
    "libssh2":       ("libssh2_", "_libssh2_"),
    "realm":         ("realm::", "_ZN5realm"),
    "libwebp":       ("WebPEncode", "WebPDecode", "WebPGet"),
    "libjpeg-turbo": ("jpeg_create_", "jpeg_start_", "tjCompress"),
    "nghttp2":       ("nghttp2_session_", "nghttp2_submit_"),
    "c-ares":        ("ares_init", "ares_query", "ares_send"),
    "libwebsockets": ("lws_create_", "lws_service", "lws_write"),
    "opencv":        ("cv::", "cvCreate", "_ZN2cv"),
    "icu4c":         ("ucnv_", "u_init", "uloc_"),
    # Flutter & React Native are JS/Dart runtimes — their string constants are
    # authoritative even without matching C symbols, so they're excluded.
}


# ── Version detection patterns ───────────────────────────────────────────────
# Each entry: (osv_package_name, osv_ecosystem, regex, version_group_index)
# Ecosystem hints OSV which data source to search. "" = try generic CVE search.
_VERSION_PATTERNS: list[tuple[str, str, re.Pattern, int]] = [
    # OpenSSL: "OpenSSL 1.1.1k  25 Mar 2021"
    ("openssl", "",
     re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)", re.IGNORECASE), 1),
    # BoringSSL has no version, but expose presence for info.
    # libcurl: "libcurl/7.68.0"
    ("curl", "",
     re.compile(rb"libcurl/(\d+\.\d+\.\d+)"), 1),
    # zlib: "inflate 1.2.11 Copyright"  /  "deflate 1.2.11"
    ("zlib", "",
     re.compile(rb"(?:inflate|deflate)\s+(\d+\.\d+\.\d+)\s+Copyright", re.IGNORECASE), 1),
    # libpng: "libpng version 1.6.37"
    ("libpng", "",
     re.compile(rb"libpng\s+version\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # SQLite: "3.34.1" with "sqlite3_" nearby – use the canonical banner
    ("sqlite", "",
     re.compile(rb"SQLite\s+version\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # nghttp2: "nghttp2/1.41.0"
    ("nghttp2", "",
     re.compile(rb"nghttp2/(\d+\.\d+\.\d+)"), 1),
    # libjpeg-turbo: "libjpeg-turbo version 2.0.6"
    ("libjpeg-turbo", "",
     re.compile(rb"libjpeg-turbo\s+version\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # libwebp: "libwebp-1.2.0"  or encoder banner
    ("libwebp", "",
     re.compile(rb"libwebp[-\s]v?(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # freetype: "FreeType 2.10.4"
    ("freetype", "",
     re.compile(rb"FreeType\s+(\d+\.\d+\.\d+)"), 1),
    # libsodium: "libsodium version 1.0.18"
    ("libsodium", "",
     re.compile(rb"libsodium\s+version\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # FFmpeg: "FFmpeg version 4.3.1"
    ("ffmpeg", "",
     re.compile(rb"FFmpeg\s+version\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), 1),
    # libxml2: "libxml2-2.9.10" / "2.9.10" in .comment
    ("libxml2", "",
     re.compile(rb"libxml2[-\s](\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # c-ares: "c-ares/1.17.1"
    ("c-ares", "",
     re.compile(rb"c-ares/(\d+\.\d+\.\d+)"), 1),
    # Flutter engine: "Flutter/3.16.0"
    ("flutter", "",
     re.compile(rb"Flutter/(\d+\.\d+\.\d+)"), 1),
    # React Native core: "ReactNativeVersion.*major.*minor.*patch"
    ("react-native", "npm",
     re.compile(rb"react-native[^\x00]{0,40}?(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # protobuf runtime: "libprotobuf 3.19.4"
    ("protobuf", "",
     re.compile(rb"libprotobuf[^\x00]{0,20}?(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # SQLCipher: "SQLCipher 4.5.2 community"
    ("sqlcipher", "",
     re.compile(rb"SQLCipher\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # Realm mobile DB: "Realm Core 13.15.1"
    ("realm", "",
     re.compile(rb"Realm\s+(?:Core|Sync)\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # gRPC C-Core: "grpc 1.47.0"
    ("grpc", "",
     re.compile(rb"grpc[-_/](\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # ICU unicode: "icu-release-70-1" / "icu4c-70_1"
    ("icu4c", "",
     re.compile(rb"icu4c[-_](\d+)[._](\d+)", re.IGNORECASE), 1),
    # Conscrypt (Android TLS): "Conscrypt/2.5.2"
    ("conscrypt", "",
     re.compile(rb"Conscrypt/(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # libssh2: "libssh2/1.9.0"
    ("libssh2", "",
     re.compile(rb"libssh2/(\d+\.\d+\.\d+)"), 1),
    # libwebsockets: "libwebsockets 4.3.2"
    ("libwebsockets", "",
     re.compile(rb"libwebsockets\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    # OpenCV: "OpenCV 4.5.5"
    ("opencv", "",
     re.compile(rb"OpenCV\s+(\d+\.\d+\.\d+)"), 1),
]

# Only these CVSS v3 base scores map to severity; fall back to OSV's own severity.
def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >  0.0: return "low"
    return "info"


# ── Cache ────────────────────────────────────────────────────────────────────
def _init_cache():
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(_CACHE_DB)) as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    key         TEXT PRIMARY KEY,
                    response    TEXT,
                    fetched_at  INTEGER
                )
            """)
    except Exception as e:
        log.debug(f"cve cache init failed: {e}")


def _cache_get(key: str) -> dict | None:
    try:
        with sqlite3.connect(str(_CACHE_DB)) as c:
            row = c.execute(
                "SELECT response, fetched_at FROM cve_cache WHERE key = ?",
                (key,),
            ).fetchone()
            if not row:
                return None
            if time.time() - row[1] > CACHE_TTL_S:
                return None
            return json.loads(row[0])
    except Exception:
        return None


def _cache_put(key: str, value: dict):
    try:
        with sqlite3.connect(str(_CACHE_DB)) as c:
            c.execute(
                "INSERT OR REPLACE INTO cve_cache (key, response, fetched_at) VALUES (?,?,?)",
                (key, json.dumps(value), int(time.time())),
            )
    except Exception:
        pass


# ── Version extraction ───────────────────────────────────────────────────────
# Section names we read strings from when LIEF is available. Narrowing to these
# eliminates false-positive matches from .data / .text noise.
_STRING_SECTIONS_ELF   = (".rodata", ".rdata", ".data.rel.ro", ".gnu.version_r")
_STRING_SECTIONS_MACHO = ("__cstring", "__const", "__text_const")


def _lief_parse_once(path: str):
    """Parse a binary with LIEF at most once per path (within this call stack)."""
    if not _LIEF_OK:
        return None
    cache = getattr(_lief_parse_once, "_cache", None)
    if cache is None:
        cache = {}
        _lief_parse_once._cache = cache
    if path in cache:
        return cache[path]
    try:
        parsed = lief.parse(path)
    except Exception:
        parsed = None
    # Keep cache tiny — drop oldest when it grows.
    if len(cache) > 8:
        cache.pop(next(iter(cache)))
    cache[path] = parsed
    return parsed


def _read_binary_strings(path: str) -> bytes:
    """
    Return a haystack of printable bytes from the binary.
    Prefers LIEF (only read-only string sections), falls back to a capped raw
    read when LIEF is unavailable or fails.
    """
    cap = MAX_STRINGS_MB * 1024 * 1024

    if _LIEF_OK:
        try:
            parsed = _lief_parse_once(path)
            if parsed is not None:
                chunks: list[bytes] = []
                # ELF / PE go through `.sections`
                sections = getattr(parsed, "sections", None) or []
                wanted = set(_STRING_SECTIONS_ELF + _STRING_SECTIONS_MACHO)
                for sec in sections:
                    sec_name = str(getattr(sec, "name", "") or "")
                    if sec_name in wanted or any(w in sec_name for w in wanted):
                        try:
                            content = bytes(getattr(sec, "content", b"") or b"")
                        except Exception:
                            continue
                        if content:
                            chunks.append(content)
                            if sum(len(c) for c in chunks) >= cap:
                                break
                if chunks:
                    return b"\x00".join(chunks)[:cap]
        except Exception:
            pass  # fall through to raw read

    # Raw read fallback
    try:
        with open(path, "rb") as f:
            size = os.path.getsize(path)
            return f.read(cap) if size > cap else f.read()
    except Exception:
        return b""


def _read_binary_symbols(path: str) -> frozenset[str]:
    """
    Return the set of imported + exported symbol names from the binary.
    Empty set if LIEF is unavailable or parsing fails — in that case callers
    should skip symbol-based cross-checks rather than reject everything.
    """
    if not _LIEF_OK:
        return frozenset()
    try:
        parsed = _lief_parse_once(path)
        if parsed is None:
            return frozenset()
        names: set[str] = set()
        # ELF / PE / Mach-O all expose `.symbols` and `.imported_functions` /
        # `.imports`; we iterate whichever is present.
        for attr in ("symbols", "imported_functions", "exported_functions"):
            seq = getattr(parsed, attr, None)
            if not seq:
                continue
            for s in seq:
                try:
                    name = str(getattr(s, "name", "") or s)
                    if name:
                        names.add(name)
                except Exception:
                    continue
            if len(names) > 20000:
                break
        return frozenset(names)
    except Exception:
        return frozenset()


def _symbol_check_passes(product: str, symbols: frozenset[str]) -> bool:
    """
    True if the binary's symbols satisfy the cross-check for `product`.
    If no symbols were extractable (e.g. LIEF missing, stripped binary), we
    default to True rather than reject — better a labeled "lower confidence"
    match than no match at all.
    """
    needed = _REQUIRED_SYMBOLS.get(product)
    if not needed:
        return True                   # product doesn't use symbol gating
    if not symbols:
        return True                   # couldn't extract — don't over-reject
    # Substring match: any required prefix appearing anywhere in symbol names.
    for sym in symbols:
        for req in needed:
            if req in sym:
                return True
    return False


def detect_components(binary_path: str) -> list[dict]:
    """
    Detect which bundled OSS libraries and versions are present in a single
    native binary. Returns a list of
      {product, version, ecosystem, binary, confidence}
    where confidence is "high" (rodata + symbol check passed) or "medium"
    (fallback raw read, or symbol data unavailable).
    """
    haystack = _read_binary_strings(binary_path)
    if not haystack:
        return []
    symbols = _read_binary_symbols(binary_path)
    # Confidence is "high" when we got strings from LIEF sections AND we have
    # symbol visibility (so the cross-check is meaningful).
    base_confidence = "high" if (_LIEF_OK and symbols) else "medium"

    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for product, ecosystem, pattern, group in _VERSION_PATTERNS:
        for m in pattern.finditer(haystack):
            try:
                ver = m.group(group).decode("ascii", errors="ignore").strip()
            except Exception:
                continue
            if not ver or (product, ver) in seen:
                continue
            if not _symbol_check_passes(product, symbols):
                log.debug(
                    f"[{binary_path}] rejected {product}@{ver} — "
                    f"no matching symbols (likely a string quoted in unrelated code)"
                )
                continue
            seen.add((product, ver))
            found.append({
                "product":    product,
                "version":    ver,
                "ecosystem":  ecosystem,
                "binary":     os.path.basename(binary_path),
                "confidence": base_confidence,
            })
    return found


# ── OSV query ────────────────────────────────────────────────────────────────
def _query_osv(product: str, version: str, ecosystem: str) -> list[dict]:
    if not _HTTPX_OK:
        return []

    key = f"{ecosystem}|{product}|{version}"
    cached = _cache_get(key)
    if cached is not None:
        return cached.get("vulns", [])

    payload: dict = {"version": version}
    if ecosystem:
        payload["package"] = {"name": product, "ecosystem": ecosystem}
    else:
        # Generic search — OSV will try to match across CVE ecosystems.
        payload["package"] = {"name": product}

    try:
        r = httpx.post(OSV_URL, json=payload, timeout=OSV_TIMEOUT_S)
        if r.status_code != 200:
            return []
        data = r.json() or {}
        _cache_put(key, data)
        return data.get("vulns", []) or []
    except Exception as e:
        log.debug(f"OSV query failed for {product}@{version}: {e}")
        return []


def _extract_cvss(vuln: dict) -> tuple[float | None, str]:
    """Return (score, vector) from the first CVSS entry we recognise."""
    for sev in vuln.get("severity", []) or []:
        if sev.get("type", "").upper().startswith("CVSS"):
            try:
                # OSV stores the vector string; parse trailing /A:X – but we want
                # the numeric base score when published directly.
                vec = sev.get("score", "")
                # Some entries stash the numeric score in the 'score' field.
                if vec.replace(".", "").isdigit():
                    return float(vec), ""
                return None, vec
            except Exception:
                pass
    return None, ""


def _vuln_to_finding(vuln: dict, comp: dict, kev_set: set[str] | None = None) -> dict:
    cve_id = next(
        (a for a in (vuln.get("aliases") or []) if a.startswith("CVE-")),
        vuln.get("id") or "UNKNOWN",
    )
    score, vector = _extract_cvss(vuln)
    severity = _cvss_to_severity(score)
    summary = (vuln.get("summary") or "").strip()
    details = (vuln.get("details") or "").strip()

    # KEV overlay: bump severity + exploitability when CISA lists active exploitation.
    is_kev = bool(kev_set and cve_id in kev_set)
    if is_kev and severity in ("info", "low", "medium"):
        severity = "high"

    # Pick a fix version if OSV told us one.
    fix_version = None
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    fix_version = ev["fixed"]
                    break
            if fix_version: break
        if fix_version: break

    location = comp.get("binary") or comp.get("file") or ""
    title = f"Vulnerable Component: {comp['product']} {comp['version']} ({cve_id})"
    ecosystem_label = comp.get("ecosystem") or "native"
    desc_lines = [
        f"{'**[KEV — known exploited]** ' if is_kev else ''}"
        f"Bundled **{comp['product']}** version **{comp['version']}** "
        f"({ecosystem_label}, in `{location}`) is affected by {cve_id}.",
    ]
    if summary:
        desc_lines.append(summary)
    elif details:
        desc_lines.append(details[:500] + ("…" if len(details) > 500 else ""))
    if score is not None:
        desc_lines.append(f"CVSS: {score}")
    if vector:
        desc_lines.append(f"Vector: `{vector}`")
    if is_kev:
        desc_lines.append(
            "CISA has confirmed in-the-wild exploitation of this vulnerability. "
            "Treat as urgent regardless of CVSS score."
        )

    rec = (
        f"Upgrade bundled `{comp['product']}` to "
        f"{'version ' + fix_version + ' or newer' if fix_version else 'the latest patched release'}."
    )

    exploitability = 95 if is_kev else (70 if score and score >= 7 else 50)

    return {
        "title":          title,
        "severity":       severity,
        "category":       "Vulnerable Component",
        "description":    "\n\n".join(desc_lines),
        "recommendation": rec,
        "file_path":      location,
        "line":           0,
        "snippet":        f"{comp['product']} {comp['version']}",
        "confidence":     (
            85 if comp.get("ecosystem") in ("Maven", "CocoaPods")
            else 80 if comp.get("confidence") == "high"
            else 60
        ),
        "exploitability": exploitability,
        "source":         "CVE-MAP",
        "rule_id":        f"CVE-{comp['product'].upper()}",
        "cve":            cve_id,
        "cvss":           score,
        "fix_version":    fix_version,
        "kev":            is_kev,
        "cwe":            "CWE-1395",   # Dependency on vulnerable component
        "masvs":          "MASVS-CODE-2",
        "owasp":          "M8",
        "component": {
            "product":   comp["product"],
            "version":   comp["version"],
            "ecosystem": comp.get("ecosystem", ""),
            "binary":    location,
        },
    }


# ── Maven (AAR) scanner ──────────────────────────────────────────────────────
# Android apps often ship third-party AARs whose Maven coords leak into
# META-INF/maven/<groupId>/<artifactId>/pom.properties after build.
_POM_RE = re.compile(
    rb"^(groupId|artifactId|version)=(.+?)$",
    re.MULTILINE,
)

def scan_maven_packages(tmpdir: str) -> list[dict]:
    """
    Walk an extracted APK for META-INF/maven/*/*/pom.properties files and
    return a list of {product: 'groupId:artifactId', version, ecosystem: 'Maven', file}.
    """
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    try:
        for root, _dirs, files in os.walk(tmpdir):
            if "META-INF" not in root or "maven" not in root.lower():
                continue
            for fn in files:
                if fn != "pom.properties":
                    continue
                p = os.path.join(root, fn)
                try:
                    with open(p, "rb") as f:
                        body = f.read(32 * 1024)
                except Exception:
                    continue
                props: dict[str, str] = {}
                for m in _POM_RE.finditer(body):
                    key = m.group(1).decode("ascii", "ignore").strip()
                    val = m.group(2).decode("utf-8", "ignore").strip()
                    props[key] = val
                gid = props.get("groupId")
                aid = props.get("artifactId")
                ver = props.get("version")
                if not (gid and aid and ver):
                    continue
                product = f"{gid}:{aid}"
                key = (product, ver)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "product":   product,
                    "version":   ver,
                    "ecosystem": "Maven",
                    "file":      os.path.relpath(p, tmpdir).replace("\\", "/"),
                })
                if len(out) >= MAX_PACKAGES:
                    return out
    except Exception as e:
        log.debug(f"maven scan failed: {e}")
    return out


# ── CocoaPods / embedded framework scanner (iOS) ─────────────────────────────
def scan_cocoapods_frameworks(app_bundle: str) -> list[dict]:
    """
    Walk Frameworks/*.framework bundles. Each has Info.plist with
    CFBundleName + CFBundleShortVersionString (marketing version) which we
    map to the CocoaPods ecosystem on OSV.
    """
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    if not app_bundle or not os.path.isdir(app_bundle):
        return out

    fw_root = None
    for cand in ("Frameworks", "frameworks"):
        p = os.path.join(app_bundle, cand)
        if os.path.isdir(p):
            fw_root = p
            break
    if not fw_root:
        return out

    try:
        import plistlib
    except Exception:
        return out

    for entry in os.listdir(fw_root):
        if not entry.endswith(".framework"):
            continue
        fw_dir = os.path.join(fw_root, entry)
        plist_path = os.path.join(fw_dir, "Info.plist")
        if not os.path.isfile(plist_path):
            continue
        try:
            with open(plist_path, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            continue
        name = (pl.get("CFBundleName") or
                pl.get("CFBundleExecutable") or
                entry[:-len(".framework")])
        ver  = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion")
        if not (name and ver):
            continue
        key = (name, str(ver))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "product":   str(name),
            "version":   str(ver),
            "ecosystem": "CocoaPods",
            "file":      f"Frameworks/{entry}",
        })
        if len(out) >= MAX_PACKAGES:
            break
    return out


# ── CISA KEV (Known Exploited Vulnerabilities) ───────────────────────────────
_KEV_CACHE_KEY = "__KEV__"

def load_kev_set() -> set[str]:
    """
    Return the set of CVE IDs CISA has flagged as actively exploited in the wild.
    Cached for 24h; returns empty set on any error.
    """
    if not _HTTPX_OK:
        return set()
    try:
        cached = _cache_get(_KEV_CACHE_KEY)
        if cached and time.time() - cached.get("_fetched", 0) < KEV_TTL_S:
            return set(cached.get("cves", []))
    except Exception:
        pass

    try:
        r = httpx.get(KEV_URL, timeout=OSV_TIMEOUT_S)
        if r.status_code != 200:
            return set()
        data = r.json() or {}
        cves = [v.get("cveID") for v in (data.get("vulnerabilities") or []) if v.get("cveID")]
        payload = {"cves": cves, "_fetched": time.time()}
        _cache_put(_KEV_CACHE_KEY, payload)
        return set(cves)
    except Exception as e:
        log.debug(f"KEV fetch failed: {e}")
        return set()


# ── Public entry point ───────────────────────────────────────────────────────
def available() -> bool:
    return _HTTPX_OK


def _lookup_and_build(components: list[dict], kev_set: set[str]) -> tuple[list[dict], list[dict]]:
    """Given a list of raw components, query OSV for each and build findings."""
    # Dedupe on (product, version, ecosystem).
    unique: dict[tuple[str, str, str], dict] = {}
    for c in components:
        k = (c["product"], c["version"], c.get("ecosystem", ""))
        unique.setdefault(k, c)

    findings: list[dict] = []
    comp_list: list[dict] = []
    comps = list(unique.values())
    if not comps:
        return comp_list, findings

    deadline = time.time() + OSV_BUDGET_S
    results_by_key: dict[int, list[dict]] = {}

    def _task(idx_comp):
        idx, comp = idx_comp
        try:
            return idx, _query_osv(comp["product"], comp["version"], comp.get("ecosystem", ""))
        except Exception:
            return idx, []

    with ThreadPoolExecutor(max_workers=min(OSV_CONCURRENCY, max(1, len(comps)))) as ex:
        futures = [ex.submit(_task, (i, c)) for i, c in enumerate(comps)]
        for fut in as_completed(futures):
            remaining = deadline - time.time()
            if remaining <= 0:
                # Budget exhausted — cancel outstanding futures and bail.
                for f2 in futures:
                    f2.cancel()
                log.debug("OSV lookup budget exceeded; skipping remaining queries")
                break
            try:
                idx, vulns = fut.result(timeout=max(0.1, remaining))
                results_by_key[idx] = vulns or []
            except Exception:
                continue

    for idx, comp in enumerate(comps):
        vulns = results_by_key.get(idx, [])
        cve_count = 0
        kev_count = 0
        for v in vulns:
            try:
                f = _vuln_to_finding(v, comp, kev_set)
                findings.append(f)
                cve_count += 1
                if f.get("kev"):
                    kev_count += 1
            except Exception:
                pass
        comp_list.append({**comp, "cve_count": cve_count, "kev_count": kev_count})
    return comp_list, findings


def analyze_native_libs(binary_paths: Iterable[str]) -> dict:
    """
    Detect components and look up CVEs for up to MAX_BINARIES native binaries.
    """
    out = {"components": [], "findings": [], "stats": {}, "available": _HTTPX_OK}
    if not _HTTPX_OK:
        return out

    _init_cache()
    kev_set = load_kev_set()
    _lief_parse_once._cache = {}  # reset per-scan

    paths = list(binary_paths)[:MAX_BINARIES]
    components: list[dict] = []
    for p in paths:
        try:
            components.extend(detect_components(p))
        except Exception as e:
            log.debug(f"component detect failed on {p}: {e}")

    comp_list, findings = _lookup_and_build(components, kev_set)

    out["components"] = comp_list
    out["findings"]   = findings
    out["stats"] = {
        "binaries_scanned":    len(paths),
        "components_detected": len(comp_list),
        "cves_matched":        len(findings),
        "kev_matched":         sum(1 for f in findings if f.get("kev")),
        "source":              "native",
    }
    return out


# ── Coverage assessment (RUN 14) ─────────────────────────────────────────────
# "0 CVEs" is only a real negative if the scanner could actually have found one. Two ways it
# silently cannot:
#
#   1. THE ECOSYSTEM IS NOT IN OSV. Every dependency in a Flutter/iOS app is a CocoaPod, and OSV
#      has no CocoaPods ecosystem — so all 39 queries return empty BY CONSTRUCTION. Reporting
#      that as "no known vulnerabilities" is a clean bill of health the scan never earned.
#   2. THE VERSION IS A PLACEHOLDER. A Flutter plugin's framework Info.plist carries
#      CFBundleShortVersionString "0.0.1", not its real pub version, so even a supported
#      ecosystem could not match it.
#
# Rather than trust a hardcoded list of OSV ecosystems (which drifts, and which I would be
# asserting from memory), this CANARY-TESTS each ecosystem at scan time: query a package/version
# that is KNOWN to have advisories. If the canary comes back empty, that ecosystem is not
# answering, and every 0 from it is UNASSESSABLE — not a negative.
_OSV_CANARIES = {
    "npm":       ("lodash", "4.17.15"),
    "PyPI":      ("django", "2.2.0"),
    "Pub":       ("http", "0.13.0"),
    "Maven":     ("org.apache.logging.log4j:log4j-core", "2.14.1"),
    "Go":        ("github.com/gin-gonic/gin", "1.6.0"),
    "CocoaPods": ("Alamofire", "4.0.0"),
    "":          ("openssl", "1.0.2"),          # generic / no-ecosystem search
}
_PLACEHOLDER_VERSIONS = frozenset({"0.0.1", "0.0.0", "1.0", "1.0.0", "", "unknown"})


def ecosystem_answers(ecosystem: str) -> bool:
    """True when OSV returns real advisories for a KNOWN-vulnerable canary in this ecosystem.

    Cached like any other OSV query, so this costs one request per ecosystem per 24h.
    """
    canary = _OSV_CANARIES.get(ecosystem)
    if not canary:
        return False
    try:
        return bool(_query_osv(canary[0], canary[1], ecosystem))
    except Exception:
        return False


def assess_coverage(components: list[dict]) -> dict:
    """Is this scan's "0 CVEs" a real negative, or an empty pass? Say so explicitly."""
    ecosystems: dict[str, dict] = {}
    placeholder = 0
    for c in components or []:
        eco = str(c.get("ecosystem") or "")
        row = ecosystems.setdefault(eco, {"components": 0, "placeholder_versions": 0})
        row["components"] += 1
        if str(c.get("version") or "").strip() in _PLACEHOLDER_VERSIONS:
            row["placeholder_versions"] += 1
            placeholder += 1

    assessable = 0
    for eco, row in ecosystems.items():
        answers = ecosystem_answers(eco)
        row["osv_answers"] = answers
        # A component is assessable only if its ecosystem answers AND its version is real.
        row["assessable"] = (row["components"] - row["placeholder_versions"]) if answers else 0
        row["reason"] = ("" if answers else
                         f"OSV returned no advisories for a known-vulnerable canary in "
                         f"'{eco or 'generic'}' — this ecosystem is not covered, so a zero "
                         f"result here is NOT a clean bill of health.")
        assessable += row["assessable"]

    total = sum(r["components"] for r in ecosystems.values())
    return {
        "components_total": total,
        "assessable": assessable,
        "unassessable": total - assessable,
        "placeholder_versions": placeholder,
        "ecosystems": ecosystems,
        "verdict": (
            "no_coverage" if total and not assessable else
            "partial" if assessable < total else
            "full" if total else "no_components"
        ),
    }


def analyze_packages(components: list[dict]) -> dict:
    """
    Look up CVEs for already-extracted ecosystem packages (Maven AARs, CocoaPods
    frameworks, etc). Input is a list of {product, version, ecosystem, file}.
    """
    out = {"components": [], "findings": [], "stats": {}, "available": _HTTPX_OK}
    if not _HTTPX_OK or not components:
        return out

    _init_cache()
    kev_set = load_kev_set()

    # Rename 'file' to 'binary' for consistency with native path.
    norm = [{**c, "binary": c.get("binary") or c.get("file", "")} for c in components]
    comp_list, findings = _lookup_and_build(norm, kev_set)

    out["components"] = comp_list
    out["findings"]   = findings
    out["stats"] = {
        "packages_scanned":    len(components),
        "components_detected": len(comp_list),
        "cves_matched":        len(findings),
        "kev_matched":         sum(1 for f in findings if f.get("kev")),
        "source":              "packages",
    }
    return out


def merge_cve_results(*results: dict) -> dict:
    """Merge multiple analyze_* results into a single components/findings blob."""
    merged = {"components": [], "findings": [], "stats": {}, "available": False}
    for r in results:
        if not r:
            continue
        merged["components"].extend(r.get("components", []))
        merged["findings"].extend(r.get("findings", []))
        if r.get("available"):
            merged["available"] = True
        for k, v in (r.get("stats") or {}).items():
            if isinstance(v, int):
                merged["stats"][k] = merged["stats"].get(k, 0) + v
            else:
                merged["stats"].setdefault(k, v)
    # Dedupe findings on (cve, product, version)
    seen: set[tuple] = set()
    deduped = []
    for f in merged["findings"]:
        comp = f.get("component", {})
        key = (f.get("cve"), comp.get("product"), comp.get("version"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    merged["findings"] = deduped
    return merged
