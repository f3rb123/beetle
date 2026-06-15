import zipfile
import os
import re
import plistlib
import hashlib
import logging
import struct
import base64
import mimetypes
import tempfile
from pathlib import Path
from datetime import datetime
from collections import defaultdict

log = logging.getLogger("cortex.ios")

from .common import (
    scan_files_for_secrets, scan_text_for_secrets,
    extract_urls, sort_findings, SEVERITY_ORDER,
    normalize_severity, compute_severity_summary, dedupe_findings,
)
from . import scan_storage
from .code_analyzer import run_ios_sast
from .string_analyzer import analyze_strings
from .scoring import calculate_score
from .path_utils import relativize_path
from .virustotal import run_virustotal
from .evidence_scanner import (
    scan_directory_for_secrets as ev_scan_secrets,
    scan_directory_for_jwts,
    scan_directory_for_ips,
)
from .secret_validator import validate_secrets

# ─── iOS Permissions (Info.plist Usage Description keys) ────────────────────
IOS_PERMISSIONS = {
    "NSContactsUsageDescription":            ("medium", "Access to contacts"),
    "NSMicrophoneUsageDescription":          ("high",   "Microphone access"),
    "NSCameraUsageDescription":              ("medium", "Camera access"),
    "NSLocationWhenInUseUsageDescription":   ("medium", "Location when in use"),
    "NSLocationAlwaysUsageDescription":      ("high",   "Always-on background location"),
    "NSLocationAlwaysAndWhenInUseUsageDescription": ("high", "Full background location"),
    "NSPhotoLibraryUsageDescription":        ("low",    "Photo library read access"),
    "NSPhotoLibraryAddUsageDescription":     ("low",    "Photo library write access"),
    "NSHealthShareUsageDescription":         ("high",   "HealthKit read access"),
    "NSHealthUpdateUsageDescription":        ("high",   "HealthKit write access"),
    "NSMotionUsageDescription":              ("medium", "Motion and fitness sensors"),
    "NSFaceIDUsageDescription":              ("low",    "Face ID biometric"),
    "NSCalendarsUsageDescription":           ("medium", "Calendar access"),
    "NSRemindersUsageDescription":           ("low",    "Reminders access"),
    "NSSpeechRecognitionUsageDescription":   ("medium", "Speech recognition"),
    "NSBluetoothAlwaysUsageDescription":     ("medium", "Always-on Bluetooth"),
    "NSBluetoothPeripheralUsageDescription": ("medium", "Bluetooth peripheral"),
    "NSUserTrackingUsageDescription":        ("medium", "ATT cross-app tracking"),
    "NSLocalNetworkUsageDescription":        ("low",    "Local network access"),
}


def analyze_ipa(ipa_path: str, scan_id: str, filename: str) -> dict:
    results = {
        "scan_id":          scan_id,
        "filename":         filename,
        "platform":         "ios",
        "app_name":         Path(filename).stem,
        "app_info":         {},
        "findings":         [],
        "attack_surface":   {"url_schemes": [], "universal_links": [], "exported_handlers": []},
        "secrets":          [],
        "jwts":             [],
        "ips":              [],
        "endpoints":        [],
        "sdks":             [],
        "framework":        {"type": "native", "details": []},
        "permissions":      {"dangerous": [], "all": []},
        "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "scan_time":        datetime.utcnow().isoformat() + "Z",
        "certificate":      {},
        "binaries":         [],
        "string_analysis":  {},
        "file_inventory":   {"total_files": 0, "suspicious": []},
        "score":            {},
        # New deep-iOS fields
        "entitlements":     {},
        "embedded_frameworks": [],
        "swift_analysis":   {},
        "ios_data_storage": {},
        "ios_crypto":       {},
        "ios_webview":      {},
        "network_config":   {},
        "virustotal":       {},
        "quick_summary":    {},
    }

    with open(ipa_path, "rb") as f:
        data = f.read()
        results["app_info"]["sha256"] = hashlib.sha256(data).hexdigest()
        results["app_info"]["md5"]    = hashlib.md5(data).hexdigest()
        results["app_info"]["size_mb"] = round(len(data) / (1024 * 1024), 2)

    # Extract IPA directly into the persistent scan root so finding paths we
    # record stay resolvable by /api/scans/{id}/file after the scan completes.
    persistent_root = scan_storage.ensure_scan_root(scan_id) / "ipa_extract"
    persistent_root.mkdir(parents=True, exist_ok=True)
    tmpdir = str(persistent_root)

    if True:
        # ── Extract IPA ───────────────────────────────────────────────────────
        try:
            with zipfile.ZipFile(ipa_path, "r") as z:
                # Safe extract: skip zip entries with path traversal
                for member in z.infolist():
                    name = member.filename.replace("\\", "/")
                    if name.startswith("/") or ".." in name.split("/"):
                        continue
                    z.extract(member, tmpdir)
        except Exception as e:
            results["findings"].append({
                "title": "IPA Extraction Warning",
                "severity": "info",
                "category": "Meta",
                "description": str(e),
            })
            return results

        # ── Find .app bundle ──────────────────────────────────────────────────
        app_bundle = _find_app_bundle(tmpdir)

        # ── Info.plist ────────────────────────────────────────────────────────
        if app_bundle:
            plist_path = os.path.join(app_bundle, "Info.plist")
            if os.path.exists(plist_path):
                _analyze_info_plist(plist_path, results)
                _extract_ios_app_icon(app_bundle, plist_path, results)

            # ── Binary analysis ───────────────────────────────────────────────
            binary_name = results["app_info"].get("bundle_executable")
            if binary_name:
                binary_path = os.path.join(app_bundle, binary_name)
                if os.path.exists(binary_path):
                    _analyze_macho(binary_path, results)
                    _scan_binary_strings(binary_path, results, tmpdir)

        # ── Parallelize heavy independent scans to speed up iOS analysis.
        # Each module is CPU-bound on file IO + regex — running them on a
        # small thread pool overlaps their walks.
        from concurrent.futures import ThreadPoolExecutor as _TPE
        with _TPE(max_workers=7) as _pool:
            # Use evidence_scanner (richer, full CWE/MASVS/OWASP metadata)
            # in addition to the legacy common.py scanner so iOS gets the same
            # quality secret detection as Android.
            _fut_secrets_ev = _pool.submit(ev_scan_secrets, tmpdir)
            _fut_secrets_lg = _pool.submit(scan_files_for_secrets, tmpdir, [
                ".plist", ".json", ".xml", ".strings", ".js", ".swift",
                ".m", ".h", ".txt", ".yml", ".yaml", ".cfg",
            ])
            _fut_jwts = _pool.submit(scan_directory_for_jwts, tmpdir)
            _fut_ips  = _pool.submit(scan_directory_for_ips, tmpdir)
            _fut_endpoints = _pool.submit(_extract_endpoints, tmpdir, results)
            _fut_strings = _pool.submit(analyze_strings, tmpdir, "ios")
            _fut_sast = _pool.submit(run_ios_sast, tmpdir, results)
            _fut_framework = _pool.submit(_detect_framework, app_bundle or tmpdir, results)

            # Merge evidence_scanner secrets (richer) with legacy scan (broader)
            ev_secrets_out = _fut_secrets_ev.result() or []
            lg_secrets_out = _fut_secrets_lg.result() or []
            # Dedup: evidence_scanner results take priority (better metadata)
            _seen_secrets: set[tuple] = set()
            merged_secrets = []
            for s in ev_secrets_out:
                k = (s.get("name", ""), s.get("value", "")[:80])
                if k not in _seen_secrets:
                    _seen_secrets.add(k)
                    merged_secrets.append(s)
            for s in lg_secrets_out:
                k = (s.get("name", ""), s.get("value", "")[:80])
                if k not in _seen_secrets:
                    _seen_secrets.add(k)
                    merged_secrets.append(s)
            results["secrets"] = merged_secrets

            results["jwts"] = _fut_jwts.result() or []
            results["ips"]  = _fut_ips.result() or []
            _fut_endpoints.result()
            results["string_analysis"] = _fut_strings.result() or {}
            _fut_sast.result()
            _fut_framework.result()

        # ── Cross-dedup: remove JWT values already in jwts section ────────────
        jwt_values = {j["value"] for j in results.get("jwts", []) if j.get("value")}
        if jwt_values:
            results["secrets"] = [
                s for s in results["secrets"]
                if s.get("value", "") not in jwt_values
            ]

        # ── JWT findings ──────────────────────────────────────────────────────
        for jwt in results.get("jwts", []):
            results["findings"].append({
                "title":             "Hardcoded JWT Token",
                "severity":          "high",
                "category":          "Auth Token",
                "description":       "A hardcoded JWT token is embedded in the IPA. This may allow authentication as the associated user/service.",
                "recommendation":    "Invalidate this token immediately. Never hardcode auth tokens in client apps.",
                "file_path":         jwt.get("file_path", ""),
                "line":              jwt.get("line", 0),
                "snippet":           jwt.get("snippet", ""),
                "code_context":      jwt.get("code_context", ""),
                "file_evidence":     jwt.get("file_evidence", []),
                "confidence":        90,
                "exploitability":    80,
                "validation_status": "validated",
                "source":            "JWT_SCANNER",
                "cwe":               "CWE-798",
                "masvs":             "MASVS-CRYPTO-2",
                "owasp":             "M1",
                "value":             jwt.get("value", ""),
            })

        # ── IP findings ───────────────────────────────────────────────────────
        public_ips = [ip for ip in results.get("ips", []) if ip.get("type") == "public"]
        if public_ips:
            results["findings"].append({
                "title":             f"Hardcoded Public IP Addresses ({len(public_ips)} found)",
                "severity":          "low",
                "category":          "Configuration",
                "description":       f"Public IP addresses hardcoded in app: {', '.join(set(ip['ip'] for ip in public_ips[:5]))}.",
                "recommendation":    "Use domain names instead of IP addresses.",
                "file_path":         public_ips[0].get("file_path", ""),
                "line":              public_ips[0].get("line", 0),
                "cwe":               "CWE-547",
                "masvs":             "MASVS-CODE-4",
                "owasp":             "M8",
            })

        # ── Secret validation ─────────────────────────────────────────────────
        try:
            results["secrets"] = validate_secrets(results.get("secrets", []))
        except Exception:
            pass

        # ── ATS check (depends on Info.plist parse earlier) ──────────────────
        _check_ats(results)

        # ── Entitlements ─────────────────────────────────────────────────────
        if app_bundle:
            _analyze_entitlements(app_bundle, results)

        # ── Embedded Frameworks ──────────────────────────────────────────────
        if app_bundle:
            _analyze_embedded_frameworks(app_bundle, results)

        # ── Overlap the remaining independent scans ─────────────────────────
        from concurrent.futures import ThreadPoolExecutor as _TPE
        with _TPE(max_workers=5) as _pool:
            _futs = [
                _pool.submit(_analyze_swift_objc_sources, tmpdir, results),
                _pool.submit(_analyze_ios_data_storage, tmpdir, results),
                _pool.submit(_analyze_ios_crypto, tmpdir, results),
                _pool.submit(_analyze_ios_webview, tmpdir, results),
                _pool.submit(_build_ios_file_inventory, tmpdir, results),
            ]
            for _f in _futs:
                try:
                    _f.result()
                except Exception:
                    pass

        # ── Mach-O deep binary protection check ──────────────────────────────
        if app_bundle:
            binary_name = results["app_info"].get("bundle_executable")
            if binary_name:
                binary_path = os.path.join(app_bundle, binary_name)
                if os.path.exists(binary_path):
                    _analyze_macho_deep(binary_path, results)

        # ── LIEF deep Mach-O scan of every binary in the .app ────────────────
        try:
            from . import lief_analyzer
            if app_bundle and lief_analyzer.available():
                lief_results = lief_analyzer.analyze_all_macho(app_bundle)
                if lief_results:
                    lief_findings = []
                    objc_class_count = 0
                    inst_hits = []
                    for r in lief_results:
                        lief_findings.extend(r.get("findings", []))
                        objc_class_count += len(r.get("objc_classes", []))
                        for f in r.get("findings", []):
                            if f.get("rule_id") == "macho_instrumentation_dylib":
                                inst_hits.append(r.get("binary"))
                    results["findings"].extend(lief_findings)
                    results["lief_macho"] = {
                        "binaries_scanned": len(lief_results),
                        "objc_class_total": objc_class_count,
                        "instrumentation_hits": inst_hits,
                    }
        except Exception as _e:
            log.debug(f"lief macho scan failed: {_e}")

        # ── CVE mapping: native Mach-O + CocoaPods frameworks ────────────────
        try:
            from . import cve_mapper
            if app_bundle and cve_mapper.available():
                # Collect Mach-O candidates (main executable + frameworks + dylibs)
                macho_paths: list[str] = []
                for root, _dirs, files in os.walk(app_bundle):
                    low_root = root.lower()
                    for fn in files:
                        p = os.path.join(root, fn)
                        low = fn.lower()
                        if (low.endswith(".dylib") or
                                ".framework" in low_root or
                                "/frameworks/" in low_root):
                            macho_paths.append(p)
                    if len(macho_paths) >= 60:
                        break

                native_out = cve_mapper.analyze_native_libs(macho_paths) if macho_paths else None
                pod_comps  = cve_mapper.scan_cocoapods_frameworks(app_bundle)
                pod_out    = cve_mapper.analyze_packages(pod_comps) if pod_comps else None
                merged     = cve_mapper.merge_cve_results(native_out, pod_out)
                if merged.get("findings"):
                    results["findings"].extend(merged["findings"])
                results["components"] = merged.get("components", [])
                results["cve_stats"]  = merged.get("stats", {})
        except Exception as _e:
            log.debug(f"cve mapping failed: {_e}")

        # ── JS bundle scan (React Native / Cordova / Capacitor) ───────────────
        try:
            from . import js_bundle_analyzer
            js_out = js_bundle_analyzer.analyze_js_bundles(tmpdir)
            if js_out.get("findings"):
                results["findings"].extend(js_out["findings"])
            if js_out.get("secrets"):
                results.setdefault("secrets", []).extend(js_out["secrets"])
            if js_out.get("framework", {}).get("type") and not results.get("framework", {}).get("type"):
                results["framework"] = js_out["framework"]
            results["js_bundles"] = js_out.get("bundles", [])
        except Exception as _e:
            log.debug(f"js bundle scan failed: {_e}")

    # ── Live cloud misconfig probes (Firebase + S3) ───────────────────────────
    try:
        from .live_checks import check_firebase_db, check_s3_buckets
        check_firebase_db(results)
        check_s3_buckets(results)
    except Exception:
        pass

    # ── VirusTotal hash lookup ────────────────────────────────────────────────
    try:
        run_virustotal(str(ipa_path), results)
    except Exception:
        results.setdefault("virustotal", {})

    # ── Severity summary ──────────────────────────────────────────────────────
    # Dedupe BEFORE sorting / summary / scoring so all three agree.
    results["findings"] = dedupe_findings(results["findings"])
    results["findings"] = sort_findings(results["findings"])
    results["severity_summary"] = compute_severity_summary(results["findings"])

    # ── Quick summary ─────────────────────────────────────────────────────────
    _build_ios_quick_summary(results)

    # ── Security Score ────────────────────────────────────────────────────────
    results["score"] = calculate_score(results)

    return results


# ─── Info.plist ───────────────────────────────────────────────────────────────
def _analyze_info_plist(plist_path: str, results: dict):
    try:
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)
    except Exception:
        try:
            # Try XML plist
            with open(plist_path, "r", errors="replace") as f:
                content = f.read()
            plist = plistlib.loads(content.encode())
        except Exception as e:
            results["findings"].append({
                "title": "Info.plist Parse Error",
                "severity": "info",
                "category": "Meta",
                "description": str(e),
            })
            return

    # ── App info ──────────────────────────────────────────────────────────────
    bundle_id = plist.get("CFBundleIdentifier", "")
    app_name  = plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or Path(plist_path).parent.name
    version   = plist.get("CFBundleShortVersionString", "?")
    build     = plist.get("CFBundleVersion", "?")
    exe       = plist.get("CFBundleExecutable", "")
    min_ios   = plist.get("MinimumOSVersion") or plist.get("LSMinimumSystemVersion", "?")

    results["app_name"] = app_name
    results["app_info"].update({
        "bundle_id":         bundle_id,
        "app_name":          app_name,
        "version":           version,
        "build":             build,
        "min_ios":           min_ios,
        "bundle_executable": exe,
        "platform":          "iOS",
    })

    # ── Permissions ───────────────────────────────────────────────────────────
    dangerous = []
    all_perms = []
    for key, (sev, desc) in IOS_PERMISSIONS.items():
        if key in plist:
            all_perms.append(key)
            dangerous.append({"permission": key, "short_name": key.replace("NS", "").replace("UsageDescription", ""),
                               "severity": sev, "description": desc})

    results["permissions"]["all"]       = all_perms
    results["permissions"]["dangerous"] = dangerous

    # ── URL Schemes ───────────────────────────────────────────────────────────
    url_types = plist.get("CFBundleURLTypes", [])
    for url_type in url_types:
        schemes = url_type.get("CFBundleURLSchemes", [])
        for scheme in schemes:
            results["attack_surface"]["url_schemes"].append(scheme)
            if scheme.lower() not in ("http", "https"):
                results["findings"].append({
                    "title":          f"Custom URL Scheme Registered — {scheme}://",
                    "severity":       "medium",
                    "category":       "Deeplinks",
                    "description":    f"App registers custom URL scheme `{scheme}://`. Any app on the device can open this scheme. "
                                      "Without Universal Links, there is no app ownership verification.",
                    "impact":         "Malicious app can register same scheme and intercept deeplink data including OAuth callbacks.",
                    "poc":            f"# Test from Safari or another app:\njavascript:window.location='{scheme}://test/path?param=value'\n\n# Or via app:\nUIApplication.shared.open(URL(string:\"{scheme}://\")!)",
                    "recommendation": "Migrate to Universal Links (HTTPS-based) with apple-app-site-association file. Validate all incoming URL parameters.",
                })

    # ── Universal Links / Associated Domains ─────────────────────────────────
    entitlements_ref = plist.get("Entitlements", {})
    assoc_domains = entitlements_ref.get("com.apple.developer.associated-domains", [])
    results["attack_surface"]["universal_links"] = assoc_domains

    # ── ATS Configuration ─────────────────────────────────────────────────────
    ats = plist.get("NSAppTransportSecurity", {})
    results["app_info"]["ats"] = ats

    if ats.get("NSAllowsArbitraryLoads"):
        results["findings"].append({
            "title":          "ATS Fully Disabled — All HTTP Connections Allowed",
            "severity":       "high",
            "category":       "Network Security",
            "description":    "NSAllowsArbitraryLoads is set to true in Info.plist. App Transport Security is fully disabled, allowing all HTTP connections.",
            "impact":         "App can communicate over unencrypted HTTP to any host. Enables MitM on any connection.",
            "recommendation": "Remove NSAllowsArbitraryLoads. Use NSExceptionDomains for specific exceptions. Migrate all connections to HTTPS.",
        })
    elif ats.get("NSAllowsArbitraryLoadsInWebContent"):
        results["findings"].append({
            "title":          "ATS Disabled for Web Content",
            "severity":       "medium",
            "category":       "Network Security",
            "description":    "NSAllowsArbitraryLoadsInWebContent is enabled. HTTP connections allowed within WKWebView.",
            "recommendation": "Restrict to HTTPS. Use WKContentRuleList to enforce HTTPS upgrade.",
        })

    exception_domains = ats.get("NSExceptionDomains", {})
    for domain, config in exception_domains.items():
        if config.get("NSExceptionAllowsInsecureHTTPLoads"):
            results["findings"].append({
                "title":          f"ATS Exception — HTTP Allowed for {domain}",
                "severity":       "low",
                "category":       "Network Security",
                "description":    f"ATS exception permits insecure HTTP connections to `{domain}`.",
                "recommendation": f"Migrate {domain} to HTTPS and remove the ATS exception.",
            })

    # ── Dangerous plist flags ─────────────────────────────────────────────────
    if plist.get("NSBluetoothAlwaysUsageDescription") and plist.get("NSLocationAlwaysUsageDescription"):
        results["findings"].append({
            "title":          "Background Bluetooth + Location — Privacy Risk",
            "severity":       "medium",
            "category":       "Permissions",
            "description":    "App requests both always-on Bluetooth and location access, enabling persistent background tracking.",
            "recommendation": "Evaluate if both background permissions are truly required. Provide clear user disclosure.",
        })

    if plist.get("NSUserTrackingUsageDescription"):
        results["findings"].append({
            "title":          "App Tracking Transparency (ATT) Requested",
            "severity":       "info",
            "category":       "Privacy",
            "description":    "App requests cross-app tracking permission via ATT framework.",
            "recommendation": "Ensure tracking data handling complies with App Store privacy nutrition labels.",
        })


# ─── Mach-O Binary Analysis ───────────────────────────────────────────────────
def _analyze_macho(binary_path: str, results: dict):
    try:
        with open(binary_path, "rb") as f:
            data = f.read()

        if len(data) < 4:
            return

        magic = struct.unpack("<I", data[:4])[0]
        is_macho = magic in (0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xBEBAFECA,
                             0xCEFAEDFE, 0xCFFAEDFE)

        if not is_macho:
            return

        # Check for stack canary (___stack_chk_guard symbol)
        has_stack_canary = b"___stack_chk_guard" in data or b"__stack_chk_guard" in data
        # Check for ARC (objc_release)
        has_arc = b"_objc_release" in data
        # Check for PIE (hard to detect from binary directly without full parsing)
        # Check for encryption (LC_ENCRYPTION_INFO)
        has_pie_flag = b"__PIE__" in data or b"-pie" in data.lower() if hasattr(data, 'lower') else False
        # Check for restricted segments
        has_rpath = b"LC_RPATH" in data or b"@rpath" in data

        protections = {
            "stack_canary": has_stack_canary,
            "arc":          has_arc,
            "rpath":        has_rpath,
        }
        results["app_info"]["binary_protections"] = protections

        if not has_stack_canary:
            results["findings"].append({
                "title":          "Stack Canary Not Detected",
                "severity":       "low",
                "category":       "Binary Hardening",
                "description":    "Stack canary protection was not detected in the binary. This increases the risk of stack buffer overflow exploitation.",
                "recommendation": "Compile with -fstack-protector-all flag. Ensure iOS deployment target is set correctly.",
            })

        if not has_arc:
            results["findings"].append({
                "title":          "ARC (Automatic Reference Counting) Not Detected",
                "severity":       "low",
                "category":       "Binary Hardening",
                "description":    "ARC was not detected. Manual memory management increases risk of use-after-free and memory corruption.",
                "recommendation": "Enable ARC in Xcode build settings.",
            })

        if has_rpath:
            results["findings"].append({
                "title":          "@rpath — Dylib Hijacking Risk",
                "severity":       "medium",
                "category":       "Binary Hardening",
                "description":    "Binary uses @rpath for dynamic library loading. If a writable rpath directory is found, dylib hijacking may be possible.",
                "poc":            "# Check rpath:\notool -l <binary> | grep -A2 LC_RPATH",
                "recommendation": "Use @executable_path or @loader_path with absolute paths. Audit all rpath entries.",
            })

        results["findings"].append({
            "title":          "Binary Hardening Analysis Complete",
            "severity":       "info",
            "category":       "Binary Hardening",
            "description":    f"Stack canary: {'✓' if has_stack_canary else '✗'} | ARC: {'✓' if has_arc else '✗'} | @rpath: {'present' if has_rpath else 'not found'}",
        })

    except Exception:
        pass


# ─── Binary strings scan ──────────────────────────────────────────────────────
def _scan_binary_strings(binary_path: str, results: dict, base_dir: str = ""):
    try:
        with open(binary_path, "rb") as f:
            raw = f.read()
        text = "".join(chr(b) if 32 <= b < 127 else " " for b in raw)
        seen = {f"{s['name']}:{s['value']}" for s in results["secrets"]}
        rel_path = relativize_path(binary_path, base_dir) if base_dir else binary_path
        for s in scan_text_for_secrets(text, rel_path):
            key = f"{s['name']}:{s['value']}"
            if key not in seen:
                seen.add(key)
                results["secrets"].append(s)
    except Exception:
        pass


# ─── Endpoint extraction ──────────────────────────────────────────────────────
def _extract_endpoints(tmpdir: str, results: dict):
    all_urls = set()
    for root, _, files in os.walk(tmpdir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
                for url in extract_urls(content):
                    all_urls.add(url)
            except Exception:
                continue
    results["endpoints"] = sorted(list(all_urls))[:200]


# ─── Framework detection ──────────────────────────────────────────────────────
def _detect_framework(app_bundle: str, results: dict):
    if not app_bundle or not os.path.exists(app_bundle):
        return

    files = set()
    for root, _, fnames in os.walk(app_bundle):
        for f in fnames:
            files.add(f.lower())

    fw_type  = "native"
    details  = []

    # Flutter
    if "flutter_assets" in os.listdir(app_bundle) if os.path.exists(app_bundle) else []:
        fw_type = "flutter"
        details.append("Flutter detected via flutter_assets directory")
        results["findings"].append({
            "title":          "Flutter Framework Detected",
            "severity":       "info",
            "category":       "Framework",
            "description":    "iOS app is built with Flutter (Dart compiled to native). Standard SSL pinning bypass may fail. Custom Frida hooks targeting ssl_crypto_x509_session_verify_cert_chain in libflutter.dylib required.",
            "poc":            "# Frida hook for Flutter SSL on iOS:\nfrida -U -l flutter_ssl_hook.js -f <bundle_id>",
            "recommendation": "N/A — informational framework note for analyst.",
        })

    # React Native
    if any("main.jsbundle" in f or "index.ios.bundle" in f for f in files):
        fw_type = "react_native"
        details.append("React Native detected via JS bundle")
        results["findings"].append({
            "title":          "React Native Framework Detected",
            "severity":       "info",
            "category":       "Framework",
            "description":    "iOS app built with React Native. JS bundle accessible from IPA for direct analysis.",
            "recommendation": "Audit JS bundle for hardcoded secrets and API endpoints.",
        })

    # Cordova
    if any("cordova.js" in f for f in files):
        fw_type = "cordova"
        details.append("Cordova detected via cordova.js")
        results["findings"].append({
            "title":          "Cordova/Ionic Hybrid Framework",
            "severity":       "medium",
            "category":       "Framework",
            "description":    "App uses Cordova/Ionic. Full HTML/JS source is directly readable from the IPA.",
            "recommendation": "Minify and obfuscate all JS. Move sensitive logic server-side.",
        })

    results["framework"] = {"type": fw_type, "details": details}


# ─── ATS follow-up checks ─────────────────────────────────────────────────────
def _check_ats(results: dict):
    ats = results["app_info"].get("ats", {})
    if not ats:
        results["findings"].append({
            "title":          "ATS Configuration Not Found",
            "severity":       "info",
            "category":       "Network Security",
            "description":    "No explicit ATS configuration found in Info.plist. Default ATS settings apply (HTTPS required).",
        })


# ─── Find .app bundle ─────────────────────────────────────────────────────────
def _find_app_bundle(tmpdir: str) -> str | None:
    payload_dir = os.path.join(tmpdir, "Payload")
    if os.path.exists(payload_dir):
        for item in os.listdir(payload_dir):
            if item.endswith(".app"):
                return os.path.join(payload_dir, item)
    # Fallback: search recursively
    for root, dirs, _ in os.walk(tmpdir):
        for d in dirs:
            if d.endswith(".app"):
                return os.path.join(root, d)
    return None


def _extract_ios_app_icon(app_bundle: str, plist_path: str, results: dict):
    """Extract an app icon from, in priority order:

      1) iTunesArtwork / iTunesArtwork@2x (legacy, full-res, best quality)
      2) CFBundleIcons -> CFBundlePrimaryIcon -> CFBundleIconFiles (from Info.plist)
      3) Any *.appiconset/*.png generated by Xcode asset catalogs
      4) Heuristic walk for AppIcon*.png / Icon*.png / *icon*.png
      5) Largest PNG inside Assets.car adjacent file if `actool`/`acextract` is
         not available we simply note it — exposes why icon is missing instead
         of silently failing.
    """
    if not app_bundle or not os.path.exists(app_bundle):
        return

    def _emit(raw: bytes, src_path: str) -> bool:
        if not raw or len(raw) > 1_500_000:
            return False
        # Quick PNG / JPEG magic sniff
        is_png = raw[:8] == b"\x89PNG\r\n\x1a\n"
        is_jpg = raw[:3] == b"\xff\xd8\xff"
        if not (is_png or is_jpg):
            return False
        mime = "image/png" if is_png else "image/jpeg"
        encoded = base64.b64encode(raw).decode("ascii")
        results["app_info"]["icon_data"] = f"data:{mime};base64,{encoded}"
        try:
            results["app_info"]["icon_path"] = os.path.relpath(src_path, app_bundle).replace("\\", "/")
        except ValueError:
            results["app_info"]["icon_path"] = os.path.basename(src_path)
        results["app_info"]["icon_source"] = "ipa"
        return True

    # (1) iTunesArtwork — present in older distribution formats
    for artwork in ("iTunesArtwork@2x", "iTunesArtwork"):
        candidate = os.path.join(os.path.dirname(app_bundle), artwork)
        if os.path.isfile(candidate):
            try:
                if _emit(Path(candidate).read_bytes(), candidate):
                    return
            except Exception:
                pass

    # (2) Info.plist CFBundleIcons
    try:
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)
    except Exception:
        plist = {}

    icon_candidates: list[str] = []
    for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        primary = ((plist.get(key) or {}).get("CFBundlePrimaryIcon") or {})
        files = primary.get("CFBundleIconFiles") or []
        if isinstance(files, str):
            files = [files]
        for icon_name in files:
            name = str(icon_name)
            for suffix in ("", ".png", "@2x.png", "@3x.png",
                           "-60.png", "-60@2x.png", "-60@3x.png",
                           "-76.png", "-76@2x.png",
                           "-83.5@2x.png", "-1024.png"):
                icon_candidates.append(os.path.join(app_bundle, name + suffix))

    # (3) + (4) heuristic walk — collect PNGs by size, prefer largest
    heuristic: list[tuple[int, str]] = []
    for root, _, filenames in os.walk(app_bundle):
        low_root = root.lower()
        for filename in filenames:
            lower = filename.lower()
            if not (lower.endswith(".png") or lower.endswith(".jpg")):
                continue
            if ("appicon" in lower or lower.startswith("icon") or
                    "appicon.appiconset" in low_root):
                full = os.path.join(root, filename)
                try:
                    heuristic.append((os.path.getsize(full), full))
                except OSError:
                    continue

    # Try explicit candidates first (plist-declared).
    seen = set()
    for candidate in icon_candidates:
        if candidate in seen or not os.path.isfile(candidate):
            continue
        seen.add(candidate)
        try:
            if _emit(Path(candidate).read_bytes(), candidate):
                return
        except Exception:
            continue

    # Then largest heuristic match.
    for _, path in sorted(heuristic, reverse=True):
        if path in seen:
            continue
        try:
            if _emit(Path(path).read_bytes(), path):
                return
        except Exception:
            continue

    # (5) Record why icon couldn't be extracted — e.g. icon lives in Assets.car
    assets_car = os.path.join(app_bundle, "Assets.car")
    if os.path.isfile(assets_car):
        results["app_info"]["icon_source"] = "assets_car_unsupported"
        results["app_info"]["icon_note"] = (
            "App icon is embedded in compiled Assets.car. "
            "Install `assetutil` (macOS) or `acextract` to extract PNGs."
        )


# ─── embedded.mobileprovision certificate parsing ────────────────────────────
def _parse_mobileprovision_certs(raw: bytes) -> list[dict]:
    """Extract leaf certificate metadata from the CMS/PKCS#7 envelope.

    Returns [] when the `cryptography` library is unavailable or the blob is
    not a valid PKCS#7 container.
    """
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        from cryptography.hazmat.primitives import hashes
    except Exception:
        return []

    certs = []
    try:
        try:
            certs = pkcs7.load_der_pkcs7_certificates(raw)
        except Exception:
            certs = pkcs7.load_pem_pkcs7_certificates(raw)
    except Exception:
        return []

    result = []
    for c in certs or []:
        try:
            entry = {
                "subject": c.subject.rfc4514_string(),
                "issuer":  c.issuer.rfc4514_string(),
                "serial":  f"{c.serial_number:x}",
                "not_before": c.not_valid_before.isoformat() + "Z",
                "not_after":  c.not_valid_after.isoformat() + "Z",
                "sha1": c.fingerprint(hashes.SHA1()).hex(),
                "sha256": c.fingerprint(hashes.SHA256()).hex(),
            }
        except Exception:
            continue
        result.append(entry)
    return result


# ─── Entitlements ─────────────────────────────────────────────────────────────
def _analyze_entitlements(app_bundle: str, results: dict):
    """
    Parse entitlements from embedded.mobileprovision (XML portion) and
    from binary entitlement blobs. Flags dangerous entitlements.
    """
    entitlements = {}

    # Method 1: embedded.mobileprovision (contains a plist in a CMS envelope)
    prov_path = os.path.join(app_bundle, "embedded.mobileprovision")
    if os.path.exists(prov_path):
        try:
            raw = Path(prov_path).read_bytes()
            # ── 1a) XML plist portion (entitlements, team, expiry, etc.) ─────
            start = raw.find(b"<?xml")
            end   = raw.find(b"</plist>")
            if start != -1 and end != -1:
                plist_bytes = raw[start:end + len(b"</plist>")]
                prov_plist  = plistlib.loads(plist_bytes)
                entitlements = prov_plist.get("Entitlements", {})
                results["app_info"]["provisioning_team"]    = prov_plist.get("TeamName", "")
                results["app_info"]["provisioning_type"]    = "development" if prov_plist.get("ProvisionedDevices") else "distribution"
                results["app_info"]["provisioning_expiry"]  = str(prov_plist.get("ExpirationDate", ""))
                results["app_info"]["provisioning_profile"] = prov_plist.get("Name", "")
                # Expiry warning
                try:
                    exp = prov_plist.get("ExpirationDate")
                    if exp and hasattr(exp, "timestamp"):
                        from datetime import datetime, timezone
                        delta = exp.timestamp() - datetime.now(timezone.utc).timestamp()
                        days = int(delta // 86400)
                        if days < 0:
                            results["findings"].append({
                                "title":   "Provisioning Profile Expired",
                                "severity": "high",
                                "category": "Code Signing",
                                "description": f"Provisioning profile expired {abs(days)} days ago ({exp}).",
                                "recommendation": "Re-sign the app with a valid provisioning profile before distribution.",
                                "file_path": "embedded.mobileprovision",
                                "cwe": "CWE-298",
                                "masvs": "MASVS-CODE-1",
                            })
                        elif days < 30:
                            results["findings"].append({
                                "title":   f"Provisioning Profile Expires in {days} days",
                                "severity": "low",
                                "category": "Code Signing",
                                "description": f"Profile expires {exp}. Refresh before release.",
                                "recommendation": "Regenerate the provisioning profile.",
                                "file_path": "embedded.mobileprovision",
                            })
                except Exception:
                    pass

            # ── 1b) PKCS#7 certificate chain — full leaf cert details ────────
            certs = _parse_mobileprovision_certs(raw)
            if certs:
                results["app_info"]["signing_certificates"] = certs
                leaf = certs[0]
                results["app_info"]["signing_cert_subject"] = leaf.get("subject", "")
                results["app_info"]["signing_cert_sha1"]    = leaf.get("sha1", "")
                results["app_info"]["signing_cert_expiry"]  = leaf.get("not_after", "")
                # Developer cert in a release build is a smell
                subj_lower = leaf.get("subject", "").lower()
                if "iphone developer" in subj_lower or "apple development" in subj_lower:
                    if not prov_plist.get("ProvisionedDevices"):
                        # distribution-tagged but dev cert — mismatch
                        results["findings"].append({
                            "title":   "Development Certificate on Distribution Profile",
                            "severity": "medium",
                            "category": "Code Signing",
                            "description": (
                                "Leaf signing certificate is a development cert "
                                f"(\"{leaf.get('subject','')}\") but the provisioning profile "
                                "has no ProvisionedDevices — indicates misconfigured or re-signed build."
                            ),
                            "recommendation": "Sign release builds with a Distribution certificate. Verify code-signing pipeline.",
                            "file_path": "embedded.mobileprovision",
                            "cwe": "CWE-295",
                            "masvs": "MASVS-CODE-1",
                        })
        except Exception:
            pass

    # Method 2: look for .xcent or Entitlements.plist in bundle
    for fname in ("Entitlements.plist", "archived-expanded-entitlements.xcent"):
        fpath = os.path.join(app_bundle, fname)
        if os.path.exists(fpath):
            try:
                with open(fpath, "rb") as f:
                    entitlements = plistlib.load(f)
                break
            except Exception:
                pass

    if not entitlements:
        return

    results["entitlements"] = entitlements

    # ── Flag dangerous entitlements ───────────────────────────────────────────
    DANGEROUS_ENTITLEMENTS = {
        "com.apple.security.cs.disable-library-validation": (
            "high", "Library Validation Disabled",
            "Any dylib can be injected into this process without signature checking.",
            "Enable library validation. Use @executable_path for all dylib loads.",
        ),
        "com.apple.security.cs.allow-unsigned-executable-memory": (
            "high", "Unsigned Executable Memory Allowed",
            "Process can map and execute unsigned memory pages — disables W^X protection.",
            "Remove this entitlement. Rewrite JIT-dependent code to use approved APIs.",
        ),
        "com.apple.security.cs.allow-dyld-environment-variables": (
            "medium", "DYLD Environment Variables Allowed",
            "DYLD_INSERT_LIBRARIES and other environment overrides can be used to inject code.",
            "Remove this entitlement unless absolutely required for a development build.",
        ),
        "com.apple.security.get-task-allow": (
            "medium", "Debuggable Process (get-task-allow)",
            "Process allows other processes to attach a debugger — should not be in production.",
            "Remove get-task-allow from release builds. Present only in development profiles.",
        ),
        "com.apple.security.network.server": (
            "low", "App Acts as Network Server",
            "App has entitlement to bind to network ports and accept incoming connections.",
            "Validate that server capability is intentional and restricted to loopback if possible.",
        ),
        "com.apple.private.security.no-sandbox": (
            "critical", "Sandbox Disabled",
            "App runs without the iOS/macOS sandbox, with unrestricted filesystem and IPC access.",
            "This entitlement is reserved for Apple system processes. Presence indicates a jailbreak or compromise.",
        ),
        "com.apple.security.app-sandbox": (
            None, None, None, None  # GOOD — skip
        ),
        "keychain-access-groups": (
            "info", "Keychain Access Groups Declared",
            "App shares Keychain items with other apps in the listed access groups.",
            "Audit keychain access group membership for least-privilege.",
        ),
        "aps-environment": (
            "info", "Push Notification Environment Declared",
            "App is registered for push notifications in this environment.",
            "Verify the environment (development vs production) matches the release type.",
        ),
    }

    for key, value in entitlements.items():
        if key not in DANGEROUS_ENTITLEMENTS:
            continue
        sev, title, description, recommendation = DANGEROUS_ENTITLEMENTS[key]
        if sev is None:
            continue  # positive entitlement — skip
        results["findings"].append({
            "title":          f"Dangerous Entitlement: {title}",
            "severity":       sev,
            "category":       "Entitlements",
            "description":    description,
            "recommendation": recommendation,
            "file_path":      "embedded.mobileprovision",
            "snippet":        f"{key} = {value}",
            "cwe":            "CWE-250",
            "masvs":          "MASVS-RESILIENCE-1",
            "owasp":          "M8",
        })

    # ── get-task-allow as definitive debug build indicator ────────────────────
    if entitlements.get("com.apple.security.get-task-allow"):
        results["app_info"]["debug_build"] = True


# ─── Embedded Frameworks ──────────────────────────────────────────────────────
# Known third-party frameworks with security implications
_KNOWN_FRAMEWORKS = {
    "Adjust":           ("analytics",  "info",   "Adjust analytics SDK"),
    "Amplitude":        ("analytics",  "info",   "Amplitude analytics SDK"),
    "AppsFlyerLib":     ("analytics",  "info",   "AppsFlyer attribution SDK"),
    "Branch":           ("deeplinks",  "info",   "Branch deep linking SDK"),
    "Braintree":        ("payments",   "medium", "Braintree payments SDK — PCI scope"),
    "Crashlytics":      ("analytics",  "info",   "Crashlytics crash reporting"),
    "FacebookCore":     ("tracking",   "medium", "Facebook SDK — cross-app tracking"),
    "FacebookLogin":    ("auth",       "medium", "Facebook Login — OAuth flow"),
    "FirebaseAuth":     ("auth",       "low",    "Firebase Authentication"),
    "FirebaseDatabase": ("storage",    "medium", "Firebase Realtime Database"),
    "FirebaseFirestore":("storage",    "medium", "Cloud Firestore"),
    "FirebaseStorage":  ("storage",    "medium", "Firebase Cloud Storage"),
    "GoogleSignIn":     ("auth",       "low",    "Google Sign-In OAuth"),
    "IDEKit":           ("debug",      "high",   "IDE integration — should not be in release"),
    "Intercom":         ("analytics",  "info",   "Intercom customer messaging"),
    "Mixpanel":         ("analytics",  "info",   "Mixpanel analytics"),
    "OneSignal":        ("push",       "info",   "OneSignal push notifications"),
    "Stripe":           ("payments",   "medium", "Stripe payments SDK — PCI scope"),
    "Sentry":           ("analytics",  "info",   "Sentry error tracking"),
    "SquareReaderSDK":  ("payments",   "high",   "Square Reader SDK — PCI scope, handles card data"),
    "TwilioVoice":      ("comms",      "medium", "Twilio Voice SDK"),
    "XCTest":           ("debug",      "high",   "XCTest framework — should not ship in release build"),
}

def _analyze_embedded_frameworks(app_bundle: str, results: dict):
    frameworks_dir = os.path.join(app_bundle, "Frameworks")
    plugins_dir    = os.path.join(app_bundle, "PlugIns")
    found = []

    for search_dir in (frameworks_dir, plugins_dir):
        if not os.path.exists(search_dir):
            continue
        try:
            for item in os.listdir(search_dir):
                name = item.replace(".framework", "").replace(".appex", "")
                info = _KNOWN_FRAMEWORKS.get(name)
                entry = {"name": name, "path": f"{os.path.basename(search_dir)}/{item}"}
                if info:
                    entry.update({"category": info[0], "severity": info[1], "description": info[2], "known": True})
                else:
                    entry.update({"category": "unknown", "severity": "info", "description": "", "known": False})
                found.append(entry)

                # Flag high-severity known frameworks as findings
                if info and info[1] in ("high", "medium"):
                    results["findings"].append({
                        "title":          f"Third-Party Framework: {name}",
                        "severity":       info[1],
                        "category":       "Third-Party SDKs",
                        "description":    info[2],
                        "recommendation": f"Audit {name} SDK configuration and data handling. Ensure it is an approved dependency.",
                        "file_path":      entry["path"],
                        "cwe":            "CWE-1035",
                        "masvs":          "MASVS-CODE-3",
                        "owasp":          "M2",
                    })
        except Exception:
            pass

    results["embedded_frameworks"] = found
    results["sdks"] = [{"name": f["name"], "category": f["category"], "description": f["description"]} for f in found]


# ─── Swift / ObjC deep source scan ───────────────────────────────────────────
_SWIFT_OBJC_RULES = [
    # NSUserDefaults sensitive data
    (r'UserDefaults\.standard\.set\([^,]+,\s*forKey:\s*["\'](?:password|token|secret|key|auth|credential)',
     "high", "CWE-312", "MASVS-STORAGE-1",
     "Sensitive Data Written to NSUserDefaults",
     "Sensitive data stored in NSUserDefaults is unencrypted and readable by any process with access to the device.",
     "Use iOS Keychain Services for sensitive data. Never store credentials in NSUserDefaults."),

    # Keychain without kSecAttrAccessibleWhenUnlocked
    (r'SecItemAdd|SecItemUpdate',
     "info", "CWE-312", "MASVS-STORAGE-1",
     "Keychain Write Detected",
     "App writes to the iOS Keychain. Verify accessibility attributes restrict access to foreground-only.",
     "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for most sensitive items."),

    # UIPasteboard write
    (r'UIPasteboard\.general\.',
     "medium", "CWE-200", "MASVS-STORAGE-2",
     "Clipboard (UIPasteboard) Access Detected",
     "App reads or writes to the system clipboard. Sensitive data written here is readable by any app on iOS 14+.",
     "Avoid writing sensitive data to UIPasteboard. Clear clipboard after use if unavoidable."),

    # UITextField secureTextEntry = false
    (r'secureTextEntry\s*=\s*false',
     "low", "CWE-200", "MASVS-STORAGE-2",
     "Password Field Not Secured (secureTextEntry = false)",
     "A text field with secureTextEntry disabled may display sensitive input in cleartext.",
     "Set secureTextEntry = true for any field accepting passwords or sensitive data."),

    # LAContext — biometric auth
    (r'LAContext\(\)\.evaluatePolicy|canEvaluatePolicy.*deviceOwnerAuthentication',
     "info", "CWE-287", "MASVS-AUTH-1",
     "Biometric Authentication (LocalAuthentication) Used",
     "App uses LocalAuthentication for biometrics. Verify fallback to passcode is controlled and not bypassable.",
     "Use kSecAccessControlBiometryCurrentSet to bind Keychain items to enrolled biometrics."),

    # LAContext with allowedBiometricsForFallback allowing bypass
    (r'evaluatePolicy.*deviceOwnerAuthentication\b(?!WithBiometrics)',
     "medium", "CWE-287", "MASVS-AUTH-1",
     "Biometric Auth Allows Passcode Fallback",
     "Using deviceOwnerAuthentication (not deviceOwnerAuthenticationWithBiometrics) allows passcode bypass of biometric check.",
     "Use deviceOwnerAuthenticationWithBiometrics where biometric-only is required. Validate business logic."),

    # Disable certificate validation
    (r'didReceive\s+challenge.*URLSession.*completionHandler.*\.useCredential|ServerTrust.*AcceptAll|URLSession.*didReceiveChallenge.*performDefaultHandling',
     "high", "CWE-295", "MASVS-NETWORK-1",
     "Custom Certificate Validation Detected",
     "App implements custom URLSession challenge handling. Incorrect implementation can disable certificate validation.",
     "Use default certificate validation. Implement certificate pinning via NSPinnedDomains in Info.plist."),

    # SQL injection via FMDB/SQLite
    (r'executeUpdate\s*:\s*[^,]*\+|executeQuery\s*:\s*[^,]*\+',
     "high", "CWE-89", "MASVS-CODE-1",
     "Possible SQL Injection via String Concatenation",
     "SQL query built using string concatenation rather than parameterised statements.",
     "Use parameterised queries: executeUpdate:withArgumentsInArray: or executeQuery:withArgumentsInArray:"),

    # Realm unencrypted
    (r'Realm\.Configuration\(\)|try!\s*Realm\(\)',
     "medium", "CWE-312", "MASVS-STORAGE-1",
     "Realm Database Opened Without Encryption",
     "Realm database instantiated without an encryption key. Database file is stored in plaintext.",
     "Provide an encryptionKey in Realm.Configuration using a key from the iOS Keychain."),

    # CoreData NSPersistentStore without NSPersistentStoreFileProtectionKey
    (r'NSPersistentStoreCoordinator|addPersistentStore',
     "info", "CWE-312", "MASVS-STORAGE-1",
     "CoreData Persistent Store Used",
     "App uses CoreData. Verify the store has file protection (NSFileProtectionComplete) set.",
     "Set NSPersistentStoreFileProtectionKey to NSFileProtectionComplete when adding the store."),

    # Dynamic library loading
    (r'dlopen\s*\(|NSBundle\.init.*path|CFBundleCreate',
     "medium", "CWE-114", "MASVS-RESILIENCE-2",
     "Dynamic Library or Bundle Loading Detected",
     "App loads code dynamically at runtime. If the path is attacker-controlled, code injection is possible.",
     "Validate paths before dynamic loading. Prefer static linking."),

    # Weak random for security
    (r'\barc4random\b|\brand\(\)\b|\brandom\(\)\b',
     "low", "CWE-338", "MASVS-CRYPTO-1",
     "Weak Pseudo-Random Number Generator Used",
     "arc4random/rand/random produce predictable output unsuitable for cryptographic use.",
     "Use SecRandomCopyBytes for cryptographic random number generation."),

    # MD5 / SHA1 for security
    (r'CC_MD5|CommonDigest.*MD5|\.md5\b|CryptoKit\.Insecure\.MD5|CC_SHA1\b',
     "medium", "CWE-327", "MASVS-CRYPTO-1",
     "Weak Hash Algorithm (MD5/SHA-1) Used",
     "MD5 and SHA-1 are cryptographically broken and unsuitable for security-sensitive operations.",
     "Use SHA-256 or SHA-3 (CryptoKit.SHA256 / CC_SHA256)."),

    # ECB mode
    (r'kCCOptionECBMode|CCAlgorithm.*kCCAlgorithmAES.*kCCOptionECBMode',
     "high", "CWE-327", "MASVS-CRYPTO-1",
     "ECB Cipher Mode Used",
     "ECB mode does not randomise blocks and leaks patterns in encrypted data.",
     "Use AES-GCM (CryptoKit.AES.GCM) or AES-CBC with a random IV."),

    # Hardcoded IVs
    (r'kCCOptionECBMode|let\s+iv\s*=\s*["\'][0-9a-fA-F]{16,}["\']|Data\(bytes:\s*\[(?:0x[0-9a-fA-F]{1,2},?\s*){8,}\]',
     "high", "CWE-330", "MASVS-CRYPTO-1",
     "Hardcoded Cryptographic IV Detected",
     "A static IV defeats the purpose of CBC/CTR mode and makes ciphertext deterministic.",
     "Generate a random IV with SecRandomCopyBytes before each encryption operation."),

    # NSLog sensitive data (logging)
    (r'NSLog\s*\(@?["\'].*(?:password|token|secret|key|auth)',
     "high", "CWE-532", "MASVS-STORAGE-2",
     "Sensitive Data Logged via NSLog",
     "Sensitive strings are passed to NSLog which writes to the device log readable by apps with logging access.",
     "Remove NSLog calls containing sensitive data from production builds. Use os_log with private flag."),

    # print() in Swift with sensitive data
    (r'print\s*\([^)]*(?:password|token|secret|key|auth)',
     "medium", "CWE-532", "MASVS-STORAGE-2",
     "Sensitive Data Logged via print()",
     "Swift print() writes to console log — readable during device debugging.",
     "Remove logging of sensitive values. Use #if DEBUG guards around diagnostic output."),

    # WKWebView addScriptMessageHandler — JS bridge
    (r'addScriptMessageHandler|WKScriptMessageHandler',
     "medium", "CWE-749", "MASVS-PLATFORM-2",
     "WKWebView JavaScript Bridge Exposed",
     "App exposes native methods to JavaScript via WKScriptMessageHandler. Unvalidated JS input can call native APIs.",
     "Validate all messages received via userContentController(_:didReceive:). Use an allowlist of permitted actions."),

    # allowsBackForwardNavigationGestures — history hijack
    (r'allowsInlineMediaPlayback\s*=\s*true',
     "info", "CWE-749", "MASVS-PLATFORM-2",
     "WKWebView Inline Media Playback Enabled",
     "Inline media playback enabled in WebView — may be exploited for UI redressing attacks.",
     "Only enable if required. Restrict loaded content to trusted origins."),

    # File sharing
    (r'UIFileSharingEnabled.*true|LSSupportsOpeningDocumentsInPlace.*true',
     "medium", "CWE-200", "MASVS-STORAGE-1",
     "File Sharing Enabled (iTunes/Files App Access)",
     "UIFileSharingEnabled or LSSupportsOpeningDocumentsInPlace exposes app documents via Files/iTunes.",
     "Disable file sharing unless required. Encrypt sensitive files before writing to Documents."),

    # Jailbreak detection bypass hint
    (r'cydia|substrate|mobilesubstrate|\.dylib.*inject|jailbreak',
     "info", "CWE-693", "MASVS-RESILIENCE-1",
     "Jailbreak-Related Strings Detected",
     "Strings referencing jailbreak artifacts (Cydia, MobileSubstrate) found — may indicate jailbreak detection or bypass strings.",
     "Harden jailbreak detection against string matching bypasses. Use multiple detection vectors."),

    # URLProtocol subclass — may intercept HTTPS
    (r'class\s+\w+\s*:\s*URLProtocol\b',
     "medium", "CWE-295", "MASVS-NETWORK-1",
     "Custom URLProtocol Subclass Detected",
     "App subclasses URLProtocol — these intercept network calls and can disable validation or exfiltrate traffic.",
     "Remove URLProtocol subclasses from production. If required, ensure TLS validation is preserved."),

    # Insecure XML external entities
    (r'XMLParser\([^)]*\)|shouldResolveExternalEntities\s*=\s*true',
     "high", "CWE-611", "MASVS-CODE-1",
     "Potential XML External Entity (XXE) Parsing",
     "XMLParser with external entity resolution can lead to XXE disclosure or SSRF.",
     "Set shouldResolveExternalEntities = false (default). Validate XML sources."),

    # PBKDF2 low iteration count
    (r'(?:kCCPBKDF2|CCKeyDerivationPBKDF)[^)]*,\s*(?:\d{1,3}|[1-9]\d{3})\s*[,)]',
     "high", "CWE-916", "MASVS-CRYPTO-1",
     "PBKDF2 With Low Iteration Count",
     "PBKDF2 iteration count under 10,000 is below OWASP recommendations and enables offline brute force.",
     "Use at least 100,000 iterations (SHA-256) or switch to Argon2id."),

    # Insecure HTTP via Data(contentsOf:)
    (r'Data\s*\(\s*contentsOf:\s*URL\(string:\s*["\']http://',
     "high", "CWE-319", "MASVS-NETWORK-1",
     "Cleartext HTTP Download via Data(contentsOf:)",
     "Data(contentsOf:) used with http:// URL — content downloaded in cleartext and tamperable.",
     "Use https:// and verify ATS settings. Pin certificates for high-risk assets."),

    # NSAllowsArbitraryLoads in code
    (r'NSAllowsArbitraryLoads\s*["\']?\s*[:=]\s*(?:true|YES|1)\b',
     "high", "CWE-319", "MASVS-NETWORK-1",
     "App Transport Security Fully Disabled",
     "NSAllowsArbitraryLoads = true disables ATS globally, permitting cleartext and weak TLS network calls.",
     "Remove NSAllowsArbitraryLoads. Use NSExceptionDomains for specific legacy hosts only."),

    # Weak TLS version forced
    (r'TLSMinimumSupportedProtocol\s*=\s*(?:kTLSProtocol1\b|kSSLProtocol)',
     "high", "CWE-326", "MASVS-NETWORK-2",
     "Weak TLS Protocol Version Forced",
     "App forces TLS 1.0/SSL which are deprecated and vulnerable to POODLE, BEAST, and downgrade attacks.",
     "Use TLS 1.2 minimum (TLSMinimumSupportedProtocolVersion = .TLSv12)."),

    # Debug/backdoor flags
    (r'#if\s+DEBUG[\s\S]{0,200}?(?:backdoor|skipAuth|bypass|adminOverride)',
     "high", "CWE-489", "MASVS-CODE-3",
     "Debug-Only Backdoor Code Detected",
     "Conditional-compilation block references bypass/backdoor flags that may leak into release builds.",
     "Remove backdoor paths entirely. Never rely on #if DEBUG to hide security-sensitive code."),

    # App Groups without file protection
    (r'NSFileProtection(?:None|CompleteUntilFirstUserAuthentication)\b',
     "medium", "CWE-312", "MASVS-STORAGE-1",
     "Weak iOS Data Protection Class",
     "File uses NSFileProtectionNone or CompleteUntilFirstUserAuthentication — accessible at boot without unlock.",
     "Use NSFileProtectionComplete for sensitive data that must be locked when device is locked."),

    # Insecure deeplink handling
    (r'func\s+application\([^)]*,\s*open\s+url:\s*URL[^{]*\{[\s\S]{0,400}(?!.*(?:scheme|host)\s*==)',
     "medium", "CWE-939", "MASVS-PLATFORM-1",
     "Potentially Unvalidated Deep Link Handling",
     "openURL handler appears to process incoming URLs without validating scheme/host — risks open redirect and IDOR.",
     "Validate scheme, host, and path before taking action. Require authentication for sensitive deep links."),

    # CFNetwork disable pinning
    (r'kCFStreamSSLValidatesCertificateChain\s*[:=]\s*(?:false|kCFBooleanFalse)\b',
     "high", "CWE-295", "MASVS-NETWORK-1",
     "CFNetwork Certificate Validation Disabled",
     "kCFStreamSSLValidatesCertificateChain set to false — accepts any TLS certificate including self-signed.",
     "Never disable certificate validation. Remove this property to use default validation."),

    # Keychain with kSecAttrAccessibleAlways
    (r'kSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b',
     "medium", "CWE-312", "MASVS-STORAGE-1",
     "Keychain Item Always Accessible",
     "kSecAttrAccessibleAlways makes the item readable even when device is locked — bypasses device lock protections.",
     "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or AfterFirstUnlockThisDeviceOnly."),

    # Info.plist dangerous permissions without purpose string
    (r'NS(?:Camera|Microphone|LocationAlwaysAndWhenInUse|PhotoLibrary|Contacts|HealthShare|HealthUpdate)UsageDescription',
     "info", "CWE-359", "MASVS-CODE-2",
     "Privacy-Sensitive Permission Declared",
     "App declares usage of a sensitive data source. Verify that the purpose string clearly explains the use to the user.",
     "Audit purpose strings for accuracy. Request at point of use, not on first launch."),

    # Dangerous Objective-C runtime APIs
    (r'method_exchangeImplementations|class_replaceMethod|objc_msgSend\s*\(',
     "info", "CWE-693", "MASVS-RESILIENCE-2",
     "Objective-C Runtime Manipulation API Used",
     "Runtime swizzling APIs can be abused for hooking. Verify usage is intentional and audited.",
     "Restrict swizzling to well-known frameworks. Add anti-tamper checks around critical methods."),

    # Firebase insecure Firestore rules hint
    (r'Firestore\.firestore\(\)\.collection\([^)]+\)\.document\([^)]+\)\.setData',
     "info", "CWE-284", "MASVS-PLATFORM-1",
     "Firebase Firestore Write Detected",
     "App writes directly to Firestore — verify server-side security rules restrict writes based on auth/user.",
     "Publish Firestore rules that enforce request.auth.uid ownership and schema validation."),

    # Insecure WKWebView configuration — allow file access
    (r'preferences\.javaScriptCanOpenWindowsAutomatically\s*=\s*true|allowFileAccessFromFileURLs',
     "medium", "CWE-749", "MASVS-PLATFORM-2",
     "WKWebView Dangerous Preferences Enabled",
     "JavaScript can open windows automatically or access local files — enables click-jacking and local-file disclosure.",
     "Disable these preferences. Load only trusted origins."),

    # Certificate pinning absent hint — allowAnyHTTPSCertificate
    (r'allowAnyHTTPSCertificate|allowsAnyHTTPSCertificate',
     "critical", "CWE-295", "MASVS-NETWORK-1",
     "All HTTPS Certificates Accepted",
     "Code explicitly accepts any HTTPS certificate — MitM attackers can transparently intercept traffic.",
     "Remove this override. Implement certificate pinning via URLSessionDelegate."),

    # SwiftUI SecureField missing
    (r'TextField\([^)]*(?:password|pin|pwd)[^)]*\)',
     "medium", "CWE-200", "MASVS-STORAGE-2",
     "SwiftUI TextField Used For Password Input",
     "Password-like field uses TextField instead of SecureField — value is visible and may be cached by autocomplete.",
     "Use SecureField for all password / PIN / token inputs."),

    # WKWebView loadHTMLString with baseURL file://
    (r'loadHTMLString\s*\([^)]+,\s*baseURL:\s*URL\(string:\s*["\']file://',
     "high", "CWE-200", "MASVS-PLATFORM-2",
     "WKWebView Loads HTML With file:// Base URL",
     "Loading remote HTML with a file:// baseURL grants the page access to local files via XHR.",
     "Use https:// baseURL or nil. Sanitize any user-supplied HTML."),

    # Anti-debug: ptrace deny attach
    (r'ptrace\s*\(\s*(?:PT_DENY_ATTACH|31)\b',
     "info", "CWE-693", "MASVS-RESILIENCE-4",
     "Anti-Debug ptrace(PT_DENY_ATTACH) Detected",
     "App uses ptrace to prevent debugger attach — typical anti-tamper technique; bypassable via dyld interposition.",
     "Combine with sysctl kinfo_proc check and syscall-level anti-debug for defense in depth."),

    # Shared keychain access group (cross-app risk)
    (r'kSecAttrAccessGroup[^=]*=\s*["\'][^"\']+\.shared',
     "medium", "CWE-668", "MASVS-STORAGE-1",
     "Keychain Shared Access Group Used",
     "Item is shared across apps in the same access group — verify all sharing apps meet the same security bar.",
     "Document the trust boundary. Avoid sharing credentials with less-privileged apps."),

    # Universal clipboard (general pasteboard)
    (r'UIPasteboard\.general\.(?:string|items|image)\s*=',
     "medium", "CWE-200", "MASVS-STORAGE-2",
     "Write To General (Universal) Pasteboard",
     "UIPasteboard.general is shared with macOS via Handoff — sensitive data is copied across the user's devices.",
     "Use a named, app-local pasteboard. Exclude sensitive data from Universal Clipboard."),

    # NSKeyedUnarchiver insecure
    (r'NSKeyedUnarchiver\.unarchiveObject\s*\(',
     "high", "CWE-502", "MASVS-CODE-1",
     "Insecure NSKeyedUnarchiver Deserialization",
     "unarchiveObject(with:) is deprecated and insecure — any class in the runtime can be deserialized.",
     "Use unarchivedObject(ofClass:from:) with a concrete, expected class set."),

    # Dangerous shell execution
    (r'NSTask\(\)|Process\(\)\.launch|popen\s*\(|system\s*\(',
     "high", "CWE-78", "MASVS-PLATFORM-1",
     "Shell Command Execution API Detected",
     "App launches subprocesses or shell commands — rare on iOS and typically indicates jailbroken-device code or risky behavior.",
     "Remove or sandbox. Never pass user input to shell APIs."),
]

_COMPILED_SWIFT_OBJC_RULES = None


def _get_compiled_ios_rules():
    """Compile the rule regex list once per process. Bad rules are dropped."""
    global _COMPILED_SWIFT_OBJC_RULES
    if _COMPILED_SWIFT_OBJC_RULES is None:
        compiled = []
        for pattern, sev, cwe, masvs, title, desc, rec in _SWIFT_OBJC_RULES:
            try:
                compiled.append((re.compile(pattern, re.IGNORECASE | re.MULTILINE),
                                 sev, cwe, masvs, title, desc, rec))
            except re.error:
                continue
        _COMPILED_SWIFT_OBJC_RULES = compiled
    return _COMPILED_SWIFT_OBJC_RULES


def _analyze_swift_objc_sources(tmpdir: str, results: dict):
    """Scan Swift and ObjC source files for security anti-patterns."""
    extensions = (".swift", ".m", ".h", ".mm")
    finding_counts: dict[str, int] = defaultdict(int)
    analysis = {"files_scanned": 0, "pattern_hits": 0}
    rules = _get_compiled_ios_rules()

    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = Path(fpath).read_text(errors="replace")
            except Exception:
                continue

            analysis["files_scanned"] += 1
            rel = os.path.relpath(fpath, tmpdir)

            for pat, sev, cwe, masvs, title, desc, rec in rules:
                matches = list(pat.finditer(content))
                if not matches:
                    continue

                # Deduplicate by title+file
                dedup_key = f"{title}:{rel}"
                if finding_counts[dedup_key] > 0:
                    continue
                finding_counts[dedup_key] += 1
                analysis["pattern_hits"] += 1

                m = matches[0]
                line_no = content[:m.start()].count("\n") + 1
                snippet = content[max(0, m.start()-40):m.end()+80].strip()

                results["findings"].append({
                    "title":          title,
                    "severity":       sev,
                    "category":       "iOS Source Analysis",
                    "description":    desc,
                    "recommendation": rec,
                    "file_path":      rel,
                    "line":           line_no,
                    "snippet":        snippet[:300],
                    "cwe":            cwe,
                    "masvs":          masvs,
                    "owasp":          "M2" if "STORAGE" in masvs else ("M5" if "NETWORK" in masvs else "M7"),
                    "source":         "iOS_SAST",
                    "confidence":     78,
                })

    results["swift_analysis"] = analysis


# ─── iOS Data Storage Patterns ────────────────────────────────────────────────
def _analyze_ios_data_storage(tmpdir: str, results: dict):
    """Identify data storage mechanisms and flag insecure patterns."""
    storage = {
        "uses_keychain":       False,
        "uses_userdefaults":   False,
        "uses_coredata":       False,
        "uses_realm":          False,
        "uses_sqlite":         False,
        "uses_file_manager":   False,
        "backup_excluded":     False,
        "data_protection":     False,
    }

    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if not any(fname.endswith(e) for e in (".swift", ".m", ".h", ".mm")):
                continue
            try:
                content = Path(os.path.join(root, fname)).read_text(errors="replace")
            except Exception:
                continue

            if re.search(r'SecItemAdd|SecItemUpdate|kSecClass', content):
                storage["uses_keychain"] = True
            if re.search(r'UserDefaults\.standard|NSUserDefaults', content):
                storage["uses_userdefaults"] = True
            if re.search(r'NSPersistentStore|NSManagedObjectContext', content):
                storage["uses_coredata"] = True
            if re.search(r'try!\s*Realm|Realm\.Configuration', content):
                storage["uses_realm"] = True
            if re.search(r'sqlite3_open|FMDatabase|FMDB', content):
                storage["uses_sqlite"] = True
            if re.search(r'FileManager\.default|NSFileManager', content):
                storage["uses_file_manager"] = True
            if re.search(r'isExcludedFromBackup|NSURLIsExcludedFromBackupKey', content):
                storage["backup_excluded"] = True
            if re.search(r'NSFileProtectionComplete|NSFileProtection', content):
                storage["data_protection"] = True

    results["ios_data_storage"] = storage

    # Warn if using file manager without data protection
    if storage["uses_file_manager"] and not storage["data_protection"]:
        results["findings"].append({
            "title":          "File Storage Without Explicit Data Protection",
            "severity":       "medium",
            "category":       "Data Storage",
            "description":    "App writes files via FileManager but no NSFileProtectionComplete attributes were detected.",
            "recommendation": "Set NSFileProtectionComplete on all sensitive files: try FileManager.default.setAttributes([.protectionKey: .complete], ofItemAtPath: path)",
            "cwe":            "CWE-312",
            "masvs":          "MASVS-STORAGE-1",
            "owasp":          "M2",
        })

    if storage["uses_coredata"] and not storage["data_protection"]:
        results["findings"].append({
            "title":          "CoreData Store Without File Protection",
            "severity":       "medium",
            "category":       "Data Storage",
            "description":    "CoreData persistent store used without detected NSFileProtectionComplete configuration.",
            "recommendation": "Add NSPersistentStoreFileProtectionKey: NSFileProtectionComplete to store options.",
            "cwe":            "CWE-312",
            "masvs":          "MASVS-STORAGE-1",
            "owasp":          "M9",
        })


# ─── iOS Crypto Usage ─────────────────────────────────────────────────────────
def _analyze_ios_crypto(tmpdir: str, results: dict):
    crypto = {
        "uses_commonCrypto":  False,
        "uses_cryptoKit":     False,
        "uses_security_fw":   False,
        "uses_openssl":       False,
        "weak_algorithms":    [],
    }

    weak_patterns = [
        (r'kCCAlgorithmDES\b',         "DES"),
        (r'kCCAlgorithm3DES\b',        "3DES"),
        (r'kCCAlgorithmRC2\b',         "RC2"),
        (r'kCCAlgorithmRC4\b',         "RC4"),
        (r'kCCAlgorithmBlowfish\b',    "Blowfish"),
        (r'CC_MD5\b|CommonDigest.*MD5',"MD5"),
        (r'CC_SHA1\b',                 "SHA-1"),
    ]

    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if not any(fname.endswith(e) for e in (".swift", ".m", ".h", ".mm")):
                continue
            try:
                content = Path(os.path.join(root, fname)).read_text(errors="replace")
            except Exception:
                continue

            if re.search(r'#import\s+<CommonCrypto|import\s+CommonCrypto', content):
                crypto["uses_commonCrypto"] = True
            if re.search(r'import\s+CryptoKit', content):
                crypto["uses_cryptoKit"] = True
            if re.search(r'#import\s+<Security/|import\s+Security\b', content):
                crypto["uses_security_fw"] = True
            if re.search(r'#import\s+.*openssl|EVP_|SSL_CTX_', content):
                crypto["uses_openssl"] = True

            for pattern, algo in weak_patterns:
                if re.search(pattern, content) and algo not in crypto["weak_algorithms"]:
                    crypto["weak_algorithms"].append(algo)

    results["ios_crypto"] = crypto

    if crypto["weak_algorithms"]:
        results["findings"].append({
            "title":          f"Weak Cryptographic Algorithms Used: {', '.join(crypto['weak_algorithms'])}",
            "severity":       "high",
            "category":       "Cryptography",
            "description":    f"Deprecated or broken algorithms detected: {', '.join(crypto['weak_algorithms'])}. These do not provide adequate security.",
            "recommendation": "Replace with AES-256-GCM (CryptoKit.AES.GCM) or ChaCha20-Poly1305. For hashing use SHA-256+.",
            "cwe":            "CWE-327",
            "masvs":          "MASVS-CRYPTO-1",
            "owasp":          "M10",
        })

    if crypto["uses_openssl"]:
        results["findings"].append({
            "title":          "OpenSSL / BoringSSL Used Directly",
            "severity":       "medium",
            "category":       "Cryptography",
            "description":    "App embeds or links OpenSSL directly. Outdated OpenSSL versions have numerous CVEs.",
            "recommendation": "Prefer Apple's native Security framework or CryptoKit. If OpenSSL is required, keep it up to date.",
            "cwe":            "CWE-327",
            "masvs":          "MASVS-CRYPTO-1",
            "owasp":          "M2",
        })


# ─── WebView Security ─────────────────────────────────────────────────────────
def _analyze_ios_webview(tmpdir: str, results: dict):
    webview = {
        "uses_wkwebview":       False,
        "uses_uiwebview":       False,
        "js_enabled":           None,
        "bridge_handlers":      [],
        "loads_local_files":    False,
        "loads_remote_urls":    False,
    }

    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if not any(fname.endswith(e) for e in (".swift", ".m", ".h", ".mm", ".storyboard", ".xib")):
                continue
            try:
                content = Path(os.path.join(root, fname)).read_text(errors="replace")
            except Exception:
                continue

            if "WKWebView" in content:
                webview["uses_wkwebview"] = True
            if "UIWebView" in content:
                webview["uses_uiwebview"] = True

            # Find JS message handler names
            for m in re.finditer(r'addScriptMessageHandler[^,]+,\s*name:\s*["\'](\w+)["\']', content):
                name = m.group(1)
                if name not in webview["bridge_handlers"]:
                    webview["bridge_handlers"].append(name)

            if re.search(r'loadFileURL|loadHTMLString|contentsOfFile.*html', content):
                webview["loads_local_files"] = True
            if re.search(r'loadRequest\s*\(|load\s*\(URLRequest', content):
                webview["loads_remote_urls"] = True

    results["ios_webview"] = webview

    if webview["uses_uiwebview"]:
        results["findings"].append({
            "title":          "Deprecated UIWebView Used",
            "severity":       "high",
            "category":       "WebView",
            "description":    "UIWebView is deprecated since iOS 12 and removed in iOS 15. It has known security issues and is rejected by App Store review.",
            "recommendation": "Migrate all UIWebView usages to WKWebView.",
            "cwe":            "CWE-477",
            "masvs":          "MASVS-PLATFORM-2",
            "owasp":          "M1",
        })

    if webview["bridge_handlers"]:
        results["findings"].append({
            "title":          f"WKWebView JavaScript Bridge ({len(webview['bridge_handlers'])} handler(s))",
            "severity":       "medium",
            "category":       "WebView",
            "description":    f"JavaScript bridge handlers exposed: {', '.join(webview['bridge_handlers'])}. "
                              "Any JavaScript running in the WebView can invoke these native handlers.",
            "recommendation": "Validate and sanitize all messages. Use an allowlist. Apply Content Security Policy headers.",
            "snippet":        str(webview["bridge_handlers"]),
            "cwe":            "CWE-749",
            "masvs":          "MASVS-PLATFORM-2",
            "owasp":          "M1",
        })


# ─── Mach-O deep binary protection ───────────────────────────────────────────
def _analyze_macho_deep(binary_path: str, results: dict):
    """
    Parse Mach-O load commands to detect binary hardening flags:
    PIE, stack canary, ARC, NX, encrypted, stripped symbols.
    """
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except Exception:
        return

    if len(data) < 28:
        return

    magic = struct.unpack("<I", data[:4])[0]
    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    is_le = magic in (0xFEEDFACE, 0xFEEDFACF)

    if magic not in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        # Fat binary — recurse on first slice
        if magic in (0xCAFEBABE, 0xBEBAFECA):
            results["app_info"].setdefault("fat_binary", True)
        return

    fmt = "<" if is_le else ">"
    header_size = 32 if is_64 else 28

    try:
        if is_64:
            _magic, _cpu, _sub, _ft, ncmds, sizeofcmds, flags, _res = struct.unpack_from(fmt + "8I", data, 0)
        else:
            _magic, _cpu, _sub, _ft, ncmds, sizeofcmds, flags = struct.unpack_from(fmt + "7I", data, 0)
    except struct.error:
        return

    # MH_PIE = 0x200000, MH_NO_HEAP_EXECUTION = 0x1000000, MH_PIE already a flag
    MH_PIE               = 0x00200000
    MH_ALLOW_STACK_EXEC  = 0x00020000
    has_pie = bool(flags & MH_PIE)
    has_nx  = not bool(flags & MH_ALLOW_STACK_EXEC)

    # Parse load commands
    has_encryption    = False
    has_stack_canary  = b"___stack_chk_guard" in data or b"__stack_chk_guard" in data
    has_arc           = b"_objc_release" in data
    symbol_stripped   = b"__SYMTAB" not in data  # rough check
    has_rpath         = b"@rpath" in data

    offset = header_size
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(fmt + "2I", data, offset)
        LC_ENCRYPTION_INFO    = 0x21
        LC_ENCRYPTION_INFO_64 = 0x2C
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            if offset + 20 <= len(data):
                _off, _size, cryptid = struct.unpack_from(fmt + "3I", data, offset + 8)
                has_encryption = cryptid != 0
        offset += max(cmdsize, 8)

    protections = {
        "pie":          has_pie,
        "nx":           has_nx,
        "stack_canary": has_stack_canary,
        "arc":          has_arc,
        "encrypted":    has_encryption,
        "rpath":        has_rpath,
        "symbol_stripped": symbol_stripped,
    }
    results["app_info"]["binary_protections"] = protections

    if not has_pie:
        results["findings"].append({
            "title":          "PIE (Position-Independent Executable) Not Enabled",
            "severity":       "medium",
            "category":       "Binary Hardening",
            "description":    "Binary was not compiled with PIE. ASLR is ineffective without PIE, making code-reuse attacks easier.",
            "recommendation": "Set ENABLE_PIE = YES in Xcode build settings. Required since iOS 4.3.",
            "cwe":            "CWE-119",
            "masvs":          "MASVS-RESILIENCE-1",
            "owasp":          "M7",
        })

    if not has_stack_canary:
        results["findings"].append({
            "title":          "Stack Canary Not Present",
            "severity":       "low",
            "category":       "Binary Hardening",
            "description":    "Stack canary protection not detected. Buffer overflow exploitation is easier without canary checks.",
            "recommendation": "Compile with -fstack-protector-all.",
            "cwe":            "CWE-121",
            "masvs":          "MASVS-RESILIENCE-1",
            "owasp":          "M7",
        })

    if not has_arc:
        results["findings"].append({
            "title":          "ARC Not Detected",
            "severity":       "low",
            "category":       "Binary Hardening",
            "description":    "Automatic Reference Counting not detected. Manual memory management increases use-after-free risk.",
            "recommendation": "Enable ARC (CLANG_ENABLE_OBJC_ARC = YES).",
            "cwe":            "CWE-416",
            "masvs":          "MASVS-RESILIENCE-1",
            "owasp":          "M7",
        })

    if not has_encryption:
        results["findings"].append({
            "title":          "Binary Not Encrypted (No FairPlay DRM)",
            "severity":       "info",
            "category":       "Binary Hardening",
            "description":    "LC_ENCRYPTION_INFO indicates cryptid=0 — binary is not FairPlay-encrypted. "
                              "This is expected for development/enterprise builds but not App Store distributions.",
            "recommendation": "Distribute via App Store for automatic FairPlay encryption. For enterprise builds, apply additional obfuscation.",
            "cwe":            "CWE-311",
            "masvs":          "MASVS-RESILIENCE-2",
            "owasp":          "M7",
        })

    if not symbol_stripped:
        results["findings"].append({
            "title":          "Debug Symbols Not Stripped",
            "severity":       "low",
            "category":       "Binary Hardening",
            "description":    "Binary appears to contain symbol table information, which aids reverse engineering.",
            "recommendation": "Set STRIP_STYLE = all and DEPLOYMENT_POSTPROCESSING = YES in release builds.",
            "cwe":            "CWE-693",
            "masvs":          "MASVS-RESILIENCE-1",
            "owasp":          "M7",
        })


# ─── File inventory ───────────────────────────────────────────────────────────
_SUSPICIOUS_EXTENSIONS = {".key", ".p12", ".pem", ".cer", ".der", ".pfx", ".p8",
                           ".sqlite", ".db", ".realm", ".sql"}
_SUSPICIOUS_NAMES = {"config.json", "config.yaml", "secrets.json", "credentials.json",
                     "database.sqlite", "app.db", "local.json", ".env"}

def _build_ios_file_inventory(tmpdir: str, results: dict):
    total = 0
    suspicious = []
    for root, _, files in os.walk(tmpdir):
        for fname in files:
            total += 1
            ext  = Path(fname).suffix.lower()
            name = fname.lower()
            if ext in _SUSPICIOUS_EXTENSIONS or name in _SUSPICIOUS_NAMES:
                rel = os.path.relpath(os.path.join(root, fname), tmpdir)
                suspicious.append({"path": rel, "reason": f"Sensitive extension ({ext})" if ext in _SUSPICIOUS_EXTENSIONS else "Sensitive filename"})

    results["file_inventory"] = {"total_files": total, "suspicious": suspicious[:50]}

    for s in suspicious[:10]:
        if any(s["path"].endswith(e) for e in (".key", ".p12", ".pem", ".p8")):
            results["findings"].append({
                "title":          f"Certificate/Key File Embedded: {Path(s['path']).name}",
                "severity":       "high",
                "category":       "Embedded Secrets",
                "description":    f"Private key or certificate file found inside IPA: {s['path']}",
                "recommendation": "Remove private keys from the app bundle. Store server certificates separately.",
                "file_path":      s["path"],
                "cwe":            "CWE-798",
                "masvs":          "MASVS-CRYPTO-2",
                "owasp":          "M1",
            })


# ─── Quick summary ────────────────────────────────────────────────────────────
def _build_ios_quick_summary(results: dict):
    findings = results.get("findings", [])
    sev_ss   = results.get("severity_summary", {})
    storage  = results.get("ios_data_storage", {})
    crypto   = results.get("ios_crypto", {})
    webview  = results.get("ios_webview", {})
    fws      = results.get("embedded_frameworks", [])

    results["quick_summary"] = {
        "total_findings":      len(findings),
        "critical":            sev_ss.get("critical", 0),
        "high":                sev_ss.get("high", 0),
        "medium":              sev_ss.get("medium", 0),
        "secrets_found":       len(results.get("secrets", [])),
        "jwts_found":          len(results.get("jwts", [])),
        "ips_found":           len(results.get("ips", [])),
        "frameworks_detected": len(fws),
        "uses_wkwebview":      webview.get("uses_wkwebview", False),
        "uses_uiwebview":      webview.get("uses_uiwebview", False),
        "uses_keychain":       storage.get("uses_keychain", False),
        "weak_crypto":         bool(crypto.get("weak_algorithms")),
        "binary_pie":          results.get("app_info", {}).get("binary_protections", {}).get("pie"),
        "debug_build":         results.get("app_info", {}).get("debug_build", False),
    }
