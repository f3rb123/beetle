import zipfile
import os
import re
import plistlib
import hashlib
import logging
import struct
import base64
import io
import zlib
import mimetypes
import tempfile
from pathlib import Path
from datetime import datetime
from collections import defaultdict

log = logging.getLogger("cortex.ios")

from .common import (
    scan_files_for_secrets, scan_text_for_secrets,
    extract_urls, sort_findings, SEVERITY_ORDER, rule_slug,
    normalize_severity, compute_severity_summary, dedupe_findings,
)
from . import scan_storage
from . import finding_model
from .code_analyzer import run_ios_sast
from .string_analyzer import analyze_strings
from .apple_png import (
    PNG_SIG, png_dimensions, renderable_image_bytes, best_icon_png_from_assets_car,
)
from .source_corpus import SourceCorpus, printable_text
from . import endpoint_intel
from .scoring import calculate_score
from .path_utils import relativize_path
from .virustotal import run_virustotal
from . import network_intel
from . import cloud_config
from . import flutter_analyzer
from . import react_native_analyzer
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
        "domain_intel":     [],
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
                "rule_id": "ios_ipa_extraction_warning",
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
            # String-scan EVERY Mach-O in the bundle, not just the main executable: a
            # Flutter app's URLs/IPs live in the framework binaries (App.framework/App),
            # which the Runner binary never contains. Fills _binary_endpoints /
            # _binary_ip_hits, merged into endpoints/ips once the pool below returns.
            _scan_binary_strings(app_bundle, results, tmpdir)
            # Which bundle files are binary-format (Mach-O / bplist) — consumed by the
            # evidence view so their "line" is never rendered as a source line.
            _record_binary_format_files(app_bundle, results, tmpdir)

        # ── Parallelize heavy independent scans to speed up iOS analysis.
        # Each module is CPU-bound on file IO + regex — running them on a
        # small thread pool overlaps their walks.
        # Priority 1 — SourceCorpus: one shared walk + read of the IPA tree for
        # every text analyzer below. Pre-warm the walk once here so the 7 threads
        # start from a populated directory cache (reads then fill lazily, keyed by
        # path — concurrent hits are idempotent). Detections are unchanged; only
        # the redundant per-analyzer traversal is removed.
        corpus = SourceCorpus()
        for _ in corpus.walk(tmpdir):
            pass
        from concurrent.futures import ThreadPoolExecutor as _TPE
        with _TPE(max_workers=7) as _pool:
            # Use evidence_scanner (richer, full CWE/MASVS/OWASP metadata)
            # in addition to the legacy common.py scanner so iOS gets the same
            # quality secret detection as Android. Phase 1.9: the evidence walk
            # applies the UNIFIED catalog (native + APKLeaks) so APKLeaks adds NO
            # extra filesystem traversal — its hits are split out below and fused.
            from . import secret_catalog as _secret_catalog
            _fut_secrets_ev = _pool.submit(ev_scan_secrets, tmpdir, None, None,
                                           _secret_catalog.combined(), corpus=corpus)
            _fut_secrets_lg = _pool.submit(scan_files_for_secrets, tmpdir, [
                ".plist", ".json", ".xml", ".strings", ".js", ".swift",
                ".m", ".h", ".txt", ".yml", ".yaml", ".cfg",
            ])
            _fut_jwts = _pool.submit(scan_directory_for_jwts, tmpdir, corpus=corpus)
            _fut_ips  = _pool.submit(network_intel.extract_ips, tmpdir, corpus=corpus)
            _fut_cc   = _pool.submit(cloud_config.scan, tmpdir, corpus=corpus)
            _fut_endpoints = _pool.submit(_extract_endpoints, tmpdir, results, corpus=corpus)
            _fut_strings = _pool.submit(analyze_strings, tmpdir, "ios", corpus=corpus)
            _fut_sast = _pool.submit(run_ios_sast, tmpdir, results, corpus=corpus)
            _fut_framework = _pool.submit(_detect_framework, app_bundle or tmpdir, results)

            # Split the combined evidence walk into native vs APKLeaks hits BEFORE
            # the native merge, so APKLeaks hits are routed/attributed (and endpoints
            # don't get misfiled as secrets) rather than collapsed by name+value.
            from .detection_sources import routing as _routing, fusion as _fusion
            ev_all = _fut_secrets_ev.result() or []
            ev_secrets_out, _apk_result = _routing.extract_apkleaks(ev_all)
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
            # Fuse the APKLeaks slice into the native streams (attribution + dedup).
            _fusion.merge_secret_streams(results, _apk_result.secrets)
            _fusion.merge_finding_streams(results, _apk_result.findings, platform="ios")
            _fusion.merge_endpoint_streams(results, _apk_result.endpoints)

            results["jwts"] = _fut_jwts.result() or []
            results["ips"]  = _fut_ips.result() or []
            # Merge Mach-O binary IP hits BEFORE annotate so they are classified,
            # owned and de-duped by the same canonical model as the text-file hits.
            _bin_ips = results.pop("_binary_ip_hits", []) or []
            if _bin_ips:
                _seen_ips = {(h.get("ip"), h.get("file_path")) for h in results["ips"]}
                for _h in _bin_ips:
                    if (_h["ip"], _h["file_path"]) not in _seen_ips:
                        _seen_ips.add((_h["ip"], _h["file_path"]))
                        results["ips"].append(_h)
            # Phase 1.99: enrich raw IP hits (classify / owner / suppress / merge /
            # intelligence) using the SAME canonical model as Android, BEFORE the
            # public-IP finding and UI consume them. Additive; URLs untouched.
            try:
                network_intel.annotate(results, platform="ios")
            except Exception:
                log.exception("[network_intel] iOS IP enrichment failed; raw IPs left as-is")
            _fut_endpoints.result()
            # Merge Mach-O binary URLs into the endpoint list, deduped against what the
            # text scan already found. These have no call site (stripped AOT code), so
            # they arrive here rather than through extract_endpoints' called-only default.
            _bin_eps = results.pop("_binary_endpoints", []) or []
            if _bin_eps:
                results["endpoints"] = sorted(set(results.get("endpoints") or []) | set(_bin_eps))
            # Phase 2.5.5: Cloud Configuration discovery (parity with Android) —
            # classify Firebase/GCS buckets + endpoints and emit findings BEFORE
            # fusion so they traverse the same pipeline.
            results["_cloud_config_hits"] = _fut_cc.result() or []
            try:
                cloud_config.annotate(results, platform="ios")
            except Exception:
                log.exception("[cloud_config] iOS cloud configuration discovery failed")
            results["string_analysis"] = _fut_strings.result() or {}
            _fut_sast.result()
            _fut_framework.result()

        # ── Flutter Security Intelligence (Phase 2.1) ─────────────────────────
        # Gated on the existing framework detection. Same canonical model as Android:
        # contributes findings/secrets/endpoints to the EXISTING streams, which then
        # flow through the unchanged finalize pipeline. Never raises into the scan.
        if results.get("framework", {}).get("type") == "flutter":
            try:
                flutter_analyzer.analyze([app_bundle or tmpdir], results, platform="ios")
            except Exception:
                log.exception("[flutter] iOS analysis failed; continuing without Flutter findings")

        # ── React Native Security Intelligence (Phase 2.2) ────────────────────
        # Same canonical model as Android/Flutter, gated on the framework flag.
        if results.get("framework", {}).get("type") == "react_native":
            try:
                react_native_analyzer.analyze([app_bundle or tmpdir], results, platform="ios")
            except Exception:
                log.exception("[react_native] iOS analysis failed; continuing without RN findings")

        # ── Domain Geo/Intel Check ───────────────────────────────────────────
        # Runs AFTER every endpoint contributor (binary strings, text scan, Flutter, RN)
        # so it sees the final list. iOS never called this, so domain_intel was absent
        # from every iOS report regardless of how many endpoints were found. Android's
        # _add_domain_intel_summary finding is deliberately NOT mirrored here — this
        # populates the section without adding a finding.
        try:
            from .domain_analyzer import check_domains
            check_domains(results.get("endpoints", []), results)
        except Exception:
            log.exception("[domain_intel] iOS domain intelligence failed; section left empty")

        # ── Semgrep SAST (Phase 2.4) — external detection engine via the SAST
        # adapter. Gated on availability (no-op + zero cost when absent); runs only
        # iOS/framework-relevant rule packs. Canonical findings flow through fusion. ──
        try:
            from .semgrep_runner import run_semgrep as _run_semgrep
            _m = _run_semgrep([tmpdir], results, platform="ios",
                              framework=(results.get("framework") or {}).get("type"))
            results.setdefault("scan_metrics", {}).setdefault("modules", {})["semgrep_sast"] = {
                "ran": _m.get("ran"), "findings": _m.get("finding_count", 0)}
        except Exception:
            log.exception("[semgrep] iOS SAST failed; continuing without Semgrep findings")

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
                # Same detector as the Android JWT scan — shared rule identity.
                "rule_id":           "hardcoded_jwt_token",
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
                "rule_id":           "hardcoded_public_ips",
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
        # ── Certificate summary — build results["certificate"] from the signing
        # certs + provisioning fields _analyze_entitlements just parsed, so the
        # report renders signing/provisioning details instead of "No certificate
        # data". Additive; iOS-only (Android builds results["certificate"] in
        # cert_analyzer). ──
        _build_ios_certificate(results)

        # ── Embedded Frameworks ──────────────────────────────────────────────
        if app_bundle:
            _analyze_embedded_frameworks(app_bundle, results)

            # ── Property Lists (enumeration surface) ─────────────────────────
            # The enumeration itself emits no findings. The ONE finding that comes out of this
            # area is the privacy-declaration DISCREPANCY, which exists only at the INTERSECTION
            # of two independent evidence chains — trackers present (RUN 11) and declarations
            # absent (RUN 12) — so it must run after both.
            try:
                from . import ios_plists
                ios_plists.analyze(app_bundle, results)
            except Exception:
                log.exception("[plists] iOS property-list enumeration failed")

            # ── Tracker detection ────────────────────────────────────────────
            # MUST run AFTER _analyze_embedded_frameworks: it is what populates results["sdks"]
            # from the real Frameworks/ directory. Running earlier left the pod list EMPTY, so
            # every tracker fell back to marker evidence and FirebaseCrashlytics — which plainly
            # ships a framework — was mislabelled "statically linked".
            #
            # NOT a wire-up of Android's detect_trackers(): all 73 of its signatures key on an
            # ANDROID PACKAGE PREFIX, which an iOS app has none of. iOS trackers are proven by
            # pod name (RUN 7), by an endpoint the app contains (RUN 1), or by a marker string
            # statically linked into a Mach-O (RUN 8's string scan) — that third signal is what
            # catches Firebase Analytics, which ships NO framework and is linked into Runner.
            try:
                from .tracker_db import detect_trackers_ios
                results["trackers"] = detect_trackers_ios(
                    sdk_names=[s.get("name") for s in results.get("sdks") or []
                               if isinstance(s, dict)],
                    endpoints=results.get("endpoints") or [],
                    binary_markers=results.pop("_binary_tracker_markers", []),
                )
            except Exception:
                log.exception("[trackers] iOS tracker detection failed")
                results.setdefault("trackers", [])

            # ── Privacy-declaration discrepancy (the ONE finding from this area) ──
            # MUST run after BOTH chains exist: the trackers (presence, above) and the property
            # lists (absence). It is precisely their INTERSECTION. Running it inside the plist
            # block put it BEFORE tracker detection, so results["trackers"] was empty and the
            # finding never fired — the same ordering trap as RUN 11.
            try:
                from . import ios_plists as _plists
                _priv = _plists.build_privacy_declaration_finding(results)
                if _priv:
                    results["findings"].append(_priv)
            except Exception:
                log.exception("[privacy] privacy-declaration check failed")

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

        # ── iOS shallow taint (Phase 1 parity) — same-file source→sink pass ──
        try:
            _ios_shallow_taint(tmpdir, results)
        except Exception:
            log.exception("[ios_taint] shallow source->sink pass failed")

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
                        "truncated_symbol_lists": [
                            r.get("binary") for r in lief_results
                            if r.get("imported_syms_truncated")
                        ],
                    }
                    # Imported-symbol API scan across the main binary AND every framework:
                    # ONE consolidated finding per class (insecure API / logging / malloc),
                    # each listing the symbols that are genuinely in the import table.
                    # Per-binary protection table (main executable first, then frameworks).
                    # The FP guard lives in binary_protections: missing canary/ARC on the
                    # Dart-AOT blob, and missing ARC on a pure-C library, are NOT findings.
                    from . import binary_protections
                    _main = results["app_info"].get("bundle_executable") or ""
                    _bundle_rel0 = relativize_path(app_bundle, tmpdir) if app_bundle else ""

                    def _owner_of(rel_binary: str) -> str:
                        """Ownership Engine verdict for a bundle binary, via its FULL
                        bundle-relative path — the same fix RUN 8 made (a bare name is
                        mistaken for a CocoaPod). Drives HIGH-vs-MEDIUM severity below."""
                        from .ownership import get_engine as _own_engine
                        from .ownership.types import OwnershipContext as _Ctx
                        from .canonical_finding import CanonicalFinding as _CF
                        path = f"{_bundle_rel0}/{rel_binary}" if _bundle_rel0 else rel_binary
                        res = _own_engine().classify(
                            _CF(title="_bin", file_path=path, platform="ios",
                                evidence_type="binary_protection"),
                            _Ctx(platform="ios"))
                        return res.owner_type

                    prot_rows = binary_protections.build_table(
                        lief_results, main_binary=_main, owner_of=_owner_of)
                    results["binary_protections"] = prot_rows
                    prot_findings, prot_suppressed = binary_protections.build_findings(prot_rows)
                    results["findings"].extend(prot_findings)
                    results["binary_protections_suppressed"] = prot_suppressed

                    from . import binary_api_scan
                    _bundle_rel = relativize_path(app_bundle, tmpdir) if app_bundle else ""
                    api_findings = binary_api_scan.build_findings(
                        lief_results, platform="ios", bundle_prefix=_bundle_rel)
                    if api_findings:
                        results["findings"].extend(api_findings)
                        results["binary_api_scan"] = {
                            f["rule_id"]: {
                                "symbols": f["matched_symbols"],
                                "binaries": f["matched_binaries"],
                            } for f in api_findings
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
    # ── Phase 1.95: Finding Fusion Engine — collapse multi-engine duplicates into
    # ONE canonical finding "Detected By" all of them, with full provenance + a
    # multi-engine agreement signal. Supersets the old exact-key dedupe (also
    # unifies cross-engine equivalents). Runs BEFORE the Confidence Engine so
    # agreement feeds confidence. Deterministic, additive. Mirror of Android. ──
    try:
        from . import fusion
        fusion.fuse(results, platform="ios")
    except Exception:
        log.exception("[fusion] failed; falling back to exact-key dedupe")
        results["findings"] = dedupe_findings(results["findings"])
    # ── Phase 0/1: canonical normalization + ownership (additive, non-destructive) ──
    _app_pkg = results.get("app_info", {}).get("bundle_id", "")
    # ── Phase 1.9: APKLeaks Detection Source — already applied. The APKLeaks
    # pattern catalog (platform-agnostic: PEM keys, cloud creds, JWTs, URLs all
    # appear in iOS bundles too) was folded into the SINGLE combined secret walk
    # near the top of this function (``secret_catalog.combined()`` →
    # ``routing.extract_apkleaks`` → fusion), so its secrets/findings/endpoints are
    # already in the native streams with attribution + de-dup. We deliberately do
    # NOT call the registry orchestrator here — that would re-walk the bundle a
    # second time. ──
    # ── Phase 1.4: Secret Intelligence Engine — multi-stage validation of every
    # detected secret. MUST run BEFORE secret_intel masking so it sees raw values;
    # it stores only derived, non-sensitive signals. Additive only; never
    # suppresses or re-severities. Deterministic, network-free. ──
    # Deterministically surface Firebase GoogleService-Info.plist config (API_KEY /
    # CLIENT_ID) as INFO before the intelligence + processing stages. Dedup-safe
    # (skips values already in results["secrets"]); iOS-only. Runs BEFORE the two
    # stages below so these config keys traverse the same masking/status pipeline.
    try:
        _extract_firebase_plist_config(app_bundle, results)
    except Exception:
        log.exception("[firebase_plist] Firebase config extraction failed")
    try:
        from . import secret_intelligence
        secret_intelligence.annotate(results)
    except Exception:
        log.exception("[secret_intelligence] failed; secrets left without intelligence metadata")
    # ── Phase 9.1: secret intelligence foundation (canonical model + masking) ──
    try:
        from . import secret_intel
        secret_intel.process_secrets(results, _app_pkg)
    except Exception:
        log.exception("[secret_intel] failed; leaving secrets unprocessed")
    finding_model.canonicalize_findings(results["findings"], _app_pkg)
    results["ownership_metrics"] = finding_model.emit_diagnostics(
        results["findings"], platform="ios", app_package=_app_pkg,
    )
    # ── Phase 2: finding inventory & noise analysis (internal diagnostics) ──
    results["finding_diagnostics"] = finding_model.build_finding_diagnostics(results["findings"])
    finding_model.log_finding_analysis(results["finding_diagnostics"], platform="ios")
    # ── Cross-section noise scrub (endpoints / IPs / binary-dump evidence) ──
    results["scrub_stats"] = finding_model.scrub_noise(results)
    # ── Phase 5: source resolution validation (before refine so confidence sees it) ──
    results["source_resolution_stats"] = finding_model.validate_source_resolution(
        results["findings"], scan_id, results.get("manifest_xml", ""),
    )
    # ── Phase 3: signal quality — library filtering, confidence, dedup, FP suppression ──
    _kept, _suppressed, _quality_stats = finding_model.refine_findings(
        results["findings"], app_package=_app_pkg, platform="ios",
    )
    results["findings"] = _kept
    results["suppressed_findings"] = _suppressed
    results["finding_quality_stats"] = _quality_stats
    finding_model.log_quality_stats(_quality_stats, platform="ios")
    # ── Phase 5.4: per-finding quality report ──
    results["finding_quality_report"] = finding_model.build_finding_quality_report(_kept)
    finding_model.log_finding_quality_report(results["finding_quality_report"], platform="ios")
    # Severity summary / score now reflect the cleaned (deduped, de-FP'd) set.
    results["findings"] = sort_findings(results["findings"])
    results["severity_summary"] = compute_severity_summary(results["findings"])

    # ── Phase 1.9: secret→finding intelligence bridge — mirror MASKED APKLeaks
    # secrets into results["findings"] so they traverse ownership → confidence →
    # evidence → triage → attack chains → bug-bounty. Placed AFTER severity_summary
    # (so the bridged copies are never double-counted in the user-facing severity
    # counts) and AFTER masking (so no raw value can enter the findings stream).
    # reconcile_bridged_findings() (after bug-bounty) copies the enrichment back
    # onto the secret and REMOVES these copies, so they never display twice. Mirror
    # of the Android placement — Android/iOS stay consistent. ──
    try:
        from .detection_sources import fusion as _ds_fusion
        _ds_fusion.bridge_secrets_to_findings(results, platform="ios")
    except Exception:
        log.exception("[detection_sources] secret->finding bridge failed")
    # ── Phase 1.2: Ownership Engine — enrich every finding with ownership
    # metadata (owner_type/name/confidence/reason/…). Additive only: it writes
    # new owner_* keys and never touches existing finding data, so reports/UI are
    # unaffected. Deterministic, no network. ──
    try:
        from . import ownership
        ownership.annotate(results)
    except Exception:
        log.exception("[ownership] failed; findings left without ownership metadata")
    # Fix 2: demote library/framework-owned generic code-pattern findings to INFO
    # library-noise (unless app-owned reachability). APPLICATION/UNKNOWN untouched.
    try:
        finding_model.demote_library_code_findings(results)
    except Exception:
        log.exception("[library_noise] demotion failed")
    # ── Phase 7.5: trust framework — evidence quality, resolution coverage scores
    # and the overall trust score. Mirror of the Android placement
    # (android_analyzer.py:984): runs AFTER findings, source-resolution stats and
    # ownership have populated, and BEFORE the v2 attack chains — so the iOS report
    # shows a real Trust Score instead of "-". Additive; annotate_trust reads only
    # results["findings"] + per-finding fields (no manifest/Android-only input),
    # so it needs no manifest_xml guard here. iOS-only call site; Android unchanged. ──
    try:
        from . import trust_engine
        trust_engine.annotate_trust(results)
    except Exception:
        log.exception("[trust_engine] failed; report left without a trust score")
    # ── Phase 1.3: Confidence Engine — explainable per-finding confidence
    # (detection/ownership/evidence/context/exploitability/overall). Additive
    # only; reads owner_* from the Ownership Engine above. Never changes severity,
    # the legacy confidence/confidence_score, suppression, reports or UI. ──
    try:
        from . import confidence
        confidence.annotate(results)
    except Exception:
        log.exception("[confidence] failed; findings left without confidence metadata")
    # ── Phase 1.5: Unified Evidence Intelligence Engine — attach a structured
    # evidence_bundle (typed items, quality, verification, reproduction,
    # correlation, data-flow, hash) to every finding. Additive only; summarizes
    # ownership/confidence metadata so it runs after them. Deterministic. ──
    try:
        from . import evidence
        evidence.annotate(results)
    except Exception:
        log.exception("[evidence] failed; findings left without structured evidence")
    # ── Phase 1.6: Intelligent Finding Triage — assign every finding an
    # explainable triage decision + visibility recommendation by reasoning over
    # ownership/confidence/evidence/secret intelligence. Additive and
    # NON-DESTRUCTIVE: nothing is deleted or hidden here (reports/UI act on
    # triage.visibility). The final quality gate before Attack Chain v2. ──
    try:
        from . import triage
        triage.annotate(results)
    except Exception:
        log.exception("[triage] failed; findings left without triage decisions")
    # ── Phase 1.96/1.97: Intelligent Evidence Selection + Report Accuracy — pick the
    # strongest application-relevant primary proof, stamp the unified evidence_view,
    # and promote it into the legacy location fields so every surface shows the right
    # file. Runs BEFORE attack chains so chains reference corrected primaries. Mirror
    # of the Android placement. ──
    try:
        from . import evidence_selection
        evidence_selection.annotate(results, platform="ios")
    except Exception:
        log.exception("[evidence_selection] failed; findings left without proof selection")
    # ── Security Control Resolution — decide ONCE, from positive evidence, whether
    # each defensive control (pinning, cleartext/ATS, jailbreak detection, …) is
    # present, so attack chains, MASVS coverage and the score cannot disagree.
    # Runs after all findings exist and before the first consumer. Additive. ──
    try:
        from . import security_controls
        results["security_controls"] = security_controls.resolve(results)
    except Exception:
        log.exception("[security_controls] failed; consumers will resolve on demand")
    # ── Phase 1.7: Attack Chain Engine v2 — build realistic, evidence-backed,
    # explainable attacker journeys from the triaged findings + attack surface
    # (SAFE CHAINING: framework noise / suppressed / FP secrets / generated code
    # are never required links). Additive: writes results['attack_chains_v2'];
    # the legacy chain output, findings, severity, reports and UI are untouched. ──
    try:
        from . import attack_chains
        attack_chains.annotate(results)
        # Project v2 chains onto the findings list (mark members + first-class chain
        # findings) so the iOS findings list and PDF chain section reference the same
        # v2 chains, with computed confidence.
        attack_chains.annotate_findings(results)
    except Exception:
        log.exception("[attack_chains_v2] failed; no v2 chains emitted")
    # ── Phase 1.8: Bug Bounty Intelligence — reportability guidance for every
    # finding AND attack chain (score/state/research-value/effort/impact/next-step)
    # from all prior engines. Additive guidance only; nothing is modified or
    # removed. The final intelligence layer. Deterministic. ──
    try:
        from . import bug_bounty
        bug_bounty.annotate(results)
    except Exception:
        log.exception("[bug_bounty] failed; no reportability guidance emitted")
    # ── Phase 1.9: reconcile the secret→finding bridge — copy the intelligence the
    # engines computed (ownership/confidence/evidence/triage/bug-bounty/chain
    # membership) back onto the linked secret, then REMOVE the bridged copies from
    # results["findings"]. After this the same secret is shown once (Secrets view),
    # carries its full intelligence, and never appears as a duplicate finding in the
    # UI / PDF / HTML / JSON / SARIF / dashboard. Runs before analyst/MASVS/
    # workspaces/quick-summary/score so none of them see the bridged copies. Mirror
    # of the Android placement. ──
    try:
        from .detection_sources import fusion as _ds_fusion
        _ds_fusion.reconcile_bridged_findings(results)
    except Exception:
        log.exception("[detection_sources] bridge reconcile failed")
    # ── Phase 10: analyst & remediation intelligence (deterministic, no LLM/network) ──
    try:
        from . import analyst_intel
        analyst_intel.annotate(results)
    except Exception:
        log.exception("[analyst_intel] failed; findings left without explanations")
    # ── Phase 11: MASVS coverage intelligence (deterministic, no network) ──
    try:
        from . import masvs_intel
        masvs_intel.annotate(results)
    except Exception:
        log.exception("[masvs_intel] failed; no MASVS coverage emitted")
    # ── Phase 11.75: analyst workspaces + evidence intelligence (additive) ──
    try:
        from . import workspaces
        workspaces.annotate(results)
    except Exception:
        log.exception("[workspaces] failed; workspace structures not emitted")
    # ── Phase 2.3: Source / Security Explorer overlay (reuses existing metadata). ──
    try:
        from . import source_explorer
        source_explorer.annotate(results)
    except Exception:
        log.exception("[source_explorer] overlay failed; explorer metadata not emitted")

    # ── Quick summary ─────────────────────────────────────────────────────────
    _build_ios_quick_summary(results)

    # ── Security Score ────────────────────────────────────────────────────────
    results["score"] = calculate_score(results)

    # ── Phase 11.95: audience-targeted report summaries (CISO + developer) ──
    try:
        from report import report_summaries
        report_summaries.annotate(results)
    except Exception:
        log.exception("[report_summaries] failed; executive summaries not emitted")

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
                "rule_id": "ios_plist_parse_error",
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
    # Read the keys ACTUALLY present in this plist — the usage-description VALUE is the
    # developer's own justification ("…uses your camera for taking photos."), which is what
    # MobSF shows and what an analyst reviews. It was being discarded in favour of Beetle's
    # static label, so the report said "Camera access" and never showed the app's reason.
    dangerous = []
    all_perms = []
    for key, (sev, desc) in IOS_PERMISSIONS.items():
        if key in plist:
            all_perms.append(key)
            reason = plist.get(key)
            reason = reason.strip() if isinstance(reason, str) else ""
            dangerous.append({
                "permission": key,
                "short_name": key.replace("NS", "").replace("UsageDescription", ""),
                "severity": sev,
                "description": desc,              # Beetle's classification of the capability
                "usage_description": reason,      # the developer's declared reason (MobSF parity)
                # An empty usage string is itself a finding-worthy smell: iOS requires a
                # non-empty purpose string, and a blank one means the user sees no reason.
                "reason_declared": bool(reason),
            })

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
                    "rule_id":        "ios_custom_url_scheme",
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
    # Distinguish "ATS not declared" (iOS enforces it by default — the SECURE state) from
    # "declared and weakened". An absent key is not the same as a false value, and the
    # report must not imply the app configured something it never configured.
    declared = "NSAppTransportSecurity" in plist
    if not declared:
        state, summary = "default", "Not declared — ATS enforced by default (HTTPS required)."
    elif ats.get("NSAllowsArbitraryLoads"):
        state, summary = "disabled", "NSAllowsArbitraryLoads = true — ATS fully disabled; cleartext HTTP allowed to any host."
    elif ats.get("NSExceptionDomains"):
        doms = list(ats.get("NSExceptionDomains") or {})
        state = "exceptions"
        summary = f"ATS enforced with {len(doms)} per-domain exception(s): {', '.join(doms[:5])}."
    else:
        state, summary = "enforced", "ATS declared and enforced; no arbitrary loads, no exception domains."

    # The global relaxations, each reported by name. NSAllowsArbitraryLoadsInWebContent /
    # ...InMedia are narrower than the blanket switch, so they are their own rows rather than
    # being collapsed into "ATS disabled" — the report should say WHICH door is open.
    global_flags = [
        {"key": "NSAllowsArbitraryLoads",
         "value": bool(ats.get("NSAllowsArbitraryLoads")),
         "severity": "high" if ats.get("NSAllowsArbitraryLoads") else "info",
         "meaning": ("Cleartext HTTP allowed to ANY host — ATS fully disabled."
                     if ats.get("NSAllowsArbitraryLoads")
                     else "Not set — HTTPS required for all connections.")},
        {"key": "NSAllowsArbitraryLoadsInWebContent",
         "value": bool(ats.get("NSAllowsArbitraryLoadsInWebContent")),
         "severity": "medium" if ats.get("NSAllowsArbitraryLoadsInWebContent") else "info",
         "meaning": ("WebView content may load over cleartext HTTP (app's own requests still "
                     "protected)." if ats.get("NSAllowsArbitraryLoadsInWebContent")
                     else "Not set — WebView content must use HTTPS.")},
        {"key": "NSAllowsArbitraryLoadsForMedia",
         "value": bool(ats.get("NSAllowsArbitraryLoadsForMedia")),
         "severity": "medium" if ats.get("NSAllowsArbitraryLoadsForMedia") else "info",
         "meaning": ("AV media may load over cleartext HTTP."
                     if ats.get("NSAllowsArbitraryLoadsForMedia")
                     else "Not set — media must use HTTPS.")},
        {"key": "NSAllowsLocalNetworking",
         "value": bool(ats.get("NSAllowsLocalNetworking")),
         "severity": "info",     # local-network exemption is not an internet exposure
         "meaning": ("Local-network (.local / literal IP) connections exempt from ATS."
                     if ats.get("NSAllowsLocalNetworking")
                     else "Not set.")},
    ]

    # Per-exception-domain rows. An exception that permits INSECURE HTTP loads is the real
    # weakness; one that merely lowers the TLS floor or disables forward secrecy is weaker but
    # still a downgrade, so each is scored on what it actually relaxes.
    domain_rows = []
    for domain, cfg in (ats.get("NSExceptionDomains") or {}).items():
        cfg = cfg if isinstance(cfg, dict) else {}
        insecure = bool(cfg.get("NSExceptionAllowsInsecureHTTPLoads")
                        or cfg.get("NSThirdPartyExceptionAllowsInsecureHTTPLoads"))
        min_tls = str(cfg.get("NSExceptionMinimumTLSVersion")
                      or cfg.get("NSThirdPartyExceptionMinimumTLSVersion") or "")
        no_pfs = (cfg.get("NSExceptionRequiresForwardSecrecy") is False
                  or cfg.get("NSThirdPartyExceptionRequiresForwardSecrecy") is False)
        weak_tls = min_tls in ("TLSv1.0", "TLSv1.1")
        if insecure:
            sev, why = "high", "Allows cleartext HTTP to this domain."
        elif weak_tls:
            sev, why = "medium", f"Lowers the TLS floor to {min_tls}."
        elif no_pfs:
            sev, why = "medium", "Disables forward secrecy for this domain."
        else:
            sev, why = "info", "Exception declared but no insecure relaxation."
        domain_rows.append({
            "domain": domain,
            "allows_insecure_http": insecure,
            "includes_subdomains": bool(cfg.get("NSIncludesSubdomains")),
            "minimum_tls": min_tls or "TLSv1.2 (default)",
            "requires_forward_secrecy": not no_pfs,
            "severity": sev,
            "why": why,
        })
    domain_rows.sort(key=lambda d: {"high": 0, "medium": 1, "info": 2}[d["severity"]])

    enforced = state in ("default", "enforced") and not any(
        f["value"] for f in global_flags if f["severity"] != "info")
    results["app_info"]["ats_state"] = {
        "declared": declared, "state": state, "summary": summary,
        "enforced": enforced,
        "allows_arbitrary_loads": bool(ats.get("NSAllowsArbitraryLoads")),
        "exception_domains": list(ats.get("NSExceptionDomains") or {}),
        "global_flags": global_flags,
        "domains": domain_rows,
        "posture": ("ATS enforced" if enforced else
                    ("ATS disabled" if ats.get("NSAllowsArbitraryLoads") else "ATS weakened")),
    }

    if ats.get("NSAllowsArbitraryLoads"):
        results["findings"].append({
            "rule_id":        "ios_ats_disabled",
            "title":          "ATS Fully Disabled — All HTTP Connections Allowed",
            "severity":       "high",
            "category":       "Network Security",
            "description":    "NSAllowsArbitraryLoads is set to true in Info.plist. App Transport Security is fully disabled, allowing all HTTP connections.",
            "impact":         "App can communicate over unencrypted HTTP to any host. Enables MitM on any connection.",
            "recommendation": "Remove NSAllowsArbitraryLoads. Use NSExceptionDomains for specific exceptions. Migrate all connections to HTTPS.",
        })
    elif ats.get("NSAllowsArbitraryLoadsInWebContent"):
        results["findings"].append({
            "rule_id":        "ios_ats_web_content_disabled",
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
                "rule_id":        "ios_ats_domain_exception",
                "title":          f"ATS Exception — HTTP Allowed for {domain}",
                "severity":       "low",
                "category":       "Network Security",
                "description":    f"ATS exception permits insecure HTTP connections to `{domain}`.",
                "recommendation": f"Migrate {domain} to HTTPS and remove the ATS exception.",
            })

    # ── Dangerous plist flags ─────────────────────────────────────────────────
    if plist.get("NSBluetoothAlwaysUsageDescription") and plist.get("NSLocationAlwaysUsageDescription"):
        results["findings"].append({
            "rule_id":        "ios_background_bluetooth_location",
            "title":          "Background Bluetooth + Location — Privacy Risk",
            "severity":       "medium",
            "category":       "Permissions",
            "description":    "App requests both always-on Bluetooth and location access, enabling persistent background tracking.",
            "recommendation": "Evaluate if both background permissions are truly required. Provide clear user disclosure.",
        })

    if plist.get("NSUserTrackingUsageDescription"):
        results["findings"].append({
            "rule_id":        "ios_att_requested",
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
                "rule_id":        "ios_binary_stack_canary_missing",
                "title":          "Stack Canary Not Detected",
                "severity":       "low",
                "category":       "Binary Hardening",
                "description":    "Stack canary protection was not detected in the binary. This increases the risk of stack buffer overflow exploitation.",
                "recommendation": "Compile with -fstack-protector-all flag. Ensure iOS deployment target is set correctly.",
            })

        if not has_arc:
            results["findings"].append({
                "rule_id":        "ios_binary_arc_missing",
                "title":          "ARC (Automatic Reference Counting) Not Detected",
                "severity":       "low",
                "category":       "Binary Hardening",
                "description":    "ARC was not detected. Manual memory management increases risk of use-after-free and memory corruption.",
                "recommendation": "Enable ARC in Xcode build settings.",
            })

        if has_rpath:
            results["findings"].append({
                "rule_id":        "ios_binary_rpath_usage",
                "title":          "@rpath — Dylib Hijacking Risk",
                "severity":       "medium",
                "category":       "Binary Hardening",
                "description":    "Binary uses @rpath for dynamic library loading. If a writable rpath directory is found, dylib hijacking may be possible.",
                "poc":            "# Check rpath:\notool -l <binary> | grep -A2 LC_RPATH",
                "recommendation": "Use @executable_path or @loader_path with absolute paths. Audit all rpath entries.",
            })

        results["findings"].append({
            "rule_id":        "ios_binary_hardening_summary",
            "title":          "Binary Hardening Analysis Complete",
            "severity":       "info",
            "category":       "Binary Hardening",
            "description":    f"Stack canary: {'✓' if has_stack_canary else '✗'} | ARC: {'✓' if has_arc else '✗'} | @rpath: {'present' if has_rpath else 'not found'}",
        })

    except Exception:
        pass


# ─── Binary strings scan ──────────────────────────────────────────────────────
_MACHO_MAGIC = (
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",   # 32/64-bit big-endian
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",   # 32/64-bit little-endian
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # fat/universal
)
_MAX_BINARIES = 40                  # matches lief_analyzer.analyze_all_macho's cap
_MAX_BINARY_BYTES = 64 * 1024 * 1024


def _iter_macho_binaries(app_bundle: str):
    """Yield every Mach-O in the .app bundle — main executable, Frameworks/*.framework/*,
    and *.dylib. Identified by magic bytes (these files are extension-less), so this needs
    no LIEF and no second full walk beyond this one."""
    count = 0
    for root, _dirs, files in os.walk(app_bundle):
        for fn in sorted(files):
            full = os.path.join(root, fn)
            try:
                if os.path.getsize(full) < 256:
                    continue
                with open(full, "rb") as f:
                    if f.read(4) not in _MACHO_MAGIC:
                        continue
            except OSError:
                continue
            yield full
            count += 1
            if count >= _MAX_BINARIES:
                return


def _record_binary_format_files(app_bundle: str, results: dict, base_dir: str = "") -> None:
    """Record every file in the bundle that is BINARY-FORMAT, by magic bytes.

    Mach-O binaries and BINARY plists (bplist00) both carry "line numbers" that are not
    source lines: a Mach-O match indexes the extracted-strings listing, and a binary plist
    has no text lines at all (GoogleService-Info.plist reports line 3 with an empty
    snippet). The evidence view consumes this set so neither is ever rendered as file:line.
    Detected by content, not by extension — an IPA's Info.plist may be XML or binary.
    """
    if not app_bundle or not os.path.isdir(app_bundle):
        return
    found: list[str] = []
    for root, _dirs, files in os.walk(app_bundle):
        for fn in files:
            full = os.path.join(root, fn)
            try:
                if os.path.getsize(full) < 8:
                    continue
                with open(full, "rb") as f:
                    head = f.read(8)
            except OSError:
                continue
            if head[:4] in _MACHO_MAGIC or head == b"bplist0" + b"0":
                found.append(relativize_path(full, base_dir) if base_dir else full)
    if found:
        results["binary_evidence_files"] = sorted(set(found))


def _scan_binary_strings(app_bundle: str, results: dict, base_dir: str = ""):
    """Dump printable strings from every Mach-O and harvest secrets + URLs + IPs.

    URLs/IPs are stashed on results["_binary_endpoints"] / ["_binary_ip_hits"] rather than
    merged here: results["endpoints"]/["ips"] are not populated until the thread pool in
    analyze_ipa returns, and merging early would just be overwritten.
    """
    if not app_bundle or not os.path.isdir(app_bundle):
        return
    seen_secrets = {f"{s['name']}:{s['value']}" for s in results.get("secrets") or []}
    urls: set[str] = set()
    ip_hits: dict[tuple, dict] = {}
    # Tracker markers for SDKs that are STATICALLY LINKED into a binary rather than shipped as a
    # framework — Firebase Analytics is linked straight into Runner in this app, so a
    # framework-only check would miss it entirely. Reuses this walk; no extra pass.
    from .tracker_db import ios_tracker_markers
    _markers = ios_tracker_markers()
    marker_hits: set[str] = set()

    for binary_path in _iter_macho_binaries(app_bundle):
        try:
            with open(binary_path, "rb") as f:
                raw = f.read(_MAX_BINARY_BYTES)
            text = printable_text(raw)
            rel_path = relativize_path(binary_path, base_dir) if base_dir else binary_path

            for s in scan_text_for_secrets(text, rel_path):
                key = f"{s['name']}:{s['value']}"
                if key not in seen_secrets:
                    seen_secrets.add(key)
                    results.setdefault("secrets", []).append(s)

            urls.update(endpoint_intel.extract_urls_from_text(text))
            for hit in network_intel.extract_ips_from_text(text, rel_path):
                ip_hits.setdefault((hit["ip"], hit["file_path"]), hit)
            marker_hits.update(m for m in _markers if m in text)
        except Exception:
            log.exception("[ios] binary string scan failed for %s", binary_path)

    results["_binary_endpoints"] = sorted(urls)
    results["_binary_ip_hits"] = list(ip_hits.values())
    results["_binary_tracker_markers"] = sorted(marker_hits)


# ─── Endpoint extraction ──────────────────────────────────────────────────────
def _extract_endpoints(tmpdir: str, results: dict, *, corpus: SourceCorpus = None):
    # Phase 2.5.6: broad, multi-source extraction shared with Android via
    # endpoint_intel (Swift/ObjC/plist/json/js + ws/wss + custom-scheme deep links).
    # verbose=True: the iOS bundle is compiled — plists, flutter_assets and framework
    # resources carry URLs as bare literals with no call site to prove, so the
    # called-only default (right for Android's decompiled Java/Kotlin source) would
    # drop nearly all of them. iOS-only; Android's extract_endpoints call is untouched.
    results["endpoints"] = endpoint_intel.extract_endpoints(
        tmpdir, corpus=corpus or SourceCorpus(), results=results, verbose=True)


# ─── Framework detection ──────────────────────────────────────────────────────
def _detect_framework(app_bundle: str, results: dict):
    if not app_bundle or not os.path.exists(app_bundle):
        return

    files = set()
    dirs_set = set()
    for root, dnames, fnames in os.walk(app_bundle):
        for d in dnames:
            dirs_set.add(d.lower())
        for f in fnames:
            files.add(f.lower())

    fw_type  = "native"
    details  = []

    # Flutter — RECURSIVE detection. `flutter_assets` is normally nested under
    # Frameworks/App.framework/ (and plugins under Frameworks/*.framework/), so a
    # top-level os.listdir misses it and the app is mislabeled "native".
    _FLUTTER_DIRS  = {"flutter_assets", "app.framework", "flutter.framework"}
    _FLUTTER_FILES = {"libapp.dylib", "libflutter.dylib"}
    # Well-known Flutter plugin Pods (ship as *.framework in Frameworks/) — their
    # presence is a strong Flutter signal even without the App/Flutter framework dirs.
    _FLUTTER_PLUGIN_PODS = {
        "webview_flutter_wkwebview", "flutter_secure_storage", "image_picker_ios",
        "path_provider_foundation", "shared_preferences_foundation", "url_launcher_ios",
        "sqflite", "sqflite_darwin", "connectivity_plus", "package_info_plus",
        "geolocator_apple", "google_maps_flutter_ios", "device_info_plus",
        "flutter_plugin_android_lifecycle", "google_sign_in_ios", "firebase_core",
    }

    def _pod_name(d):  # a *.framework dir's pod name
        return d[:-len(".framework")] if d.endswith(".framework") else d

    plugin_hit = next((_pod_name(d) for d in dirs_set if _pod_name(d) in _FLUTTER_PLUGIN_PODS), None)
    _flutter_dir_hit = dirs_set & _FLUTTER_DIRS
    _flutter_file_hit = files & _FLUTTER_FILES
    if _flutter_dir_hit or _flutter_file_hit or plugin_hit:
        fw_type = "flutter"
        why = []
        if "flutter_assets" in dirs_set: why.append("flutter_assets directory")
        if "app.framework" in dirs_set: why.append("Frameworks/App.framework")
        if "flutter.framework" in dirs_set: why.append("Frameworks/Flutter.framework")
        if _flutter_file_hit: why.append(", ".join(sorted(_flutter_file_hit)))
        if plugin_hit: why.append(f"Flutter plugin pod ({plugin_hit})")
        details.append("Flutter detected via " + "; ".join(why))
        results["findings"].append({
            "rule_id":        "framework_flutter_detected",
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
            "rule_id":        "framework_react_native_detected",
            "rule_id":        "framework_react_native_detected",
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
            "rule_id":        "framework_cordova_detected",
            "rule_id":        "framework_cordova_detected",
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
            "rule_id":        "ios_ats_config_missing",
            "rule_id":        "ios_ats_not_configured",
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

    # Best candidate seen so far: (pixel_area, renderable_bytes, src_path, source).
    # Every candidate is judged by what it ACTUALLY DECODES TO, never by its filename:
    # the bundle's AppIcon PNGs are Apple CgBI (unrenderable until converted), and the
    # plist-declared name is not necessarily the highest-resolution rendition.
    best: list = []

    def _consider(raw: bytes, src_path: str, source: str = "ipa") -> None:
        std = renderable_image_bytes(raw)
        if not std:
            return
        dims = png_dimensions(std) if std[:8] == PNG_SIG else None
        if dims:
            w, h = dims
            if w != h or w < 20:        # an app icon is square
                return
            area = w * h
        else:
            area = 1                    # JPEG — keep, but never outrank a sized PNG
        if not best or area > best[0][0]:
            best[:] = [(area, std, src_path, source)]

    def _emit_best() -> bool:
        if not best:
            return False
        _area, std, src_path, source = best[0]
        mime = "image/png" if std[:8] == PNG_SIG else "image/jpeg"
        results["app_info"]["icon_data"] = f"data:{mime};base64,{base64.b64encode(std).decode('ascii')}"
        try:
            results["app_info"]["icon_path"] = os.path.relpath(src_path, app_bundle).replace("\\", "/")
        except ValueError:
            results["app_info"]["icon_path"] = os.path.basename(src_path)
        results["app_info"]["icon_source"] = source
        return True

    # (1) iTunesArtwork — present in older distribution formats
    for artwork in ("iTunesArtwork@2x", "iTunesArtwork"):
        candidate = os.path.join(os.path.dirname(app_bundle), artwork)
        if os.path.isfile(candidate):
            try:
                _consider(Path(candidate).read_bytes(), candidate)
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

    # Consider every plist-declared candidate and every heuristic PNG — then pick the
    # highest-resolution one that actually decodes (see _consider). Previously the first
    # readable candidate won, which on this app meant the iPad 76x76@2x rendition.
    seen = set()
    for candidate in icon_candidates:
        if candidate in seen or not os.path.isfile(candidate):
            continue
        seen.add(candidate)
        try:
            _consider(Path(candidate).read_bytes(), candidate)
        except Exception:
            continue

    for _, path in sorted(heuristic, reverse=True):
        if path in seen:
            continue
        seen.add(path)
        try:
            _consider(Path(path).read_bytes(), path)
        except Exception:
            continue

    # (5) Assets.car — modern Xcode/Flutter builds compile the AppIcon asset-catalog into
    # Assets.car and may ship NO loose PNGs. Carve the embedded PNG renditions directly
    # (no actool/macOS needed). Considered alongside the loose files, not only as a last
    # resort, so the largest rendition wins wherever it lives.
    assets_car = os.path.join(app_bundle, "Assets.car")
    carved = None
    if os.path.isfile(assets_car):
        try:
            carved = best_icon_png_from_assets_car(Path(assets_car).read_bytes())
        except Exception:
            carved = None
        if carved:
            _consider(carved, assets_car, source="assets_car")

    if _emit_best():
        return

    # Nothing decodable anywhere — record WHY instead of failing silently, keeping the
    # Assets.car diagnosis distinct from "the bundle simply has no icon".
    if os.path.isfile(assets_car) and not carved:
        results["app_info"]["icon_source"] = "assets_car_unsupported"
        results["app_info"]["icon_note"] = (
            "App icon is embedded in compiled Assets.car and could not be carved. "
            "Install `assetutil` (macOS) or `acextract` to extract PNGs."
        )
    else:
        results["app_info"]["icon_source"] = "unavailable"
        results["app_info"]["icon_note"] = (
            "No renderable app icon found: the bundle ships no standard PNG/JPEG icon, and "
            "no CgBI (Apple-crushed) PNG could be decoded."
        )


# ─── Firebase GoogleService-Info.plist config extraction ─────────────────────
# Deterministically surface the Firebase client config (API_KEY / CLIENT_ID) as
# INFO application-config secrets. The generic AIza pattern already catches API_KEY,
# but CLIENT_ID (an OAuth client id, not an AIza key) is matched by NO pattern, so it
# was invisible. A dedicated structured parse guarantees both keys render (INFO, like
# the Android Firebase key) regardless of how the plist is stored (XML or binary) and
# is dedup-safe (a value already present in results["secrets"] is not re-emitted).
# iOS-only call site; Android is untouched.
_FIREBASE_PLIST_KEYS = (
    # plist key,       secret title,               rule_id / type,          confidence
    ("API_KEY",        "Google API Key",           "secret_google_api_key",  90),
    ("CLIENT_ID",      "Google OAuth Client ID",   "secret_google_client_id", 80),
    ("GOOGLE_APP_ID",  "Firebase App ID",          "secret_firebase_app_id",  75),
)


def _secret_has_evidence(s: dict) -> bool:
    """Mirror of the evidence gate in secret_intel._build_canonical (secret_intel.py:747):
    a secret without path AND line AND snippet is dropped there ("no evidence, no finding").
    """
    path = s.get("full_path") or s.get("file_path") or s.get("source")
    return bool(path and s.get("line") and s.get("snippet"))


def _extract_firebase_plist_config(app_bundle: str, results: dict) -> None:
    if not app_bundle or not os.path.isdir(app_bundle):
        return
    added = 0
    for root, _dirs, files in os.walk(app_bundle):
        for fname in files:
            if fname != "GoogleService-Info.plist":
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as f:
                    plist = plistlib.load(f)
            except Exception:
                continue
            rel = os.path.relpath(fpath, os.path.dirname(app_bundle)).replace("\\", "/")
            for key, title, rule_id, conf in _FIREBASE_PLIST_KEYS:
                val = plist.get(key)
                if not isinstance(val, str) or not val.strip():
                    continue
                val = val.strip()
                # GoogleService-Info.plist is a BINARY plist, so the generic scanners
                # extract the value but cannot quote a source line — they emit it with an
                # empty snippet, and the shared evidence gate then drops it silently. A
                # blind "already seen -> skip" therefore SUPPRESSED the key entirely: the
                # only copy with real evidence (this one) was never added. So: keep a
                # generic hit that HAS evidence, but replace evidence-less duplicates,
                # which would not survive the gate anyway.
                prior = [s for s in results.get("secrets") or []
                         if str(s.get("value") or "").strip() == val]
                if any(_secret_has_evidence(s) for s in prior):
                    continue  # already surfaced WITH evidence — do not duplicate
                if prior:
                    results["secrets"] = [s for s in results["secrets"]
                                          if str(s.get("value") or "").strip() != val]
                results.setdefault("secrets", []).append({
                    "title": title, "name": title,
                    "severity": "info", "category": "API Key",
                    "description": (f"{title} from GoogleService-Info.plist ({key}). Firebase "
                                    "client-side identifiers are shipped in every app and are not "
                                    "confidential; surfaced for inventory."),
                    "recommendation": ("Restrict the key in the Google Cloud console (API + app "
                                       "restrictions). No action if already restricted."),
                    "file_path": rel, "line": 1,
                    "snippet": f"{key} = {val[:6]}…",
                    "confidence": conf, "exploitability": 20,
                    "validation_status": "detected",
                    "rule_id": rule_id, "evidence_type": "plist_key",
                    "value": val, "source": "firebase_plist",
                    "cwe": "CWE-200", "masvs": "MASVS-STORAGE-1", "owasp": "M1",
                    "provenance": "beetle_native", "kind": "client_key",
                })
                added += 1
    if added:
        results.setdefault("scan_metrics", {})["firebase_plist_secrets"] = added


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


def _rfc4514_attrs(dn: str) -> dict:
    """Parse an RFC4514 distinguished-name string (as produced by
    x509 .rfc4514_string()) into {CN, O, OU, C, ...}. First value per type wins.

    Splits on unescaped commas only (rfc4514 escapes literal commas as '\\,').
    """
    attrs: dict[str, str] = {}
    if not dn:
        return attrs
    parts, buf, esc = [], [], False
    for ch in dn:
        if esc:
            buf.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            k = k.strip().upper()
            if k and k not in attrs:
                attrs[k] = v.strip()
    return attrs


def _ios_cert_date(iso: str) -> str:
    """Normalize an ISO cert timestamp (e.g. '2024-01-01T00:00:00Z') to YYYY-MM-DD."""
    if not iso:
        return ""
    return str(iso).split("T", 1)[0]


def _ios_cert_expired(not_after_iso: str) -> bool | None:
    """True/False if the leaf cert not_after is in the past/future; None if unknown.

    Derived from the parsed date (evidence), never assumed.
    """
    if not not_after_iso:
        return None
    from datetime import datetime, timezone
    s = str(not_after_iso).rstrip("Z")
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < datetime.now(timezone.utc)


def _build_ios_certificate(results: dict) -> None:
    """Populate results["certificate"] for iOS from the already-parsed signing
    certificates + provisioning fields in results["app_info"].

    Leaves results["certificate"] unset when the IPA carries no signing/provisioning
    data (unsigned / stripped) — the report then shows "No certificate data", the same
    as before. Additive; never overwrites an existing certificate dict.
    """
    if results.get("certificate"):
        return
    ai = results.get("app_info", {}) or {}
    certs = ai.get("signing_certificates") or []
    team          = ai.get("provisioning_team", "")
    prov_type     = ai.get("provisioning_type", "")
    prov_profile  = ai.get("provisioning_profile", "")
    prov_expiry   = ai.get("provisioning_expiry", "")
    if not certs and not (team or prov_type or prov_profile):
        return  # nothing was parsed → no certificate section

    leaf = certs[0] if certs else {}
    subject = _rfc4514_attrs(leaf.get("subject", ""))
    issuer  = _rfc4514_attrs(leaf.get("issuer", ""))
    not_after = leaf.get("not_after", "")

    cert = {
        "available": True,
        "platform": "ios",
        "subject": subject,
        "issuer": issuer,
        "signing_identity": subject.get("CN", ""),
        "team": team,
        "provisioning_type": prov_type,
        "provisioning_profile": prov_profile,
        "provisioning_expiry": prov_expiry,
        "valid_from": _ios_cert_date(leaf.get("not_before", "")),
        "valid_to": _ios_cert_date(not_after),
        "serial": leaf.get("serial", ""),
        "sha1_fingerprint": leaf.get("sha1", ""),
        "sha256_fingerprint": leaf.get("sha256", ""),
    }
    expired = _ios_cert_expired(not_after)
    if expired is not None:
        cert["expired"] = expired
    results["certificate"] = cert


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
                                "rule_id": "ios_provisioning_profile_expired",
                                "rule_id": "ios_provisioning_profile_expired",
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
                                "rule_id": "ios_provisioning_profile_expiring",
                                "rule_id": "ios_provisioning_profile_expiring",
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
                            "rule_id": "ios_dev_cert_on_distribution",
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
            "rule_id":        rule_slug("ios_entitlement", key),
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

    # ── Flutter runtime — NOT third-party SDKs ────────────────────────────────
    # "App" is the app's OWN compiled Dart code (the AOT blob) and "Flutter" is the
    # engine. Listing them as unknown third-party dependencies misattributes the app's
    # own code to a vendor, so they are categorised as runtime and never flagged.
    "App":     ("runtime", "info", "Dart AOT blob — the app's OWN compiled code, not a third-party SDK"),
    "Flutter": ("runtime", "info", "Flutter engine runtime"),

    # ── Firebase / Google (this app ships 13 Firebase modules) ────────────────
    "FirebaseCore":               ("backend",   "info", "Firebase core SDK"),
    "FirebaseCoreExtension":      ("backend",   "info", "Firebase core extension"),
    "FirebaseCoreInternal":       ("backend",   "info", "Firebase core internals"),
    "FirebaseSharedSwift":        ("backend",   "info", "Firebase shared Swift support"),
    "FirebaseInstallations":      ("backend",   "info", "Firebase Installations — per-install identifier"),
    "FirebaseRemoteConfig":       ("backend",   "info", "Firebase Remote Config — server-driven config"),
    "FirebaseRemoteConfigInterop":("backend",   "info", "Firebase Remote Config interop"),
    "FirebaseABTesting":          ("analytics", "info", "Firebase A/B Testing"),
    "FirebaseSessions":           ("analytics", "info", "Firebase Sessions — session telemetry"),
    "FirebasePerformance":        ("analytics", "info", "Firebase Performance Monitoring"),
    "FirebaseCrashlytics":        ("analytics", "info", "Crashlytics crash reporting"),
    "GoogleDataTransport":        ("utility",   "info", "Google data transport — telemetry delivery"),
    "GoogleUtilities":            ("utility",   "info", "Google shared utilities"),
    "FBLPromises":                ("utility",   "info", "Google FBLPromises — async primitives"),
    "Promises":                   ("utility",   "info", "PromisesSwift — async primitives"),
    "nanopb":                     ("utility",   "info", "nanopb — embedded protobuf codec"),

    # ── Security / anti-tamper ────────────────────────────────────────────────
    "IOSSecuritySuite":                 ("security", "info", "iOS Security Suite — jailbreak / debugger / hook detection"),
    "flutter_jailbreak_detection_plus": ("security", "info", "Flutter jailbreak-detection plugin"),

    # ── Flutter plugins present in this bundle ────────────────────────────────
    "webview_flutter_wkwebview":     ("webview",  "info", "Flutter WKWebView plugin — renders web content in-app"),
    "flutter_secure_storage":        ("storage",  "info", "Flutter secure storage — Keychain-backed"),
    "shared_preferences_foundation": ("storage",  "info", "Flutter shared preferences — NSUserDefaults-backed"),
    "path_provider_foundation":      ("storage",  "info", "Flutter path provider — filesystem locations"),
    "connectivity_plus":             ("network",  "info", "Flutter connectivity state plugin"),
    "network_speed":                 ("network",  "info", "Network speed measurement plugin"),
    "camera_avfoundation":           ("media",    "info", "Flutter camera plugin (AVFoundation)"),
    "image_picker_ios":              ("media",    "info", "Flutter image picker — photo library / camera"),
    "just_audio":                    ("media",    "info", "Flutter audio playback plugin"),
    "audio_session":                 ("media",    "info", "Flutter audio session management"),
    "nfc_manager":                   ("nfc",      "info", "Flutter NFC plugin"),
    "qr_code_scanner_plus":          ("scanning", "info", "Flutter QR / barcode scanner"),
    "snowfinch_logger":              ("logging",  "info", "Snowfinch logger (vendor plugin)"),
    "snowfinch_app_logger":          ("logging",  "info", "Snowfinch app logger (vendor plugin)"),
    "package_info_plus":             ("platform", "info", "Flutter package info plugin"),
    "device_info_plus":              ("platform", "info", "Flutter device info plugin"),
    "battery_plus":                  ("platform", "info", "Flutter battery state plugin"),
    "flutter_timezone":              ("platform", "info", "Flutter timezone plugin"),
    "fluttertoast":                  ("platform", "info", "Flutter toast/UI plugin"),
}

# Family fallbacks — so a Firebase/Google module NOT named above is still categorised
# instead of landing in "unknown". Checked only after an exact-name miss; a genuinely
# unrecognised pod still reports "unknown", which is the honest answer.
_FRAMEWORK_PREFIXES = (
    ("Firebase", ("backend",   "info", "Firebase module")),
    ("Google",   ("utility",   "info", "Google SDK module")),
    ("GTM",      ("utility",   "info", "Google Tag Manager module")),
)


def _classify_framework(name: str):
    """(category, severity, description, known) for an embedded framework.

    Exact name first, then family prefix. Anything still unmatched stays "unknown" —
    RUN 7 is about categorising what this bundle ACTUALLY ships, not about guessing.
    """
    info = _KNOWN_FRAMEWORKS.get(name)
    if info:
        return info[0], info[1], info[2], True
    for prefix, fallback in _FRAMEWORK_PREFIXES:
        if name.startswith(prefix):
            return fallback[0], fallback[1], f"{fallback[2]} ({name})", True
    return "unknown", "info", "", False

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
                category, severity, description, known = _classify_framework(name)
                entry = {"name": name, "path": f"{os.path.basename(search_dir)}/{item}"}
                entry.update({"category": category, "severity": severity,
                              "description": description, "known": known})
                found.append(entry)

                # Flag high-severity known frameworks as findings. Every framework added in
                # RUN 7 is severity "info" by design: categorising a dependency must not
                # invent a finding about it.
                info = _KNOWN_FRAMEWORKS.get(name)
                if info and info[1] in ("high", "medium"):
                    results["findings"].append({
                        "rule_id":        "ios_third_party_framework",
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
    from .tracker_db import normalize_sdks
    results["sdks"] = normalize_sdks(
        [{"name": f["name"], "category": f["category"], "description": f["description"]} for f in found]
    )


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


# ── iOS shallow taint (Phase 1) ───────────────────────────────────────────────
# A minimal, SAME-FILE source→sink co-occurrence pass — NOT inter-procedural (that is
# the Phase 2 engine). Sources are untrusted-input entry points; sinks are dangerous
# consumers. When a source and a sink appear within a proximity window in one file,
# emit a heuristic flow so iOS reaches parity with Android's Data Flow surface.
_IOS_TAINT_SOURCES = (
    (re.compile(r'\bopen\s+url\b|openURL|application\([^)]*open\b|url\.host|url\.query|'
                r'queryItems|URLComponents|\.absoluteString', re.I),
     "URL Scheme", "URL-scheme / deep-link handler input"),
    (re.compile(r'UIPasteboard\.general\.(?:string|url|image|items)|\.pasteboard\b', re.I),
     "Clipboard", "pasteboard read"),
    (re.compile(r'SecItemCopyMatching|kSecClass\b', re.I),
     "Keychain", "keychain read"),
)
_IOS_TAINT_SINKS = (
    (re.compile(r'\bloadRequest\b|\bevaluateJavaScript\b|\bloadHTMLString\b|\bloadFileURL\b|'
                r'\bwebView\b[^\n]*\.load\s*\(', re.I),
     "WebView", "WebView load / JS eval"),
    (re.compile(r'\bFileManager\b|\.write\s*\(\s*to|contentsOfFile|Data\s*\(\s*contentsOf|'
                r'\bcreateFile\b', re.I),
     "FileSystem", "file read/write"),
    (re.compile(r'\bURLSession\b|\.dataTask\b|\.uploadTask\b|URLRequest\s*\(', re.I),
     "Network", "network request"),
)
_IOS_TAINT_WINDOW = 40   # lines: source and sink must be within this to be a flow
_IOS_SENSITIVE_SOURCES = frozenset(("Clipboard", "Keychain"))


def _ios_shallow_taint(tmpdir: str, results: dict) -> None:
    """Emit heuristic source→sink flows (same-file, proximity-based) into
    results["findings"] and results["taint_flows"] (Android-compatible shape)."""
    flows = results.setdefault("taint_flows", [])
    seen: set = set()
    extensions = (".swift", ".m", ".mm", ".h")
    for root, _dirs, files in os.walk(tmpdir):
        for fname in files:
            if not fname.endswith(extensions):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = Path(fpath).read_text(errors="replace")
            except Exception:
                continue
            low = content.lower()
            if "://" not in content and not any(
                    k in low for k in ("openurl", "open url", "uipasteboard", "secitem",
                                       "webview", "urlsession", "filemanager", "url.host",
                                       "url.query", "absolutestring", "loadrequest",
                                       "evaluatejavascript")):
                continue
            rel = os.path.relpath(fpath, tmpdir)
            lines = content.splitlines()

            def _hits(table):
                out = []
                for rx, cat, label in table:
                    for m in rx.finditer(content):
                        out.append((content[:m.start()].count("\n") + 1, cat, label))
                return out

            src_hits = _hits(_IOS_TAINT_SOURCES)
            sink_hits = _hits(_IOS_TAINT_SINKS)
            if not (src_hits and sink_hits):
                continue
            for s_line, s_cat, s_label in src_hits:
                for k_line, k_cat, k_label in sink_hits:
                    # Forward flow only: the sink must be at/after the source (small
                    # tolerance) and within the proximity window — reduces spurious
                    # backward cross-products in this same-file heuristic.
                    if k_line < s_line - 2 or k_line - s_line > _IOS_TAINT_WINDOW:
                        continue
                    key = (rel, s_cat, k_cat)
                    if key in seen:
                        continue
                    seen.add(key)
                    # Injection/exfil sinks are the concern regardless of source; a
                    # sensitive source (keychain/clipboard) reaching any sink is worse.
                    risk = "high" if (k_cat in ("WebView", "Network")
                                      or s_cat in _IOS_SENSITIVE_SOURCES) else "medium"
                    line_no = min(s_line, k_line)
                    snippet = "\n".join(lines[max(0, line_no - 1):line_no + 2]).strip()[:300]
                    results["findings"].append({
                        "rule_id":        rule_slug("ios_taint", f"{s_cat}->{k_cat}"),
                        "title":          f"iOS Data Flow: {s_cat} → {k_cat}",
                        "severity":       risk,
                        "category":       "Taint Analysis",
                        "description":    (f"Untrusted input from **{s_label}** ({s_cat}) may reach "
                                           f"**{k_label}** ({k_cat}) in `{rel}` without visible validation. "
                                           "Heuristic same-file flow — confirm the value is sanitized before "
                                           "it reaches the sink."),
                        "recommendation": (f"Validate/encode all {s_cat} input before it reaches {k_cat} "
                                           "APIs (allow-list URLs, parameterize, avoid loading untrusted "
                                           "content into WebViews)."),
                        "file_path":      rel,
                        "line":           line_no,
                        "snippet":        snippet,
                        "cwe":            "CWE-20",
                        "masvs":          "MASVS-CODE-4",
                        "owasp":          "M7",
                        "source":         "iOS_TAINT",
                        "confidence":     55,   # heuristic (same-file proximity, not inter-procedural)
                        # Shallow first pass: produces some false pairs — keep it out of
                        # the default high-signal view; retained in the full export until
                        # the Phase 2 inter-procedural engine lands.
                        "verbose_only":   True,
                        "taint_flow":     {"source": s_label, "source_cat": s_cat,
                                           "sink": k_label, "sink_cat": k_cat, "chain": []},
                    })
                    flows.append({
                        "source": s_label, "source_cat": s_cat, "sink": k_label, "sink_cat": k_cat,
                        "risk": risk, "call_chain": [f"{rel}:{s_line}", f"{rel}:{k_line}"],
                        "class_name": rel, "file": rel, "line": line_no,
                        "method_name": "", "owner_type": "Application",
                    })


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
                    # Stable per-RULE id from the SAST rule's static title.
                    "rule_id":        rule_slug("ios_sast", title),
                    "evidence_type":  "regex_match",
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
            "rule_id":        "ios_file_no_data_protection",
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
            "rule_id":        "ios_coredata_no_protection",
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
            "rule_id":        "ios_weak_crypto_algorithms",
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
            "rule_id":        "ios_openssl_direct_use",
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
            "rule_id":        "ios_deprecated_uiwebview",
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
            "rule_id":        "ios_wkwebview_js_bridge",
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
            "rule_id":        "ios_macho_pie_missing",
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
            "rule_id":        "ios_macho_stack_canary_missing",
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
            "rule_id":        "ios_macho_arc_missing",
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
            "rule_id":        "ios_macho_not_encrypted",
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
            "rule_id":        "ios_macho_symbols_not_stripped",
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
                "rule_id":        "ios_embedded_key_file",
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

    from .attack_chains import to_quick_summary
    chain_summary = to_quick_summary(results)

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
        "attack_chain":        chain_summary,
        "chain_count":         len(chain_summary),
        "chain_severity":      chain_summary[0]["severity"] if chain_summary else "none",
    }
