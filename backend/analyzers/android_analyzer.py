import zipfile
import os
import re
import json
import hashlib
import base64
import mimetypes
import tempfile
import traceback
import time
import logging

log = logging.getLogger("cortex.android")

def _stage(scan_id: str, name: str, t0: float):
    log.info(f"[{scan_id}] stage={name} took={int((time.perf_counter()-t0)*1000)}ms")
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from xml.etree import ElementTree as ET
from urllib.parse import urlparse

from .common import (
    ns, DANGEROUS_PERMISSIONS, SDK_SIGNATURES,
    scan_files_for_secrets, scan_text_for_secrets,
    extract_urls, sort_findings, sort_findings_by_priority, SEVERITY_ORDER,
    shannon_entropy, rule_slug,
    normalize_severity, compute_severity_summary, dedupe_findings,
)
from . import scan_storage
from .source_corpus import SourceCorpus
from . import reachability_engine
from . import trust_engine
from . import finding_model
from .code_analyzer import run_android_sast, resolve_sql_raw_query_severity
from .semgrep_runner import run_semgrep, semgrep_available
from .osv_scanner import scan_dependencies
from .string_analyzer import analyze_strings
from .cert_analyzer import analyze_certificate
from .elf_analyzer import analyze_elf_binaries
from .scoring import calculate_score
from .live_checks import (
    check_firebase_db, check_assetlinks, check_s3_buckets,
    analyze_file_inventory, detect_obfuscation
)
from .tracker_db import detect_trackers, analyze_malware_permissions, normalize_sdks
from .api_analyzer import analyze_android_apis, extract_emails_from_app, detect_apkid_features
from .domain_analyzer import check_domains
from . import network_intel
from . import cloud_config
from . import flutter_analyzer
from . import react_native_analyzer
from .evidence_scanner import (
    scan_directory_for_secrets, scan_directory_for_ips,
    scan_directory_for_jwts, extract_urls
)
from .path_utils import relativize_path, normalize_relative_path, make_file_evidence
from .chain_analyzer import synthesize_attack_chains
from . import posture_analyzer
from .secret_validator import validate_secrets
from .taint_analyzer import run_taint_analysis
from .virustotal import run_virustotal

try:
    # Silence androguard's loguru logger — its DEBUG output on AXML parsing
    # can emit tens of thousands of lines per APK and stalls scans under
    # Docker's log driver. Must be done BEFORE importing androguard.
    try:
        from loguru import logger as _loguru_logger
        _loguru_logger.remove()
        _loguru_logger.add(lambda _m: None, level="ERROR")
    except Exception:
        pass
    import logging as _stdlog
    for _name in ("androguard", "androguard.core", "androguard.core.axml",
                  "androguard.core.apk", "androguard.core.analysis"):
        _stdlog.getLogger(_name).setLevel(_stdlog.ERROR)
    os.environ.setdefault("LOGURU_LEVEL", "ERROR")

    try:
        from androguard.core.apk import APK as AndroAPK   # v3.x
    except ImportError:
        from androguard.core import APK as AndroAPK        # v4.x
    ANDROGUARD = True
except ImportError:
    ANDROGUARD = False


BEHAVIOR_RULES = {
    "Get SMS Messages": {
        "severity": "high",
        "title": "SMS Access Behavior Detected",
        "description": "Code paths that access SMS APIs were detected. This materially increases privacy and account-takeover risk, especially around OTP harvesting.",
        "impact": "Compromised or abused code paths can read OTPs, transactional SMS messages, and other sensitive user communications.",
        "recommendation": "Verify SMS access is essential and user-consented. Remove the capability from release builds where possible.",
        "cwe": "CWE-359",
        "masvs": "MASVS-PRIVACY-1",
        "owasp": "M2",
    },
    "Read/Write Contacts": {
        "severity": "high",
        "title": "Contact Book Access Behavior Detected",
        "description": "The app interacts with contact APIs and can enumerate or modify the user's address book.",
        "impact": "This expands privacy exposure and can enable large-scale data harvesting if abused.",
        "recommendation": "Validate business need, scope access tightly, and review how contact data is stored and transmitted.",
        "cwe": "CWE-359",
        "masvs": "MASVS-PRIVACY-1",
        "owasp": "M2",
    },
    "Get Cell Information": {
        "severity": "medium",
        "title": "Telephony / Device Identifier Access Detected",
        "description": "The app accesses telephony APIs that can expose IMEI, cell, or network identifiers.",
        "impact": "Device-unique identifiers can be used for tracking, profiling, or correlation across services.",
        "recommendation": "Prefer resettable identifiers and remove device identifiers unless strictly required.",
        "cwe": "CWE-359",
        "masvs": "MASVS-PRIVACY-1",
        "owasp": "M2",
    },
    "Get Subscriber ID": {
        "severity": "high",
        "title": "Subscriber Identifier Access Detected",
        "description": "The app contains code paths that retrieve IMSI or subscriber identifiers.",
        "impact": "Subscriber identifiers are highly sensitive and can be used for tracking and correlation.",
        "recommendation": "Eliminate IMSI/subscriber access unless mandatory for core telecom workflows.",
        "cwe": "CWE-359",
        "masvs": "MASVS-PRIVACY-1",
        "owasp": "M2",
    },
    "GPS Location": {
        "severity": "medium",
        "title": "Location Collection Behavior Detected",
        "description": "The app accesses GPS or location APIs.",
        "impact": "Precise location collection materially increases privacy impact and breach severity.",
        "recommendation": "Collect only when necessary and clearly gate the flows with runtime consent.",
        "cwe": "CWE-359",
        "masvs": "MASVS-PRIVACY-1",
        "owasp": "M2",
    },
    "Audio Record": {
        "severity": "high",
        "title": "Audio Recording Capability Detected",
        "description": "Microphone or audio recording APIs were found in the app.",
        "impact": "Abuse of these code paths can capture voice, ambient conversations, or other sensitive audio.",
        "recommendation": "Audit every microphone use case and ensure clear user awareness and consent.",
        "cwe": "CWE-359",
        "masvs": "MASVS-PRIVACY-1",
        "owasp": "M2",
    },
    "Accessibility Service": {
        "severity": "high",
        "title": "Accessibility Automation Capability Detected",
        "description": "Accessibility APIs were found. These can read screen content and perform actions on behalf of the user.",
        "impact": "Accessibility services are frequently abused in mobile malware and fraud tooling.",
        "recommendation": "Review whether accessibility support is essential and constrain privileged flows aggressively.",
        "cwe": "CWE-269",
        "masvs": "MASVS-PLATFORM-1",
        "owasp": "M1",
    },
    "Execute OS Command": {
        "severity": "high",
        "title": "OS Command Execution Primitive Detected",
        "description": "Runtime command execution APIs are present in the app.",
        "impact": "Command execution expands the impact of code injection or tainted input vulnerabilities.",
        "recommendation": "Remove shell execution where possible. Strictly control command arguments and inputs.",
        "cwe": "CWE-78",
        "masvs": "MASVS-CODE-3",
        "owasp": "M7",
    },
    "Dynamic Class and Dexloading": {
        "severity": "high",
        "title": "Dynamic Code Loading Detected",
        "description": "The app uses dynamic class loading or in-memory DEX loading APIs.",
        "impact": "Dynamic code loading weakens reviewability and can be abused to fetch or execute untrusted code.",
        "recommendation": "Remove dynamic loading from production where possible or enforce strong integrity controls.",
        "cwe": "CWE-94",
        "masvs": "MASVS-RESILIENCE-2",
        "owasp": "M8",
    },
    "Network Operations": {
        "severity": "low",
        "title": "Low-Level Network Socket Usage Detected",
        "description": "The app uses low-level network socket APIs beyond standard HTTP clients.",
        "impact": "Custom socket logic can bypass expected network-security controls and is worth reviewing during pentest.",
        "recommendation": "Review custom socket usage and verify TLS, certificate validation, and protocol hardening.",
        "cwe": "CWE-319",
        "masvs": "MASVS-NETWORK-1",
        "owasp": "M5",
    },
}

QUICK_INSIGHT_TITLES = (
    "Application is Debuggable",
    "Potentially Debuggable (Flag Missing)",
    "Debug Certificate Used to Sign APK",
    "Only APK Signature Scheme v1 Used",
    "Only Weak APK Signature Scheme Detected",
    "Exported Content Provider Without Permission",
    "Exported Intent to JS-Enabled WebView Attack Chain",
    "Session Recording SDK Present",
)


def _record_module_metric(results: dict, module: str, started_at: float, **extra):
    metrics = results.setdefault("scan_metrics", {"modules": {}, "cache": {}, "summary": {}})
    payload = {"duration_ms": int((time.perf_counter() - started_at) * 1000)}
    payload.update({k: v for k, v in extra.items() if v is not None})
    metrics.setdefault("modules", {})[module] = payload


def _timed_value(module: str, func, *args, **kwargs):
    started_at = time.perf_counter()
    value = func(*args, **kwargs)
    return module, value, int((time.perf_counter() - started_at) * 1000)


def _build_certificate_security_overview(certificate: dict, apk_path: str = "") -> dict:
    scheme = {entry.lower() for entry in (certificate or {}).get("scheme", [])}
    v4_enabled = bool(apk_path and os.path.exists(f"{apk_path}.idsig"))
    flags = {
        "v1": "v1" in scheme,
        "v2": "v2" in scheme,
        "v3": "v3" in scheme,
        "v4": v4_enabled,
    }
    if flags["v1"] and not (flags["v2"] or flags["v3"] or flags["v4"]):
        overall_status = "vulnerable"
        overall_text = "Vulnerable"
    elif flags["v2"] or flags["v3"] or flags["v4"]:
        overall_status = "secure"
        overall_text = "Secure"
    else:
        overall_status = "limited"
        overall_text = "Limited visibility"

    return {
        "v1": {"enabled": flags["v1"], "label": "Enabled (Weak)" if flags["v1"] else "Disabled"},
        "v2": {"enabled": flags["v2"], "label": "Enabled" if flags["v2"] else "Disabled (Missing)"},
        "v3": {"enabled": flags["v3"], "label": "Enabled" if flags["v3"] else "Disabled"},
        "v4": {"enabled": flags["v4"], "label": "Enabled" if flags["v4"] else "Disabled"},
        "overall": overall_text,
        "overall_status": overall_status,
        "janus_risk": flags["v1"] and not (flags["v2"] or flags["v3"] or flags["v4"]),
    }


def _apply_finding_validation_layer(results: dict):
    cache_stats = results.setdefault("scan_metrics", {}).setdefault("cache", {})
    cache_stats.setdefault("regex_cache", "enabled")
    cache_stats.setdefault("incremental_dedupe", "enabled")

    for finding in results.get("findings", []):
        validation_status = (finding.get("validation_status") or "detected").lower()
        confidence = finding.get("confidence")
        if isinstance(confidence, str):
            confidence = {"high": 85, "medium": 65, "low": 45}.get(confidence.lower(), 65)
            finding["confidence"] = confidence
        if confidence is None:
            confidence = 55 if validation_status in {"heuristic", "potential", "uncertain"} else 72
            finding["confidence"] = confidence

        if confidence < 60 or validation_status in {"heuristic", "potential", "uncertain"}:
            finding["confidence_label"] = "Low Confidence"
            finding.setdefault("validation_status", "heuristic")
        elif confidence < 80:
            finding["confidence_label"] = "Medium Confidence"
        else:
            finding["confidence_label"] = "High Confidence"

        finding.setdefault("description", finding.get("title", "Security finding detected."))
        finding.setdefault("recommendation", "Review the affected component and harden the implementation before release.")
        finding.setdefault("explanation", finding.get("description", ""))
        finding.setdefault("remediation", finding.get("recommendation", ""))

        evidence_path = finding.get("file_path", "")
        line = finding.get("line")
        if evidence_path:
            finding["evidence"] = f"{evidence_path}{f':{line}' if line else ''}"
        elif finding.get("file_evidence"):
            first = next((entry for entry in finding["file_evidence"] if entry.get("path")), None)
            if first:
                first_line = (first.get("lines") or [None])[0]
                finding["evidence"] = f"{first['path']}{f':{first_line}' if first_line else ''}"
        else:
            finding.setdefault("evidence", "Evidence requires analyst verification.")


def _build_quick_summary(results: dict):
    findings = results.get("findings", [])
    severity_counts = {
        level: len([finding for finding in findings if finding.get("severity") == level])
        for level in ("critical", "high", "medium", "low", "info")
    }
    key_issues = []
    seen = set()
    for finding in findings:
        title = finding.get("title", "")
        if (
            finding.get("severity") in {"critical", "high"}
            or any(token in title for token in QUICK_INSIGHT_TITLES)
        ) and title and title not in seen:
            seen.add(title)
            key_issues.append(title)
    debug_state = results.get("manifest_security", {}).get("debuggable", {})
    certificate_overview = results.get("certificate", {}).get("security_overview", {})
    secure_signals = []
    if debug_state.get("state") == "false":
        secure_signals.append("Debuggable flag explicitly disabled")
    if certificate_overview.get("overall_status") == "secure":
        secure_signals.append("Modern APK signature scheme detected")

    # Attack chains come from the v2 engine (projected to legacy keys so existing
    # readers keep working). The legacy _chain_data survives ONLY as a hint feeder
    # for pentest hints; it no longer defines quick_summary.attack_chain.
    from .attack_chains import to_quick_summary
    chain_summary = to_quick_summary(results)
    chain_data = results.pop("_chain_data", None) or synthesize_attack_chains(results)
    chain_severity = chain_summary[0]["severity"] if chain_summary else "none"

    results["quick_summary"] = {
        "total_vulnerabilities": len([finding for finding in findings if finding.get("severity") != "info"]),
        "severity_counts": severity_counts,
        "key_critical_issues": key_issues[:6],
        "highlight_count": len(key_issues),
        "secure_signals": secure_signals,
        "attack_chain":   chain_summary,
        "pentest_hints":  chain_data.get("pentest_playbook", []),
        "chain_count":    len(chain_summary),
        "chain_severity": chain_severity,
    }
    results["view_modes"] = {
        "quick": {"recommended_tabs": ["dashboard", "findings", "manifest", "surface", "cert"]},
        "detailed": {"recommended_tabs": [tab for tab in ("dashboard", "findings", "source", "code", "manifest", "permissions", "surface", "cert", "domains", "binary", "api")]},
    }


def analyze_apk(apk_path: str, scan_id: str, filename: str,
                jadx_dir: str = None, apktool_dir: str = None) -> dict:
    overall_started = time.perf_counter()
    results = {
        "scan_id":          scan_id,
        "filename":         filename,
        "platform":         "android",
        "app_name":         Path(filename).stem,
        "app_info":         {},
        "findings":         [],
        "attack_surface":   {"activities": [], "services": [], "receivers": [], "providers": []},
        "secrets":          [],
        "endpoints":        [],
        "sdks":             [],
        "framework":        {"type": "native", "details": []},
        "permissions":      {"dangerous": [], "all": []},
        "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "scan_time":        datetime.utcnow().isoformat() + "Z",
        "certificate":      {},
        "binaries":         [],
        "string_analysis":  {},
        "file_inventory":   {},
        "score":            {},
        "android_api":      {},
        "emails":           [],
        "apkid":            {},
        "trackers":         [],
        "malware_perms":    {},
        "domain_intel":     [],
        "manifest_xml":     "",
        "manifest_permissions": [],
        "manifest_security": {},
        "network_config":   {},
        "dependencies":     {},
        "sdk_secrets":      [],
        "behavior_analysis": [],
        "ips":              [],
        "jwts":             [],
        "taint_flows":      [],
        "virustotal":       {},
        "quick_summary":    {},
        "view_modes":       {},
        "scan_metrics":     {"modules": {}, "cache": {}, "summary": {}},
        "decompile_info":   {"jadx_dir": jadx_dir, "apktool_dir": apktool_dir, "tools_used": []},
    }
    preferred_source_dirs = [d for d in [jadx_dir, apktool_dir] if d and os.path.exists(d)]

    # Priority 1 — SourceCorpus: ONE walk + ONE read of the decompiled tree,
    # shared by every text analyzer below. Each analyzer keeps its own filtering,
    # so detections are unchanged; only the redundant filesystem I/O is removed.
    corpus = SourceCorpus()

    with tempfile.TemporaryDirectory() as tmpdir:
        extract_started = time.perf_counter()
        # ── Extract APK ──────────────────────────────────────────────────────
        log.info(f"[{scan_id}] stage=apk_extract start")
        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                z.extractall(tmpdir)
        except Exception as e:
            results["findings"].append(_meta_finding(f"APK extraction warning: {e}"))

        # ── Persist extraction for code viewer (so viewer works without jadx) ─
        _persist_extraction(tmpdir, scan_id)
        _record_module_metric(results, "apk_extraction", extract_started)
        _stage(scan_id, "apk_extract", extract_started)

        # ── App hash ─────────────────────────────────────────────────────────
        hash_started = time.perf_counter()
        with open(apk_path, "rb") as f:
            data = f.read()
            results["app_info"]["sha256"] = hashlib.sha256(data).hexdigest()
            results["app_info"]["md5"]    = hashlib.md5(data).hexdigest()
            results["app_info"]["size_mb"] = round(len(data) / (1024 * 1024), 2)
        _record_module_metric(results, "package_hashing", hash_started)

        # ── Androguard analysis ───────────────────────────────────────────────
        manifest_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=manifest_analysis start")
        apk = None
        if ANDROGUARD:
            try:
                apk = AndroAPK(apk_path)
                _parse_manifest(apk, results)
                _analyze_permissions(apk, results)
                _analyze_components(apk, tmpdir, results)
                _detect_sdks(apk, tmpdir, results)
            except Exception as e:
                results["findings"].append(_meta_finding(f"Manifest parse partial: {e}"))
        else:
            results["findings"].append(_meta_finding("androguard not available — manifest analysis skipped"))

        # ── Persist a decoded manifest for the source viewer ──────────────────
        # Guarantees View Code shows readable XML (never the compiled binary
        # AXML in apk_extract) even when apktool failed or timed out.
        _persist_decoded_manifest(scan_id, results)

        # ── Persist decoded resources.arsc string values for the secret walk ──
        # String resources (res/values/strings.xml) are where Android apps embed
        # Cognito pool ids, Firebase/API config, etc. — but they live ONLY in the
        # compiled resources.arsc. jadx runs with --no-res and apktool's resource
        # decoder can throw on some APKs, leaving NO decoded strings.xml, so those
        # values never reach the unified secret walk (which scans jadx+apktool).
        # androguard (already loaded) reconstructs them exactly like MobSF does;
        # we write them to the canonical apktool/res/values/strings.xml location
        # the walk already scans — only when apktool didn't produce one itself.
        arsc_dir = _persist_decoded_resource_strings(scan_id, apk)
        if arsc_dir and arsc_dir not in preferred_source_dirs:
            preferred_source_dirs.append(arsc_dir)

        # ── Framework detection ───────────────────────────────────────────────
        _record_module_metric(results, "manifest_analysis", manifest_started, components=sum(len(results["attack_surface"].get(key, [])) for key in ("activities", "services", "receivers", "providers")))
        _stage(scan_id, "manifest_analysis", manifest_started)
        framework_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=framework_detect start")
        _detect_framework(tmpdir, results)
        _record_module_metric(results, "framework_detection", framework_started, framework=results.get("framework", {}).get("type"))
        _stage(scan_id, "framework_detect", framework_started)

        # ── Secrets scan ──────────────────────────────────────────────────────
        secrets_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=secrets start")
        if preferred_source_dirs:
            # Phase 1.9: single combined walk (Beetle Native + APKLeaks) sets
            # results["secrets"] (native) and fuses APKLeaks secrets/findings/endpoints.
            _scan_precise_source_secrets(results, preferred_source_dirs, corpus=corpus)
        else:
            results["secrets"] = scan_files_for_secrets(tmpdir)
            # Only fall back to raw DEX strings when JADX source is unavailable.
            _scan_dex_strings(tmpdir, results)
            # No-JADX fallback: native uses the legacy text scanner above, so run
            # the APKLeaks slice as one additional ev walk over the extract dir.
            try:
                from . import detection_sources
                detection_sources.run_detection_sources(results, [tmpdir], platform="android")
            except Exception:
                log.exception("[detection_sources] APKLeaks fallback scan failed")
        if results.get("sdk_secrets"):
            results["secrets"].extend(results["sdk_secrets"])
        _record_module_metric(results, "secret_detection", secrets_started, findings=len(results.get("secrets", [])))
        _stage(scan_id, "secrets", secrets_started)

        # ── Endpoint extraction ───────────────────────────────────────────────
        resource_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=resource_scan start")
        _extract_endpoints(tmpdir, results, preferred_source_dirs, corpus=corpus)

        # ── Network security config ───────────────────────────────────────────
        _analyze_network_security_config(tmpdir, results)

        # ── React Native Security Intelligence (Phase 2.2) ────────────────────
        # First-class sub-analyzer (replaces the old inline _analyze_rn_bundle),
        # mirroring Flutter: RN-idiomatic findings (native bridge / storage / network /
        # deep links / env) + canonical secrets/endpoints into the EXISTING streams.
        if results["framework"]["type"] == "react_native":
            try:
                rn_roots = (preferred_source_dirs[:] or []) + [tmpdir]
                react_native_analyzer.analyze(rn_roots, results, platform="android")
            except Exception:
                log.exception("[react_native] analysis failed; continuing without RN findings")
        # ── Flutter Security Intelligence (Phase 2.1) ─────────────────────────
        # Gated on the existing framework detection — mirrors the RN sub-analyzer.
        # Contributes canonical findings/secrets/endpoints to the EXISTING streams,
        # which then flow through the unchanged finalize pipeline. Never raises.
        if results["framework"]["type"] == "flutter":
            try:
                flutter_roots = (preferred_source_dirs[:] or []) + [tmpdir]
                flutter_analyzer.analyze(flutter_roots, results, platform="android")
            except Exception:
                log.exception("[flutter] analysis failed; continuing without Flutter findings")
        _record_module_metric(results, "resource_analysis", resource_started, endpoints=len(results.get("endpoints", [])))
        _stage(scan_id, "resource_scan", resource_started)

        # ── Binary protection summary ─────────────────────────────────────────
        protection_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=binary_protections start")
        _check_apk_protections(tmpdir, results)
        _record_module_metric(results, "binary_protections", protection_started)
        _stage(scan_id, "binary_protections", protection_started)

        # ── NEW: SAST Code Analysis ───────────────────────────────────────────
        sast_roots = preferred_source_dirs[:] or [tmpdir]
        if results["framework"]["type"] == "react_native" and tmpdir not in sast_roots:
            sast_roots.append(tmpdir)
        code_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=sast start")
        run_android_sast(sast_roots, results, corpus=corpus)
        _record_module_metric(results, "code_scanning", code_started, sast_findings=len([finding for finding in results.get("findings", []) if finding.get("source") == "SAST" or finding.get("rule_id")]))
        _stage(scan_id, "sast", code_started)

        # ── Semgrep SAST (optional — requires semgrep on PATH) ────────────────
        semgrep_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=semgrep start")
        semgrep_metrics = run_semgrep(sast_roots, results)
        _record_module_metric(
            results, "semgrep_sast", semgrep_started,
            ran=semgrep_metrics.get("ran"),
            findings=semgrep_metrics.get("finding_count", 0),
            error=semgrep_metrics.get("error"),
        )
        results["scan_metrics"]["semgrep"] = semgrep_metrics
        _stage(scan_id, "semgrep", semgrep_started)

        # ── Supply chain CVE lookup (OSV.dev) ────────────────────────────────
        osv_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=osv start")
        osv_metrics = scan_dependencies(sast_roots, results)
        _record_module_metric(
            results, "osv_scan", osv_started,
            deps=osv_metrics.get("dep_count", 0),
            vulns=osv_metrics.get("vuln_count", 0),
            error=osv_metrics.get("error"),
        )
        results["scan_metrics"]["osv"] = osv_metrics
        _stage(scan_id, "osv", osv_started)

        # ── Taint Analysis (Androguard DEX call-graph) ───────────────────────
        taint_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=taint start")
        try:
            taint_metrics = run_taint_analysis(str(apk_path), results)
            _record_module_metric(
                results, "taint_analysis", taint_started,
                ran=taint_metrics.get("ran"),
                flows=taint_metrics.get("flow_count", 0),
                error=taint_metrics.get("error"),
            )
            results["scan_metrics"]["taint"] = taint_metrics
        except Exception as _te:
            _record_module_metric(results, "taint_analysis", taint_started, error=str(_te))
            results.setdefault("taint_flows", [])
        _stage(scan_id, "taint", taint_started)

        # ── Raw-SQL severity reconciliation ──────────────────────────────────
        # Now that taint has run, decide android_sqlite_raw_query severity from
        # real evidence (taint reach or string-building), downgrade parameterized
        # queries to INFO, and drop the SAST finding where a taint SQLite finding
        # already represents the same sink (no double count).
        try:
            resolve_sql_raw_query_severity(results)
        except Exception:
            log.exception("[sast] raw-SQL severity reconciliation failed")

        # ── VirusTotal hash lookup ────────────────────────────────────────────
        vt_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=virustotal start")
        try:
            vt_metrics = run_virustotal(str(apk_path), results)
            _record_module_metric(
                results, "virustotal", vt_started,
                ran=vt_metrics.get("ran"),
                verdict=vt_metrics.get("main_verdict"),
                error=vt_metrics.get("error"),
            )
            results["scan_metrics"]["virustotal"] = vt_metrics
        except Exception as _vt_err:
            _record_module_metric(results, "virustotal", vt_started, error=str(_vt_err))
            results.setdefault("virustotal", {})
        _stage(scan_id, "virustotal", vt_started)

        # ── NEW: String Analysis ──────────────────────────────────────────────
        extra_dirs = preferred_source_dirs[:]
        parallel_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=strings_parallel start")
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {
                "string_analysis": pool.submit(_timed_value, "string_analysis", analyze_strings, tmpdir, "android", corpus=corpus),
                "emails": pool.submit(_timed_value, "email_detection", extract_emails_from_app, tmpdir, apk_path, corpus=corpus),
                "apkid": pool.submit(_timed_value, "apkid_detection", detect_apkid_features, tmpdir, corpus=corpus),
                "ips": pool.submit(_timed_value, "ip_detection", network_intel.extract_ips, tmpdir, extra_dirs, corpus=corpus),
                "_cloud_config_hits": pool.submit(_timed_value, "cloud_config_scan", cloud_config.scan, tmpdir, extra_dirs, corpus=corpus),
                "jwts": pool.submit(_timed_value, "jwt_detection", scan_directory_for_jwts, tmpdir, extra_dirs, corpus=corpus),
            }
            for key, future in futures.items():
                # Guarded: one noisy analyzer (e.g. IP scan on a pathological
                # smali blob) must not torch the whole parallel phase. Record
                # the error in metrics and seed an empty default for the key.
                try:
                    module_name, value, duration_ms = future.result(timeout=600)
                    results[key] = value
                    results["scan_metrics"]["modules"][module_name] = {
                        "duration_ms": duration_ms
                    }
                except Exception as _pe:
                    log.warning(f"[{scan_id}] parallel analyzer {key!r} failed: {_pe}")
                    results.setdefault(key, [])
                    results["scan_metrics"]["modules"][key] = {
                        "duration_ms": 0,
                        "error": str(_pe)[:200],
                    }
        results["scan_metrics"]["summary"]["parallel_phase_ms"] = int((time.perf_counter() - parallel_started) * 1000)
        _stage(scan_id, "strings_parallel", parallel_started)

        # ── Phase 1.99: Network Intelligence — enrich the raw IP hits (classify,
        # owner-attribute via the Ownership Engine, suppress noise, merge duplicates,
        # tag intelligence) BEFORE any downstream consumer (the public-IP finding
        # below, network_workspace, UI). Additive; never touches URL extraction. ──
        try:
            network_intel.annotate(results, platform="android")
        except Exception:
            log.exception("[network_intel] IP enrichment failed; raw IPs left as-is")

        # ── Phase 2.5.5: Cloud Configuration discovery — classify the raw cloud
        # config hits (Firebase/GCS buckets, project endpoints), attribute ownership,
        # and emit "Cloud Configuration" findings. Runs BEFORE Finding Fusion so the
        # findings traverse fusion → ownership → confidence → evidence like any other. ──
        try:
            cloud_config.annotate(results, platform="android")
        except Exception:
            log.exception("[cloud_config] cloud configuration discovery failed")

        # ── NEW: ELF/SO Binary Analysis ───────────────────────────────────────
        binaries_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=elf_binaries start")
        analyze_elf_binaries(tmpdir, results)
        _record_module_metric(results, "native_binary_analysis", binaries_started, libraries=len(results.get("binaries", [])))
        _stage(scan_id, "elf_binaries", binaries_started)

        # ── LIEF deep ELF scan (only if lief is installed) ────────────────────
        lief_started = time.perf_counter()
        log.info(f"[{scan_id}] stage=lief start")
        so_files: list[str] = []
        try:
            from . import lief_analyzer
            for root, _dirs, files in os.walk(tmpdir):
                for fn in files:
                    if fn.endswith(".so"):
                        so_files.append(os.path.join(root, fn))
                if len(so_files) >= 40:
                    break
            if lief_analyzer.available():
                # Parallel LIEF scan — each analyze_elf call is ~1–3s of pure
                # parsing + heuristics; serial at 30 files that's 30–90s. With
                # 6-way threading it drops to ~5–15s.
                # NOTE: ThreadPoolExecutor is imported at module scope — do NOT
                # re-import here or Python makes it a local binding and the
                # earlier usage in this function blows up with UnboundLocalError.
                from concurrent.futures import as_completed
                targets = so_files[:30]
                with ThreadPoolExecutor(max_workers=min(6, max(1, len(targets)))) as pool:
                    futs = [pool.submit(lief_analyzer.analyze_elf, so) for so in targets]
                    for fut in as_completed(futs):
                        try:
                            r = fut.result(timeout=60)
                        except Exception:
                            continue
                        for f in r.get("findings", []):
                            results["findings"].append(f)
        except Exception:
            pass
        _stage(scan_id, "lief", lief_started)

        # ── CVE mapping: native .so + Maven (AAR) packages ────────────────────
        try:
            from . import cve_mapper
            if cve_mapper.available():
                cve_started = time.perf_counter()
                log.info(f"[{scan_id}] stage=cve_mapping start")
                native_out = cve_mapper.analyze_native_libs(so_files) if so_files else None
                maven_comps = cve_mapper.scan_maven_packages(tmpdir)
                maven_out   = cve_mapper.analyze_packages(maven_comps) if maven_comps else None
                merged      = cve_mapper.merge_cve_results(native_out, maven_out)
                if merged.get("findings"):
                    results["findings"].extend(merged["findings"])
                results["components"] = merged.get("components", [])
                results["cve_stats"]  = merged.get("stats", {})
                _record_module_metric(
                    results, "cve_mapping", cve_started,
                    components=len(results["components"]),
                    cves=len(merged.get("findings", [])),
                    kev=merged.get("stats", {}).get("kev_matched", 0),
                )
                _stage(scan_id, "cve_mapping", cve_started)
        except Exception as _e:
            log.debug(f"cve mapping failed: {_e}")

        # ── NEW: Obfuscation Detection ────────────────────────────────────────
        obfuscation_started = time.perf_counter()
        detect_obfuscation(tmpdir, results)
        _record_module_metric(results, "obfuscation_detection", obfuscation_started)

        # ── NEW: File Inventory ───────────────────────────────────────────────
        inventory_started = time.perf_counter()
        analyze_file_inventory(apk_path, results)
        _record_module_metric(results, "file_inventory", inventory_started)

        # ── NEW: Android API Analysis ─────────────────────────────────────────
        api_started = time.perf_counter()
        analyze_android_apis(tmpdir, results, source_dirs=preferred_source_dirs, corpus=corpus)
        _build_behavior_findings(results)
        _record_module_metric(results, "api_behavior_analysis", api_started, categories=len(results.get("android_api", {})))

        # ── NEW: Email Extraction ─────────────────────────────────────────────

        # ── NEW: APKiD-style Detection ────────────────────────────────────────

        # ── Evidence: IP Detection ────────────────────────────────────────────

        # Add high-severity IP findings
        public_ips = [ip for ip in results["ips"] if ip["type"] == "public"]
        if public_ips:
            public_ip_evidence = [
                make_file_evidence(ip["file_path"], ip.get("line", 0), ip.get("snippet", ""))
                for ip in public_ips
                if ip.get("file_path")
            ]
            results["findings"].append({
                "rule_id":           "hardcoded_public_ips",
                "title":             f"Hardcoded Public IP Addresses ({len(public_ips)} found)",
                "severity":          "low",
                "category":          "Configuration",
                "description":       f"Public IP addresses hardcoded in app: {', '.join(set(ip['ip'] for ip in public_ips[:5]))}. May expose infrastructure.",
                "recommendation":    "Use domain names instead of IP addresses. Remove dev/test server references.",
                "file_path":         public_ips[0]["file_path"] if public_ips else "",
                "line":              public_ips[0]["line"] if public_ips else 0,
                "snippet":           public_ips[0]["snippet"] if public_ips else "",
                "file_evidence":     public_ip_evidence,
                "confidence":        85,
                "exploitability":    25,
                "validation_status": "validated",
                "source":            "IP_SCANNER",
                "cwe":               "CWE-547",
                "masvs":             "MASVS-CODE-4",
                "owasp":             "M8",
                "files":             list(set(ip["file_path"] for ip in public_ips)),
                "file_count":        len(public_ip_evidence),
            })

        # ── Evidence: JWT Detection ───────────────────────────────────────────
        for jwt in results["jwts"]:
            results["findings"].append({
                "rule_id":           "hardcoded_jwt_token",
                "title":             "Hardcoded JWT Token",
                "severity":          "high",
                "category":          "Auth Token",
                "description":       "A hardcoded JWT token is embedded in the app. This may allow authentication as the associated user/service without credentials.",
                "impact":            "Attacker can reuse this token for unauthorized API access until it expires.",
                "recommendation":    "Invalidate this token immediately. Never hardcode auth tokens in client apps.",
                "poc":               f"# Decode JWT header/payload (no signature verification):\nimport base64, json\ntoken = \"{jwt['value'][:50]}...\"\nparts = token.split('.')\nprint(json.loads(base64.b64decode(parts[1] + '==').decode()))",
                "file_path":         jwt["file_path"],
                "line":              jwt["line"],
                "snippet":           jwt["snippet"],
                "code_context":      jwt["code_context"],
                "file_evidence":     jwt.get("file_evidence") or [make_file_evidence(jwt["file_path"], jwt.get("line", 0), jwt.get("snippet", ""))],
                "confidence":        90,
                "exploitability":    80,
                "validation_status": "validated",
                "source":            "JWT_SCANNER",
                "cwe":               "CWE-798",
                "masvs":             "MASVS-CRYPTO-2",
                "owasp":             "M1",
                "value":             jwt["value"],
                "files":             [jwt["file_path"]] if jwt.get("file_path") else [],
                "file_count":        1 if jwt.get("file_path") else 0,
            })

        # ── Evidence: Enhanced Secret Scanning (jadx+apktool output) ──────────
    # ── NEW: Certificate Analysis (done outside tmpdir) ───────────────────────
    cert_started = time.perf_counter()
    analyze_certificate(apk_path, results)
    results["certificate"]["security_overview"] = _build_certificate_security_overview(results.get("certificate", {}), apk_path)
    _record_module_metric(results, "certificate_analysis", cert_started, available=results.get("certificate", {}).get("available"))

    # ── Fix cert unavailable message ─────────────────────────────────────────
    if not results.get("certificate", {}).get("available"):
        scheme = results.get("certificate", {}).get("scheme", [])
        scheme_str = "/".join(s.upper() for s in scheme) or "v2/v3"
        results["certificate"]["unavailable_reason"] = (
            f"APK uses {scheme_str} signature scheme. "
            "Limited certificate extraction available via META-INF parsing. "
            "Full details require apksigner or androguard."
        )

    # ── NEW: Live Checks ──────────────────────────────────────────────────────
    live_checks_started = time.perf_counter()
    check_firebase_db(results)
    check_assetlinks(results)
    try:
        check_s3_buckets(results)
    except Exception:
        pass
    _record_module_metric(results, "live_checks", live_checks_started)

    # ── NEW: Tracker Detection ────────────────────────────────────────────────
    tracker_started = time.perf_counter()
    package_hints = set(results.get("app_info", {}).get("package_hints", []))
    results["trackers"] = detect_trackers(package_hints) if package_hints else []
    _record_module_metric(results, "tracker_detection", tracker_started, trackers=len(results.get("trackers", [])))

    # ── NEW: Malware Permission Analysis ──────────────────────────────────────
    malware_started = time.perf_counter()
    all_perms = results.get("permissions", {}).get("all", [])
    results["malware_perms"] = analyze_malware_permissions(all_perms)
    _add_malware_permission_findings(results)
    _record_module_metric(results, "malware_permission_analysis", malware_started, overlap=results.get("malware_perms", {}).get("malware_permission_overlap"))

    # ── NEW: Domain Geo/Intel Check ───────────────────────────────────────────
    domains_started = time.perf_counter()
    check_domains(results.get("endpoints", []), results)
    _add_domain_intel_summary(results)
    _add_exported_webview_attack_chain(results)
    _enrich_findings_with_standards(results)
    _record_module_metric(results, "domain_intelligence", domains_started, domains=len(results.get("domain_intel", [])))

    # ── Cross-dedup: remove JWT-looking secrets already surfaced by JWT scanner ─
    # The JWT scanner produces results["jwts"] which are shown in their own UI
    # section. Any secret entry whose value matches a known JWT (eyJ…) should be
    # removed from results["secrets"] to prevent double-reporting. We only do
    # this for patterns that produce JWT-format values (Supabase key etc.) since
    # plain secrets and JWTs use completely different value formats.
    jwt_values = {jwt["value"] for jwt in results.get("jwts", []) if jwt.get("value")}
    if jwt_values:
        results["secrets"] = [
            s for s in results.get("secrets", [])
            if s.get("value", "") not in jwt_values
        ]

    # ── Live secret validation ────────────────────────────────────────────────
    validation_started = time.perf_counter()
    try:
        results["secrets"] = validate_secrets(results.get("secrets", []))
        live_count = sum(1 for s in results["secrets"] if s.get("validated"))
        _record_module_metric(results, "secret_validation", validation_started, live_secrets=live_count)
    except Exception:
        _record_module_metric(results, "secret_validation", validation_started, live_secrets=0)

    # ── JS bundle scan (React Native / Cordova / Capacitor) ───────────────────
    try:
        from . import js_bundle_analyzer
        js_scan_root = str(scan_storage.scan_root(scan_id) / "apk_extract")
        js_out = js_bundle_analyzer.analyze_js_bundles(js_scan_root)
        if js_out.get("findings"):
            results["findings"].extend(js_out["findings"])
        if js_out.get("secrets"):
            results.setdefault("secrets", []).extend(js_out["secrets"])
        if js_out.get("framework", {}).get("type") and not results.get("framework", {}).get("type"):
            results["framework"] = js_out["framework"]
        results["js_bundles"] = js_out.get("bundles", [])
    except Exception:
        pass

    # ── Post-JS-bundle cross-dedup: JS bundles may re-introduce JWT values ────
    # The primary cross-dedup ran before the JS bundle scan, so any JWTs found
    # in JS bundles (React Native, Cordova, Capacitor) may have been appended to
    # results["secrets"] again. Re-apply the dedup now.
    jwt_values_final = {jwt["value"] for jwt in results.get("jwts", []) if jwt.get("value")}
    if jwt_values_final:
        results["secrets"] = [
            s for s in results.get("secrets", [])
            if s.get("value", "") not in jwt_values_final
        ]

    # ── Phase 1.4: Secret Intelligence Engine — multi-stage validation of every
    # detected secret (type/provider, format/checksum/entropy, false-positive
    # detection, status). MUST run BEFORE secret_intel masking so it sees raw
    # values; it stores only derived, non-sensitive signals. Additive only;
    # never suppresses or re-severities. Deterministic, network-free. ──
    try:
        from . import secret_intelligence
        secret_intelligence.annotate(results)
    except Exception:
        log.exception("[secret_intelligence] failed; secrets left without intelligence metadata")
    # ── Phase 9.1: secret intelligence foundation (canonical model + masking) ──
    # Runs AFTER all secret producers + legacy validation + JWT/JS dedup so it is
    # the single choke point that masks raw values before serialization. Additive
    # and network-free; partitions results["secrets"] and builds secrets_summary.
    try:
        from . import secret_intel
        secret_intel.process_secrets(results, results.get("app_info", {}).get("package", ""))
    except Exception:
        log.exception("[secret_intel] failed; leaving secrets unprocessed")

    # ── Severity summary ──────────────────────────────────────────────────────
    finalize_started = time.perf_counter()
    _apply_finding_validation_layer(results)
    # sort_findings normalizes severity in-place before sorting. Recompute the
    # summary AFTER validation layer runs so counts and findings always match.
    # ── Phase 1.95: Finding Fusion Engine — collapse multi-engine duplicates into
    # ONE canonical finding "Detected By" all of them, with full provenance + a
    # multi-engine agreement signal. Supersets the old exact-key dedupe: it also
    # unifies cross-engine equivalents (different rule ids / small line drift) from
    # Beetle Native + APKLeaks today and any future engine. Runs BEFORE the
    # Confidence Engine so agreement feeds confidence. Deterministic, additive. ──
    try:
        from . import fusion
        fusion.fuse(results, platform="android")
    except Exception:
        log.exception("[fusion] failed; falling back to exact-key dedupe")
        results["findings"] = dedupe_findings(results["findings"])
    # ── Phase 0/1: canonical normalization + ownership (additive, non-destructive) ──
    _app_pkg = results.get("app_info", {}).get("package", "")
    finding_model.canonicalize_findings(results["findings"], _app_pkg)
    # ── Phase 6 Task 6: manifest evidence enforcement (drop unproven manifest findings) ──
    results["findings"], results["manifest_evidence_stats"] = finding_model.enforce_manifest_evidence(
        results["findings"], scan_id, results.get("manifest_xml", ""),
    )
    # ── Attack-chain correlation HINTS only ──────────────────────────────────
    # The legacy synthesizer is demoted to a correlation-hint feeder: it produces
    # results["_chain_data"] (still consumed by posture exploitability, the attack
    # graph and pentest hints) but NO LONGER injects first-class chain findings and
    # NO LONGER sets quick_summary.attack_chain. The displayed chains — findings
    # list, PDF section, dashboard, AI context — all come from the v2 engine below,
    # via attack_chains.annotate_findings, so one engine drives every surface.
    results["_chain_data"] = synthesize_attack_chains(results)
    results["ownership_metrics"] = finding_model.emit_diagnostics(
        results["findings"], platform="android", app_package=_app_pkg,
    )
    # ── Phase 2: finding inventory & noise analysis (internal diagnostics) ──
    results["finding_diagnostics"] = finding_model.build_finding_diagnostics(results["findings"])
    finding_model.log_finding_analysis(results["finding_diagnostics"], platform="android")
    # ── Cross-section noise scrub (endpoints / IPs / binary-dump evidence) ──
    results["scrub_stats"] = finding_model.scrub_noise(results)
    # ── Phase 5: source resolution validation (before refine so confidence sees it) ──
    results["source_resolution_stats"] = finding_model.validate_source_resolution(
        results["findings"], scan_id, results.get("manifest_xml", ""),
    )
    # ── Phase 3: signal quality — library filtering, confidence, dedup, FP suppression ──
    _kept, _suppressed, _quality_stats = finding_model.refine_findings(
        results["findings"], app_package=_app_pkg, platform="android",
    )
    results["findings"] = _kept
    results["suppressed_findings"] = _suppressed
    results["finding_quality_stats"] = _quality_stats
    # ── Phase K: executive security summary (raw → high-signal funnel) ──
    results["executive_summary"] = finding_model.build_executive_summary(_quality_stats, _suppressed)
    finding_model.log_quality_stats(_quality_stats, platform="android")
    # ── Phase 5.4: per-finding quality report ──
    results["finding_quality_report"] = finding_model.build_finding_quality_report(_kept)
    finding_model.log_finding_quality_report(results["finding_quality_report"], platform="android")
    # Normalize severities before posture/reachability read them.
    results["findings"] = sort_findings(results["findings"])
    # ── Phase C/F/H: attack surface inventory, exploitability, attack graph ──
    # Runs before _build_quick_summary (which consumes results["_chain_data"]).
    posture_analyzer.analyze_posture(results)
    # ── Phase 7 Task 1/2: reachability + attack-path generation. Needs the
    # exploitability + chain data posture produced; may adjust severity. ──
    reachability_engine.analyze_reachability(results)
    # ── Phase 7.5: trust framework — evidence quality, reachability confidence,
    # resolution coverage scores, and the overall trust score. ──
    trust_engine.annotate_trust(results)
    # ── Phase 7 Task 5: prioritize by reachability → exploitability → severity ──
    results["findings"] = sort_findings_by_priority(results["findings"])
    # Attack-chain findings always lead the list (before normal findings).
    _ac = [f for f in results["findings"] if f.get("is_attack_chain")]
    if _ac:
        results["findings"] = _ac + [f for f in results["findings"] if not f.get("is_attack_chain")]
    # Severity influence (reachability) changed severities — recompute summary.
    results["severity_summary"] = compute_severity_summary(results["findings"])
    # ── Phase 1.9: secret→finding intelligence bridge — mirror MASKED APKLeaks
    # secrets into results["findings"] so they traverse ownership → confidence →
    # evidence → triage → attack chains → bug-bounty. Placed AFTER severity_summary
    # so the bridged copies are never double-counted in the user-facing severity
    # counts, and AFTER masking so no raw value can enter the findings stream.
    # reconcile_bridged_findings() (after bug-bounty) copies the enrichment back
    # onto the secret and REMOVES these copies, so they never display twice. ──
    try:
        from .detection_sources import fusion as _ds_fusion
        _ds_fusion.bridge_secrets_to_findings(results, platform="android")
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
    # strongest, most application-relevant primary proof per finding (demoting AndroidX
    # / GMS / generated / framework files; preferring the manifest for declaration-
    # driven findings), stamp the unified evidence_view every renderer consumes, and
    # promote the chosen primary into the legacy location fields so all surfaces show
    # the correct file. Runs BEFORE attack chains so chains reference the corrected
    # primaries; ownership/confidence/evidence/reachability are already present. ──
    try:
        from . import evidence_selection
        evidence_selection.annotate(results, platform="android")
    except Exception:
        log.exception("[evidence_selection] failed; findings left without proof selection")
    # ── Security Control Resolution — decide ONCE, from positive evidence, whether
    # each defensive control (pinning, cleartext, root/frida/attestation detection,
    # obfuscation, FLAG_SECURE) is present. Attack chains, MASVS coverage and the
    # security score all read this instead of substring-matching finding text, so a
    # "No Certificate Pinning" finding can never mark pinning present. Runs after all
    # findings exist and before the first consumer. Additive: results['security_controls'].
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
        # Project v2 chains onto the findings list: mark participating findings
        # (in_attack_chain) and prepend one first-class finding per chain, carrying
        # v2's COMPUTED confidence. This is what makes the findings list and the PDF
        # chain section reference the same (v2) chains instead of the legacy engine.
        _n_chain_findings = attack_chains.annotate_findings(results)
        if _n_chain_findings:
            finding_model.canonicalize_findings(
                [f for f in results["findings"] if f.get("is_attack_chain")], _app_pkg)
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
    # UI / PDF / HTML / JSON / dashboard. Runs before analyst/MASVS/workspaces/
    # quick-summary/score so none of them see the bridged copies. ──
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
    # ── Phase 2.3: Source / Security Explorer overlay — projects the finalized
    # findings/secrets/IPs into file_index + security_index for the explorer UI.
    # Reuses existing metadata only (no extraction). Additive. ──
    try:
        from . import source_explorer
        source_explorer.annotate(results)
    except Exception:
        log.exception("[source_explorer] overlay failed; explorer metadata not emitted")
    _build_quick_summary(results)
    _record_module_metric(results, "finalize_results", finalize_started, finding_count=len(results.get("findings", [])))

    # ── Security Score ────────────────────────────────────────────────────────
    score_started = time.perf_counter()
    results["score"] = calculate_score(results)
    _record_module_metric(results, "security_scoring", score_started, score=results.get("score", {}).get("score"))

    # ── Phase 11.95: audience-targeted report summaries (CISO + developer) ──
    # Reuse-only rollups; must run AFTER scoring + masvs_intel so they read the
    # final score, severity summary, masvs maturity and attack chains.
    try:
        from report import report_summaries
        report_summaries.annotate(results)
    except Exception:
        log.exception("[report_summaries] failed; executive summaries not emitted")

    results["scan_metrics"]["summary"]["total_duration_ms"] = int((time.perf_counter() - overall_started) * 1000)
    results["scan_metrics"]["summary"]["module_count"] = len(results.get("scan_metrics", {}).get("modules", {}))

    return results


# ─── Manifest ────────────────────────────────────────────────────────────────
def _parse_manifest(apk, results):
    pkg     = apk.get_package()     or ""
    # androguard 4.x renamed get_app_name to get_app_name, but it may need try/except
    try:
        appname = apk.get_app_name() or pkg.split(".")[-1] if pkg else "Unknown"
    except Exception:
        appname = pkg.split(".")[-1] if pkg else "Unknown"

    results["app_name"] = appname
    results["app_info"].update({
        "package":        pkg,
        "app_name":       appname,
        "version_name":   apk.get_androidversion_name() or "?",
        "version_code":   apk.get_androidversion_code() or "?",
        "min_sdk":        apk.get_min_sdk_version()     or "?",
        "target_sdk":     apk.get_target_sdk_version()  or "?",
        "main_activity":  apk.get_main_activity()       or "?",
    })
    _extract_android_app_icon(apk, results)

    # ── Manifest-level binary flags ───────────────────────────────────────────
    try:
        manifest = apk.get_android_manifest_xml()
        app_elem = manifest.find("application")
        if app_elem is not None:
            _check_app_flags(app_elem, results)
            metadata = []
            for meta in app_elem.findall("meta-data"):
                name = meta.get(ns("name")) or meta.get("name") or ""
                value = meta.get(ns("value")) or meta.get("value") or meta.get(ns("resource")) or meta.get("resource") or ""
                if name:
                    metadata.append({"name": name, "value": value})
            if metadata:
                results["app_info"]["manifest_metadata"] = metadata
        manifest_permissions = []
        for perm in manifest.findall("permission"):
            name = perm.get(ns("name")) or perm.get("name") or ""
            protection = perm.get(ns("protectionLevel")) or perm.get("protectionLevel") or ""
            if name:
                manifest_permissions.append({
                    "name": name,
                    "protection_level": _normalize_protection_level(protection),
                    "raw_protection_level": protection or "unknown",
                })
        results["manifest_permissions"] = manifest_permissions
        # Store manifest as clean string. Register the Android namespace first so
        # attributes serialize with the canonical `android:` prefix instead of the
        # auto-generated `ns0:` — the latter renders as valid-but-unfamiliar XML that
        # looks corrupted/"encrypted" to anyone expecting a normal AndroidManifest.
        try:
            from xml.etree.ElementTree import indent, tostring, register_namespace
            register_namespace("android", "http://schemas.android.com/apk/res/android")
            try:
                indent(manifest)
            except TypeError:
                pass  # indent() not in Python < 3.9
            results["manifest_xml"] = tostring(manifest, encoding="unicode")
        except Exception:
            try:
                from xml.etree.ElementTree import tostring, register_namespace
                register_namespace("android", "http://schemas.android.com/apk/res/android")
                results["manifest_xml"] = tostring(manifest, encoding="unicode")
            except Exception:
                pass
    except Exception:
        pass

    # ── SDK version checks ─────────────────────────────────────────────────────
    try:
        min_sdk = int(apk.get_min_sdk_version() or 0)
        if 0 < min_sdk < 21:
            results["findings"].append({
                "rule_id":        "manifest_low_min_sdk",
                "title":          "Low Minimum SDK Version",
                "severity":       "medium",
                "category":       "Configuration",
                "description":    f"minSdkVersion is {min_sdk} (Android {_sdk_to_version(min_sdk)}). "
                                  "Devices running this version lack modern security controls "
                                  "(full-disk encryption, SELinux enforcing, etc.).",
                "impact":         "App can be installed on devices with known OS-level vulnerabilities.",
                "recommendation": "Raise minSdkVersion to at least 23 (Android 6.0) to enforce runtime permissions.",
            })
        elif 0 < min_sdk < 24:
            results["findings"].append({
                "rule_id":        "manifest_below_recommended_min_sdk",
                "title":          "Below-Recommended Minimum SDK",
                "severity":       "low",
                "category":       "Configuration",
                "description":    f"minSdkVersion is {min_sdk}. Android 6 and 7 lack Certificate Transparency and newer TLS defaults.",
                "recommendation": "Consider raising minSdkVersion to 24+ for stronger TLS and security defaults.",
                "impact":         "Users on older OS versions miss security improvements.",
            })
    except (ValueError, TypeError):
        pass


def _check_app_flags(app_elem, results):
    def attr(name): return app_elem.get(ns(name)) or app_elem.get(name)

    debuggable = attr("debuggable")
    manifest_security = results.setdefault("manifest_security", {})
    if debuggable and debuggable.lower() in ("true", "1"):
        manifest_security["debuggable"] = {
            "value": "true",
            "state": "true",
            "status": "True (Vulnerable)",
            "severity": "high",
            "reason": "android:debuggable is explicitly enabled and exposes the process to ADB debugging.",
        }
        results["findings"].append({
            "rule_id":        "manifest_debuggable",
            "title":          "Application is Debuggable",
            "severity":       "high",
            "category":       "Binary Hardening",
            "description":    "android:debuggable=\"true\" is set. Any user with ADB access can attach a debugger, dump memory, extract data, and bypass certificate pinning.",
            "impact":         "Full application memory accessible via ADB. SSL pinning trivially bypassed.",
            "poc":            "adb shell run-as <package> ls /data/data/<package>/\nadb jdwp  # list debuggable processes",
            "recommendation": "Remove android:debuggable or ensure it is false. Never ship debug builds to production.",
            "cwe":            "CWE-489",
            "masvs":          "MASVS-CODE-2",
            "owasp":          "M7",
            "manifest_evidence_spec": {"attr": "debuggable", "value": "true", "anchor": "application"},
        })
    elif debuggable and debuggable.lower() in ("false", "0"):
        manifest_security["debuggable"] = {
            "value": "false",
            "state": "false",
            "status": "False (Secure)",
            "severity": "info",
            "reason": "android:debuggable is explicitly disabled in the manifest.",
        }
    else:
        manifest_security["debuggable"] = {
            "value": "missing",
            "state": "missing",
            "status": "Missing (Potential Risk)",
            "severity": "low",
            "reason": "The manifest does not explicitly set android:debuggable. Build-time configuration should be verified.",
        }
        results["findings"].append({
            "rule_id":        "manifest_debuggable_flag_missing",
            "title":          "Potentially Debuggable (Flag Missing)",
            "severity":       "low",
            "category":       "Binary Hardening",
            "description":    "android:debuggable is not explicitly declared in the manifest. Release builds normally resolve this to false, but the missing flag increases the risk of an insecure build configuration or misconfigured signing pipeline.",
            "impact":         "A misconfigured release pipeline could accidentally ship a debuggable build without the manifest making that intent explicit.",
            "recommendation": "Set android:debuggable=\"false\" explicitly for production releases and verify the final merged manifest in CI.",
            "cwe":            "CWE-16",
            "masvs":          "MASVS-CODE-2",
            "owasp":          "M7",
            "confidence":     55,
            "validation_status": "heuristic",
            "manifest_evidence_spec": {"anchor": "application"},
        })

    allow_backup = attr("allowBackup")
    if allow_backup is None or allow_backup.lower() in ("true", "1"):
        # Explicit allowBackup="true" matches the attribute line; an unset flag
        # (defaults to true) anchors to the <application> element it pertains to.
        _backup_spec = ({"attr": "allowBackup", "value": "true", "anchor": "application"}
                        if allow_backup is not None else {"anchor": "application"})
        results["findings"].append({
            "rule_id":        "manifest_allow_backup",
            "title":          "Backup Enabled — Data Extraction Risk",
            "severity":       "medium",
            "category":       "Data Storage",
            "description":    "android:allowBackup is true (or unset, which defaults to true before API 31). App data can be extracted via ADB without root.",
            "impact":         "Credentials, tokens, and local databases extractable without rooting the device.",
            "poc":            "adb backup -f backup.ab -noapk <package>\ndd if=backup.ab bs=24 skip=1 | python3 -c \"import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))\" | tar xvf -",
            "recommendation": "Set android:allowBackup=\"false\" or configure android:fullBackupContent with exclusion rules for sensitive files.",
            "manifest_evidence_spec": _backup_spec,
        })

    cleartext = attr("usesCleartextTraffic")
    if cleartext and cleartext.lower() in ("true", "1"):
        results["findings"].append({
            "rule_id":        "manifest_cleartext_traffic",
            "title":          "Cleartext HTTP Traffic Permitted",
            "severity":       "high",
            "category":       "Network Security",
            "description":    "android:usesCleartextTraffic=\"true\" allows the app to communicate over unencrypted HTTP. This enables trivial MitM attacks on the same network.",
            "impact":         "All HTTP traffic is in cleartext — credentials, tokens, and PII exposed to network observers.",
            "poc":            "# Set up MitM proxy on same network\n# All http:// traffic will be readable in plaintext",
            "recommendation": "Remove usesCleartextTraffic or set to false. Migrate all endpoints to HTTPS.",
            "manifest_evidence_spec": {"attr": "usesCleartextTraffic", "value": "true", "anchor": "application"},
        })

    test_only = attr("testOnly")
    if test_only and test_only.lower() in ("true", "1"):
        results["findings"].append({
            "rule_id":        "manifest_test_only",
            "title":          "Test-Only Build in Production",
            "severity":       "high",
            "category":       "Binary Hardening",
            "description":    "android:testOnly=\"true\" detected. This is a test build that should never reach end users.",
            "impact":         "Test builds may have reduced security controls, debug endpoints, and verbose logging.",
            "recommendation": "Remove testOnly flag. Ensure production release builds are properly configured.",
            "manifest_evidence_spec": {"attr": "testOnly", "value": "true", "anchor": "application"},
        })


# ─── Permissions ─────────────────────────────────────────────────────────────
def _analyze_permissions(apk, results):
    perms = apk.get_permissions() or []
    results["permissions"]["all"] = perms

    # Classify every permission with status + description
    classified = []
    dangerous = []
    for p in perms:
        if p in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[p]
            entry = {
                "permission": p,
                "short_name": p.split(".")[-1],
                "status":     "dangerous",
                "severity":   sev,
                "description": desc,
            }
            dangerous.append(entry)
            classified.append(entry)
        else:
            # Normal / signature / unknown
            normal_desc = _NORMAL_PERMISSION_DESCS.get(p)
            if normal_desc:
                status = "normal"
            elif p.startswith("android.permission.") or p.startswith("com.google."):
                status = "normal"
                normal_desc = "Standard Android/Google permission."
            else:
                status = "unknown"
                normal_desc = "Unknown permission — may be custom or from a third-party library."
            classified.append({
                "permission": p,
                "short_name": p.split(".")[-1],
                "status":     status,
                "severity":   "info",
                "description": normal_desc or "",
            })

    results["permissions"]["classified"] = classified
    results["permissions"]["dangerous"] = dangerous

    if len(dangerous) >= 8:
        results["findings"].append({
            "rule_id":        "permissions_excessive_dangerous",
            "title":          "Excessive Dangerous Permissions",
            "severity":       "medium",
            "category":       "Permissions",
            "description":    f"App requests {len(dangerous)} dangerous/sensitive permissions. Over-permissioning increases the blast radius of a compromise.",
            "impact":         "If exploited or compromised, attacker gains access to broad device data.",
            "recommendation": "Apply principle of least privilege. Remove permissions not essential to core functionality.",
        })

    has_sms  = "android.permission.READ_SMS" in perms or "android.permission.RECEIVE_SMS" in perms
    has_call = "android.permission.READ_CALL_LOG" in perms or "android.permission.PROCESS_OUTGOING_CALLS" in perms
    if has_sms and has_call:
        results["findings"].append({
            "rule_id":        "permissions_sms_calllog_combo",
            "title":          "SMS + Call Log Access — Spyware-Like Permission Combo",
            "severity":       "high",
            "category":       "Permissions",
            "description":    "App requests both SMS and call log permissions simultaneously.",
            "recommendation": "Audit whether both are genuinely required.",
            "impact":         "App can silently capture all communications metadata.",
        })


# Normal permission descriptions (subset of most common)
_NORMAL_PERMISSION_DESCS = {
    "android.permission.INTERNET":                "Allows full Internet access. Required for any networked app.",
    "android.permission.ACCESS_NETWORK_STATE":    "Allows viewing network connection status.",
    "android.permission.ACCESS_WIFI_STATE":       "Allows viewing Wi-Fi connection info.",
    "android.permission.CHANGE_WIFI_STATE":       "Allows connecting/disconnecting Wi-Fi networks.",
    "android.permission.VIBRATE":                 "Allows control of the vibrator.",
    "android.permission.WAKE_LOCK":               "Prevents phone from sleeping.",
    "android.permission.RECEIVE_BOOT_COMPLETED":  "Allows app to start at boot.",
    "android.permission.FOREGROUND_SERVICE":      "Allows running foreground services.",
    "android.permission.FOREGROUND_SERVICE_LOCATION": "Allows foreground services with location.",
    "android.permission.MODIFY_AUDIO_SETTINGS":   "Allows modification of global audio settings.",
    "android.permission.USE_BIOMETRIC":           "Allows use of biometric hardware.",
    "android.permission.USE_FINGERPRINT":         "Deprecated: use USE_BIOMETRIC instead.",
    "android.permission.POST_NOTIFICATIONS":      "Allows sending push notifications.",
    "android.permission.BLUETOOTH":               "Allows Bluetooth connections.",
    "android.permission.BLUETOOTH_ADMIN":         "Allows Bluetooth device discovery and pairing.",
    "android.permission.NFC":                     "Allows NFC communications.",
    "android.permission.QUERY_ALL_PACKAGES":      "Allows querying all installed apps.",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "Allows requesting battery optimization exemption.",
    "com.google.android.c2dm.permission.RECEIVE": "Allows receiving FCM push notifications.",
    "com.google.android.gms.permission.AD_ID":    "Allows access to Google Advertising ID.",
    "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE": "Google Play install referrer.",
}


# ─── Components ──────────────────────────────────────────────────────────────
def _analyze_components(apk, tmpdir, results):
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception:
        return

    app_elem = manifest.find("application")
    if app_elem is None:
        return

    pkg = results["app_info"].get("package", "")

    for comp_type in ["activity", "service", "receiver", "provider"]:
        for elem in app_elem.iter(comp_type):
            _process_component(elem, comp_type, pkg, results)


def _exported_severity(comp_type, short_name, browsable, schemes, deeplinks, actions):
    """Phase 6 Task 3 — contextual exploitability severity for exported components.

    Severity reflects reachable impact, not a flat "medium": a plain exported
    AboutUsActivity is LOW; one that accepts URLs/deeplinks or is named for a
    sensitive flow is HIGH; receivers wired to sensitive system actions are
    HIGH; providers are handled separately (always high)."""
    name = (short_name or "").lower()
    acts = " ".join(actions or []).lower()
    url_like = bool(browsable) or any(s in ("http", "https") for s in (schemes or [])) or bool(deeplinks)
    sensitive_name = any(k in name for k in (
        "login", "auth", "pay", "transfer", "account", "admin", "webview",
        "deeplink", "url", "browser", "sync", "upload", "download", "export",
        "reset", "token", "oauth", "file", "share", "import",
    ))
    if comp_type == "activity":
        if url_like or sensitive_name:
            return "high"
        return "medium" if actions else "low"
    if comp_type == "service":
        return "high" if sensitive_name else "medium"
    if comp_type == "receiver":
        sensitive_action = any(k in acts for k in (
            "boot_completed", "sms", "telephony", "push", "gcm", "fcm",
            "package_added", "package_removed", "connectivity", "device_admin",
            "new_outgoing_call", "user_present",
        ))
        if sensitive_action or sensitive_name:
            return "high"
        return "medium" if actions else "low"
    return "medium"


def _process_component(elem, comp_type, pkg, results):
    def attr(name): return elem.get(ns(name)) or elem.get(name)

    raw_name = attr("name") or ""
    full_name = raw_name if raw_name.startswith(pkg) else (pkg + raw_name if raw_name.startswith(".") else raw_name)
    short_name = raw_name.split(".")[-1] if "." in raw_name else raw_name

    exported_val = attr("exported")
    permission   = attr("permission")
    read_perm    = attr("readPermission")
    write_perm   = attr("writePermission")
    authority    = attr("authorities") or ""
    permission_level = _permission_protection_level(permission, results)

    # Determine if exported
    intent_filters = list(elem.iter("intent-filter"))
    has_filter = len(intent_filters) > 0

    if exported_val is not None:
        is_exported = exported_val.lower() in ("true", "1")
    elif comp_type == "provider":
        is_exported = bool(authority)
    else:
        # Default: exported if has intent-filter (pre-API31 behavior)
        is_exported = has_filter

    # Collect intent filters
    actions   = []
    schemes   = []
    hosts     = []
    deeplinks = []
    browsable = False

    for intent_filter in intent_filters:
        for action in intent_filter.iter("action"):
            name = action.get(ns("name")) or action.get("name") or ""
            if name: actions.append(name)
        for category in intent_filter.iter("category"):
            cat = category.get(ns("name")) or ""
            if "BROWSABLE" in cat: browsable = True
        for data in intent_filter.iter("data"):
            scheme = data.get(ns("scheme")) or ""
            host   = data.get(ns("host"))   or ""
            path   = data.get(ns("path"))   or data.get(ns("pathPattern")) or data.get(ns("pathPrefix")) or ""
            if scheme: schemes.append(scheme)
            if host:   hosts.append(host)
            if scheme and host:
                deeplinks.append(f"{scheme}://{host}{path}")

    comp_info = {
        "name":       full_name,
        "short_name": short_name,
        "exported":   is_exported,
        "permission": permission,
        "permission_protection": permission_level,
        "read_permission": read_perm,
        "write_permission": write_perm,
        "authorities": authority,
        "actions":    actions,
        "schemes":    schemes,
        "hosts":      hosts,
        "deeplinks":  deeplinks,
        "browsable":  browsable,
    }

    # Add to attack surface
    key_map = {"activity": "activities", "service": "services",
               "receiver": "receivers", "provider": "providers"}
    results["attack_surface"][key_map[comp_type]].append(comp_info)

    if not is_exported:
        return

    # Phase B: every exported-component finding below targets this component's
    # decompiled class. Tagging file_path with the class FQN lets the source
    # resolver open the jadx/apktool source and enable View Code (never the
    # raw manifest binary). Patched in once at the end of the function.
    _component_finding_start = len(results["findings"])

    if permission and permission_level in {"normal", "dangerous", "unknown"}:
        results["findings"].append({
            "rule_id":        "manifest_weak_exported_permission",
            "title":          f"Weak Exported Component Permission Protection — {short_name}",
            "severity":       "medium",
            "category":       "Attack Surface",
            "description":    f"Exported {comp_type} `{short_name}` is protected only by `{permission}` with protection level `{permission_level}`. Third-party apps can often obtain or satisfy this permission.",
            "impact":         "This component may remain externally reachable despite a declared permission boundary.",
            "recommendation": "Use signature-level permissions for exported privileged components or set android:exported=\"false\".",
            "cwe":            "CWE-926",
            "masvs":          "MASVS-PLATFORM-1",
            "owasp":          "M1",
        })

    # ── Exported component findings ───────────────────────────────────────────
    adb_intent = f"adb shell am start -n {pkg}/{full_name}" if comp_type == "activity" else \
                 f"adb shell am startservice -n {pkg}/{full_name}" if comp_type == "service" else \
                 f"adb shell am broadcast -a {actions[0] if actions else 'ACTION'} -n {pkg}/{full_name}"

    exp_sev = _exported_severity(comp_type, short_name, browsable, schemes, deeplinks, actions)

    if comp_type == "activity" and not permission:
        if browsable and not any(s in ["http", "https"] for s in schemes):
            # Custom scheme deeplink
            for dl in deeplinks:
                results["findings"].append({
                    "rule_id":        "manifest_custom_scheme_deeplink",
                    "title":          f"Custom Scheme Deeplink Hijacking Surface — {short_name}",
                    "severity":       "high",
                    "category":       "Deeplinks",
                    "description":    f"Activity handles custom URL scheme `{dl}` without Android App Links verification. "
                                      "Any app on the device can register the same scheme and intercept these intents.",
                    "impact":         "Malicious app can steal deeplink payloads including OAuth tokens, reset tokens, and session data.",
                    "poc":            f"# Check assetlinks.json\ncurl https://{hosts[0] if hosts else 'host'}/.well-known/assetlinks.json\n\n# Test deeplink\nadb shell am start -a android.intent.action.VIEW -d '{dl}?token=test' {pkg}",
                    "recommendation": "Migrate to Android App Links (https:// with verified assetlinks.json). Validate all incoming deeplink data.",
                })
        elif browsable or schemes or deeplinks:
            # Exported activity that accepts URLs/data — high reachable impact.
            results["findings"].append({
                "rule_id":        "manifest_exported_url_activity",
                "title":          f"Exported URL-Handling Activity — {short_name}",
                "severity":       exp_sev,
                "category":       "Attack Surface",
                "description":    f"Activity `{short_name}` is exported and accepts external URL/intent data ({', '.join(deeplinks or schemes or actions) or 'intent data'}) without a permission. Attacker-controlled input reaches this entry point.",
                "impact":         "Untrusted URLs/intents can drive sensitive in-app flows (open redirect, WebView injection, parameter tampering).",
                "poc":            adb_intent,
                "recommendation": "Validate all incoming URL/intent data and restrict the activity with a permission or android:exported=\"false\" if external access is not required.",
            })
        elif not actions:
            results["findings"].append({
                "rule_id":        "manifest_exported_activity",
                "title":          f"Exported Activity Without Protection — {short_name}",
                "severity":       exp_sev,
                "category":       "Attack Surface",
                "description":    f"Activity `{short_name}` is exported without a required permission or intent filter. Any app can launch it.",
                "impact":         "Unauthorized activity launch may bypass authentication or trigger unintended app flows.",
                "poc":            adb_intent,
                "recommendation": "Add android:permission attribute or set android:exported=\"false\" if external access is not required.",
            })

    elif comp_type == "service" and not permission:
        results["findings"].append({
            "rule_id":        "manifest_exported_service",
            "title":          f"Exported Service Without Permission — {short_name}",
            "severity":       exp_sev,
            "category":       "Attack Surface",
            "description":    f"Service `{short_name}` is exported without a required permission. Any app can bind or start it.",
            "impact":         "Third-party apps can interact with this service to trigger unintended background operations.",
            "poc":            adb_intent,
            "recommendation": "Add android:permission to restrict service access.",
        })

    elif comp_type == "receiver" and not permission:
        results["findings"].append({
            "rule_id":        "manifest_exported_receiver",
            "title":          f"Exported Broadcast Receiver Without Permission — {short_name}",
            "severity":       exp_sev,
            "category":       "Attack Surface",
            "description":    f"BroadcastReceiver `{short_name}` is exported without required permission. "
                              "Any app can send broadcasts to trigger it.",
            "impact":         "Attacker-controlled app can send crafted broadcasts to manipulate app state.",
            "poc":            adb_intent,
            "recommendation": "Add android:permission or use LocalBroadcastManager for internal broadcasts.",
        })

    elif comp_type == "provider":
        if not (permission or read_perm or write_perm):
            results["findings"].append({
                "rule_id":        "manifest_exported_provider",
                "title":          f"Exported Content Provider Without Permission — {short_name}",
                "severity":       "high",
                "category":       "Attack Surface",
                "description":    f"ContentProvider `{short_name}` (authority: `{authority}`) is exported without read/write permissions. "
                                  "Any app can query, insert, update, or delete data.",
                "impact":         "Potential unauthorized data access or manipulation including SQLi via ContentProvider URIs.",
                "poc":            f"# Query provider\nadb shell content query --uri content://{authority}/\n\n# Or via app\nContentResolver cr = getContentResolver();\nCursor c = cr.query(Uri.parse(\"content://{authority}/\"), null, null, null, null);",
                "recommendation": "Add readPermission and writePermission with appropriate protectionLevel. Implement URI permission grants.",
                "cwe":            "CWE-926",
                "masvs":          "MASVS-PLATFORM-1",
                "owasp":          "M1",
            })

    # Phase B: point each exported-component finding at the component's class so
    # the source resolver can locate decompiled source and offer View Code.
    if full_name and "." in full_name:
        for f in results["findings"][_component_finding_start:]:
            f.setdefault("file_path", full_name)
            f.setdefault("component", full_name)
            # The exposure is the app's responsibility even when the component
            # class is implemented by a library (e.g. an exported service backed
            # by net.gotev.uploadservice) — keep it application-owned so it is
            # not hidden as library noise. View Code still opens the impl class.
            f["app_owned_exposure"] = True


# ─── SDK detection ────────────────────────────────────────────────────────────
def _detect_sdks(apk, tmpdir, results):
    found_sdks = []
    seen = set()
    all_packages = _collect_package_hints(apk, tmpdir, results)
    results["app_info"]["package_hints"] = sorted(all_packages)
    try:
        for pkg_prefix, (sdk_name, category, sev) in SDK_SIGNATURES.items():
            if any(p.startswith(pkg_prefix) for p in all_packages):
                key = sdk_name
                if key not in seen:
                    seen.add(key)
                    found_sdks.append({
                        "name":     sdk_name,
                        "package":  pkg_prefix,
                        "category": category,
                        "severity": sev,
                    })
                    if sev in ("high", "medium"):
                        results["findings"].append({
                            "rule_id":        "sdk_debug_sensitive_detected",
                            "title":          f"Debug/Sensitive SDK Detected — {sdk_name}",
                            "severity":       sev,
                            "category":       "Third-Party SDKs",
                            "description":    f"`{sdk_name}` ({pkg_prefix}) detected in app. This SDK should not be present in production builds.",
                            "recommendation": "Remove debug SDKs from release builds using build variants.",
                        })
    except Exception:
        pass

    tracker_hits = detect_trackers(all_packages)
    for tracker in tracker_hits:
        key = tracker.get("name")
        if key and key not in seen:
            seen.add(key)
            found_sdks.append({
                "name": tracker.get("name", ""),
                "package": tracker.get("pkg", ""),
                "category": tracker.get("category", ""),
                "severity": "high" if tracker.get("category") == "Session Replay" else "info",
                "url": tracker.get("url", ""),
            })

    _detect_session_recording_sdk_issues(tmpdir, all_packages, tracker_hits, results)
    results["sdks"] = normalize_sdks(found_sdks)


def _normalize_protection_level(protection: str) -> str:
    value = (protection or "").lower()
    if not value:
        return "unknown"
    if "signatureorsystem" in value or "signature|system" in value:
        return "signature"
    if "signature" in value:
        return "signature"
    if "dangerous" in value:
        return "dangerous"
    if "normal" in value:
        return "normal"
    return value.split("|")[0]


def _permission_protection_level(permission: str, results: dict) -> str:
    if not permission:
        return "none"
    for perm in results.get("manifest_permissions", []):
        if perm.get("name") == permission:
            return perm.get("protection_level", "unknown")
    if permission.startswith("android.permission."):
        return "dangerous" if permission in DANGEROUS_PERMISSIONS else "normal"
    return "unknown"


def _collect_package_hints(apk, tmpdir: str, results: dict) -> set[str]:
    packages = set()
    pkg = results.get("app_info", {}).get("package")
    if pkg:
        packages.add(pkg)

    try:
        components = list(apk.get_activities()) + list(apk.get_services()) + list(apk.get_receivers()) + list(apk.get_providers())
        for comp in components:
            parts = [part for part in comp.split(".") if part]
            for i in range(2, len(parts)):
                packages.add(".".join(parts[:i]))
    except Exception:
        pass

    manifest_xml = results.get("manifest_xml", "")
    for match in re.findall(r"\b([a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*){1,})\b", manifest_xml):
        if len(match.split(".")) >= 2:
            packages.add(match)

    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if not fname.endswith((".java", ".kt", ".smali", ".xml")):
                continue
            rel = normalize_relative_path(os.path.relpath(os.path.join(root, fname), tmpdir))
            parts = [part for part in rel.split("/") if part]
            if parts[:1] == ["smali"] or (len(parts) > 1 and parts[0].startswith("smali")):
                pkg_parts = parts[1:-1]
            else:
                pkg_parts = parts[:-1]
            cleaned = [part for part in pkg_parts if re.fullmatch(r"[A-Za-z_]\w*", part)]
            for i in range(2, len(cleaned) + 1):
                packages.add(".".join(cleaned[:i]))

    return {value for value in packages if "." in value}


def _detect_session_recording_sdk_issues(tmpdir: str, all_packages: set[str], tracker_hits: list, results: dict):
    session_trackers = [tracker for tracker in tracker_hits if tracker.get("category") == "Session Replay"]
    if not session_trackers:
        return

    metadata = results.get("app_info", {}).get("manifest_metadata", [])
    text_hits = []
    id_pattern = re.compile(r"(?i)(appid|app_id|projectkey|project_key|api[_-]?key|token)[\"'\s:=/>\-]{1,12}([A-Za-z0-9._:-]{6,80})")

    for item in metadata:
        name = item.get("name", "")
        value = item.get("value", "")
        if name and value and not value.lower().startswith("@string/"):
            for tracker in session_trackers:
                tracker_name = tracker.get("name", "").split()[0].lower()
                tracker_pkg = tracker.get("pkg", "").lower()
                if tracker_name in name.lower() or tracker_pkg in name.lower():
                    text_hits.append(("AndroidManifest.xml", f"{name}={value}"))

    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if not fname.endswith((".xml", ".json", ".properties", ".java", ".kt", ".smali")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as handle:
                    content = handle.read()
            except Exception:
                continue
            lowered = content.lower()
            if not any(tracker.get("pkg", "").lower() in lowered or tracker.get("name", "").split()[0].lower() in lowered for tracker in session_trackers):
                continue
            for match in id_pattern.finditer(content):
                value = match.group(2)
                if value and not value.lower().startswith("@string/"):
                    rel = normalize_relative_path(os.path.relpath(fpath, tmpdir))
                    text_hits.append((rel, f"{match.group(1)}={value}"))

    added = set()
    for tracker in session_trackers:
        name = tracker.get("name", "")
        if name in added:
            continue
        added.add(name)
        tracker_key = name.split()[0].lower()
        relevant_hits = [
            hit for hit in text_hits
            if tracker_key in hit[0].lower() or tracker_key in hit[1].lower()
        ][:3] or text_hits[:3]
        evidence = [make_file_evidence(path, 0, snippet) for path, snippet in relevant_hits]
        description = f"{name} session-recording SDK is present. Session replay SDKs can capture screen content, taps, and sensitive user flows."
        if relevant_hits:
            description += " A hardcoded identifier or configuration value was also detected."
        results["findings"].append({
            "rule_id": "sdk_session_recording_present",
            "title": f"Session Recording SDK Present — {name}",
            "severity": "high",
            "category": "Third-Party SDKs",
            "description": description,
            "impact": "Session replay tooling materially increases privacy exposure and can capture sensitive in-app content if not tightly controlled.",
            "recommendation": "Review whether the SDK is acceptable for production, minimize capture scope, and move identifiers or configuration out of the client where possible.",
            "file_path": relevant_hits[0][0] if relevant_hits else "AndroidManifest.xml",
            "snippet": relevant_hits[0][1] if relevant_hits else "",
            "file_evidence": evidence,
            "files": [path for path, _ in relevant_hits],
            "file_count": len(relevant_hits),
            "cwe": "CWE-359",
            "masvs": "MASVS-PRIVACY-1",
            "owasp": "M2",
        })
        for path, snippet in relevant_hits:
            results["sdk_secrets"].append({
                "name": f"{name} Identifier",
                "category": "Privacy SDK",
                "severity": "high",
                "value": snippet.split("=", 1)[-1][:80],
                "source": path,
                "full_path": path,
                "description": f"Potential hardcoded {name} identifier detected.",
                "recommendation": "Review whether this SDK identifier should be exposed in the client build and limit capture scope.",
            })


def _build_behavior_findings(results: dict):
    api_results = results.get("android_api", {})
    api_evidence = results.get("android_api_evidence", {})
    behavior_entries = []
    seen_titles = {finding.get("title") for finding in results.get("findings", [])}

    def _is_binary(p):
        p = str(p or "").lower()
        return p.endswith((".dex", ".so", ".dylib", ".arsc", ".odex", ".vdex", ".oat"))

    for category, files in api_results.items():
        rule = BEHAVIOR_RULES.get(category)
        if not rule:
            continue
        source_files = [f for f in files if not _is_binary(f)]
        # Phase 6 Task 4: a behaviour finding MUST carry real proof — file, line
        # and code snippet. Evidence with a resolved line comes from
        # api_evidence; if none exists, the finding is dropped entirely.
        evidence = [e for e in api_evidence.get(category, [])
                    if e.get("path") and not _is_binary(e.get("path")) and e.get("line") and e.get("snippet")]

        behavior_entries.append({
            "category": category,
            "title": rule["title"],
            "severity": rule["severity"],
            "description": rule["description"],
            "files": source_files[:10],
            "file_count": len(source_files),
            "cwe": rule["cwe"],
            "masvs": rule["masvs"],
            "owasp": rule["owasp"],
        })
        if rule["title"] in seen_titles:
            continue
        if not evidence:
            # No file+line+snippet proof -> do not generate the finding.
            continue
        primary = evidence[0]
        results["findings"].append({
            # Stable id per behaviour CATEGORY (the rule key), not its title.
            "rule_id": rule_slug("behavior", category),
            "title": rule["title"],
            "severity": rule["severity"],
            "category": "Behavior Analysis",
            "description": rule["description"],
            "impact": rule["impact"],
            "recommendation": rule["recommendation"],
            "cwe": rule["cwe"],
            "masvs": rule["masvs"],
            "owasp": rule["owasp"],
            "file_path": primary["path"],
            "line": primary["line"],
            "snippet": primary["snippet"],
            "files": [e["path"] for e in evidence],
            "file_count": len(evidence),
            "file_evidence": [{"path": e["path"], "lines": [e["line"]], "snippet": e["snippet"]} for e in evidence],
        })
        seen_titles.add(rule["title"])
    results["behavior_analysis"] = behavior_entries


def _add_malware_permission_findings(results: dict):
    stats = results.get("malware_perms", {})
    malware = stats.get("malware_permissions", {})
    common = stats.get("common_malware_permissions", {})
    malware_count = malware.get("count", 0)
    common_count = common.get("count", 0)
    if not malware_count and not common_count:
        return
    severity = "high" if malware_count >= 12 else "medium" if malware_count >= 6 or common_count >= 10 else "low"
    results["findings"].append({
        "rule_id": "permissions_malware_overlap",
        "title": "Malware Permission Overlap Elevated",
        "severity": severity,
        "category": "Permissions",
        "description": f"The app requests {malware_count}/{malware.get('total', 0)} permissions seen in common Android malware sets and {common_count}/{common.get('total', 0)} permissions from broader abuse datasets.",
        "impact": "A high overlap does not prove malware, but it increases analyst focus on abuse potential and blast radius.",
        "recommendation": "Review whether all requested permissions are essential and remove non-core access from release builds.",
        "cwe": "CWE-250",
        "masvs": "MASVS-PLATFORM-1",
        "owasp": "M2",
    })


def _add_domain_intel_summary(results: dict):
    intel = results.get("domain_intel", [])
    risky = [item for item in intel if item.get("risk_score", 0) >= 20]
    if not risky:
        return
    results["findings"].append({
        "rule_id": "domain_intel_review_required",
        "title": "Domain Intelligence Review Required",
        "severity": "low" if len(risky) < 3 else "medium",
        "category": "Network Intelligence",
        "description": f"{len(risky)} discovered domains were enriched with suspicious or review-worthy indicators such as staging hosts, dynamic DNS, suspicious TLDs, or sanctioned geographies.",
        "recommendation": "Review the enriched domain list and validate whether non-production or high-risk infrastructure belongs in the shipped app.",
        "cwe": "CWE-200",
        "masvs": "MASVS-NETWORK-1",
        "owasp": "M5",
    })


def _add_exported_webview_attack_chain(results: dict):
    findings = results.get("findings", [])
    activities = [activity for activity in results.get("attack_surface", {}).get("activities", []) if activity.get("exported")]
    js_findings = [finding for finding in findings if "WebView JavaScript Enabled" in finding.get("title", "")]
    file_findings = [finding for finding in findings if "WebView File System Access Enabled" in finding.get("title", "")]
    if not activities or not js_findings or not file_findings:
        return

    candidate = next((
        activity for activity in activities
        if any(token in action.upper() for action in activity.get("actions", []) for token in ("OPEN_WEB_URL", "VIEW", "WEB"))
        or activity.get("browsable")
        or any(scheme in ("http", "https") for scheme in activity.get("schemes", []))
    ), None)
    if not candidate:
        return

    title = f"Exported Intent to JS-Enabled WebView Attack Chain — {candidate.get('short_name')}"
    if any(finding.get("title") == title for finding in findings):
        return

    evidence = []
    for finding in (js_findings[:1] + file_findings[:1]):
        evidence.extend(finding.get("file_evidence") or [make_file_evidence(finding.get("file_path", ""), finding.get("line", 0), finding.get("snippet", ""))])

    actions = ", ".join(candidate.get("actions", [])[:3]) or "intent launch"
    results["findings"].append({
        "rule_id": "chain_exported_intent_webview",
        "title": title,
        "severity": "high",
        "category": "Attack Surface",
        "description": f"Exported activity `{candidate.get('short_name')}` accepts externally triggerable intents ({actions}) and the app also enables JavaScript plus file access in WebView flows. This forms an open redirect or arbitrary URL loading chain into a high-risk WebView configuration.",
        "impact": "An attacker-controlled app can drive the exported flow into a JavaScript-enabled WebView and increase the likelihood of XSS, phishing, or local-file exposure.",
        "poc": f"adb shell am start -n {results.get('app_info', {}).get('package', '')}/{candidate.get('name')} --es url 'https://attacker.example'",
        "recommendation": "Gate exported URL-entry activities, validate allowed destinations, and disable JavaScript or file access unless strictly required.",
        "file_path": js_findings[0].get("file_path") or file_findings[0].get("file_path", ""),
        "snippet": js_findings[0].get("snippet") or file_findings[0].get("snippet", ""),
        "file_evidence": [entry for entry in evidence if entry.get("path")][:4],
        "files": list({entry.get("path") for entry in evidence if entry.get("path")}),
        "file_count": len({entry.get("path") for entry in evidence if entry.get("path")}),
        "cwe": "CWE-601",
        "masvs": "MASVS-PLATFORM-2",
        "owasp": "M1",
    })


def _enrich_findings_with_standards(results: dict):
    defaults = [
        (("Attack Surface", "Deeplinks"), ("CWE-926", "MASVS-PLATFORM-1", "M1")),
        (("WebView",), ("CWE-749", "MASVS-PLATFORM-2", "M1")),
        (("Permissions", "Behavior Analysis"), ("CWE-359", "MASVS-PRIVACY-1", "M2")),
        (("Network Security", "Network Intelligence"), ("CWE-319", "MASVS-NETWORK-1", "M5")),
        (("Third-Party SDKs",), ("CWE-1104", "MASVS-PLATFORM-3", "M9")),
        (("Binary Hardening", "Certificate"), ("CWE-693", "MASVS-CODE-4", "M7")),
        (("Configuration",), ("CWE-16", "MASVS-CODE-1", "M8")),
    ]
    for finding in results.get("findings", []):
        if finding.get("cwe") and finding.get("masvs") and finding.get("owasp"):
            continue
        category = finding.get("category", "")
        title = finding.get("title", "")
        for categories, mapping in defaults:
            if category in categories or any(token in title for token in categories):
                finding.setdefault("cwe", mapping[0])
                finding.setdefault("masvs", mapping[1])
                finding.setdefault("owasp", mapping[2])
                break


# ─── Framework detection ──────────────────────────────────────────────────────
def _detect_framework(tmpdir, results):
    files = set()
    for root, _, fnames in os.walk(tmpdir):
        for f in fnames:
            rel = normalize_relative_path(os.path.relpath(os.path.join(root, f), tmpdir))
            files.add(rel.replace("\\", "/"))

    framework_type = "native"
    details = []

    # React Native
    rn_bundle = next((f for f in files if "index.android.bundle" in f or
                      ("assets" in f and f.endswith(".bundle"))), None)
    if rn_bundle or any("libreactnativejni.so" in f for f in files):
        framework_type = "react_native"
        details.append("React Native detected via JS bundle / libreactnativejni.so")
        results["findings"].append({
            "rule_id":        "framework_react_native_detected",
            "title":          "React Native Framework Detected",
            "severity":       "info",
            "category":       "Framework",
            "description":    "App is built with React Native. JS bundle contains business logic, API keys, and endpoint URLs in a more accessible format than compiled Java.",
            "impact":         "JS bundles can be extracted and analyzed without decompilation, revealing secrets and API surface.",
            "recommendation": "Ensure no sensitive keys in JS bundle. Use Hermes bytecode (not plain JS). Consider JS bundle encryption for sensitive apps.",
        })

    # Flutter
    if any("libflutter.so" in f for f in files) or any("libapp.so" in f for f in files):
        framework_type = "flutter"
        details.append("Flutter detected via libflutter.so / libapp.so")
        results["findings"].append({
            "rule_id":        "framework_flutter_detected",
            "title":          "Flutter Framework Detected",
            "severity":       "info",
            "category":       "Framework",
            "description":    "App uses Flutter (Dart compiled to native). Standard SSL pinning bypass tools (Objection, reFlutter) may fail. "
                              "Custom Frida hooks targeting ADRP+ADD instruction sequences in libflutter.so are required.",
            "poc":            "# Auto-generate Frida hook with K!ll Fl!utter:\n# python3 killflutter.py <apk_path>\n\n# Manual offset scan:\nreadelf -d libflutter.so | grep -i ssl",
            "recommendation": "N/A — informational framework note for analyst.",
        })

    # Xamarin
    if any("assemblies/" in f and f.endswith(".dll") for f in files):
        framework_type = "xamarin"
        details.append("Xamarin detected via .NET assemblies")
        results["findings"].append({
            "rule_id":        "framework_xamarin_detected",
            "title":          "Xamarin/.NET Framework Detected",
            "severity":       "info",
            "category":       "Framework",
            "description":    "App uses Xamarin (.NET). DLL assemblies can be extracted and decompiled with ILSpy/dnSpy for full source access.",
            "poc":            "# Extract DLLs:\nunzip app.apk assemblies/ -d extracted/\n# Decompile:\n# Open .dll files in ILSpy or dnSpy",
            "recommendation": "Enable Dotfuscator or equivalent obfuscation for Xamarin release builds.",
        })

    # Cordova/Ionic
    if any("assets/www/index.html" in f or "assets/www/cordova.js" in f for f in files):
        framework_type = "cordova"
        details.append("Cordova/Ionic detected via assets/www/")
        results["findings"].append({
            "rule_id":        "framework_cordova_detected",
            "title":          "Cordova/Ionic Hybrid Framework Detected",
            "severity":       "medium",
            "category":       "Framework",
            "description":    "App is built with Cordova/Ionic. Full HTML/JS source is accessible in assets/www/. Business logic, API keys, and endpoints are trivially readable.",
            "poc":            "unzip app.apk assets/www/ -d extracted/\nls extracted/assets/www/",
            "recommendation": "Minify and obfuscate JS. Move all sensitive logic server-side. Never store credentials in JS.",
        })

    results["framework"] = {"type": framework_type, "details": details}


# ─── Network Security Config ──────────────────────────────────────────────────
def _parse_nsc_trust_anchors(elem) -> dict:
    """Parse <trust-anchors> element into structured dict."""
    anchors = {"system": False, "user": False, "custom_certs": []}
    for cert in elem.findall("certificates"):
        src = cert.get("src", "")
        overridePins = cert.get("overridePins", "false").lower() == "true"
        if src == "system":
            anchors["system"] = True
        elif src == "user":
            anchors["user"] = True
        elif src:
            anchors["custom_certs"].append({"src": src, "overridePins": overridePins})
    return anchors


def _parse_nsc_pin_set(elem) -> dict:
    """Parse <pin-set> into structured dict."""
    expiration = elem.get("expiration", "")
    pins = []
    for pin in elem.findall("pin"):
        pins.append({"digest": pin.get("digest", "SHA-256"), "value": (pin.text or "").strip()})
    return {"expiration": expiration, "pins": pins}


def _nsc_bool(elem, attr: str, default: bool) -> bool:
    val = elem.get(attr, "")
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    return default


def _analyze_network_security_config(tmpdir, results):
    nsc_paths = []
    for root, _, files in os.walk(tmpdir):
        for f in files:
            if "network_security_config" in f.lower() and f.endswith(".xml"):
                nsc_paths.append(os.path.join(root, f))

    if not nsc_paths:
        results["network_config"] = {"present": False}
        return

    nsc_path = nsc_paths[0]
    try:
        tree      = ET.parse(nsc_path)
        root_elem = tree.getroot()
        xml_text  = ET.tostring(root_elem, encoding="unicode")
    except Exception:
        results["network_config"] = {"present": False, "parse_error": True}
        return

    # ── Base config ───────────────────────────────────────────────────────────
    base_elem = root_elem.find("base-config")
    base_config = None
    if base_elem is not None:
        cleartext = _nsc_bool(base_elem, "cleartextTrafficPermitted", True)
        trust_el  = base_elem.find("trust-anchors")
        anchors   = _parse_nsc_trust_anchors(trust_el) if trust_el is not None else {"system": True, "user": False, "custom_certs": []}
        base_config = {"cleartextTrafficPermitted": cleartext, "trust_anchors": anchors}

    # ── Debug overrides ───────────────────────────────────────────────────────
    debug_elem    = root_elem.find("debug-overrides")
    debug_overrides = None
    if debug_elem is not None:
        cleartext    = _nsc_bool(debug_elem, "cleartextTrafficPermitted", True)
        trust_el     = debug_elem.find("trust-anchors")
        anchors      = _parse_nsc_trust_anchors(trust_el) if trust_el is not None else {"system": True, "user": False, "custom_certs": []}
        pin_override = False
        for cert in debug_elem.findall(".//certificates"):
            if cert.get("overridePins", "false").lower() == "true":
                pin_override = True
        debug_overrides = {
            "cleartextTrafficPermitted": cleartext,
            "trust_anchors": anchors,
            "overridePins": pin_override,
        }

    # ── Domain configs ────────────────────────────────────────────────────────
    domain_configs = []
    for dc in root_elem.findall("domain-config"):
        cleartext = _nsc_bool(dc, "cleartextTrafficPermitted", False)
        domains   = [d.text.strip() for d in dc.findall("domain") if d.text]
        incl_sub  = [d.get("includeSubdomains", "false").lower() == "true" for d in dc.findall("domain")]

        trust_el  = dc.find("trust-anchors")
        anchors   = _parse_nsc_trust_anchors(trust_el) if trust_el is not None else None

        pin_el    = dc.find("pin-set")
        pin_set   = _parse_nsc_pin_set(pin_el) if pin_el is not None else None

        domain_configs.append({
            "domains":                  domains,
            "includeSubdomains":        incl_sub,
            "cleartextTrafficPermitted": cleartext,
            "trust_anchors":            anchors,
            "pin_set":                  pin_set,
        })

    # ── Summarise overall posture ─────────────────────────────────────────────
    has_pinning       = any(dc.get("pin_set") for dc in domain_configs)
    user_ca_trusted   = (base_config and base_config["trust_anchors"].get("user")) or \
                        any(dc.get("trust_anchors") and dc["trust_anchors"].get("user") for dc in domain_configs)
    cleartext_global  = base_config["cleartextTrafficPermitted"] if base_config else ("cleartextTrafficPermitted=\"true\"" in xml_text)
    cleartext_domains = [dc for dc in domain_configs if dc.get("cleartextTrafficPermitted")]
    pin_override      = debug_overrides.get("overridePins") if debug_overrides else False

    network_config = {
        "present":            True,
        "file":               os.path.relpath(nsc_path, tmpdir),
        "xml":                xml_text,
        "base_config":        base_config,
        "debug_overrides":    debug_overrides,
        "domain_configs":     domain_configs,
        "summary": {
            "has_pinning":        has_pinning,
            "user_ca_trusted":    user_ca_trusted,
            "cleartext_global":   cleartext_global,
            "cleartext_domains":  [dc["domains"] for dc in cleartext_domains],
            "pin_override":       pin_override,
            "domain_count":       len(domain_configs),
            "pinned_domain_count": sum(1 for dc in domain_configs if dc.get("pin_set")),
        },
    }
    results["network_config"] = network_config

    # ── Generate findings ─────────────────────────────────────────────────────

    # 1. Global cleartext
    if cleartext_global:
        results["findings"].append({
            "rule_id":        "nsc_global_cleartext",
            "title":          "Network Security Config — Global Cleartext HTTP Permitted",
            "severity":       "high",
            "category":       "Network Security",
            "description":    "base-config sets cleartextTrafficPermitted=\"true\", allowing all HTTP traffic from the app. Any data sent over HTTP is visible to passive network observers.",
            "impact":         "Login credentials, session tokens, and user data can be captured by anyone on the same network.",
            "poc":            "# Run mitmproxy or Burp on same network — HTTP traffic appears in cleartext",
            "recommendation": "Set cleartextTrafficPermitted=\"false\" in base-config. Migrate all endpoints to HTTPS.",
            "masvs":          "MASVS-NETWORK-1",
            "owasp":          "M5",
        })

    # 2. Per-domain cleartext
    for dc in cleartext_domains:
        domains_str = ", ".join(dc["domains"][:3])
        results["findings"].append({
            "rule_id":        "nsc_domain_cleartext",
            "title":          f"Cleartext HTTP Permitted for Domain(s): {domains_str}",
            "severity":       "medium",
            "category":       "Network Security",
            "description":    f"domain-config explicitly permits cleartext HTTP for: {', '.join(dc['domains'])}. Traffic to these domains is unencrypted.",
            "recommendation": "Remove cleartextTrafficPermitted=\"true\" from domain-config or migrate to HTTPS.",
            "masvs":          "MASVS-NETWORK-1",
            "owasp":          "M5",
        })

    # 3. User CA trust
    if user_ca_trusted:
        results["findings"].append({
            "rule_id":        "nsc_user_ca_trusted",
            "title":          "User-Installed CA Certificates Trusted",
            "severity":       "high",
            "category":       "Network Security",
            "description":    "network_security_config trusts user-installed CA certificates. This allows trivial TLS interception: install a proxy CA cert (Burp, mitmproxy) and all HTTPS traffic is readable.",
            "impact":         "Any attacker with physical access or social engineering can install a CA cert and intercept all app traffic.",
            "poc":            "1. Install Burp Suite CA cert on device (Settings > Security > Install certificate)\n2. All HTTPS traffic visible in Burp with no SSL errors",
            "recommendation": "Remove <certificates src=\"user\"/> from all non-debug trust-anchors.",
            "masvs":          "MASVS-NETWORK-2",
            "owasp":          "M5",
        })

    # 4. Pin override in debug config (leak risk)
    if pin_override:
        results["findings"].append({
            "rule_id":        "nsc_pin_override_debug",
            "title":          "Certificate Pinning Override in Debug Config",
            "severity":       "medium",
            "category":       "Network Security",
            "description":    "debug-overrides contains overridePins=\"true\". If this XML is present in a production APK, pinning can be bypassed during pentest/debug sessions.",
            "recommendation": "Verify debug-overrides is excluded from release builds. Use build flavors to strip debug NSC in production.",
            "masvs":          "MASVS-NETWORK-2",
            "owasp":          "M5",
        })

    # 5. No pinning configured at all
    if not has_pinning:
        results["findings"].append({
            "rule_id":        "nsc_no_pinning",
            "title":          "No Certificate Pinning Configured",
            "severity":       "medium",
            "category":       "Network Security",
            "description":    "network_security_config.xml does not define any <pin-set> elements. Without pinning, any trusted CA — including those installed by attackers — can issue valid certificates for your domain.",
            "recommendation": "Add <pin-set> to your domain-config with your server certificate's public key hash. Include a backup pin.",
            "masvs":          "MASVS-NETWORK-2",
            "owasp":          "M5",
        })
    else:
        # 6. Pinning configured — check for expired or missing backup pins
        from datetime import datetime as _dt
        for dc in domain_configs:
            pin_set = dc.get("pin_set")
            if not pin_set:
                continue
            domains_str = ", ".join(dc["domains"][:2])

            # Expiry check
            exp = pin_set.get("expiration", "")
            if exp:
                try:
                    exp_date = _dt.strptime(exp, "%Y-%m-%d")
                    if exp_date < _dt.utcnow():
                        results["findings"].append({
                            "rule_id":        "nsc_expired_pin",
                            "title":          f"Expired Certificate Pin — {domains_str}",
                            "severity":       "high",
                            "category":       "Network Security",
                            "description":    f"Pin-set for {domains_str} expired on {exp}. Connections to these domains will fail — effectively a self-inflicted DoS.",
                            "recommendation": f"Rotate pin-set expiration date and update pins for {domains_str}.",
                            "masvs":          "MASVS-NETWORK-2",
                            "owasp":          "M5",
                        })
                except ValueError:
                    pass

            # Backup pin check (< 2 pins = no backup)
            if len(pin_set.get("pins", [])) < 2:
                results["findings"].append({
                    "rule_id":        "nsc_no_backup_pin",
                    "title":          f"Certificate Pinning — No Backup Pin for {domains_str}",
                    "severity":       "low",
                    "category":       "Network Security",
                    "description":    f"Only one pin defined for {domains_str}. If the pinned certificate is rotated without updating the app, all connections will fail.",
                    "recommendation": "Always define at least two pins: the current cert and one backup (next rotation cert or CA pin).",
                    "masvs":          "MASVS-NETWORK-2",
                    "owasp":          "M5",
                })
            else:
                # Positive finding — pinning is properly configured
                results["findings"].append({
                    "rule_id":        "nsc_pinning_configured",
                    "title":          f"Certificate Pinning Configured — {domains_str}",
                    "severity":       "info",
                    "category":       "Network Security",
                    "description":    f"Certificate pinning is configured for {domains_str} with {len(pin_set['pins'])} pin(s). This significantly raises the bar for MitM attacks.",
                })


# React Native bundle analysis is handled by the first-class `react_native_analyzer`
# sub-analyzer (Phase 2.2), gated on `framework == "react_native"` above — it replaces
# the former inline `_analyze_rn_bundle`. Generic JS dangerous-sink detection + bundle
# inventory remain in `js_bundle_analyzer` (which runs for every app).


# ─── DEX string scanning ──────────────────────────────────────────────────────
def _scan_dex_strings(tmpdir, results):
    dex_files = []
    for root, _, files in os.walk(tmpdir):
        for f in files:
            if f.endswith(".dex"):
                dex_files.append(os.path.join(root, f))

    seen = {f"{s['name']}:{s['value']}" for s in results["secrets"]}

    for dex_path in dex_files:
        try:
            with open(dex_path, "rb") as f:
                raw = f.read()
            # Extract printable strings
            text = printable_text(raw)
            for s in scan_text_for_secrets(text, relativize_path(dex_path, tmpdir)):
                key = f"{s['name']}:{s['value']}"
                if key not in seen:
                    seen.add(key)
                    results["secrets"].append(s)
        except Exception:
            continue


# ─── Endpoint extraction ──────────────────────────────────────────────────────
def _extract_endpoints(tmpdir, results, extra_dirs=None, *, corpus: SourceCorpus = None):
    # Phase 2.5.6: broad, multi-source extraction (Java/Kotlin/Smali/Dart/TS/HTML/
    # config + ws/wss/ftp + custom-scheme deep links), shared with iOS via
    # endpoint_intel. Replaces the previous narrow http(s)-only resource scan.
    from . import endpoint_intel
    results["endpoints"] = endpoint_intel.extract_endpoints(tmpdir, extra_dirs, corpus=corpus or SourceCorpus())


# ─── APK Protection Checks ────────────────────────────────────────────────────
def _check_apk_protections(tmpdir, results):
    # Check for obfuscation (presence of short class names in smali/dex)
    # Heuristic: count very short filenames in extracted dex
    short_names = 0
    total = 0
    for root, _, files in os.walk(tmpdir):
        for f in files:
            if f.endswith(".dex"):
                total += 1

    if total == 0:
        pass  # no dex to analyze


# ─── Helpers ─────────────────────────────────────────────────────────────────
def _meta_finding(msg: str) -> dict:
    return {
        "rule_id":     "analysis_note",
        "title":       "Analysis Note",
        "severity":    "info",
        "category":    "Meta",
        "description": msg,
    }


def _extract_android_app_icon(apk, results):
    candidate_paths = []
    for method_name in ("get_app_icon",):
        getter = getattr(apk, method_name, None)
        if not callable(getter):
            continue
        try:
            icon_path = getter(max_dpi=65535)
        except TypeError:
            try:
                icon_path = getter()
            except Exception:
                icon_path = None
        except Exception:
            icon_path = None
        if icon_path:
            candidate_paths.append(str(icon_path))

    try:
        manifest = apk.get_android_manifest_xml()
        app_elem = manifest.find("application")
        if app_elem is not None:
            icon_ref = app_elem.get(ns("icon")) or app_elem.get("{http://schemas.android.com/apk/res/android}icon")
            if icon_ref:
                candidate_paths.extend(_expand_android_icon_reference(str(icon_ref)))
    except Exception:
        pass

    seen = set()
    for candidate in candidate_paths:
        for variant in _expand_android_icon_reference(candidate):
            if variant in seen:
                continue
            seen.add(variant)
            icon = _read_android_icon_candidate(apk, variant)
            if not icon:
                continue
            results["app_info"]["icon_data"] = icon["data"]
            results["app_info"]["icon_path"] = variant
            results["app_info"]["icon_source"] = "apk"
            return


def _expand_android_icon_reference(icon_ref: str) -> list[str]:
    ref = (icon_ref or "").strip()
    if not ref:
        return []
    if ref.startswith("@"):
        ref = ref[1:]
    if ref.startswith("res/"):
        base = ref.rsplit(".", 1)[0]
        refs = [base]
    elif "/" in ref:
        refs = [f"res/{ref}"]
    else:
        refs = [ref]

    variants = []
    for base in refs:
        base = base.rsplit(".", 1)[0]
        variants.extend([
            f"{base}.png",
            f"{base}.webp",
            f"{base}.jpg",
            f"{base}.jpeg",
            f"{base}.xml",
        ])
        name = os.path.basename(base)
        if name and name != base:
            variants.extend([
                f"res/mipmap-anydpi-v26/{name}.png",
                f"res/mipmap-anydpi-v26/{name}.webp",
                f"res/mipmap-xxxhdpi-v4/{name}.png",
                f"res/mipmap-xxhdpi-v4/{name}.png",
                f"res/mipmap-xhdpi-v4/{name}.png",
                f"res/drawable-xxxhdpi-v4/{name}.png",
                f"res/drawable-xxhdpi-v4/{name}.png",
                f"res/drawable-xhdpi-v4/{name}.png",
            ])
    return variants


def _read_android_icon_candidate(apk, path: str):
    norm_path = (path or "").replace("\\", "/")
    if not norm_path or norm_path.endswith(".xml"):
        return None
    try:
        raw = apk.get_file(norm_path)
    except Exception:
        raw = None
    if not raw or len(raw) > 800_000:
        return None
    mime = mimetypes.guess_type(norm_path)[0] or "image/png"
    encoded = base64.b64encode(raw).decode("ascii")
    return {"data": f"data:{mime};base64,{encoded}"}


def _reshape_native_secrets(hits: list) -> list:
    """Reshape raw evidence-scanner hits into native secret dicts.

    Dedup key is (name, value[:80]) so two different rules matching the same
    string value are NOT collapsed — they surface as distinct findings with
    different names and recommendations.
    """
    findings = []
    seen: set[tuple[str, str]] = set()
    for finding in hits or []:
        name = finding.get("name") or finding.get("title", "")
        val  = finding.get("value", "")
        key  = (name, val[:80])
        if not val or key in seen:
            continue
        seen.add(key)
        findings.append({
            "name":           name,
            "category":       finding["category"],
            "severity":       finding["severity"],
            "value":          val,
            "source":         os.path.basename(finding.get("file_path", "")),
            "full_path":      finding.get("file_path", ""),
            "line":           finding.get("line", 0),
            "snippet":        finding.get("snippet", ""),
            "code_context":   finding.get("code_context", ""),
            "description":    finding["description"],
            "recommendation": finding["recommendation"],
            "confidence":     finding.get("confidence", 70),
            "cwe":            finding.get("cwe", ""),
            "masvs":          finding.get("masvs", ""),
            "owasp":          finding.get("owasp", ""),
        })
    return findings


def _scan_precise_source_secrets(results: dict, source_dirs: list[str], *, corpus: SourceCorpus = None) -> None:
    """Single combined walk (Beetle Native + APKLeaks) over JADX/apktool dirs.

    Phase 1.9: ONE filesystem traversal applies the unified catalog
    (``secret_catalog.combined()``). Native hits become ``results["secrets"]``
    exactly as before (same reshape + dedup); APKLeaks hits are fused into
    secrets / findings / endpoints with source attribution + cross-source merge.
    Eliminates the separate APKLeaks walk that previously re-traversed the tree.
    """
    from .evidence_scanner import scan_directory_for_secrets as ev_secrets
    from . import secret_catalog
    from .detection_sources import routing, fusion

    # Collect the resource-ID constant classes skipped during the secret walk so
    # evidence selection / chains can exclude them as proof locations too.
    res_id_sink: set = set()
    hits = ev_secrets("", source_dirs, patterns=secret_catalog.combined(),
                      corpus=corpus or SourceCorpus(), resource_id_sink=res_id_sink)
    if res_id_sink:
        existing = set(results.get("resource_id_classes") or [])
        results["resource_id_classes"] = sorted(existing | res_id_sink)
    native_hits, apk = routing.extract_apkleaks(hits)
    results["secrets"] = _reshape_native_secrets(native_hits)
    fusion.merge_secret_streams(results, apk.secrets)
    fusion.merge_finding_streams(results, apk.findings, platform="android")
    fusion.merge_endpoint_streams(results, apk.endpoints)


def _persist_extraction(tmpdir: str, scan_id: str):
    """
    Copy source files from the APK ZIP extraction into the persistent scan
    directory so the code viewer can access smali/xml/dex-string files even
    without jadx. Dispatches to the shared `scan_storage.persist_tree` helper
    which uses a much higher file cap and broader extension set than the old
    implementation (old cap: 2000 files / 500 KB and ~16 exts; see bug report).
    """
    scan_storage.persist_tree(
        tmpdir, scan_id, "apk_extract",
        extra_binary_dump=True,   # also dump .dex / .so printable strings
    )


def _persist_decoded_manifest(scan_id: str, results: dict):
    """Persist a decoded, human-readable AndroidManifest.xml for the viewer.

    The manifest extracted straight from the APK (apk_extract/AndroidManifest.xml)
    is compiled AXML — it renders as a "compiled binary" card in the source
    viewer. apktool decodes a readable manifest under apktool/, but it can fail
    or time out. When it does, we fall back to the androguard-reconstructed
    manifest captured during parsing and write it to apktool/AndroidManifest.xml
    (the canonical decoded location the resolver prefers). A real apktool decode
    is higher fidelity, so we never overwrite one.
    """
    manifest_xml = (results.get("manifest_xml") or "").strip()
    if not manifest_xml:
        return
    try:
        dest = scan_storage.scan_root(scan_id) / "apktool" / "AndroidManifest.xml"
        if dest.exists():
            return  # apktool already produced a decoded manifest — keep it.
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(manifest_xml, encoding="utf-8", errors="replace")
    except Exception:
        pass


def _persist_decoded_resource_strings(scan_id: str, apk) -> str | None:
    """Decode resources.arsc string values to a scannable apktool/res/values/strings.xml.

    Why this exists: the AWS Cognito Identity Pool id (and most Android string-resource
    secrets — Firebase/API config, etc.) live only inside the compiled ``resources.arsc``.
    Beetle's secret walk scans the jadx + apktool trees, but jadx is invoked with
    ``--no-res`` and apktool's resource decoder can throw on some APKs (it does on
    InsecureShop) — so no ``strings.xml`` is produced and the value is never matched.
    MobSF finds it because it reads ``resources.arsc`` directly via androguard's
    ``ARSCParser``; we do the same, reusing the already-loaded APK object, and write the
    reconstructed ``<string name=…>…</string>`` table to the canonical decoded location
    the unified walk already scans. This is a FALLBACK only — if a real apktool decode
    already produced strings.xml we never overwrite it, and there is no second matcher:
    the value flows through the one ``secret_catalog.combined()`` walk like any other.

    Returns the apktool root dir (so the caller can ensure it is scanned) or ``None``.
    """
    if apk is None:
        return None
    try:
        dest = scan_storage.scan_root(scan_id) / "apktool" / "res" / "values" / "strings.xml"
        apktool_root = str(scan_storage.scan_root(scan_id) / "apktool")
        if dest.exists():
            return apktool_root  # a real apktool decode already wrote it — keep it.
        arsc = apk.get_android_resources()
        if arsc is None:
            return None
        xml = arsc.get_strings_resources()
        if isinstance(xml, bytes):
            xml = xml.decode("utf-8", "replace")
        if not xml or "<string" not in xml:
            return None
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(xml, encoding="utf-8", errors="replace")
        return apktool_root
    except Exception:
        log.exception(f"[{scan_id}] resources.arsc string reconstruction failed")
        return None


def _extract_strings_for_viewer(data: bytes, min_len: int = 6) -> str:
    """Extract printable strings from binary for code viewer display."""
    result, current = [], []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    header = f"// Extracted strings from binary file\n// {len(result)} strings found\n// jadx/apktool not available — showing raw string extraction\n\n"
    return header + "\n".join(result)


def _sdk_to_version(sdk: int) -> str:
    mapping = {
        16: "4.1", 17: "4.2", 18: "4.3", 19: "4.4",
        21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0",
        25: "7.1", 26: "8.0", 27: "8.1", 28: "9",
        29: "10",  30: "11",  31: "12",  32: "12L",
        33: "13",  34: "14",
    }
    return mapping.get(sdk, str(sdk))
