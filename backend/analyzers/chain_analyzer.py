"""
Cortex Attack Chain Synthesis Engine
=====================================
Reads all findings, attack surface, permissions, secrets, and certificate data
to automatically identify and narrate multi-step attack chains.

Each chain is a connected sequence of exploitable weaknesses leading to a
concrete attacker outcome (RCE, data exfil, auth bypass, privacy leak, etc.)
"""

from __future__ import annotations

# ─── Severity helpers ─────────────────────────────────────────────────────────
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _rank(sev: str) -> int:
    return _SEV_RANK.get(str(sev).lower(), 4)


def _highest(*sevs: str) -> str:
    ranked = sorted(sevs, key=_rank)
    return ranked[0] if ranked else "medium"


def _has_finding(findings: list, *keywords: str) -> dict | None:
    """Return first finding whose title matches any keyword (case-insensitive)."""
    for f in findings:
        title = (f.get("title") or "").lower()
        if any(kw.lower() in title for kw in keywords):
            return f
    return None


def _all_findings(findings: list, *keywords: str) -> list:
    """Return all findings whose title matches any keyword."""
    results = []
    for f in findings:
        title = (f.get("title") or "").lower()
        if any(kw.lower() in title for kw in keywords):
            results.append(f)
    return results


def _has_permission(permissions: list, *perms: str) -> bool:
    all_perms = [str(p.get("permission") or p.get("name") or "").upper() for p in permissions]
    return any(any(perm.upper() in ap for ap in all_perms) for perm in perms)


def _count_exported(surface: dict) -> dict:
    counts = {}
    for key in ("activities", "services", "receivers", "providers"):
        items = surface.get(key) or []
        counts[key] = sum(1 for i in items if i.get("exported"))
    return counts


# ─── Chain detectors ──────────────────────────────────────────────────────────

def _chain_webview_rce(findings, surface, permissions, secrets, cert, manifest_sec):
    """
    WebView RCE Chain:
    Exported deeplink activity → JS-enabled WebView → File access / SSL bypass → RCE / data theft
    """
    steps = []

    exported = _count_exported(surface)
    has_exported_activity = exported.get("activities", 0) > 0
    has_browsable = any(
        a.get("browsable") for a in (surface.get("activities") or [])
    )

    webview_js = _has_finding(findings, "WebView JavaScript Enabled", "setJavaScriptEnabled")
    webview_ssl = _has_finding(findings, "WebView SSL", "onReceivedSslError", "SSL Certificate Errors Ignored")
    webview_js_iface = _has_finding(findings, "addJavascriptInterface", "JavascriptInterface")
    webview_file = _has_finding(findings, "WebView File", "setAllowFileAccess", "File System Access")

    if not (webview_js and (has_exported_activity or has_browsable)):
        return None

    severity_parts = []

    if has_browsable:
        steps.append({
            "title": "Externally Triggerable Entry Point",
            "description": f"App has {sum(1 for a in surface.get('activities',[]) if a.get('browsable'))} browsable activit{'ies' if sum(1 for a in surface.get('activities',[]) if a.get('browsable')) != 1 else 'y'} reachable via URI intent from any app or browser on the device.",
            "severity": "high",
            "type": "entry_point",
        })
        severity_parts.append("high")
    elif has_exported_activity:
        steps.append({
            "title": "Exported Activity — No Permission Required",
            "description": f"{exported['activities']} exported activit{'ies' if exported['activities'] != 1 else 'y'} can be started by any app on the device without declaring a permission.",
            "severity": "high",
            "type": "entry_point",
        })
        severity_parts.append("high")

    steps.append({
        "title": "JavaScript Execution Enabled in WebView",
        "description": "The activity loads content in a WebView with JavaScript enabled. If the loaded URL is attacker-controlled or served over HTTP, arbitrary JS executes in the app's context.",
        "severity": "medium",
        "type": "vulnerability",
    })
    severity_parts.append("medium")

    if webview_ssl:
        steps.append({
            "title": "SSL Errors Silently Ignored",
            "description": "onReceivedSslError calls handler.proceed(), accepting any certificate including self-signed or MitM certs. An attacker on the same network can intercept all WebView HTTPS traffic.",
            "severity": "critical",
            "type": "vulnerability",
        })
        severity_parts.append("critical")

    if webview_file:
        steps.append({
            "title": "File System Access from WebView",
            "description": "WebView can read local app files via file:// URIs. Combined with JS execution this allows exfiltration of SharedPreferences, databases, and stored tokens.",
            "severity": "high",
            "type": "impact",
        })
        severity_parts.append("high")

    if webview_js_iface:
        steps.append({
            "title": "Native Java Bridge Exposed to JavaScript",
            "description": "addJavascriptInterface() exposes Java methods to WebView JavaScript. Any XSS or MitM can call these methods directly, potentially achieving native code execution.",
            "severity": "critical",
            "type": "impact",
        })
        severity_parts.append("critical")

    if len(steps) < 2:
        return None

    chain_sev = _highest(*severity_parts)

    narrative = (
        "An attacker can trigger this app's WebView via "
        + ("a crafted URI deeplink (no installation needed — works from a browser)" if has_browsable else "an intent from any installed app")
        + ". The WebView loads the attacker-supplied URL with JavaScript enabled"
        + (", ignoring SSL certificate errors which enables full MitM interception" if webview_ssl else "")
        + (", and allows file system access letting JavaScript read local app storage" if webview_file else "")
        + (", and exposes native Java methods to JavaScript via addJavascriptInterface" if webview_js_iface else "")
        + ". The end result is JavaScript execution inside the app's security context"
        + (", full MitM of app traffic, and potential exfiltration of all local storage" if webview_ssl and webview_file else "")
        + "."
    )

    return {
        "id": "webview_rce",
        "title": "Deep Link → WebView Exploit Chain",
        "severity": chain_sev,
        "exploitability": 88 if has_browsable else 72,
        "prerequisites": ["Network access (for MitM)" if webview_ssl else "Installed companion app"],
        "impact": "JavaScript execution in app context, potential data exfiltration, MitM of all WebView traffic",
        "owasp": ["M4", "M5"],
        "masvs": ["MASVS-PLATFORM-2", "MASVS-NETWORK-2"],
        "steps": steps,
        "narrative": narrative,
    }


def _chain_debug_backup_exfil(findings, surface, permissions, secrets, cert, manifest_sec):
    """
    Debug / Backup Data Exfiltration Chain:
    Debug build + backup enabled + exported content provider → full data exfiltration
    """
    steps = []
    severity_parts = []

    debuggable = manifest_sec.get("debuggable", {})
    backup = manifest_sec.get("backup", {})
    is_debuggable = debuggable.get("state") in ("true", True) or debuggable.get("status", "").lower() in ("enabled", "vulnerable")
    is_backupable = backup.get("state") in ("true", True) or backup.get("status", "").lower() in ("enabled", "vulnerable", "allowed")

    exported = _count_exported(surface)
    debug_cert = (cert or {}).get("debug_cert", False)
    exported_provider = exported.get("providers", 0) > 0

    if not (is_debuggable or is_backupable or debug_cert):
        return None

    if debug_cert:
        steps.append({
            "title": "Debug Certificate Used for Signing",
            "description": "APK is signed with a debug certificate. This confirms the app has not gone through a proper release process and debug features may be active.",
            "severity": "high",
            "type": "entry_point",
        })
        severity_parts.append("high")

    if is_debuggable:
        steps.append({
            "title": "Application is Debuggable",
            "description": "android:debuggable=true is set. Any app on the device can attach a debugger, inspect memory, extract secrets, and call arbitrary methods via adb.",
            "severity": "critical",
            "type": "vulnerability",
        })
        severity_parts.append("critical")

    if is_backupable:
        steps.append({
            "title": "Full App Data Backup Enabled",
            "description": "android:allowBackup=true with no backup rules. Any computer with adb access can extract the complete app data directory: databases, shared preferences, tokens, and cached credentials.",
            "severity": "high",
            "type": "vulnerability",
        })
        severity_parts.append("high")

    if exported_provider:
        steps.append({
            "title": f"Exported Content Provider{'s' if exported['providers'] > 1 else ''} — No Permission Required",
            "description": f"{exported['providers']} content provider{'s' if exported['providers'] > 1 else ''} can be queried by any app without permission. May expose internal database tables directly.",
            "severity": "high",
            "type": "impact",
        })
        severity_parts.append("high")

    if len(steps) < 2:
        return None

    chain_sev = _highest(*severity_parts)

    narrative = (
        "A physical attacker or malicious app can fully compromise this app's data. "
        + ("With the debug certificate, this is clearly a non-release build. " if debug_cert else "")
        + ("The debuggable flag allows attaching a debugger via adb to read memory, extract keys, and bypass runtime checks. " if is_debuggable else "")
        + ("The backup flag allows 'adb backup com.package.name' to extract the full data directory including databases and stored credentials. " if is_backupable else "")
        + (f"Additionally, {exported['providers']} content provider{'s' if exported['providers'] > 1 else ''} can be queried directly to read internal database rows. " if exported_provider else "")
        + "Combined, these allow complete offline extraction of all app data."
    )

    return {
        "id": "debug_backup_exfil",
        "title": "Debug Config → Full Data Exfiltration Chain",
        "severity": chain_sev,
        "exploitability": 91 if is_debuggable else 78,
        "prerequisites": ["USB/ADB access" if is_debuggable else "Any installed app on same device"],
        "impact": "Complete extraction of all app data: databases, credentials, tokens, cached user data",
        "owasp": ["M9", "M1"],
        "masvs": ["MASVS-STORAGE-1", "MASVS-CODE-4"],
        "steps": steps,
        "narrative": narrative,
    }


def _chain_hardcoded_secret_exfil(findings, surface, permissions, secrets, cert, manifest_sec):
    """
    Hardcoded Secret → Cloud Resource Access Chain
    """
    steps = []
    severity_parts = []

    critical_secrets = [s for s in secrets if s.get("severity") in ("critical", "high")]
    if not critical_secrets:
        return None

    has_aws = any("aws" in (s.get("name") or s.get("title") or "").lower() for s in critical_secrets)
    has_gcp = any("gcp" in (s.get("name") or s.get("title") or "").lower() or "service_account" in (s.get("name") or "").lower() for s in critical_secrets)
    has_stripe = any("stripe" in (s.get("name") or s.get("title") or "").lower() for s in critical_secrets)
    has_github = any("github" in (s.get("name") or s.get("title") or "").lower() for s in critical_secrets)
    has_pem = any("pem" in (s.get("name") or s.get("title") or "").lower() or "private key" in (s.get("name") or s.get("title") or "").lower() for s in critical_secrets)

    no_obfuscation = _has_finding(findings, "Obfuscation Not Detected", "ProGuard")

    steps.append({
        "title": f"{len(critical_secrets)} High/Critical Credential{'s' if len(critical_secrets) != 1 else ''} Embedded in App Bundle",
        "description": f"The APK contains {len(critical_secrets)} hardcoded credential{'s' if len(critical_secrets) != 1 else ''} extractable by anyone who downloads the app from any app store or sideload source.",
        "severity": "critical",
        "type": "entry_point",
    })
    severity_parts.append("critical")

    if no_obfuscation:
        steps.append({
            "title": "No Code Obfuscation — Credentials Trivially Readable",
            "description": "ProGuard/R8 obfuscation is not enabled. All class names and strings are in plaintext, making credential extraction a simple 'strings' command or dex decompilation.",
            "severity": "high",
            "type": "vulnerability",
        })
        severity_parts.append("high")

    if has_aws:
        steps.append({
            "title": "AWS Credentials — Cloud Infrastructure Access",
            "description": "AWS Access Key ID found. Combined with the Secret Key, an attacker can authenticate to AWS and enumerate/access S3 buckets, Lambda functions, RDS databases, and any other resource the key is scoped to.",
            "severity": "critical",
            "type": "impact",
        })
        severity_parts.append("critical")
    if has_gcp:
        steps.append({
            "title": "GCP Service Account Key — Google Cloud Access",
            "description": "GCP service account credentials embedded. Attacker can authenticate as this service account and access all GCP resources within its IAM scope.",
            "severity": "critical",
            "type": "impact",
        })
        severity_parts.append("critical")
    if has_stripe:
        steps.append({
            "title": "Stripe Secret Key — Payment System Access",
            "description": "Stripe live secret key found. Attacker can list customers, create charges, issue refunds, and access all payment data via the Stripe API.",
            "severity": "critical",
            "type": "impact",
        })
        severity_parts.append("critical")
    if has_github:
        steps.append({
            "title": "GitHub Token — Source Code & Repository Access",
            "description": "GitHub Personal Access Token found. Attacker can clone private repositories, access CI/CD secrets, push code, and potentially compromise the entire software supply chain.",
            "severity": "critical",
            "type": "impact",
        })
        severity_parts.append("critical")
    if has_pem:
        steps.append({
            "title": "Embedded Private Key — Cryptographic Identity Compromise",
            "description": "PEM-encoded private key found in app bundle. Any service authenticating with the corresponding certificate or public key is now compromised.",
            "severity": "critical",
            "type": "impact",
        })
        severity_parts.append("critical")

    if len(steps) < 2:
        return None

    chain_sev = _highest(*severity_parts)
    impact_parts = []
    if has_aws: impact_parts.append("AWS cloud infrastructure")
    if has_gcp: impact_parts.append("GCP cloud resources")
    if has_stripe: impact_parts.append("Stripe payment system")
    if has_github: impact_parts.append("GitHub repositories")
    if has_pem: impact_parts.append("cryptographic identity")
    if not impact_parts: impact_parts.append("backend services")

    narrative = (
        f"Any person who downloads this app — from a store, via sideloading, or from an APK sharing site — can extract "
        f"{len(critical_secrets)} hardcoded credential{'s' if len(critical_secrets) != 1 else ''} using nothing more than a free APK decompiler. "
        + ("Without code obfuscation, extraction requires only running 'strings' on the DEX file. " if no_obfuscation else "")
        + f"These credentials grant direct access to: {', '.join(impact_parts)}. "
        + "Rotate all extracted credentials immediately — they must be considered fully compromised."
    )

    return {
        "id": "hardcoded_secret_exfil",
        "title": "Hardcoded Secrets → Cloud/Backend Takeover",
        "severity": chain_sev,
        "exploitability": 96,
        "prerequisites": ["APK download only — no device access needed"],
        "impact": f"Unauthorized access to: {', '.join(impact_parts)}",
        "owasp": ["M1", "M9"],
        "masvs": ["MASVS-CRYPTO-2", "MASVS-STORAGE-2"],
        "steps": steps,
        "narrative": narrative,
    }


def _chain_permission_data_leak(findings, surface, permissions, secrets, cert, manifest_sec):
    """
    Dangerous Permission + Tracker + No Certificate Pinning → Privacy Leak Chain
    """
    steps = []
    severity_parts = []

    all_perms = permissions if isinstance(permissions, list) else (permissions.get("all") or permissions.get("dangerous") or [])

    has_location  = _has_permission(all_perms, "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION")
    has_contacts  = _has_permission(all_perms, "READ_CONTACTS", "WRITE_CONTACTS")
    has_sms       = _has_permission(all_perms, "READ_SMS", "RECEIVE_SMS")
    has_camera    = _has_permission(all_perms, "CAMERA")
    has_mic       = _has_permission(all_perms, "RECORD_AUDIO")
    has_call_log  = _has_permission(all_perms, "READ_CALL_LOG", "WRITE_CALL_LOG")
    has_phone     = _has_permission(all_perms, "READ_PHONE_STATE", "READ_PHONE_NUMBERS")

    no_pinning   = _has_finding(findings, "certificate pinning", "No Certificate Pinning", "cert pin")
    no_pinning   = no_pinning or not _has_finding(findings, "Certificate Pinning Detected")

    tracker_count = 0  # will be filled from results

    sensitive_perms = [
        ("Location", has_location),
        ("Contacts", has_contacts),
        ("SMS", has_sms),
        ("Camera", has_camera),
        ("Microphone", has_mic),
        ("Call Log", has_call_log),
        ("Phone State", has_phone),
    ]
    active_sensitive = [name for name, active in sensitive_perms if active]

    if len(active_sensitive) < 1:
        return None

    steps.append({
        "title": f"Sensitive Permission{'s' if len(active_sensitive) > 1 else ''}: {', '.join(active_sensitive[:3])}{'...' if len(active_sensitive) > 3 else ''}",
        "description": f"App declares {len(active_sensitive)} sensitive permission{'s' if len(active_sensitive) > 1 else ''} granting access to: {', '.join(active_sensitive)}. These represent user PII and behavioral data.",
        "severity": "high",
        "type": "entry_point",
    })
    severity_parts.append("high")

    no_cleartext = not _has_finding(findings, "Cleartext Traffic", "HTTP", "cleartext", "allowCleartextTraffic")
    if not no_cleartext:
        steps.append({
            "title": "Cleartext HTTP Traffic Permitted",
            "description": "App allows unencrypted HTTP communication. Data collected via sensitive permissions can be transmitted in plaintext, readable by any network observer.",
            "severity": "high",
            "type": "vulnerability",
        })
        severity_parts.append("high")

    steps.append({
        "title": "Sensitive Data Collection Without Network Integrity Guarantee",
        "description": "Without certificate pinning, even HTTPS traffic can be intercepted by installing a trusted CA on the test device (standard pentest/proxy setup). All data sent to backend servers is readable.",
        "severity": "medium",
        "type": "impact",
    })
    severity_parts.append("medium")

    if len(active_sensitive) >= 3:
        _sms_part = "SMS/call records, " if has_sms or has_call_log else ""
        steps.append({
            "title": "High-Value PII Aggregation Profile",
            "description": f"Combination of {', '.join(active_sensitive)} permissions creates a rich PII profile: precise location history, contacts, {_sms_part}and device identifiers. If transmitted off-device, constitutes significant privacy exposure.",
            "severity": "high",
            "type": "impact",
        })
        severity_parts.append("high")

    chain_sev = _highest(*severity_parts)

    narrative = (
        f"This app collects sensitive personal data via {len(active_sensitive)} permissions ({', '.join(active_sensitive)}). "
        + ("Network traffic is not protected by certificate pinning, meaning a standard MitM proxy intercepts all transmitted data. " if not no_cleartext else "")
        + ("Cleartext HTTP is explicitly permitted, allowing passive network observers to read transmitted data. " if not no_cleartext else "")
        + "The combination creates a privacy risk where user PII — "
        + ("precise location, " if has_location else "")
        + ("contacts, " if has_contacts else "")
        + ("SMS messages, " if has_sms else "")
        + "and device identifiers — may be transmitted to and accessible by third parties."
    )

    return {
        "id": "permission_data_leak",
        "title": "Sensitive Permissions → PII Exfiltration Chain",
        "severity": chain_sev,
        "exploitability": 74,
        "prerequisites": ["Network position (for MitM)" if not no_cleartext else "Installed proxy certificate"],
        "impact": f"Exfiltration of: {', '.join(active_sensitive)} data",
        "owasp": ["M6", "M5"],
        "masvs": ["MASVS-NETWORK-2", "MASVS-STORAGE-2"],
        "steps": steps,
        "narrative": narrative,
    }


def _chain_intent_injection(findings, surface, permissions, secrets, cert, manifest_sec):
    """
    Exported component + unvalidated intent extras → SQL injection / path traversal
    """
    steps = []
    severity_parts = []

    exported = _count_exported(surface)
    exported_services = exported.get("services", 0)
    exported_receivers = exported.get("receivers", 0)
    exported_providers = exported.get("providers", 0)

    sql_findings = _all_findings(findings, "SQL", "SQLite", "ContentProvider", "query")
    path_traversal = _has_finding(findings, "path traversal", "directory traversal", "file path")
    intent_findings = _has_finding(findings, "intent", "getExtra", "putExtra")
    implicit_intent = _has_finding(findings, "Implicit Intent", "implicit broadcast")

    if not (exported_services or exported_receivers or exported_providers) or not sql_findings:
        return None

    if exported_providers:
        steps.append({
            "title": f"{exported_providers} Exported Content Provider{'s' if exported_providers > 1 else ''}",
            "description": f"{exported_providers} content provider{'s' if exported_providers > 1 else ''} exported without permission restriction. Any app can send queries directly.",
            "severity": "high",
            "type": "entry_point",
        })
        severity_parts.append("high")
    elif exported_services:
        steps.append({
            "title": f"{exported_services} Exported Service{'s' if exported_services > 1 else ''}",
            "description": f"Service component exported without permission. Can receive intents with arbitrary extra data from any app.",
            "severity": "medium",
            "type": "entry_point",
        })
        severity_parts.append("medium")

    steps.append({
        "title": "SQLite Database Access in Component",
        "description": "SQL database operations detected in components reachable from exported entry points. If query parameters are not sanitized, SQL injection is possible via intent extras.",
        "severity": "high",
        "type": "vulnerability",
    })
    severity_parts.append("high")

    if implicit_intent:
        steps.append({
            "title": "Implicit Intents — Interception Risk",
            "description": "App sends implicit intents that any installed app can intercept. Sensitive data in intent extras may be captured by a malicious app registered for the same action.",
            "severity": "medium",
            "type": "vulnerability",
        })
        severity_parts.append("medium")

    steps.append({
        "title": "SQL Injection / Data Manipulation Impact",
        "description": "Successful SQL injection via ContentProvider allows: reading all database tables, modifying application data, potentially accessing other apps' data if shared storage is used.",
        "severity": "critical",
        "type": "impact",
    })
    severity_parts.append("critical")

    chain_sev = _highest(*severity_parts)

    narrative = (
        f"Exported {'content providers' if exported_providers else 'services/receivers'} accept "
        "untrusted input from any installed app. SQL operations performed with unsanitized intent "
        "extras enable SQL injection attacks, allowing an attacker app to read or modify all "
        "data stored in the application's SQLite database without any permissions."
    )

    return {
        "id": "intent_injection",
        "title": "Intent Injection → SQL Injection Chain",
        "severity": chain_sev,
        "exploitability": 79,
        "prerequisites": ["Malicious app installed on same device"],
        "impact": "Read/write access to all application database tables",
        "owasp": ["M4", "M9"],
        "masvs": ["MASVS-PLATFORM-1", "MASVS-STORAGE-1"],
        "steps": steps,
        "narrative": narrative,
    }


def _chain_crypto_failure(findings, surface, permissions, secrets, cert, manifest_sec):
    """
    Weak crypto + hardcoded key + sensitive storage → data decryption chain
    """
    steps = []
    severity_parts = []

    weak_cipher  = _has_finding(findings, "ECB", "DES", "3DES", "Weak Cipher")
    weak_hash    = _has_finding(findings, "MD5", "SHA-1", "Weak Hash")
    hardcoded_key = _has_finding(findings, "hardcoded key", "static key", "Hardcoded IV")
    insecure_storage = _has_finding(findings, "Insecure Storage", "SharedPreferences", "External Storage", "World-readable")

    if not (weak_cipher and (hardcoded_key or insecure_storage)):
        return None

    steps.append({
        "title": "Broken Encryption Algorithm in Use",
        "description": f"{'ECB mode encryption' if weak_cipher and 'ecb' in (weak_cipher.get('title') or '').lower() else 'Weak cipher'} detected. ECB mode is deterministic — identical plaintexts produce identical ciphertexts, leaking data patterns. DES/3DES are brute-forceable.",
        "severity": "high",
        "type": "vulnerability",
    })
    severity_parts.append("high")

    if weak_hash:
        steps.append({
            "title": "Broken Hash Algorithm",
            "description": "MD5 or SHA-1 used for integrity or password hashing. MD5 collisions are trivially generated. Neither provides meaningful security for password storage.",
            "severity": "high",
            "type": "vulnerability",
        })
        severity_parts.append("high")

    if hardcoded_key:
        steps.append({
            "title": "Hardcoded Encryption Key",
            "description": "Encryption key is hardcoded in the application binary. Any person who downloads the APK has the key, making the encryption meaningless for data confidentiality.",
            "severity": "critical",
            "type": "vulnerability",
        })
        severity_parts.append("critical")

    if insecure_storage:
        steps.append({
            "title": "Encrypted Data Stored Insecurely",
            "description": "Application stores encrypted data in locations accessible to other apps or backed up via adb. Combined with the hardcoded key, stored data is fully decryptable.",
            "severity": "high",
            "type": "impact",
        })
        severity_parts.append("high")

    chain_sev = _highest(*severity_parts)

    narrative = (
        "The application applies encryption using a broken cipher"
        + (" in ECB mode" if weak_cipher and "ecb" in (weak_cipher.get("title") or "").lower() else "")
        + (" with a hardcoded key embedded in the APK" if hardcoded_key else "")
        + ". Since the key is extractable from the binary, any encrypted data — "
        + "whether stored locally or transmitted — can be decrypted by anyone who downloads the app. "
        + "The encryption provides zero confidentiality guarantee."
    )

    return {
        "id": "crypto_failure",
        "title": "Broken Crypto + Hardcoded Key → Data Decryption",
        "severity": chain_sev,
        "exploitability": 82,
        "prerequisites": ["APK download — no device access needed"],
        "impact": "Decryption of all application-encrypted data",
        "owasp": ["M10", "M9"],
        "masvs": ["MASVS-CRYPTO-1", "MASVS-CRYPTO-2"],
        "steps": steps,
        "narrative": narrative,
    }


def _chain_firebase_exposure(findings, surface, permissions, secrets, cert, manifest_sec):
    """Firebase URL + confirmed unauthenticated access → data breach"""
    steps = []
    severity_parts = []

    firebase_confirmed = _has_finding(findings, "Firebase Database — Unauthenticated Read Access CONFIRMED")
    firebase_accessible = _has_finding(findings, "Firebase Database — Accessible")
    firebase_url = _has_finding(findings, "Firebase Realtime Database URL", "firebaseio.com")

    if not (firebase_confirmed or firebase_accessible):
        return None

    steps.append({
        "title": "Firebase Database URL Discovered in APK",
        "description": "Firebase Realtime Database URL extracted from the app bundle. This URL is the direct endpoint for the backend database.",
        "severity": "medium",
        "type": "entry_point",
    })
    severity_parts.append("medium")

    if firebase_confirmed:
        steps.append({
            "title": "CONFIRMED: Unauthenticated Read Access",
            "description": "LIVE PROBE CONFIRMED: The Firebase database returned data (HTTP 200) without any authentication token. All database contents are publicly readable.",
            "severity": "critical",
            "type": "vulnerability",
        })
        severity_parts.append("critical")

        steps.append({
            "title": "Full Database Contents Exposed",
            "description": "Any person on the internet can read all data in this Firebase database by appending /.json to the URL. No credentials, no device, no app installation required.",
            "severity": "critical",
            "type": "impact",
        })
        severity_parts.append("critical")
    else:
        steps.append({
            "title": "Firebase Database Accessible (Empty)",
            "description": "Firebase database returned HTTP 200 but empty data. Security rules may be misconfigured — database is empty or rules allow read but no data exists yet.",
            "severity": "high",
            "type": "vulnerability",
        })
        severity_parts.append("high")

    chain_sev = _highest(*severity_parts)

    narrative = (
        "The Firebase Realtime Database URL was extracted from the APK bundle. "
        + ("A live probe confirmed the database returns data without authentication — any internet user can read all stored data by simply appending /.json to the URL. " if firebase_confirmed else "The database endpoint is accessible without authentication. ")
        + "This requires no app installation, no account, and no special tools — just a browser or curl command."
    )

    return {
        "id": "firebase_exposure",
        "title": "Firebase URL → Unauthenticated Database Read",
        "severity": chain_sev,
        "exploitability": 99 if firebase_confirmed else 80,
        "prerequisites": ["Internet access only"],
        "impact": "Read access to all Firebase database contents from anywhere on the internet",
        "owasp": ["M8", "M9"],
        "masvs": ["MASVS-NETWORK-1", "MASVS-STORAGE-2"],
        "steps": steps,
        "narrative": narrative,
    }


# ─── Pentest Playbook Builder ─────────────────────────────────────────────────

def _build_pentest_playbook(results: dict, chains: list) -> list:
    """Generate concrete, evidence-based pentest steps from scan results."""
    steps = []
    findings = results.get("findings", [])
    surface  = results.get("attack_surface", {})
    secrets  = results.get("secrets", [])
    permissions = results.get("permissions", {})
    all_perms = permissions if isinstance(permissions, list) else (permissions.get("all") or permissions.get("dangerous") or [])
    cert     = results.get("certificate", {})
    manifest_sec = results.get("manifest_security", {})
    trackers = results.get("trackers", [])
    domain_intel = results.get("domain_intel", [])
    jwts     = results.get("jwts", [])
    ips      = results.get("ips", [])

    exported = _count_exported(surface)

    # ── Dynamic analysis setup ───────────────────────────────────────────────
    steps.append(
        "Set up MitM proxy (Burp Suite / mitmproxy): install CA cert on test device, "
        "configure app's network traffic through proxy, and run all app flows to capture API calls."
    )

    # ── Exported components ──────────────────────────────────────────────────
    total_exported = sum(exported.values())
    if total_exported > 0:
        browsable = [a for a in (surface.get("activities") or []) if a.get("browsable")]
        if browsable:
            schemes = set()
            for a in browsable:
                for s in (a.get("schemes") or []):
                    schemes.add(s)
            steps.append(
                f"Test {len(browsable)} browsable activit{'ies' if len(browsable) > 1 else 'y'}: "
                f"send malformed URI intents using adb shell am start with schemes {', '.join(list(schemes)[:4])} "
                "— test for path traversal, XSS in WebView, and intent extra injection."
            )
        if exported.get("activities", 0):
            steps.append(
                f"Enumerate {exported['activities']} exported activit{'ies' if exported['activities'] > 1 else 'y'} with "
                "'adb shell dumpsys package <pkg> | grep -A2 Activity'. "
                "Send crafted intents: adb shell am start -n <pkg>/<activity> --es key value"
            )
        if exported.get("providers", 0):
            steps.append(
                f"Query {exported['providers']} exported content provider{'s' if exported['providers'] > 1 else ''}: "
                "adb shell content query --uri content://<authority>/ — test for SQL injection via --where clause and path traversal."
            )

    # ── Secrets and credentials ──────────────────────────────────────────────
    if secrets:
        critical_secrets = [s for s in secrets if s.get("severity") in ("critical", "high")]
        if critical_secrets:
            steps.append(
                f"Validate {len(critical_secrets)} high/critical credential{'s' if len(critical_secrets) > 1 else ''}: "
                "test each against its respective API (AWS: aws sts get-caller-identity, "
                "GitHub: curl -H 'Authorization: token <tok>' api.github.com/user, "
                "Stripe: curl https://api.stripe.com/v1/tokens -u <key>:). Rotate any that are live."
            )

    # ── JWTs ─────────────────────────────────────────────────────────────────
    if jwts:
        steps.append(
            f"Analyze {len(jwts)} extracted JWT{'s' if len(jwts) > 1 else ''}: decode at jwt.io to check algorithm (reject 'none' and RS256→HS256 confusion), "
            "expiry, and claims. Test if tokens are accepted across environments."
        )

    # ── WebView ──────────────────────────────────────────────────────────────
    webview_js = _has_finding(findings, "WebView JavaScript Enabled", "setJavaScriptEnabled")
    webview_ssl = _has_finding(findings, "WebView SSL", "SSL Certificate Errors Ignored")
    if webview_js:
        steps.append(
            "Test WebView for XSS: identify activities that load URLs, send crafted intent with "
            "javascript:alert(document.cookie) as URL parameter. If addJavascriptInterface is present, "
            "call exposed Java methods via JS to test for native code execution."
        )
    if webview_ssl:
        steps.append(
            "Confirm MitM via WebView: with proxy CA installed, intercept WebView HTTPS traffic — "
            "the app ignores SSL errors so any certificate is accepted. Modify responses in-flight to test injection."
        )

    # ── Certificate ──────────────────────────────────────────────────────────
    if cert.get("debug_cert"):
        steps.append(
            "Debug certificate confirmed: run 'adb shell run-as <package>' to access app's private data directory. "
            "Use 'adb backup' to extract full data: adb backup -noapk -f backup.ab <package> && dd if=backup.ab bs=1 skip=24 | python3 -c 'import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' | tar xv"
        )

    # ── Debuggable ───────────────────────────────────────────────────────────
    debuggable = manifest_sec.get("debuggable", {})
    if debuggable.get("state") in ("true", True):
        steps.append(
            "App is debuggable: attach debugger with 'adb jdwp' to get PID, then use jdb or Android Studio debugger. "
            "Set breakpoints on crypto operations, login handlers, and token storage to extract runtime values."
        )

    # ── Network and IPs ──────────────────────────────────────────────────────
    public_ips = [ip for ip in ips if ip.get("type") == "public"]
    if public_ips:
        steps.append(
            f"Probe {len(public_ips)} hardcoded public IP{'s' if len(public_ips) > 1 else ''}: "
            "nmap -sV -p 80,443,8080,8443,22,3306,5432 <ip> to identify running services. "
            "Test for admin panels, default credentials, and unpatched services."
        )

    # ── Domains ──────────────────────────────────────────────────────────────
    flagged_domains = [d for d in domain_intel if d.get("flagged") or d.get("risk") in ("high", "medium")]
    if flagged_domains:
        steps.append(
            f"Investigate {len(flagged_domains)} flagged domain{'s' if len(flagged_domains) > 1 else ''}: "
            "check for subdomain takeover (dig CNAME, test if target service is unclaimed), "
            "certificate mismatches, and DNS hijack risk."
        )

    # ── Trackers ─────────────────────────────────────────────────────────────
    if len(trackers) > 3:
        steps.append(
            f"Document {len(trackers)} embedded trackers for privacy assessment: "
            "capture traffic to each tracker domain in proxy, verify what data is sent (IDFA/GAID, location, behavior). "
            "Cross-reference against app's stated privacy policy for GDPR/CCPA gaps."
        )

    # ── Obfuscation ──────────────────────────────────────────────────────────
    no_obfuscation = _has_finding(findings, "Obfuscation Not Detected")
    if no_obfuscation:
        steps.append(
            "No obfuscation detected: decompile with jadx-gui (free) for full readable Java source. "
            "Search for: password|secret|key|token|auth|api in source to find additional hardcoded values not caught by automated scanning."
        )

    # ── Binary protections ───────────────────────────────────────────────────
    missing_pie = _has_finding(findings, "PIE", "Position Independent", "binary", "NX bit")
    if missing_pie:
        steps.append(
            "Native libraries lack binary hardening: test for memory corruption using fuzzing tools. "
            "Missing PIE/NX makes exploitation of buffer overflows significantly easier."
        )

    return steps[:10]  # cap at 10 actionable steps


# ─── First-class attack-chain findings (Phase 6 Task 2) ──────────────────────
# Map each chain id to the finding titles that contribute to it, so we can mark
# member findings (in_attack_chain) and aggregate their evidence into the
# synthesized chain finding. Keyword match is case-insensitive substring.
CHAIN_MEMBER_KEYWORDS = {
    "webview_rce": [
        "WebView JavaScript", "setJavaScriptEnabled", "addJavascriptInterface",
        "WebView SSL", "SSL Certificate Errors Ignored", "WebView File",
        "setAllowFileAccess", "File System Access",
    ],
    "debug_backup_exfil": [
        "Debuggable", "Backup Enabled", "Debug Certificate", "Content Provider",
    ],
    "permission_data_leak": [
        "Cleartext", "Certificate Pinning", "HTTP Traffic",
    ],
    "intent_injection": [
        "SQL", "SQLite", "ContentProvider", "Implicit Intent", "Exported",
    ],
    "crypto_failure": [
        "ECB", "DES", "Weak Cipher", "MD5", "SHA-1", "Weak Hash",
        "hardcoded key", "static key", "Hardcoded IV", "Insecure Storage",
        "SharedPreferences",
    ],
    "firebase_exposure": [
        "Firebase",
    ],
    "hardcoded_secret_exfil": [
        "Credential", "Secret", "API Key", "Private Key", "Token",
    ],
}


def _member_evidence(member: dict) -> list:
    """Pull whatever locatable evidence a member finding carries."""
    ev = []
    fe = member.get("file_evidence")
    if isinstance(fe, list):
        for e in fe:
            if isinstance(e, dict) and e.get("path"):
                ev.append({
                    "path": e.get("path"),
                    "lines": e.get("lines") or ([member["line"]] if member.get("line") else []),
                    "snippet": e.get("snippet") or member.get("snippet") or member.get("title", ""),
                })
    if not ev:
        path = member.get("file_path") or member.get("file")
        if path:
            ev.append({
                "path": path,
                "lines": [member["line"]] if member.get("line") else [],
                "snippet": member.get("snippet") or member.get("title", ""),
            })
    return ev


def build_attack_chain_findings(findings: list, chains: list) -> list:
    """Convert synthesized chains into first-class findings (Phase 6 Task 2).

    For each chain: locate the contributing findings, mark them
    `in_attack_chain=True`, aggregate their evidence, and emit one finding with
    is_attack_chain / attack_chain_id / attack_chain_members set. Returns the new
    finding dicts (caller prepends them so they sort ahead of normal findings).
    """
    chain_findings = []
    for chain in chains or []:
        cid = chain.get("id", "chain")
        keywords = CHAIN_MEMBER_KEYWORDS.get(cid, [])
        members = _all_findings(findings, *keywords) if keywords else []

        member_refs = []
        aggregated_evidence = []
        seen_paths = set()
        for m in members:
            m["in_attack_chain"] = True
            m.setdefault("attack_chain_id", cid)
            member_refs.append({
                "id": m.get("canonical_id") or m.get("rule_id") or m.get("id") or "",
                "title": m.get("title", ""),
                "severity": m.get("severity", ""),
                "file_path": m.get("file_path") or m.get("file") or "",
            })
            for e in _member_evidence(m):
                key = (e.get("path"), tuple(e.get("lines") or []))
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                aggregated_evidence.append(e)

        # Evidence text summarizes the steps + the contributing findings so the
        # chain is actionable even when individual members have no source line.
        step_lines = [f"{i}. [{s.get('severity','').upper()}] {s.get('title','')}"
                      for i, s in enumerate(chain.get("steps", []), 1)]
        member_lines = [f"  • {r['title']} ({r['severity']})" for r in member_refs]
        evidence_text = "\n".join(
            ["Chain steps:"] + step_lines
            + (["", "Contributing findings:"] + member_lines if member_lines else [])
        )

        # Phase 7.5 Task 4 — chain confidence from how many contributing findings
        # carry locatable evidence. A chain synthesized purely from manifest /
        # permission signals (no evidenced finding members) is heuristic (LOW).
        evidenced = sum(1 for m in members if _member_evidence(m))
        total_members = len(members)
        if total_members == 0:
            chain_confidence = "LOW"
        else:
            ratio = evidenced / total_members
            chain_confidence = "HIGH" if ratio >= 0.7 else ("MEDIUM" if ratio >= 0.34 else "LOW")
        # Mirror onto the source chain dict so the dashboard / attack paths
        # (which read quick_summary.attack_chain) can show it too.
        chain["chain_confidence"] = chain_confidence

        cf = {
            "title": f"Attack Chain: {chain.get('title', 'Correlated Exploit Chain')}",
            "severity": chain.get("severity", "high"),
            "category": "Attack Chain",
            "is_attack_chain": True,
            "chain_confidence": chain_confidence,
            "attack_chain_id": cid,
            "attack_chain_members": member_refs,
            "confidence": 90,
            "confidence_score": 90,
            "description": chain.get("narrative", ""),
            "impact": chain.get("impact", ""),
            "recommendation": (
                "Break the chain by remediating any one link — the highest-severity "
                "step is the priority. Address the contributing findings listed in the evidence."
            ),
            "steps": chain.get("steps", []),
            "exploitability": chain.get("exploitability", 0),
            "owasp": chain.get("owasp", []),
            "masvs": chain.get("masvs", []),
            "evidence": evidence_text,
            "file_evidence": aggregated_evidence,
            "files": [e["path"] for e in aggregated_evidence],
            "evidence_count": max(len(aggregated_evidence), 1),
            # App-level synthesized issue — owned by the application, always shown.
            "ownership_label": "APPLICATION",
        }
        chain_findings.append(cf)
    return chain_findings


def correlate_attack_chains(results: dict) -> dict:
    """Synthesize chains AND emit first-class chain findings (Phase 6 Task 2).

    Returns the same dict as synthesize_attack_chains plus
    `attack_chain_findings`. Member findings in results["findings"] are mutated
    in place (in_attack_chain=True). Idempotent enough for one finalize pass.
    """
    chain_data = synthesize_attack_chains(results)
    chain_findings = build_attack_chain_findings(
        results.get("findings", []), chain_data.get("attack_chains", []),
    )
    chain_data["attack_chain_findings"] = chain_findings
    return chain_data


# ─── Main entry point ─────────────────────────────────────────────────────────

def synthesize_attack_chains(results: dict) -> dict:
    """
    Main function — called from android_analyzer after all modules complete.
    Returns a dict with attack_chains list and pentest_playbook list.
    """
    findings     = results.get("findings", [])
    surface      = results.get("attack_surface", {})
    permissions  = results.get("permissions", {})
    secrets      = results.get("secrets", [])
    cert         = results.get("certificate", {})
    manifest_sec = results.get("manifest_security", {})

    all_perms = permissions if isinstance(permissions, list) else (
        permissions.get("classified", []) or permissions.get("all", []) or []
    )

    detectors = [
        _chain_webview_rce,
        _chain_debug_backup_exfil,
        # _chain_hardcoded_secret_exfil intentionally disabled — Google API keys
        # (the common case that triggered this) are client-side keys and do not
        # warrant "Cloud/Backend Takeover" framing. Re-enable only when we have
        # a higher-fidelity signal than "any high-severity secret detection."
        _chain_permission_data_leak,
        _chain_intent_injection,
        _chain_crypto_failure,
        _chain_firebase_exposure,
    ]

    chains = []
    for detector in detectors:
        try:
            chain = detector(findings, surface, all_perms, secrets, cert, manifest_sec)
            if chain:
                chains.append(chain)
        except Exception:
            pass  # never let a chain detector crash the scan

    # Sort chains: highest severity + highest exploitability first
    chains.sort(key=lambda c: (_rank(c.get("severity", "info")), -(c.get("exploitability", 0))))

    playbook = _build_pentest_playbook(results, chains)

    return {
        "attack_chains": chains,
        "pentest_playbook": playbook,
        "chain_count": len(chains),
        "highest_chain_severity": chains[0].get("severity", "info") if chains else "info",
    }
