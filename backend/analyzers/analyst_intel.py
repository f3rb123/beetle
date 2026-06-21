"""
Analyst & Remediation Intelligence — Phase 10.

Turns findings into explainable analyst intelligence: WHY a finding matters, how
it could be attacked, what to check before believing it, and how to fix it. This
is NOT a chatbot and NOT autonomous scanning — it is a pure, deterministic,
rule-driven layer. No external LLM, no network (Task 8).

Attaches `analyst_explanation` (the AnalystExplanation model) to every finding
and every cloud attack path, and builds results["analyst_summary"] (Task 7).
"""
from __future__ import annotations

import logging

log = logging.getLogger("cortex.analyst_intel")

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─── Category templates (Task 2) ─────────────────────────────────────────────
# Each template provides the static analyst narrative for a category. Per-finding
# fields (title, evidence, standards) are merged on top at build time.
_TEMPLATES: dict[str, dict] = {
    "WEBVIEW": {
        "why_it_matters": "WebViews bridge untrusted web content into the app's trusted context. With JavaScript, a JavaScript interface, or file access enabled, attacker-influenced content can run code or read local files inside the app sandbox.",
        "attack_scenario": "An attacker who can influence a loaded URL (deep link, MITM on cleartext traffic, or a compromised ad/CDN) injects JavaScript that calls an exposed `@JavascriptInterface` method or loads `file://` URLs to exfiltrate app-private data.",
        "prerequisites": ["Attacker can control or inject content into a loaded URL", "JavaScript and/or file access enabled on the WebView"],
        "impact": "Local file theft, session/token exfiltration, or code execution within the app sandbox.",
        "remediation_summary": "Disable JavaScript and file access unless required; remove or restrict `addJavascriptInterface`; allowlist and validate every loaded URL; load only HTTPS content.",
        "references": ["OWASP MASTG MASVS-PLATFORM-7", "CWE-749"],
        "false_positive_notes": "A WebView that only loads bundled, static, trusted content is low risk. Findings on third-party SDK WebViews (ads/analytics) are informational unless app code feeds them untrusted input.",
        "masvs": "MASVS-PLATFORM-2", "owasp": "M4",
    },
    "CRYPTO": {
        "why_it_matters": "Weak or misused cryptography (MD5/SHA-1, ECB mode, hardcoded keys/IVs, insecure random) provides a false sense of protection — the data is effectively unprotected against a capable attacker.",
        "attack_scenario": "An attacker who obtains ciphertext or hashes (from storage, traffic, or a backup) brute-forces or replays them because the algorithm is broken or the key is predictable/embedded.",
        "prerequisites": ["Attacker obtains protected data (storage, backup, or network capture)", "The weak primitive or static key is in use on that data"],
        "impact": "Disclosure of credentials, PII, or tokens that were assumed encrypted; integrity bypass.",
        "remediation_summary": "Use AES-GCM (or platform Keystore-backed crypto), SHA-256+, and a CSPRNG; never hardcode keys/IVs — derive or store them in the Android Keystore / iOS Keychain.",
        "references": ["OWASP MASVS-CRYPTO-1", "CWE-327"],
        "false_positive_notes": "MD5/SHA-1 used for non-security purposes (cache keys, ETags, checksums) is not a vulnerability. Confirm the hash/cipher guards security-relevant data before escalating.",
        "masvs": "MASVS-CRYPTO-1", "owasp": "M10",
    },
    "NETWORK": {
        "why_it_matters": "Cleartext traffic or disabled/weak TLS validation lets a network attacker read and modify data in transit, defeating transport security entirely.",
        "attack_scenario": "An attacker on the same network (public Wi-Fi, rogue AP, or a malicious proxy) intercepts cleartext HTTP or presents a forged certificate the app accepts, then reads or rewrites requests and responses.",
        "prerequisites": ["Attacker has a network position (MITM)", "App sends cleartext traffic or does not validate TLS"],
        "impact": "Credential/token theft, response tampering, and injection of malicious content or updates.",
        "remediation_summary": "Enforce HTTPS everywhere, set a strict Network Security Config (no cleartext, no user CAs), and remove custom TrustManagers/hostname verifiers that bypass validation; consider certificate pinning.",
        "references": ["OWASP MASVS-NETWORK-1", "CWE-319"],
        "false_positive_notes": "Cleartext to `localhost`/loopback or to documented sandbox/test hosts is not exploitable in production. Schema/namespace URLs are not network endpoints.",
        "masvs": "MASVS-NETWORK-1", "owasp": "M5",
    },
    "SECRETS": {
        "why_it_matters": "A hardcoded credential ships to every user and can be extracted by unpacking the app. If it is live, an attacker uses it directly against your backend or a third-party service at your cost and liability.",
        "attack_scenario": "An attacker unzips the APK/IPA, recovers the key, and authenticates to the issuer's API — sending mail, reading databases, or spending your cloud/billing quota — without ever touching a user's device.",
        "prerequisites": ["The secret is application-owned and live (not a public/test key)", "The corresponding service is reachable from the internet"],
        "impact": "Account/service takeover, data access, financial loss, or abuse attributed to your organization.",
        "remediation_summary": "Revoke and rotate the credential immediately, move it server-side, and scope/restrict any key that must reach the client. Never embed secret keys in mobile builds.",
        "references": ["OWASP MASVS-CRYPTO-2", "CWE-798"],
        "false_positive_notes": "Publishable/anon keys (Stripe `pk_`, Mapbox, analytics client tokens) are designed to be public — informational. SDK-owned keys are suppressed by default; escalate only application-owned secrets.",
        "masvs": "MASVS-CRYPTO-2", "owasp": "M1",
    },
    "FIREBASE": {
        "why_it_matters": "A Firebase database with permissive security rules is readable (and sometimes writable) by anyone with the URL — no app, no auth, no exploit required.",
        "attack_scenario": "An attacker extracts the Firebase URL from the app and requests `<db>/.json`; if rules are open, the entire database is dumped or, when write is open, poisoned.",
        "prerequisites": ["Firebase URL is recoverable from the app", "Security rules allow public read and/or write"],
        "impact": "Mass disclosure of user data, or data/integrity compromise when public write is allowed.",
        "remediation_summary": "Set Firebase security rules to require authentication (`auth != null`) and scope per-user access; never rely on URL secrecy as a control.",
        "references": ["OWASP MASVS-STORAGE-2", "CWE-200"],
        "false_positive_notes": "A Firebase URL alone is not an exposure — confirm public read/write before escalating. A database that returns 401 has correct rules and is informational.",
        "masvs": "MASVS-NETWORK-1", "owasp": "M8",
    },
    "S3": {
        "why_it_matters": "A public S3 bucket lists and serves its objects to anyone, turning storage misconfiguration into direct data exposure.",
        "attack_scenario": "An attacker takes the bucket URL from the app, requests the bucket listing, and downloads exposed objects (backups, uploads, configs).",
        "prerequisites": ["Bucket name/URL is recoverable from the app", "Bucket policy/ACL allows public listing or object read"],
        "impact": "Disclosure of stored files — user uploads, backups, or internal data.",
        "remediation_summary": "Block public access at the bucket and account level, remove public-read ACLs/policies, and serve user content via signed URLs.",
        "references": ["OWASP MASVS-STORAGE-2", "CWE-200"],
        "false_positive_notes": "A bucket that returns AccessDenied exists but is private — informational. Detecting that listing is enabled does not require (and here does not perform) object enumeration.",
        "masvs": "MASVS-STORAGE-2", "owasp": "M8",
    },
    "CERTIFICATE": {
        "why_it_matters": "Signing-scheme and certificate weaknesses (v1-only signing/Janus, debug certificates, small RSA keys) can let an attacker tamper with or repackage the app.",
        "attack_scenario": "On a device that accepts v1-signed APKs, an attacker exploits the Janus vulnerability to inject a malicious DEX while keeping the original signature, distributing a trojanized build.",
        "prerequisites": ["App relies on a weak signing scheme or debug/weak certificate", "Attacker can deliver the repackaged app to a vulnerable device"],
        "impact": "App tampering, code injection, or impersonation of the publisher.",
        "remediation_summary": "Sign with APK Signature Scheme v2+/v3, use a production certificate with a 2048-bit+ RSA (or EC) key, and never ship debug-signed builds.",
        "references": ["OWASP MASVS-RESILIENCE-1", "CWE-295"],
        "false_positive_notes": "Certificate metadata findings describe configuration, not a proven exploit — they may not be actionable on modern (v2+/v3 only) devices. Treat as context unless a concrete weakness is confirmed.",
        "masvs": "MASVS-RESILIENCE-1", "owasp": "M7",
    },
    "ROOT_DETECTION": {
        "why_it_matters": "Root/jailbreak detection is a defensive control, not a vulnerability. It raises the bar for casual tampering but is bypassable on a determined attacker's own device.",
        "attack_scenario": "There is no attacker scenario for the control itself; the relevant risk is over-reliance — an attacker with a rooted device hooks or patches the check and proceeds.",
        "prerequisites": ["N/A — this is a security control, not a weakness"],
        "impact": "None directly; weak if used as the sole anti-tampering measure.",
        "remediation_summary": "Keep the check, but combine it with server-side Play Integrity / DeviceCheck attestation; never treat on-device root detection as a hard security boundary.",
        "references": ["OWASP MASVS-RESILIENCE-1"],
        "false_positive_notes": "This is expected, desirable behavior — reported as INFO. Do not treat root detection as a finding to 'fix'.",
        "masvs": "MASVS-RESILIENCE-1", "owasp": "M7",
    },
    "DEEP_LINKS": {
        "why_it_matters": "Deep links and app links are externally reachable entry points. Unverified or overly broad links let other apps or web pages drive the app into sensitive flows with attacker-chosen data.",
        "attack_scenario": "A malicious web page or app fires a crafted deep link that lands in an authenticated screen or passes a tainted URL into a WebView/redirect, bypassing intended navigation.",
        "prerequisites": ["An exported, browsable deep-link entry point", "The handler trusts link parameters without validation or auth checks"],
        "impact": "Authentication/authorization bypass, open redirect, or tainted input reaching a sensitive sink.",
        "remediation_summary": "Verify App Links (autoVerify + assetlinks.json), authenticate before acting on deep-link state, and validate/allowlist all link parameters.",
        "references": ["OWASP MASVS-PLATFORM-3", "CWE-939"],
        "false_positive_notes": "A deep link to a benign, unauthenticated landing screen is low risk. The finding matters when the handler performs sensitive actions or forwards untrusted input.",
        "masvs": "MASVS-PLATFORM-3", "owasp": "M4",
    },
    "INTENT_INJECTION": {
        "why_it_matters": "Exported components and unsafe Intent handling let other apps invoke functionality or supply data the developer assumed was internal.",
        "attack_scenario": "A malicious app sends an Intent to an exported component (or a redirected/implicit Intent) to trigger privileged actions, read returned data, or forward the Intent to an internal component.",
        "prerequisites": ["A component is exported (or an Intent is redirected) without permission/validation", "A malicious app is installed on the device"],
        "impact": "Privilege escalation, data leakage between apps, or invocation of unintended internal flows.",
        "remediation_summary": "Set `exported=false` unless required, enforce signature-level permissions, and validate the Intent action/component/extras before acting or re-dispatching.",
        "references": ["OWASP MASVS-PLATFORM-1", "CWE-926"],
        "false_positive_notes": "Components exported intentionally for launchers or documented integrations with their own permission checks are not vulnerabilities. Confirm there is no guarding permission before escalating.",
        "masvs": "MASVS-PLATFORM-1", "owasp": "M4",
    },
    "SQL_INJECTION": {
        "why_it_matters": "Concatenating untrusted input into SQL lets an attacker alter the query — reading or corrupting local database contents.",
        "attack_scenario": "Attacker-controlled input (a deep link, IPC extra, or synced field) flows into a raw SQL string, letting the attacker change the WHERE clause to read other rows or drop data.",
        "prerequisites": ["Untrusted input reaches a raw SQL statement", "The query runs against a database holding sensitive data"],
        "impact": "Disclosure or corruption of local database data; auth/logic bypass via query manipulation.",
        "remediation_summary": "Use parameterized queries / bound arguments (`?` placeholders, query builders); never concatenate untrusted input into SQL.",
        "references": ["OWASP MASVS-CODE-4", "CWE-89"],
        "false_positive_notes": "Queries built entirely from constant strings (no external input) are not injectable. Confirm a real taint path from an untrusted source before escalating.",
        "masvs": "MASVS-CODE-4", "owasp": "M7",
    },
    "FILE_STORAGE": {
        "why_it_matters": "Sensitive data written to world-readable or external storage can be read by other apps or recovered from backups, bypassing the app sandbox.",
        "attack_scenario": "Another app (or an attacker with backup/USB access) reads files the app wrote to external/shared storage or to MODE_WORLD_READABLE locations.",
        "prerequisites": ["Sensitive data is written to external/shared/world-readable storage", "Another app or backup channel can read that location"],
        "impact": "Disclosure of tokens, PII, or other sensitive data stored outside the sandbox.",
        "remediation_summary": "Store sensitive data in app-internal storage with Keystore/Keychain-backed encryption; never use external/world-readable storage or plaintext SharedPreferences for secrets.",
        "references": ["OWASP MASVS-STORAGE-1", "CWE-922"],
        "false_positive_notes": "Non-sensitive caches/media on external storage are expected. The finding matters only when the data written is sensitive.",
        "masvs": "MASVS-STORAGE-1", "owasp": "M9",
    },
    "GENERIC": {
        "why_it_matters": "This finding indicates a security-relevant weakness or misconfiguration in the application.",
        "attack_scenario": "An attacker who can reach the affected code path leverages the weakness to move toward data access or control of app behavior.",
        "prerequisites": ["The affected code/configuration is reachable by an attacker"],
        "impact": "Depends on context — review the evidence and surrounding code to determine blast radius.",
        "remediation_summary": "Review the cited evidence, confirm exploitability, and apply the platform's secure-coding guidance for this weakness class.",
        "references": ["OWASP MASVS", "OWASP Mobile Top 10"],
        "false_positive_notes": "Heuristic findings (no resolved source, library/framework-owned, import-only references) are frequently informational — verify against the evidence before action.",
        "masvs": "", "owasp": "",
    },
}


# ─── Category detection ──────────────────────────────────────────────────────
def _text(finding: dict) -> str:
    return " ".join(str(finding.get(k, "")) for k in (
        "title", "category", "description", "rule_id", "cwe", "name")).lower()


def categorize(finding: dict) -> str:
    """Map a finding to a template category. First match wins (ordered)."""
    t = _text(finding)
    cwe = str(finding.get("cwe", "")).upper()

    if finding.get("is_attack_chain") or finding.get("is_cloud_chain"):
        return "GENERIC"  # chains get their own explainer
    if "webview" in t:
        return "WEBVIEW"
    if "sql" in t or cwe == "CWE-89":
        return "SQL_INJECTION"
    if "firebase" in t:
        return "FIREBASE"
    if "s3" in t or "bucket" in t:
        return "S3"
    if "deeplink" in t or "deep link" in t or "app link" in t or "applinks" in t or cwe == "CWE-939":
        return "DEEP_LINKS"
    if ("intent" in t and ("inject" in t or "redirect" in t or "export" in t)) or "exported component" in t or cwe in ("CWE-926", "CWE-927"):
        return "INTENT_INJECTION"
    if "root detection" in t or "security control" in t or finding.get("security_control"):
        return "ROOT_DETECTION"
    if "certificate" in t or finding.get("category") == "Certificate" or cwe == "CWE-295":
        return "CERTIFICATE"
    if any(w in t for w in ("cipher", "encrypt", "decrypt", "crypto", "md5", "sha-1", "sha1", "ecb", "insecure random")) or cwe in ("CWE-327", "CWE-328", "CWE-326", "CWE-330"):
        return "CRYPTO"
    if any(w in t for w in ("secret", "api key", "api_key", "token", "password", "credential", "private key")) or cwe in ("CWE-798", "CWE-321", "CWE-522"):
        return "SECRETS"
    if any(w in t for w in ("cleartext", "http traffic", "tls", "ssl", "hostname", "trustmanager", "network security")) or cwe == "CWE-319":
        return "NETWORK"
    if any(w in t for w in ("external storage", "world-readable", "world readable", "shared pref", "file storage", "mode_world")) or cwe == "CWE-922":
        return "FILE_STORAGE"
    return "GENERIC"


# ─── Confidence explanation (Task 4) ─────────────────────────────────────────
def _confidence_reason(finding: dict) -> str:
    quality = finding.get("evidence_quality") or _band(finding.get("confidence_score") or finding.get("confidence"))
    reasons: list[str] = []
    if finding.get("source_resolved"):
        reasons.append("source file and line resolved")
    if finding.get("file_evidence") or finding.get("snippet") or finding.get("call_chain") or finding.get("taint_flow"):
        reasons.append("code evidence available")
    label = finding.get("ownership_label") or finding.get("ownership")
    if label == "APPLICATION" or label == "APP":
        reasons.append("confirmed application-owned code")
    elif label and label != "UNKNOWN":
        reasons.append(f"owned by {label.replace('_', ' ').lower()}")
    if finding.get("validated") or finding.get("validation_result") == "valid":
        reasons.append("validated against the issuer/exposure")
    if str(finding.get("reachability", "")).upper() == "YES":
        reasons.append("reachable from an entry point")
    if str(finding.get("reachability", "")).upper() in ("NO", "MAYBE"):
        reasons.append("reachability is heuristic")
    if not finding.get("source_resolved") and not reasons:
        reasons.append("heuristic match without resolved source")
    joined = "; ".join(reasons) if reasons else "based on the detector's pattern confidence"
    return f"Confidence {quality}: {joined}."


def _band(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"
    return "HIGH" if s >= 70 else ("MEDIUM" if s >= 40 else "LOW")


# ─── Detector-specific detail (Task 3): why_dangerous / developer_fix / example ─
_DETAIL = {
    "WEBVIEW": {
        "why_dangerous": "The WebView accepts attacker-controllable content or exposes a JS bridge, so injected script runs with the app's privileges.",
        "developer_fix": "Disable JS/file access if unused; remove or @JavascriptInterface-restrict bridges; allowlist loaded URLs; in onReceivedSslError call handler.cancel().",
        "code_example": "// Reject invalid certificates instead of proceeding:\nwebView.setWebViewClient(new WebViewClient(){\n  public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e){ h.cancel(); }\n});",
    },
    "CRYPTO": {
        "why_dangerous": "A broken primitive or hardcoded key means the protected data can be recovered or forged by an attacker who obtains it.",
        "developer_fix": "Use AES-GCM with a Keystore-backed key, SHA-256+, and a CSPRNG; never hardcode keys/IVs.",
        "code_example": "KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,\n  KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)\n  .setBlockModes(KeyProperties.BLOCK_MODE_GCM)\n  .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build();",
    },
    "NETWORK": {
        "why_dangerous": "Cleartext or unvalidated TLS lets a network attacker read and modify traffic in transit.",
        "developer_fix": "Enforce HTTPS via a strict Network Security Config (no cleartext, no user CAs) and remove custom TrustManagers.",
        "code_example": "<!-- res/xml/network_security_config.xml -->\n<network-security-config>\n  <base-config cleartextTrafficPermitted=\"false\"/>\n</network-security-config>",
    },
    "SECRETS": {
        "why_dangerous": "A shipped credential is extractable from the binary and usable directly against your backend or a third-party service.",
        "developer_fix": "Revoke + rotate the key, move it server-side, and scope any key that must reach the client.",
        "code_example": "// Client calls your backend; the backend holds the secret:\nString token = api.getScopedToken();  // no provider secret in the app",
    },
    "FIREBASE": {
        "why_dangerous": "Permissive Firebase rules expose the database to anyone with the URL — no auth required.",
        "developer_fix": "Require authentication in the rules and scope per-user access.",
        "code_example": "{ \"rules\": { \".read\": \"auth != null\", \".write\": \"auth != null\" } }",
    },
    "S3": {
        "why_dangerous": "A public bucket lists and serves its objects to anyone.",
        "developer_fix": "Enable Block Public Access, remove public-read ACLs, and serve content via signed URLs.",
        "code_example": "aws s3api put-public-access-block --bucket <b> \\\n  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true",
    },
    "CERTIFICATE": {
        "why_dangerous": "Weak signing (v1/Janus, debug cert, small key) lets an attacker repackage or impersonate the app.",
        "developer_fix": "Sign with APK Signature Scheme v2+/v3, use a 2048-bit+ production key, never ship debug builds.",
        "code_example": "// build.gradle signingConfigs — release key, v2/v3 enabled\nv2SigningEnabled true\nv3SigningEnabled true",
    },
    "ROOT_DETECTION": {
        "why_dangerous": "Not dangerous in itself — but treating on-device root detection as a hard boundary is bypassable.",
        "developer_fix": "Combine with server-side Play Integrity / DeviceCheck attestation.",
        "code_example": "IntegrityManagerFactory.create(ctx)\n  .requestIntegrityToken(...);  // verify the token server-side",
    },
    "DEEP_LINKS": {
        "why_dangerous": "An unverified deep link lets external content drive the app into sensitive flows with attacker-chosen data.",
        "developer_fix": "Verify App Links (autoVerify + assetlinks.json), authenticate before acting, and validate link params.",
        "code_example": "<intent-filter android:autoVerify=\"true\"> … </intent-filter>",
    },
    "INTENT_INJECTION": {
        "why_dangerous": "An exported component lets any installed app invoke privileged functionality or read returned data.",
        "developer_fix": "Set exported=false unless required, enforce a signature permission, and validate Intent action/extras.",
        "code_example": "<activity android:name=\".Secret\" android:exported=\"false\"/>",
    },
    "SQL_INJECTION": {
        "why_dangerous": "Untrusted input concatenated into SQL lets an attacker rewrite the query.",
        "developer_fix": "Use parameterized queries with bound arguments — never concatenate input.",
        "code_example": "db.rawQuery(\"SELECT * FROM t WHERE id = ?\", new String[]{ userId });",
    },
    "FILE_STORAGE": {
        "why_dangerous": "Sensitive data on external/world-readable storage can be read by other apps or backups.",
        "developer_fix": "Use app-internal storage with Keystore-backed encryption (EncryptedFile / EncryptedSharedPreferences).",
        "code_example": "EncryptedSharedPreferences.create(ctx, \"secret\", masterKey,\n  PrefKeyEncryptionScheme.AES256_SIV, PrefValueEncryptionScheme.AES256_GCM);",
    },
    "GENERIC": {
        "why_dangerous": "An attacker who reaches this code path can leverage the weakness toward data access or control.",
        "developer_fix": "Review the evidence, confirm exploitability, and apply the platform's secure-coding guidance.",
        "code_example": "// See the remediation summary and references for the secure pattern.",
    },
}


def _evidence_locations(finding: dict) -> list:
    """Task 2 — exact, navigable evidence: file + line_start/end + highlight_line."""
    locs = []
    fe = finding.get("file_evidence")
    if isinstance(fe, list):
        for e in fe:
            if not isinstance(e, dict) or not e.get("path"):
                continue
            lines = e.get("lines") or ([finding["line"]] if finding.get("line") else [])
            hl = lines[0] if lines else None
            locs.append({
                "file": e["path"],
                "line_start": min(lines) if lines else None,
                "line_end": max(lines) if lines else None,
                "highlight_line": hl,
                "snippet": e.get("snippet") or finding.get("snippet") or "",
            })
    if not locs:
        path = finding.get("file_path") or finding.get("full_path")
        if path:
            ln = finding.get("line") or None
            locs.append({
                "file": path, "line_start": ln, "line_end": ln,
                "highlight_line": ln, "snippet": finding.get("snippet") or "",
            })
    return locs


# ─── AnalystExplanation builder (Task 1/2/3) ─────────────────────────────────
def build_explanation(finding: dict) -> dict:
    cat = categorize(finding)
    tpl = _TEMPLATES[cat]
    det = _DETAIL.get(cat, _DETAIL["GENERIC"])
    masvs = finding.get("masvs") or tpl["masvs"]
    owasp = finding.get("owasp") or tpl["owasp"]
    references = list(tpl["references"])
    if finding.get("cwe") and finding["cwe"] not in " ".join(references):
        references.append(str(finding["cwe"]))
    # what_found is the CONCRETE thing detected (matched code), not a template.
    what_found = (finding.get("snippet") or finding.get("value")
                  or finding.get("matched_string") or "").strip() or det.get("why_dangerous", "")[:0] or "See evidence."
    return {
        "title": finding.get("title") or finding.get("name") or "Finding",
        "category_template": cat,
        "what_found": what_found,
        "why_it_matters": tpl["why_it_matters"],
        "why_dangerous": det["why_dangerous"],
        "attack_scenario": tpl["attack_scenario"],
        "prerequisites": list(tpl["prerequisites"]),
        "impact": tpl["impact"],
        "remediation": {
            "summary": finding.get("recommendation") or tpl["remediation_summary"],
            "developer_fix": det["developer_fix"],
            "masvs": masvs,
            "owasp": owasp,
        },
        "developer_fix": det["developer_fix"],
        "code_example": det["code_example"],
        "evidence_locations": _evidence_locations(finding),
        "references": references,
        "false_positive_notes": tpl["false_positive_notes"],
        "confidence_reason": _confidence_reason(finding),
    }


# ─── Attack-chain explanation (Task 3) ───────────────────────────────────────
def build_chain_explanation(chain: dict) -> dict:
    provider = chain.get("provider", "cloud")
    confidence = chain.get("confidence", "MEDIUM")
    steps = [c.get("label", "") for c in chain.get("components", []) if c.get("label")]
    flow = " → ".join(steps) if steps else chain.get("summary", "")
    validated = any(c.get("kind") == "validation" and c.get("state") == "valid"
                    for c in chain.get("components", []))
    why = (
        f"Individually these findings look minor, but together they form a usable path: "
        f"{flow}. A {provider} credential present in the app combined with a confirmed public "
        f"exposure means an attacker can go from 'string in the binary' to actual data access "
        f"without a device or a user."
    )
    conf_reason = (
        "Confidence HIGH: the credential was validated AND the exposure was confirmed by a read-only probe."
        if confidence == "HIGH" else
        "Confidence MEDIUM: the exposure was confirmed by a read-only probe, but the credential itself was not live-validated."
        if confidence == "MEDIUM" else
        "Confidence LOW: a credential is present but no public exposure was confirmed."
    )
    return {
        "title": chain.get("title", "Cloud Attack Path"),
        "category_template": "ATTACK_CHAIN",
        "why_it_matters": why,
        "attack_scenario": (
            f"Attacker extracts the {provider} credential from the app bundle, confirms the linked "
            f"public exposure, and reads the exposed data directly from the internet."
        ),
        "prerequisites": ["Credential recoverable from the app bundle",
                          "Linked cloud asset is publicly reachable"],
        "impact": "Direct disclosure (or, for public write, modification) of cloud-hosted data.",
        "remediation": {
            "summary": "Rotate the credential, lock down the exposed asset's access policy/rules, and move secret material server-side.",
            "masvs": "MASVS-NETWORK-1", "owasp": "M8",
        },
        "references": ["OWASP MASVS-STORAGE-2", "OWASP Mobile Top 10 M8"],
        "false_positive_notes": (
            "If the exposure was not confirmed (LOW chain), this is a credential-hygiene issue, "
            "not a proven data-exposure path."
        ),
        "confidence_reason": conf_reason,
    }


# ─── Executive analyst summary (Task 7) ──────────────────────────────────────
def _exploit_rank(f: dict) -> tuple:
    reach = 0 if str(f.get("reachability", "")).upper() == "YES" else 1
    return (_SEV_RANK.get(f.get("severity", "info"), 4), reach,
            -int(f.get("exploitability") or f.get("exploitability_score") or 0))


def build_summary(results: dict, findings: list[dict]) -> dict:
    ranked = sorted(findings, key=_exploit_rank)
    top_risks = [{
        "title": f.get("title"),
        "severity": f.get("severity"),
        "why": (f.get("analyst_explanation") or {}).get("why_it_matters", "")[:200],
    } for f in ranked[:5]]

    chains = list(results.get("cloud_attack_paths") or [])
    chains += [f for f in findings if f.get("is_attack_chain")]
    chains.sort(key=lambda c: -int(c.get("risk_score") or 0))
    most_exploitable = [{
        "title": c.get("title"),
        "summary": c.get("summary") or (c.get("analyst_explanation") or {}).get("why_it_matters", "")[:160],
        "confidence": c.get("confidence") or c.get("chain_confidence"),
        "risk_score": c.get("risk_score"),
    } for c in chains[:5]]

    high_conf = [f for f in findings if (f.get("evidence_quality") == "HIGH"
                 or _band(f.get("confidence_score") or f.get("confidence")) == "HIGH")]
    high_conf.sort(key=_exploit_rank)
    return {
        "top_risks": top_risks,
        "most_exploitable_chains": most_exploitable,
        "high_confidence_findings": {
            "count": len(high_conf),
            "items": [{"title": f.get("title"), "severity": f.get("severity")} for f in high_conf[:8]],
        },
    }


# ─── Public entry point ──────────────────────────────────────────────────────
def annotate(results: dict) -> dict:
    """Attach analyst_explanation to every finding + cloud attack path, and build
    results["analyst_summary"]. Deterministic; no network, no LLM."""
    findings = [f for f in (results.get("findings") or []) if isinstance(f, dict)]
    for f in findings:
        if f.get("is_attack_chain"):
            f["analyst_explanation"] = build_chain_explanation(f)
        else:
            f["analyst_explanation"] = build_explanation(f)

    for chain in results.get("cloud_attack_paths") or []:
        if isinstance(chain, dict):
            chain["analyst_explanation"] = build_chain_explanation(chain)

    results["analyst_summary"] = build_summary(results, findings)
    log.info("[analyst_intel] explained %d findings, %d cloud chains",
             len(findings), len(results.get("cloud_attack_paths") or []))
    return results["analyst_summary"]
