"""
Analyst Workspaces & Evidence Intelligence — Phase 11.75 (backend).

Builds graph-ready, analyst-oriented data structures from the intelligence the
pipeline ALREADY produced. Purely additive and deterministic: it only reads
existing result keys and writes NEW ones. No detection, no network, no changes to
findings logic / trust scoring / chain generation.

Adds:
  * chain_evidence[] + confidence_explanation on every attack chain (Task 1)
  * results["permissions_workspace"]   (Task 4)
  * results["certificate_workspace"]   (Task 5)
  * results["android_posture"]         (Task 6)
  * results["network_workspace"]       (Task 7)
  * used_in_files[] enrichment         (Task 8)
  * results["taint_graph"]             (Task 9, graph-ready)
"""
from __future__ import annotations

import logging
import os
import re

from .analyst_intel import is_v2_chain
from .finding_model import evidence_dict

log = logging.getLogger("cortex.workspaces")

_WS = re.compile(r"^wss?://", re.I)


def _findings(results: dict) -> list:
    return [f for f in (results.get("findings") or []) if isinstance(f, dict)]


def _conf(f: dict) -> str:
    if f.get("evidence_quality"):
        return f["evidence_quality"]
    n = f.get("confidence_score") or f.get("confidence")
    try:
        n = float(n)
        return "HIGH" if n >= 70 else ("MEDIUM" if n >= 40 else "LOW")
    except (TypeError, ValueError):
        return "LOW"


# ═══════════════════════ Task 1 — chain evidence + confidence ═══════════════
# Role detection from a member finding's title/category, used both for the
# per-member "why_it_contributes" and the chain's self-explaining confidence.
_ROLE_RULES = [
    ("pii_source", re.compile(r"read_contacts|read_sms|location|get_accounts|camera|microphone|read_phone|pii|contacts|fine_location", re.I),
     "Collects sensitive user data (PII)."),
    ("transport_weakness", re.compile(r"cleartext|http traffic|tls|ssl|pinning|trustmanager|hostname", re.I),
     "Weak transport — traffic can be intercepted (MITM)."),
    ("exfil_sink", re.compile(r"exfil|upload|loadurl|webview|network request|http post|sendto|outbound", re.I),
     "Data can leave the device through this sink."),
    ("credential", re.compile(r"secret|credential|api key|token|password|private key|aws|firebase|stripe", re.I),
     "A usable credential is present in the app."),
    ("exposure", re.compile(r"public|s3|firebase.*read|unrestricted|exposed", re.I),
     "A public cloud exposure is confirmed."),
    ("entry_point", re.compile(r"exported|deeplink|deep link|browsable|intent", re.I),
     "An externally reachable entry point."),
]


def _role(title: str) -> tuple[str, str]:
    for role, rx, why in _ROLE_RULES:
        if rx.search(title or ""):
            return role, why
    return "step", "Contributes a step to the attack path."


def _all_chains(results: dict) -> list:
    chains = [f for f in _findings(results) if f.get("is_attack_chain")]
    chains += [c for c in (results.get("cloud_attack_paths") or []) if isinstance(c, dict)]
    return chains


_STRONG_EVIDENCE = frozenset(("HIGH", "Excellent", "Good"))


def _v2_confidence_checks(chain: dict, evidence: list, has_runtime: bool) -> list:
    """Confidence checklist for a v2 engine chain from its REAL proof signals —
    reachability_proof, a reachable entry point, member evidence quality and whether
    a security control blocks it — instead of the cloud PII/exposure rubric."""
    proof = str(chain.get("reachability_proof") or "").lower()
    entry = chain.get("entry_point") if isinstance(chain.get("entry_point"), dict) else {}
    member_confs = [e.get("confidence") for e in evidence]
    strong_members = bool(member_confs) and all(c in _STRONG_EVIDENCE for c in member_confs)
    return [
        {"label": "Reachability proven by data-flow (taint)", "met": proof == "proven"},
        {"label": "Reachability supported (not manifest-only)", "met": proof in ("proven", "heuristic")},
        {"label": "Externally reachable entry point", "met": bool(entry.get("reachable"))},
        {"label": "Required links backed by strong evidence", "met": strong_members},
        {"label": "Runtime / data-flow proof present", "met": bool(has_runtime)},
        {"label": "Not blocked by a security control", "met": not bool(chain.get("blocked"))},
    ]


def _member_evidence(full: dict, member: dict):
    """(file, line, evidence_view) for a chain member — sourced from the Evidence
    Selection Engine so chains render the same primary proof as the finding does.
    Falls back to the member/finding fields when selection did not run."""
    view = None
    if full:
        try:
            from .evidence_selection import primary_location, build_evidence_view
            file, line, _snip = primary_location(full)
            view = build_evidence_view(full)
            if file:
                return file, line, view
        except Exception:  # noqa: BLE001 — never let chain enrichment fail a scan
            view = None
    # `evidence` is polymorphic (see finding_model.evidence_dict): certificate
    # and chain findings carry proof TEXT here, not a location dict. Those
    # findings legitimately have no file/line — the text stays on the finding.
    ev = evidence_dict(full) if full else {}
    file = (member.get("file_path") or member.get("file")
            or (full.get("file_path") if full else "")
            or ev.get("file_path") or "")
    line = (full.get("line") if full else 0) or ev.get("line") or 0
    return file, line, view


def enrich_chains(results: dict) -> None:
    findings = _findings(results)
    by_id, by_title = {}, {}
    for f in findings:
        fid = f.get("canonical_id") or f.get("rule_id") or f.get("id")
        if fid:
            by_id.setdefault(str(fid), f)
        if f.get("title"):
            by_title.setdefault(f["title"], f)

    for chain in _all_chains(results):
        members = chain.get("attack_chain_members") or chain.get("components") or []
        evidence, roles = [], set()
        for m in members:
            if not isinstance(m, dict):
                continue
            title = m.get("title") or m.get("label") or ""
            fid = str(m.get("id") or m.get("ref") or "")
            full = by_id.get(fid) or by_title.get(title) or {}
            # Phase 1.998: chains consume the SAME proof the Evidence Selection Engine
            # chose for the member finding — never an independent file_path pick. This
            # gives chains the application-owned primary (app/manifest over framework),
            # plus ownership + the honest framework-only label/reason.
            file, line, view = _member_evidence(full, m)
            role, why = _role(title)
            roles.add(role)
            entry = {
                "finding_id": fid or (full.get("canonical_id") or ""),
                "title": title, "file": file, "line": line,
                "confidence": _conf(full) if full else (m.get("state") and "HIGH" or "LOW"),
                "why_it_contributes": why,
            }
            if view:
                entry["ownership"] = view.get("evidence_ownership") or ""
                entry["detection_sources"] = view.get("detection_sources") or []
                entry["evidence_reason"] = view.get("selection_reason") or ""
                if view.get("framework_only"):
                    entry["framework_only"] = True
                    entry["evidence_reason"] = "No application-owned implementation was found."
            evidence.append(entry)
        chain["chain_evidence"] = evidence

        has_runtime = any(
            (by_id.get(e["finding_id"]) or by_title.get(e["title"]) or {}).get("taint_flow")
            or e["line"] for e in evidence
        )
        # Type-aware "Why confidence is X" checklist: a v2 engine chain is scored on
        # its OWN proof signals (reachability_proof, member evidence, blocking), NOT
        # the cloud PII/credential/exposure rubric — that rubric belongs to cloud
        # attack paths only.
        if is_v2_chain(chain):
            checks = _v2_confidence_checks(chain, evidence, has_runtime)
            conf = chain.get("chain_confidence") or _conf(chain)
        else:
            checks = [
                {"label": "PII / sensitive source confirmed", "met": "pii_source" in roles},
                {"label": "Transport / control weakness confirmed", "met": "transport_weakness" in roles},
                {"label": "Exfiltration sink / endpoint found", "met": "exfil_sink" in roles},
                {"label": "Usable credential present", "met": "credential" in roles},
                {"label": "Public exposure confirmed", "met": "exposure" in roles},
                {"label": "Runtime / data-flow proof", "met": bool(has_runtime)},
            ]
            conf = chain.get("chain_confidence") or chain.get("confidence") or "LOW"
        met = [c["label"] for c in checks if c["met"]]
        missing = [c["label"] for c in checks if not c["met"]]
        # Merge, so the engine's own confidence_explanation (why_members/why_confidence)
        # is preserved alongside the rendered checklist rather than clobbered.
        existing_cx = chain.get("confidence_explanation") if isinstance(chain.get("confidence_explanation"), dict) else {}
        chain["confidence_explanation"] = {
            **existing_cx,
            "confidence": conf,
            "checks": checks,
            "summary": (
                f"Confidence {conf} — confirmed: {', '.join(met) or 'none'}."
                + (f" Missing: {', '.join(missing)}." if missing else "")
            ),
        }


# ═══════════════════════ Task 4 — permissions workspace ═════════════════════
# Phase 11.987 — real permission evidence. A single, capped pass over the
# decompiled source finds where each permission constant is actually referenced
# (Manifest.permission.X, the permission string, runtime checks) so the
# permissions page can show file:line:snippet + View Code with Prev/Next.
_PERM_EV_PER_PERM = 6
_PERM_EV_TOTAL = 500
_PERM_EV_MAX_FILES = 12000
_PERM_EV_MAX_BYTES = 256 * 1024


def _scan_permission_evidence(scan_id: str, short_names: list[str]) -> dict:
    """short_name -> [{path, line, snippet}] from one bounded source pass."""
    out: dict[str, list] = {}
    if not scan_id or not short_names:
        return out
    try:
        from . import scan_storage
    except Exception:
        return out
    root = scan_storage.scan_root(scan_id)
    if not root.exists():
        return out
    toks = sorted({s for s in short_names if s and len(s) >= 5}, key=len, reverse=True)
    if not toks:
        return out
    pat = re.compile(r"\b(" + "|".join(re.escape(t) for t in toks) + r")\b")
    text_exts = scan_storage.TEXT_EXTS
    skip = scan_storage.SKIP_DIRNAMES
    seen: dict[str, set] = {t: set() for t in toks}
    total = files = 0
    for sub in ("jadx", "apktool", "apk_extract"):
        base = root / sub
        if not base.exists():
            continue
        for r, dirs, names in os.walk(base):
            dirs[:] = [d for d in dirs if d not in skip]
            for name in names:
                if os.path.splitext(name)[1].lower() not in text_exts:
                    continue
                files += 1
                if files > _PERM_EV_MAX_FILES or total >= _PERM_EV_TOTAL:
                    return out
                fp = os.path.join(r, name)
                try:
                    with open(fp, "r", errors="replace") as fh:
                        data = fh.read(_PERM_EV_MAX_BYTES)
                except Exception:
                    continue
                if not any(t in data for t in toks):  # fast reject
                    continue
                rel = os.path.relpath(fp, base).replace("\\", "/")
                for i, ln in enumerate(data.splitlines(), 1):
                    m = pat.search(ln)
                    if not m:
                        continue
                    tok = m.group(1)
                    bucket = out.setdefault(tok, [])
                    if len(bucket) >= _PERM_EV_PER_PERM:
                        continue
                    key = f"{rel}#{i}"
                    if key in seen[tok]:
                        continue
                    seen[tok].add(key)
                    bucket.append({"path": rel, "line": i, "snippet": ln.strip()[:200]})
                    total += 1
                    if total >= _PERM_EV_TOTAL:
                        return out
    return out


def build_permissions_workspace(results: dict) -> None:
    perms = (results.get("permissions") or {}).get("classified") or []
    if not perms:
        all_perms = (results.get("permissions") or {}).get("all") or []
        perms = [{"permission": p, "short_name": str(p).split(".")[-1], "status": "normal"} for p in all_perms]
    findings = _findings(results)
    short_names = [p.get("short_name") or (p.get("permission") or "").split(".")[-1] for p in perms]
    scan_id = results.get("scan_id") or ""
    ev_map = _scan_permission_evidence(scan_id, short_names)

    # Manifest fallback: every declared permission appears in the manifest by
    # definition, so a permission with no in-code reference still resolves to its
    # <uses-permission name="…"> line. Reuse finding_model's manifest helpers so
    # the path/line scheme matches the already-working manifest findings.
    try:
        from .finding_model import _load_manifest_text, _find_manifest_line
        man_text, man_path = _load_manifest_text(scan_id, results.get("manifest_xml") or "")
    except Exception:
        man_text, man_path = "", "AndroidManifest.xml"

    def _manifest_ev(full_name: str) -> list:
        if not man_text or not full_name:
            return []
        line, snippet = _find_manifest_line(man_text, {"attr": "name", "value": full_name})
        if not line:
            return []
        return [{"path": man_path, "line": line, "snippet": (snippet or "").strip()[:200]}]

    out = []
    for p in perms:
        name = p.get("permission") or ""
        short = p.get("short_name") or name.split(".")[-1]
        ev = ev_map.get(short, [])
        if not ev:
            ev = _manifest_ev(name)
        files_used = sorted({e["path"] for e in ev})
        related = [f.get("title") for f in findings
                   if short and short.lower() in f"{f.get('title','')} {f.get('description','')}".lower()]
        out.append({
            "permission": name,
            "short_name": short,
            "type": p.get("status") or "normal",
            "severity": p.get("severity") or ("medium" if p.get("status") == "dangerous" else "info"),
            "reason": p.get("description", "") or "Declared in the app manifest.",
            "description": p.get("description", ""),
            "where_used": files_used,
            "used_in_files": files_used,
            "reference_count": len(ev),
            "evidence": ev,
            "findings": related[:10],
        })
    results["permissions_workspace"] = out


# ═══════════════════════ Task 5 — certificate workspace ═════════════════════
# Phase 11.987 — per-issue certificate intelligence. Instead of one generic
# narrative for every certificate weakness, each detected issue carries its own
# affected versions, attack scenario, prerequisites, business/technical impact,
# MASVS/OWASP mapping, severity, remediation and developer fix (analyst_intel
# style — concrete, no boilerplate).
def _build_cert_issues(c: dict, schemes: list, janus: bool, self_signed: bool) -> list:
    issues: list[dict] = []
    algo = str(c.get("signature_algo") or "")
    algo_l = algo.lower()
    key_type = str(c.get("key_type") or "")
    key_size = c.get("key_size")
    try:
        key_bits = int(key_size) if key_size is not None else None
    except (TypeError, ValueError):
        key_bits = None
    scheme_l = [str(s).lower() for s in schemes]
    has_v2plus = any(s in ("v2", "v3", "v4") for s in scheme_l)

    if c.get("debug_cert"):
        issues.append({
            "id": "debug_certificate",
            "title": "APK signed with a debug certificate",
            "severity": "high",
            "affected_versions": "All Android versions — the Android debug keystore key (CN=Android Debug) is shared and publicly known.",
            "attack_scenario": "An attacker downloads the APK, strips the signature, modifies code or resources, and re-signs with the same well-known Android debug key. Because the debug certificate is identical across machines, the repackaged build is indistinguishable from the original by certificate, and any device or sideload flow keyed to that identity accepts it.",
            "prerequisites": ["Attacker can obtain and redistribute the APK", "A distribution channel that does not enforce Play App Signing"],
            "business_impact": "Trojanized clones of the app can be distributed under an identity anyone can reproduce, enabling fraud, credential theft from users, and brand damage. Google Play rejects debug-signed uploads outright.",
            "technical_impact": "No meaningful authorship guarantee: signature-based update integrity and signature-permission protections are void because the signing key is public.",
            "masvs": "MASVS-RESILIENCE-1",
            "owasp": "M7: Insufficient Binary Protection",
            "remediation": "Sign release builds with a private, securely stored release keystore; never ship debug-signed artifacts. Enable Google Play App Signing.",
            "developer_fix": "Build with the `release` signingConfig (not `debug`) and verify with `apksigner verify --print-certs`; the subject must not be CN=Android Debug.",
        })

    if "sha1" in algo_l or "sha-1" in algo_l or "md5" in algo_l:
        weak = "MD5" if "md5" in algo_l else "SHA-1"
        issues.append({
            "id": "weak_signature_algo",
            "title": f"Certificate signed with weak {weak} digest ({algo})",
            "severity": "high" if weak == "MD5" else "medium",
            "affected_versions": "Exploitable wherever the APK v1 (JAR) signature is trusted — Android 4.x–6.0 verify v1 only; collision attacks on SHA-1 are practical since the 2017 SHAttered research, and MD5 collisions for over a decade.",
            "attack_scenario": f"An attacker crafts a second APK whose {weak} digest collides with the legitimate one, so the existing v1 signature block validates against malicious content. On devices that rely on v1 verification, the forged package installs and updates as if genuinely signed.",
            "prerequisites": [f"{weak} is used for the signature digest", "Target devices verify the v1/JAR signature (no v2+ enforcement)"],
            "business_impact": "App integrity can be forged, allowing malware to masquerade as a legitimate update and undermining the trust users place in the publisher.",
            "technical_impact": f"Tamper-evidence of the signature is broken — {weak} no longer provides collision resistance, so signed content is no longer reliably authentic.",
            "masvs": "MASVS-CRYPTO-1",
            "owasp": "M10: Insufficient Cryptography",
            "remediation": "Re-sign with a SHA-256 (or stronger) digest and APK Signature Scheme v2+/v3, which use modern hashing and protect the whole archive.",
            "developer_fix": "Regenerate the certificate with `-sigalg SHA256withRSA` and enable v2/v3 signing in the Gradle signingConfig; drop reliance on v1-only verification.",
        })

    if key_bits is not None and "rsa" in key_type.lower() and key_bits < 2048:
        issues.append({
            "id": "small_rsa_key",
            "title": f"Weak {key_bits}-bit RSA signing key",
            "severity": "high" if key_bits <= 512 else "medium",
            "affected_versions": "All versions — NIST has deprecated RSA below 2048 bits; 1024-bit RSA is considered factorable by well-resourced adversaries and 512-bit is breakable on commodity hardware.",
            "attack_scenario": f"A sufficiently resourced attacker factors the {key_bits}-bit RSA modulus to recover the private key, then signs arbitrary malicious builds that validate against the app's published certificate — a full impersonation of the publisher.",
            "prerequisites": [f"Signing key is {key_bits}-bit RSA", "Attacker has the compute/time to factor the modulus (feasible for ≤1024-bit for capable actors)"],
            "business_impact": "Catastrophic if the key is recovered: the attacker can sign updates and apps indistinguishable from the genuine publisher, enabling supply-chain compromise of the entire user base.",
            "technical_impact": "The signing key's secrecy — the root of all signature trust — is at risk; key compromise voids every integrity and update guarantee.",
            "masvs": "MASVS-CRYPTO-2",
            "owasp": "M10: Insufficient Cryptography",
            "remediation": "Generate a new 2048-bit+ RSA (or 256-bit EC) signing key and migrate signing; rotate via the Play App Signing key-upgrade flow.",
            "developer_fix": "Create a fresh keystore with `keytool -genkeypair -keyalg RSA -keysize 2048` (or `-keyalg EC -keysize 256`) and re-sign.",
        })

    if janus:
        issues.append({
            "id": "janus_v1_only",
            "title": "v1-only signing — Janus tampering risk (CVE-2017-13156)",
            "severity": "high",
            "affected_versions": "Android 5.0–8.0 (API 21–26) that accept v1-signed APKs without v2 verification are vulnerable to the Janus DEX-injection attack.",
            "attack_scenario": "Using Janus, an attacker prepends a malicious DEX to the APK; because v1 (JAR) signing does not cover the whole file, the original signature still validates while the runtime loads the attacker's injected code on a vulnerable device.",
            "prerequisites": ["APK is signed with v1 only (no v2/v3)", "Target runs Android 5.0–8.0 and verifies v1 signatures"],
            "business_impact": "Attackers can ship a trojanized build that passes signature checks, leading to malware distribution under the app's identity.",
            "technical_impact": "Arbitrary code injection at load time with the app's own permissions and identity.",
            "masvs": "MASVS-RESILIENCE-1",
            "owasp": "M7: Insufficient Binary Protection",
            "remediation": "Enable APK Signature Scheme v2 and v3 (whole-file signing), which closes Janus; keep v1 only for legacy compatibility alongside v2+.",
            "developer_fix": "In the Gradle signingConfig set `v2SigningEnabled true` and `v3SigningEnabled true`; verify with `apksigner verify -v` that v2/v3 are present.",
        })
    elif "v1" in scheme_l and has_v2plus:
        issues.append({
            "id": "v1_scheme_enabled",
            "title": "Legacy v1 (JAR) signature still enabled",
            "severity": "low",
            "affected_versions": "Pre-Android 7.0 devices fall back to v1 verification; modern devices prefer v2+ when present.",
            "attack_scenario": "On old devices that only check v1, the weaker per-entry JAR signature is used, which does not protect the full archive the way v2+ does — a smaller version of the Janus exposure.",
            "prerequisites": ["v1 signature is present", "App is installed on a pre-7.0 device"],
            "business_impact": "Marginal residual tampering exposure on legacy devices only.",
            "technical_impact": "Whole-file integrity relies on v2+; v1 fallback offers weaker guarantees.",
            "masvs": "MASVS-RESILIENCE-1",
            "owasp": "M7: Insufficient Binary Protection",
            "remediation": "If minSdk ≥ 24, you may drop v1 entirely and rely on v2/v3; otherwise the risk is contained by v2+ on modern devices.",
            "developer_fix": "Set `v1SigningEnabled false` when `minSdkVersion >= 24`, keeping `v2SigningEnabled`/`v3SigningEnabled` true.",
        })

    if c.get("expired"):
        issues.append({
            "id": "expired_certificate",
            "title": "Signing certificate has expired",
            "severity": "medium",
            "affected_versions": "All versions — an expired signing certificate can block installs/updates and signals poor key lifecycle management.",
            "attack_scenario": "An expired certificate cannot be used to publish updates on Play, and on some flows installation fails; users may be steered to unofficial sideloaded builds, widening the attack surface for trojanized copies.",
            "prerequisites": ["Certificate validity window has passed", "App needs to be updated or freshly installed"],
            "business_impact": "Inability to ship security updates through normal channels, leaving users on vulnerable versions and pushing them toward untrusted sources.",
            "technical_impact": "Update/installation friction; degraded trust signals for the publisher identity.",
            "masvs": "MASVS-RESILIENCE-1",
            "owasp": "M7: Insufficient Binary Protection",
            "remediation": "Use a long-lived release certificate (Play requires validity through at least 2033) and adopt Play App Signing so Google manages the signing key.",
            "developer_fix": "Generate a new keystore with a long validity (`-validity 10000`) and migrate via Play App Signing key rotation.",
        })

    if self_signed and not c.get("debug_cert"):
        issues.append({
            "id": "self_signed_certificate",
            "title": "Self-signed signing certificate (expected for Android, noted)",
            "severity": "info",
            "affected_versions": "All versions — Android app signing certificates are self-signed by design; this is informational, not a vulnerability on its own.",
            "attack_scenario": "There is no direct attack from self-signing of the app's own package; the risk only arises if the same self-signed cert is reused as a TLS server/trust anchor, where no CA validates it.",
            "prerequisites": ["N/A for app signing", "Relevant only if the cert is reused for TLS or custom trust"],
            "business_impact": "None for app signing; review only if this certificate is also used outside package signing.",
            "technical_impact": "None inherent to APK signing — the certificate is the publisher's self-asserted identity anchor.",
            "masvs": "MASVS-RESILIENCE-1",
            "owasp": "M7: Insufficient Binary Protection",
            "remediation": "No action needed for app signing. If reused for TLS, replace with a CA-issued certificate.",
            "developer_fix": "Keep the self-signed cert for package signing; do not embed or trust it as a TLS anchor.",
        })

    return issues


def build_certificate_workspace(results: dict) -> None:
    c = results.get("certificate") or {}
    if not c:
        results["certificate_workspace"] = {}
        return
    schemes = c.get("scheme") or c.get("schemes") or []
    has = lambda v: any(v in str(s).lower() for s in schemes)
    janus = c.get("janus_risk")
    if janus is None:
        janus = has("v1") and not has("v2") and not has("v3")
    subj = c.get("subject") or {}
    iss = c.get("issuer") or {}
    self_signed = bool(subj) and subj == iss
    cert_findings = [f.get("title") for f in _findings(results)
                     if "certificate" in f"{f.get('category','')} {f.get('title','')}".lower()]
    cert_issues = _build_cert_issues(c, schemes, bool(janus), self_signed)
    results["certificate_workspace"] = {
        "subject": ", ".join(f"{k}={v}" for k, v in subj.items()),
        "issuer": ", ".join(f"{k}={v}" for k, v in iss.items()),
        "serial": c.get("serial"),
        "sha1": c.get("sha1_fingerprint") or c.get("sha1"),
        "sha256": c.get("sha256_fingerprint") or c.get("sha256"),
        "sha512": c.get("sha512_fingerprint") or c.get("sha512"),
        "algorithm": c.get("signature_algo"),
        "key_size": c.get("key_size"),
        "key_type": c.get("key_type"),
        "signature_schemes": schemes,
        "debug_cert": bool(c.get("debug_cert")),
        "self_signed": self_signed,
        "janus_possible": bool(janus),
        "valid_from": c.get("valid_from"),
        "valid_to": c.get("valid_to"),
        "expired": bool(c.get("expired")),
        "findings": cert_findings,
        "issues": cert_issues,
        "issue_count": len(cert_issues),
    }


# ═══════════════════════ Task 6 — android posture ══════════════════════════
def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _item(value, risk):
    return {"value": value, "risk": risk}


def build_android_posture(results: dict) -> None:
    if results.get("platform") == "ios":
        return
    ms = results.get("manifest_security") or {}
    info = results.get("app_info") or {}
    nc = results.get("network_config") or {}
    sumc = nc.get("summary") or {}
    cert = results.get("certificate") or {}
    findings = _findings(results)
    has = lambda rx: any(re.search(rx, f"{f.get('title','')} {f.get('category','')}", re.I) for f in findings)

    min_sdk = _as_int(ms.get("min_sdk") if ms.get("min_sdk") is not None else info.get("min_sdk"))
    target_sdk = _as_int(ms.get("target_sdk") if ms.get("target_sdk") is not None else info.get("target_sdk"))
    debuggable = ms.get("debuggable") if ms.get("debuggable") is not None else info.get("debuggable")
    allow_backup = ms.get("allow_backup")
    schemes = cert.get("scheme") or cert.get("schemes") or []
    janus = cert.get("janus_risk")
    if janus is None:
        janus = any("v1" in str(s).lower() for s in schemes) and not any(("v2" in str(s).lower() or "v3" in str(s).lower()) for s in schemes)

    results["android_posture"] = {
        "debuggable": _item(debuggable, "risk" if debuggable else "good"),
        "allowBackup": _item(allow_backup, "warn" if allow_backup else "good"),
        "minSdk": _item(min_sdk, "warn" if (min_sdk is not None and min_sdk < 24) else "good"),
        "targetSdk": _item(target_sdk, "warn" if (target_sdk is not None and target_sdk < 30) else "good"),
        "cleartextTraffic": _item(sumc.get("cleartext_global"), "risk" if sumc.get("cleartext_global") else "good"),
        "networkSecurityConfig": _item(nc.get("present"), "good" if nc.get("present") else "warn"),
        "signatureScheme": _item(schemes, "good" if any(("v2" in str(s).lower() or "v3" in str(s).lower()) for s in schemes) else "warn"),
        "janusRisk": _item(bool(janus), "risk" if janus else "good"),
        "backupRisk": _item(bool(allow_backup), "warn" if allow_backup else "good"),
        "legacyAndroidSupport": _item(bool(min_sdk is not None and min_sdk < 24), "warn" if (min_sdk is not None and min_sdk < 24) else "good"),
        "installationOnOldVersions": _item(bool(min_sdk is not None and min_sdk < 21), "warn" if (min_sdk is not None and min_sdk < 21) else "good"),
        "rootDetection": _item(has(r"root detection|rootbeer"), "good" if has(r"root detection|rootbeer") else "warn"),
        "fridaDetection": _item(has(r"frida|instrumentation"), "good" if has(r"frida") else "warn"),
        "screenshotProtection": _item(has(r"flag_secure|screenshot"), "good" if has(r"flag_secure|screenshot") else "warn"),
        "certificatePinning": _item(sumc.get("has_pinning"), "good" if sumc.get("has_pinning") else "warn"),
    }


# ═══════════════════════ Task 7 — network workspace ════════════════════════
def build_network_workspace(results: dict) -> None:
    nc = results.get("network_config") or {}
    sumc = nc.get("summary") or {}
    base = nc.get("base_config") or {}
    ta = base.get("trust_anchors") or {}
    eps = results.get("endpoints") or []
    domains = [d.get("domain") for d in (results.get("domain_intel") or []) if isinstance(d, dict) and d.get("domain")]
    if not domains:
        domains = sorted({re.sub(r"^[a-z]+://", "", u).split("/")[0] for u in eps if "://" in u})

    results["network_workspace"] = {
        "domains": domains,
        "urls": [u for u in eps if not _WS.match(u)],
        "websockets": [u for u in eps if _WS.match(u)],
        "endpoints": eps,
        "ips": results.get("ips") or [],
        "trust_anchors": {
            "system": ta.get("system"),
            "user": ta.get("user"),
            "custom": [c.get("src") for c in (ta.get("custom_certs") or []) if isinstance(c, dict)],
        },
        "cleartext_enabled": bool(sumc.get("cleartext_global")),
        "pinning_detected": bool(sumc.get("has_pinning")),
        "network_security_config": bool(nc.get("present")),
    }


# ═══════════════════════ Task 9 — taint graph (graph-ready) ═════════════════
def build_taint_graph(results: dict) -> None:
    # ONE canonical, source→sink-deduped list drives the Data Flow panel, its metrics
    # AND the PDF taint table, so the counts can never contradict. Each entry carries
    # call_site_count (multiple call sites of the same pair collapse into one row).
    # Calibrated severity is the single source of truth — never an "info" default.
    from .taint_analyzer import reconcile_taint_flows, explain_flow
    reconciled = reconcile_taint_flows(results)
    results["taint_flows_reconciled"] = reconciled
    graph = []
    for e in reconciled:
        # Plain-English copy so a non-security reader understands WHAT happens, WHY it
        # matters, and what the source/sink actually ARE. Additive fields.
        human = explain_flow(e.get("source_cat") or "", e.get("sink_cat") or "",
                             e.get("source") or "", e.get("sink") or "")
        graph.append({
            "id": f"taint:{e.get('source')}->{e.get('sink')}",
            "source": e.get("source"),
            "source_cat": e.get("source_cat"),
            "sink": e.get("sink"),
            "sink_cat": e.get("sink_cat"),
            "call_chain": e.get("call_chain") or [],
            "file": e.get("file") or "",
            "line": e.get("line") or 0,
            "method_name": e.get("method_name") or "",
            "risk": e.get("risk"),
            "call_site_count": e.get("call_site_count", 1),
            "call_sites": e.get("call_sites") or [],
            "plain_summary": human["plain_summary"],
            "why_it_matters": human["why_it_matters"],
            "source_explainer": human["source_explainer"],
            "sink_explainer": human["sink_explainer"],
        })
    results["taint_graph"] = graph


# ═══════════════════════ Orchestrator ══════════════════════════════════════
def annotate(results: dict) -> None:
    """Build every workspace structure. Each step is independently guarded so a
    failure in one never blocks the others or the scan."""
    for fn in (enrich_chains, build_permissions_workspace, build_certificate_workspace,
               build_android_posture, build_network_workspace, build_taint_graph):
        try:
            fn(results)
        except Exception:
            log.exception("[workspaces] %s failed", fn.__name__)
    log.info("[workspaces] perms=%d cert=%s posture=%s net_urls=%d taint=%d chains=%d",
             len(results.get("permissions_workspace") or []),
             bool(results.get("certificate_workspace")),
             bool(results.get("android_posture")),
             len((results.get("network_workspace") or {}).get("urls") or []),
             len(results.get("taint_graph") or []),
             len(_all_chains(results)))
