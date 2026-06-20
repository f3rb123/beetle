import zipfile
import struct
import hashlib
import os
from datetime import datetime

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def analyze_certificate(apk_path: str, results: dict):
    """Extract and analyze APK signing certificate."""
    cert_info = {
        "available":        False,
        "subject":          {},
        "issuer":           {},
        "serial":           "",
        "valid_from":       "",
        "valid_to":         "",
        "expired":          False,
        "self_signed":      False,
        "debug_cert":       False,
        "signature_algo":   "",
        "key_type":         "",
        "key_size":         0,
        "sha1_fingerprint": "",
        "sha256_fingerprint": "",
        "scheme":           [],
        "security_overview": {},
    }

    # ── Detect signature scheme versions ─────────────────────────────────────
    try:
        with open(apk_path, "rb") as f:
            data = f.read()
        # V2/V3 signature block magic
        if b"APK Sig Block 42" in data:
            cert_info["scheme"].append("v2")
        if b"\x1a\x19\xf0\x50" in data:
            cert_info["scheme"].append("v3")
    except Exception:
        pass

    # ── Extract certificate from META-INF ─────────────────────────────────────
    raw_cert = None
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC")):
                    raw_pkcs7 = z.read(name)
                    raw_cert = _extract_cert_from_pkcs7(raw_pkcs7)
                    if raw_cert:
                        cert_info["scheme"].insert(0, "v1")
                    break
    except Exception:
        pass

    # If no v1 cert found, try androguard (handles v2/v3 APK Signature Scheme)
    if not raw_cert:
        try:
            try:
                from androguard.core.apk import APK as AndroAPK
            except ImportError:
                from androguard.core import APK as AndroAPK
            apk_obj = AndroAPK(apk_path)
            for candidate in _iter_androguard_certificate_candidates(apk_obj):
                raw_cert = _coerce_cert_bytes(candidate)
                if raw_cert:
                    break
        except Exception:
            pass

    if raw_cert and CRYPTO_AVAILABLE:
        try:
            cert = x509.load_der_x509_certificate(raw_cert, default_backend())
            cert_info["available"] = True

            # Subject
            cert_info["subject"] = _parse_name(cert.subject)
            cert_info["issuer"]  = _parse_name(cert.issuer)

            # Dates
            cert_info["valid_from"] = cert.not_valid_before_utc.strftime("%Y-%m-%d") if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before)
            cert_info["valid_to"]   = cert.not_valid_after_utc.strftime("%Y-%m-%d") if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after)

            # Expired?
            try:
                expiry = cert.not_valid_after_utc
                cert_info["expired"] = expiry < datetime.now(expiry.tzinfo)
            except Exception:
                pass

            # Self-signed?
            cert_info["self_signed"] = (cert.subject == cert.issuer)

            # Debug certificate detection
            subject_cn = cert_info["subject"].get("CN", "").lower()
            subject_o  = cert_info["subject"].get("O",  "").lower()
            cert_info["debug_cert"] = any(kw in subject_cn or kw in subject_o
                                          for kw in ["android debug", "test", "debug"])

            # Signature algorithm
            cert_info["signature_algo"] = cert.signature_algorithm_oid.dotted_string
            try:
                cert_info["signature_algo"] = cert.signature_hash_algorithm.name.upper() + "with" + cert.public_key().__class__.__name__.replace("_", "").upper()
            except Exception:
                pass

            # Public key
            pub = cert.public_key()
            try:
                cert_info["key_type"] = type(pub).__name__.replace("_CryptographyBackend", "").replace("Backend", "")
                cert_info["key_size"] = pub.key_size
            except AttributeError:
                try:
                    cert_info["key_size"] = pub.curve.key_size  # EC
                    cert_info["key_type"] = "EC"
                except Exception:
                    pass

            # Serial
            cert_info["serial"] = hex(cert.serial_number)

            # Fingerprints
            der = cert.public_bytes(serialization.Encoding.DER)
            cert_info["sha1_fingerprint"]   = ":".join(f"{b:02X}" for b in hashlib.sha1(der).digest())
            cert_info["sha256_fingerprint"] = ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())

        except Exception as e:
            cert_info["parse_error"] = str(e)

    elif raw_cert and not CRYPTO_AVAILABLE:
        # Minimal parsing without cryptography library
        cert_info["available"] = True
        cert_info["raw_sha256"] = hashlib.sha256(raw_cert).hexdigest()

    cert_info["security_overview"] = _build_signature_overview(cert_info, apk_path)
    results["certificate"] = cert_info

    # ── Generate findings from cert analysis ──────────────────────────────────
    if not cert_info["available"]:
        results["findings"].append({
            "title":       "Certificate Analysis Unavailable",
            "severity":    "info",
            "category":    "Certificate",
            "description": "Could not extract signing certificate from APK. The app may use APK Signature Scheme v2/v3 only without v1 signatures.",
        })
        return

    if cert_info.get("debug_cert"):
        results["findings"].append({
            "title":          "Debug Certificate Used to Sign APK",
            "severity":       "high",
            "category":       "Certificate",
            "description":    f"APK is signed with a debug certificate (CN: {cert_info['subject'].get('CN', '?')}). "
                               "Debug-signed APKs should never be released to production.",
            "impact":         "Debug certs are untrusted and the private key is widely known. The app may have debug features enabled.",
            "recommendation": "Re-sign with a proper production certificate. Generate a production keystore with `keytool`, "
                               "configure the release signingConfig in build.gradle, and verify with `apksigner verify --print-certs`.",
            "evidence":       _cert_evidence(cert_info),
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    # SHA-1 signature algorithm (MEDIUM). Generated here — not inline above — so
    # the evidence block can carry the full computed fingerprints.
    if "SHA1" in cert_info.get("signature_algo", "").upper():
        results["findings"].append({
            "title":          "Certificate Signed with SHA-1 — Collision Risk",
            "severity":       "medium",
            "category":       "Certificate",
            "description":    f"APK certificate uses {cert_info['signature_algo']}. SHA-1 is cryptographically broken "
                               "with practical collision attacks (SHAttered). Google has deprecated SHA-1 signed APKs.",
            "impact":         "A SHA-1 signature offers weaker integrity guarantees than SHA-256 and may be rejected by newer tooling/stores.",
            "recommendation": "Re-sign with SHA256withRSA or SHA256withECDSA and enable APK Signature Scheme v2+.",
            "evidence":       _cert_evidence(cert_info),
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    if cert_info.get("expired"):
        results["findings"].append({
            "title":          "Signing Certificate Expired",
            "severity":       "medium",
            "category":       "Certificate",
            "description":    f"The APK signing certificate expired on {cert_info['valid_to']}.",
            "recommendation": "Rotate to a new certificate before the current one expires.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    key_size = cert_info.get("key_size", 0)
    key_type = cert_info.get("key_type", "")
    if key_size and "rsa" in key_type.lower() and key_size < 2048:
        results["findings"].append({
            "title":          f"Weak RSA Signing Key — {key_size}-bit",
            "severity":       "medium",
            "category":       "Certificate",
            "description":    f"APK is signed with an RSA-{key_size} key. RSA keys below 2048 bits (e.g. 1024-bit) are "
                               "considered insecure and are deprecated by NIST and the CA/Browser Forum.",
            "impact":         "A 1024-bit RSA key is within reach of well-resourced factoring attacks, weakening signature trust.",
            "recommendation": "Re-key with RSA-2048 or higher, or switch to EC (P-256 / P-384) for smaller, stronger keys.",
            "evidence":       _cert_evidence(cert_info),
            "masvs":          "MASVS-CRYPTO-1",
            "owasp":          "M10",
        })

    # Self-signed (subject == issuer). Expected for Android app signing (no CA
    # chain), so INFO — but absent a debug cert it is still worth surfacing for
    # MobSF parity and to prompt signing-key verification. Skip when already
    # flagged as a debug cert (the stronger, more specific signal).
    if cert_info.get("self_signed") and not cert_info.get("debug_cert"):
        results["findings"].append({
            "title":          "Self-Signed Signing Certificate",
            "severity":       "info",
            "category":       "Certificate",
            "description":    "The APK is signed with a self-signed certificate (subject == issuer). "
                               "This is normal for Android app signing (there is no CA chain of trust), "
                               "but it means trust rests entirely on the signing key itself.",
            "impact":         "No certificate authority vouches for this identity; integrity trust is pinned to the raw signing key.",
            "recommendation": "Confirm the SHA-256 signing fingerprint matches your release key and is enrolled in Play App Signing, and keep the keystore protected.",
            "evidence":       _cert_evidence(cert_info),
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })

    if "v1" in cert_info["scheme"] and "v2" not in cert_info["scheme"]:
        results["findings"].append({
            "title":          "Only APK Signature Scheme v1 Used",
            "severity":       "medium",
            "category":       "Certificate",
            "description":    "APK uses only v1 (JAR) signatures. v1 does not protect all APK content and is vulnerable to Janus vulnerability (CVE-2017-13156).",
            "recommendation": "Enable both v1 and v2 signature schemes. v2 is mandatory for Android 7.0+.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })
    elif not any(scheme in cert_info["scheme"] for scheme in ("v2", "v3", "v4")):
        results["findings"].append({
            "title":          "Only Weak APK Signature Scheme Detected",
            "severity":       "medium",
            "category":       "Certificate",
            "description":    "The APK does not expose evidence of v2, v3, or v4 signing. Modern signature schemes provide stronger integrity coverage than legacy v1-only validation.",
            "recommendation": "Enable APK Signature Scheme v2 or higher for release builds.",
            "masvs":          "MASVS-CODE-4",
            "owasp":          "M7",
        })


def _cert_evidence(cert_info: dict) -> str:
    """Human-readable evidence block built from the parsed certificate facts.

    Certificate findings have no source line — their evidence IS the certificate
    metadata (subject, signing algorithm, key, fingerprint). Presenting it as a
    formatted block keeps these findings actionable and verifiable.
    """
    subj = cert_info.get("subject", {}) or {}
    subject_str = ", ".join(f"{k}={v}" for k, v in subj.items()) or "?"
    key_type = cert_info.get("key_type") or "?"
    key_size = cert_info.get("key_size") or 0
    lines = [
        f"Subject:           {subject_str}",
        f"Signature algo:    {cert_info.get('signature_algo') or '?'}",
        f"Public key:        {key_type} {key_size}-bit" if key_size else f"Public key:        {key_type}",
        f"Valid:             {cert_info.get('valid_from') or '?'} → {cert_info.get('valid_to') or '?'}",
        f"SHA-1 fingerprint: {cert_info.get('sha1_fingerprint') or '?'}",
        f"SHA-256 fingerprint: {cert_info.get('sha256_fingerprint') or '?'}",
        f"Signature schemes: {', '.join(cert_info.get('scheme') or []) or '?'}",
    ]
    return "\n".join(lines)


def _build_signature_overview(cert_info: dict, apk_path: str) -> dict:
    schemes = {scheme.lower() for scheme in cert_info.get("scheme", [])}
    v4_enabled = os.path.exists(f"{apk_path}.idsig") if apk_path else False
    flags = {
        "v1": "v1" in schemes,
        "v2": "v2" in schemes,
        "v3": "v3" in schemes,
        "v4": v4_enabled,
    }
    if flags["v1"] and not (flags["v2"] or flags["v3"] or flags["v4"]):
        overall = "Vulnerable"
    elif flags["v2"] or flags["v3"] or flags["v4"]:
        overall = "Secure"
    else:
        overall = "Limited visibility"

    return {
        "v1": {"enabled": flags["v1"], "label": "Enabled (Weak)" if flags["v1"] else "Disabled"},
        "v2": {"enabled": flags["v2"], "label": "Enabled" if flags["v2"] else "Disabled (Missing)"},
        "v3": {"enabled": flags["v3"], "label": "Enabled" if flags["v3"] else "Disabled"},
        "v4": {"enabled": flags["v4"], "label": "Enabled" if flags["v4"] else "Disabled"},
        "overall": overall,
        "janus_risk": flags["v1"] and not (flags["v2"] or flags["v3"] or flags["v4"]),
    }


def _extract_cert_from_pkcs7(pkcs7_data: bytes) -> bytes | None:
    """
    Minimal PKCS#7 SignedData parser to extract the first certificate.
    Returns DER-encoded certificate bytes or None.
    """
    try:
        # Find X.509 certificate marker in DER: SEQUENCE (0x30) tag
        # PKCS7 structure: SEQUENCE { OID signedData, [0] EXPLICIT SEQUENCE { ... certs ... } }
        # Simple approach: find all SEQUENCE headers and try to parse as cert
        pos = 0
        while pos < len(pkcs7_data) - 4:
            if pkcs7_data[pos] == 0x30:  # SEQUENCE tag
                # Try to read length
                length_byte = pkcs7_data[pos + 1]
                if length_byte == 0x82:  # 2-byte length
                    length = struct.unpack(">H", pkcs7_data[pos+2:pos+4])[0]
                    end = pos + 4 + length
                    if end <= len(pkcs7_data) and length > 100:
                        candidate = pkcs7_data[pos:end]
                        # Very basic heuristic: cert SEQUENCE should contain version, serial, algo, ...
                        if CRYPTO_AVAILABLE:
                            try:
                                from cryptography import x509
                                from cryptography.hazmat.backends import default_backend
                                x509.load_der_x509_certificate(candidate, default_backend())
                                return candidate
                            except Exception:
                                pass
                        elif length > 200:
                            return candidate  # best guess
            pos += 1
        return None
    except Exception:
        return None


def _iter_androguard_certificate_candidates(apk_obj):
    method_names = (
        "get_certificates_der_v3",
        "get_certificates_der_v2",
        "get_certificates_der",
        "get_certificates_v3",
        "get_certificates_v2",
        "get_certificates",
    )
    for method_name in method_names:
        method = getattr(apk_obj, method_name, None)
        if not callable(method):
            continue
        try:
            certs = method() or []
        except Exception:
            continue
        for cert in certs:
            yield cert


def _coerce_cert_bytes(candidate) -> bytes | None:
    if not candidate:
        return None
    if isinstance(candidate, bytes):
        return candidate
    try:
        return bytes(candidate)
    except Exception:
        pass
    for attr in ("dump", "public_bytes", "to_der"):
        fn = getattr(candidate, attr, None)
        if not callable(fn):
            continue
        try:
            if attr == "public_bytes" and CRYPTO_AVAILABLE:
                return fn(serialization.Encoding.DER)
            return fn()
        except Exception:
            continue
    return None


def _parse_name(name) -> dict:
    """Parse X.509 name into a dict."""
    result = {}
    try:
        for attr in name:
            try:
                key = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid.dotted_string)
                # Map common OIDs to short names
                oid_map = {
                    "commonName":           "CN",
                    "organizationName":     "O",
                    "organizationalUnitName": "OU",
                    "countryName":          "C",
                    "stateOrProvinceName":  "ST",
                    "localityName":         "L",
                    "emailAddress":         "E",
                }
                key = oid_map.get(key, key)
                result[key] = attr.value
            except Exception:
                continue
    except Exception:
        pass
    return result
