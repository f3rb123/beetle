"""
Secret Intelligence Engine — secret-type database + deterministic validators
(Beetle 2.0, Phase 1.4).

DATA + small pure validators. The engine reads this; adding a provider/type is a
one-record edit. Validation is deterministic wherever possible (format, base64/
hex/UUID structure, JWT/PEM structure, CRC32 checksums) — never live network.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import zlib

# ── kinds drive the base detection confidence + status hints ─────────────────
KIND_PROVIDER = "provider"      # specific provider prefix+format (AKIA…, ghp_…)
KIND_STRUCTURED = "structured"  # JWT / PEM private key — structurally validated
KIND_PUBLIC = "public"          # public key / certificate — not sensitive
KIND_CLIENT = "client"          # package/referrer-restricted CLIENT key (Firebase/GCP
                                # AIza…) — designed to ship in the app, NOT confidential
KIND_GENERIC = "generic"        # high-entropy token, no provider
KIND_WEAK = "weak"              # named "password"/"apikey" with low signal


def _t(type, provider, regex, *, kind=KIND_PROVIDER, checksum=None,
       structure=None, match="full", note=""):
    return {
        "type": type, "provider": provider,
        "regex": re.compile(regex),
        "kind": kind, "checksum": checksum, "structure": structure,
        "match": match, "note": note,
    }


# ════════════════════════════════════════════════════════════════════════════
# SECRET TYPE DATABASE  (priority order — first match wins)
# ════════════════════════════════════════════════════════════════════════════
SECRET_TYPES = [
    # ── Public material first, so a public key/cert is never called a secret ──
    _t("Certificate", "PEM", r"-----BEGIN CERTIFICATE-----",
       kind=KIND_PUBLIC, structure="pem_public", match="search"),
    _t("Public Key", "PEM", r"-----BEGIN (?:RSA |EC |DSA )?PUBLIC KEY-----",
       kind=KIND_PUBLIC, structure="pem_public", match="search"),
    _t("SSH Public Key", "SSH", r"ssh-(?:rsa|ed25519|dss) AAAA[0-9A-Za-z+/=]+",
       kind=KIND_PUBLIC, match="search"),

    # ── Private keys / PEM blocks ───────────────────────────────────────────
    _t("RSA Private Key", "PRIVATE_KEY", r"-----BEGIN RSA PRIVATE KEY-----",
       kind=KIND_STRUCTURED, structure="pem_private", match="search"),
    _t("EC Private Key", "PRIVATE_KEY", r"-----BEGIN EC PRIVATE KEY-----",
       kind=KIND_STRUCTURED, structure="pem_private", match="search"),
    _t("OpenSSH Private Key", "SSH", r"-----BEGIN OPENSSH PRIVATE KEY-----",
       kind=KIND_STRUCTURED, structure="pem_private", match="search"),
    _t("PGP Private Key", "PGP", r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
       kind=KIND_STRUCTURED, structure="pem_private", match="search"),
    _t("Private Key", "PRIVATE_KEY", r"-----BEGIN (?:DSA |ENCRYPTED )?PRIVATE KEY-----",
       kind=KIND_STRUCTURED, structure="pem_private", match="search"),

    # ── JWT ─────────────────────────────────────────────────────────────────
    _t("JWT", "JWT", r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*",
       kind=KIND_STRUCTURED, structure="jwt", match="search"),

    # ── Provider-prefixed API keys / tokens ─────────────────────────────────
    _t("AWS Access Key", "AWS",
       r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}"),
    # An AIza… key is the Android/browser/iOS CLIENT key shape: it is DESIGNED to
    # ship in the app and is restricted server-side by package name + signing SHA-1.
    # Google's own guidance treats it as public → classified as a client key, never a
    # confidential secret. Server-side Google credentials are DISTINCT shapes below
    # (FCM server key, OAuth client secret, service-account private key) and stay HIGH.
    _t("Google API Key", "GOOGLE", r"AIza[0-9A-Za-z_\-]{35}", kind=KIND_CLIENT,
       note="Firebase/GCP client key — package-restricted (SHA-1 + package), not confidential"),
    _t("Google OAuth Client Secret", "GOOGLE", r"GOCSPX-[0-9A-Za-z_\-]{28}"),
    _t("FCM Server Key", "FIREBASE", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}"),
    _t("Firebase Database URL", "FIREBASE",
       r"https://[a-z0-9\-]+\.firebaseio\.com", match="search"),
    _t("GitHub Token", "GITHUB", r"gh[pousr]_[0-9A-Za-z]{36,251}", checksum="github"),
    _t("GitHub Fine-grained PAT", "GITHUB", r"github_pat_[0-9A-Za-z_]{82}"),
    _t("GitLab Token", "GITLAB", r"glpat-[0-9A-Za-z_\-]{20}"),
    _t("Slack Token", "SLACK", r"xox[baprs]-[0-9A-Za-z\-]{10,72}"),
    _t("Slack Webhook", "SLACK",
       r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", match="search"),
    _t("Stripe Secret Key", "STRIPE", r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,99}"),
    _t("Stripe Publishable Key", "STRIPE", r"pk_(?:live|test)_[0-9A-Za-z]{16,99}"),
    _t("Twilio Account SID", "TWILIO", r"AC[0-9a-fA-F]{32}"),
    _t("Twilio API Key", "TWILIO", r"SK[0-9a-fA-F]{32}"),
    _t("SendGrid API Key", "SENDGRID", r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}"),
    _t("Mailgun API Key", "MAILGUN", r"key-[0-9a-f]{32}"),
    _t("OpenAI API Key", "OPENAI", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    _t("Anthropic API Key", "ANTHROPIC", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    _t("Telegram Bot Token", "TELEGRAM", r"\d{8,10}:[A-Za-z0-9_\-]{35}"),
    _t("Discord Bot Token", "DISCORD",
       r"[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}"),
    _t("Mapbox Token", "MAPBOX", r"(?:pk|sk)\.[A-Za-z0-9]{20,}\.[A-Za-z0-9]{20,}"),
    _t("npm Token", "NPM", r"npm_[0-9A-Za-z]{36}"),
    _t("Square Access Token", "SQUARE", r"(?:sq0atp|sq0csp|EAAA)[0-9A-Za-z_\-]{20,}"),
    _t("Shopify Token", "SHOPIFY", r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"),
    _t("DigitalOcean Token", "DIGITALOCEAN", r"dop_v1_[a-f0-9]{64}"),
    _t("Heroku API Key", "HEROKU",
       r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", note="uuid-form"),
    _t("Azure Storage Key", "AZURE",
       r"AccountKey=[0-9A-Za-z+/=]{80,}", match="search"),

    # ── Credentials in URLs / basic auth ────────────────────────────────────
    _t("Basic Auth in URL", "GENERIC",
       r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+", kind=KIND_GENERIC, match="search"),

    # ── UUID (commonly a false positive unless context says otherwise) ───────
    _t("UUID", "GENERIC",
       r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
       kind=KIND_WEAK, structure="uuid", note="often-fp"),

    # ── Generic high-entropy fallbacks ──────────────────────────────────────
    _t("Hex Secret", "GENERIC", r"[0-9a-fA-F]{32,}", kind=KIND_GENERIC, structure="hex"),
    _t("Base64 Secret", "GENERIC", r"[A-Za-z0-9+/]{24,}={0,2}", kind=KIND_GENERIC, structure="base64"),
]


def classify_value(value: str) -> dict | None:
    """Return the first secret-type record whose pattern matches ``value``."""
    if not value:
        return None
    v = value.strip()
    for rec in SECRET_TYPES:
        if rec["match"] == "search":
            if rec["regex"].search(v):
                return rec
        else:
            if rec["regex"].fullmatch(v):
                return rec
    return None


# ════════════════════════════════════════════════════════════════════════════
# DETERMINISTIC VALIDATORS
# ════════════════════════════════════════════════════════════════════════════
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_hex(s: str) -> bool:
    s = s.strip()
    return len(s) >= 2 and len(s) % 2 == 0 and bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def is_base64(s: str) -> bool:
    s = s.strip()
    if len(s) < 8 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return False
    try:
        base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def is_uuid(s: str) -> bool:
    return bool(re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        s.strip()))


def jwt_structure(value: str) -> tuple[bool, str]:
    """True when the value is a structurally valid JWT (header b64url→JSON w/ alg)."""
    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", value or "")
    if not m:
        return False, "no jwt"
    parts = m.group(0).split(".")
    if len(parts) != 3:
        return False, "wrong segment count"
    try:
        header_raw = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_raw))
    except Exception:
        return False, "header not base64url JSON"
    if not isinstance(header, dict) or "alg" not in header:
        return False, "header missing alg"
    return True, f"valid JWT (alg={header.get('alg')})"


def pem_structure(value: str) -> tuple[bool, str]:
    """Validate a PEM block has matching BEGIN/END and a base64 body."""
    m = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", value or "", re.S)
    if not m:
        # A lone BEGIN line (truncated capture) still indicates PEM material.
        if re.search(r"-----BEGIN [A-Z0-9 ]+-----", value or ""):
            return True, "PEM header present"
        return False, "no PEM block"
    body = re.sub(r"\s+", "", m.group(2))
    body = re.sub(r"Proc-Type.*|DEK-Info.*", "", body)
    try:
        base64.b64decode(body + "=" * (-len(body) % 4), validate=False)
        return True, f"valid PEM ({m.group(1).strip()})"
    except Exception:
        return False, "PEM body not base64"


_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b62(n: int) -> str:
    if n == 0:
        return "0"
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(_B62[r])
    return "".join(reversed(out))


def github_checksum_valid(token: str) -> bool | None:
    """GitHub-style CRC32/base62 checksum (last 6 chars of the body).

    Deterministic: the 6-char suffix is base62(crc32(body[:-6])) zero-padded.
    Returns True/False, or None when the token shape can't carry a checksum.
    Note: real GitHub tokens follow this scheme; a mismatch only drops the
    checksum signal, never the format-based classification.
    """
    m = re.fullmatch(r"gh[pousr]_([0-9A-Za-z]{36,251})", token or "")
    if not m:
        m = re.fullmatch(r"github_pat_([0-9A-Za-z_]{82})", token or "")
        if not m:
            return None
    body = m.group(1)
    if len(body) < 7:
        return None
    payload, checksum = body[:-6], body[-6:]
    expected = _b62(zlib.crc32(payload.encode()) & 0xFFFFFFFF).rjust(6, "0")
    return checksum == expected


def luhn_valid(number: str) -> bool | None:
    digits = [int(c) for c in re.sub(r"\D", "", number or "")]
    if len(digits) < 12:
        return None
    total, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def make_github_token(payload30: str = "ABCdef0123ABCdef0123ABCdef0123") -> str:
    """Helper (tests/tools): build a checksum-valid ghp_ token from a payload."""
    cs = _b62(zlib.crc32(payload30.encode()) & 0xFFFFFFFF).rjust(6, "0")
    return f"ghp_{payload30}{cs}"
