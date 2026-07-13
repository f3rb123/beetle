"""Browsable Strings section (RUN 13) — both platforms.

THE HIGHEST SECRET-LEAK RISK SURFACE IN THE PRODUCT.

Everything else reports *about* strings; this section shows the strings themselves. The secret
pipeline masks only the fields it knows about — that is exactly how RUN 12 leaked the Firebase
API key in plaintext through a brand-new section. So every value here goes through
:func:`redact` BEFORE it can reach the report: if the string looks like a credential, only its
masked form is emitted, using secret_intel.mask_value (the SAME masking the secrets table uses —
one implementation, never a second that drifts).

The email sub-section exists to beat MobSF's, which is ~95% garbage. On this app the raw regex
yields 48 "emails" and 44 of them (91%) are Dart runtime symbols
(_AnonymousRestorationInformation@133124995.fromSerializableData). Those are rejected by
string_analyzer._is_real_email; this module adds the two classes it does not cover — printf
format-string hosts (%@.app-analytics-services.com) and library-internal addresses
(appro@openssl.org) — leaving only real addresses.
"""
from __future__ import annotations

import re

from .common import scan_text_for_secrets
from .secret_intel import mask_value
from .string_analyzer import _is_real_email

# A "local part" that is a printf/NSString format placeholder is not an address —
# "%@.app-analytics-services.com" is a runtime-assembled host (same class as RUN 1.1's
# format-string URLs).
_FORMAT_LOCAL_RE = re.compile(r"%[@sdiuf@]|%\d+\$")

# Library-internal contact addresses baked into vendor code. Real addresses, but they are the
# LIBRARY's, not the app's — reporting them as "emails found in the app" is noise.
_LIBRARY_EMAIL_DOMAINS = (
    "openssl.org", "example.com", "example.org", "sqlite.org", "gnu.org",
    "apache.org", "python.org", "golang.org",
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def is_reportable_email(value: str) -> bool:
    """True only for an address that is plausibly the APP's.

    Layer 1 — string_analyzer._is_real_email: kills the Dart-symbol class (leading underscore,
              all-digit domain label, camelCase pseudo-TLD). 91% of this app's raw hits.
    Layer 2 — here: format-string hosts and library-internal addresses.
    """
    v = (value or "").strip()
    if not _is_real_email(v):
        return False
    local, domain = v.split("@", 1)
    # A format placeholder anywhere in the local part: "%@.app-analytics-services.com" splits to
    # local="%", so requiring a character AFTER the % would miss it.
    if "%" in local or _FORMAT_LOCAL_RE.search(local):
        return False
    # An empty domain label ("@.app-…") is a malformed host, not an address.
    if any(not lbl for lbl in domain.split(".")):
        return False
    if any(domain.lower().endswith(d) for d in _LIBRARY_EMAIL_DOMAINS):
        return False
    return True


# Categories whose members are credential CANDIDATES by definition. string_analyzer already
# labels these "…(Potential Secret)" / key / token, so printing their raw value would be
# self-contradicting: the section says "this may be a secret" and then shows it.
_SECRET_CATEGORY_RE = re.compile(r"secret|key|token|credential|password|private", re.I)


def redact(value: str, category: str = "") -> tuple[str, bool]:
    """(display_value, was_masked). A credential-looking string is NEVER emitted in the clear.

    Two triggers:
      * the secret CATALOG matches the value (scan_text_for_secrets) — so the Strings section
        masks exactly what the secrets table considers a secret and cannot drift into showing a
        key the rest of the pipeline hides;
      * the value sits in a category that is ITSELF a credential class ("Base64 Encoded String
        (Potential Secret)"). Showing the raw value of a string the report has just called a
        potential secret would be the RUN 12 leak wearing a different hat.
    """
    v = str(value or "")
    if not v:
        return v, False
    if category and _SECRET_CATEGORY_RE.search(category):
        return mask_value(v), True
    try:
        hits = scan_text_for_secrets(v, "strings")
    except Exception:
        hits = []
    if hits:
        return mask_value(v), True
    return v, False


def build(results: dict, extra_emails=None) -> dict:
    """Build results["strings"] from what the scan already gathered. Emits NO findings."""
    sa = results.get("string_analysis") or {}

    categories = []
    for name, entry in sa.items():
        if not isinstance(entry, dict):
            continue
        matches = []
        for m in entry.get("matches") or []:
            if not isinstance(m, dict):
                continue
            shown, masked = redact(m.get("value", ""), name)
            matches.append({"value": shown, "masked": masked,
                            "files": (m.get("files") or [])[:5]})
        categories.append({
            "name": name,
            "severity": entry.get("severity", "info"),
            "description": entry.get("description", ""),
            "count": entry.get("count", len(matches)),
            "matches": matches,
        })
    categories.sort(key=lambda c: (-c["count"], c["name"]))

    # Emails: the string_analysis category (text files) + anything the caller harvested from the
    # binaries. Both go through the SAME two-layer filter.
    raw_emails = {m["value"] for m in (sa.get("Email Address") or {}).get("matches") or []
                  if isinstance(m, dict) and m.get("value")}
    raw_emails.update(extra_emails or [])
    kept = sorted(e for e in raw_emails if is_reportable_email(e))
    rejected = sorted(e for e in raw_emails if not is_reportable_email(e))

    return {
        "categories": categories,
        "category_count": len(categories),
        "total_matches": sum(c["count"] for c in categories),
        "masked_count": sum(1 for c in categories for m in c["matches"] if m["masked"]),
        "urls": sorted(results.get("endpoints") or [])[:500],
        "ips": sorted({i.get("ip") for i in (results.get("ips") or [])
                       if isinstance(i, dict) and i.get("ip")}),
        "emails": kept,
        "emails_rejected": len(rejected),
        "emails_rejected_sample": rejected[:5],
    }
