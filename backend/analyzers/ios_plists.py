"""Property Lists section for iOS (RUN 12) — enumerate every plist, surface what matters.

THREE RULES THIS MODULE ENFORCES

1. EVERY plist is read through ``plistlib``, never as text. 67 of this bundle's 69 plists are
   BINARY (bplist00). RUN 3 and RUN 4 both traced real bugs back to binary plists being treated
   as text: the generic scanner produced an empty snippet (so the Firebase key was silently
   dropped), and a "line 3" was reported that does not exist. plistlib decodes binary and XML
   transparently, so there is one read path and no garbage.

2. RAW BYTES ARE NEVER EMITTED. A plist ``data`` value is summarised ("<data: N bytes>"), and
   anything that looks like an image goes through apple_png.renderable_image_bytes() — the RUN
   5.1 gate — which converts an Apple CgBI PNG or returns None. A bundled iOS PNG passed
   through raw is an image no browser can decode (RUN 5).

3. IT CROSS-LINKS, IT DOES NOT RE-REPORT. ATS has its own section (RUN 10); the Firebase keys
   are already surfaced as INFO secrets (RUN 3); the usage descriptions are already in the
   Info.plist section (RUN 6). This section points at them and emits NO findings of its own —
   it is an enumeration surface, not a detection source.
"""
from __future__ import annotations

import os
import plistlib

from .apple_png import renderable_image_bytes

# Keys worth pulling out of any plist in the bundle, with where they are already reported.
SECURITY_KEYS = {
    "NSAppTransportSecurity": ("Network", "See the App Transport Security section (RUN 10)."),
    "NSAllowsArbitraryLoads": ("Network", "See the App Transport Security section."),
    "CFBundleURLTypes": ("URL Handling", "Custom URL schemes the app registers — deep-link surface."),
    "CFBundleURLSchemes": ("URL Handling", "Custom URL schemes the app registers — deep-link surface."),
    "LSApplicationQueriesSchemes": ("URL Handling", "Schemes the app can probe for on the device."),
    "NSUserTrackingUsageDescription": ("Privacy", "ATT prompt string — required to track across apps."),
    "UIFileSharingEnabled": ("Storage", "Exposes the app's Documents directory over USB/iTunes."),
    "LSSupportsOpeningDocumentsInPlace": ("Storage", "Documents opened in place from other apps."),
    "UIBackgroundModes": ("Platform", "Background execution capabilities."),
    "ITSAppUsesNonExemptEncryption": ("Crypto", "Export-compliance declaration."),
    "API_KEY": ("Secrets", "Already surfaced as an INFO secret (RUN 3) — not re-reported here."),
    "CLIENT_ID": ("Secrets", "Already surfaced as an INFO secret (RUN 3) — not re-reported here."),
    "GOOGLE_APP_ID": ("Secrets", "Already surfaced as an INFO secret (RUN 3)."),
    "STORAGE_BUCKET": ("Cloud", "Firebase storage bucket reference."),
    "PROJECT_ID": ("Cloud", "Firebase project identifier."),
}

# Keys whose VALUE is a credential. This surface must never print one in the clear: RUN 3
# surfaces the Firebase key as a MASKED secret (AIza…88rI), and the secret pipeline's
# cross-scrub only purges raw values from the secrets it knows about — it has never heard of
# results["property_lists"]. Enumerating a plist must not become a way to leak the secret the
# rest of the pipeline is careful to mask. Reuses secret_intel.mask_value, so there is ONE
# masking implementation, not a second one that drifts.
_SECRET_VALUE_KEYS = frozenset({"API_KEY", "CLIENT_ID", "GOOGLE_APP_ID", "GCM_SENDER_ID"})

_MAX_VALUE_CHARS = 160


def _summarize(value):
    """A safe, renderable summary of a plist value. NEVER returns raw bytes."""
    if isinstance(value, bytes):
        # The one place image bytes could reach a report. Route through the RUN 5.1 gate so a
        # CgBI PNG is converted (or rejected) rather than emitted as a broken image.
        std = renderable_image_bytes(value)
        kind = "image" if std else "data"
        return f"<{kind}: {len(value)} bytes>"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value if len(value) <= _MAX_VALUE_CHARS else value[:_MAX_VALUE_CHARS] + "…"
    if isinstance(value, list):
        return ", ".join(_summarize(v) for v in value[:8])[:_MAX_VALUE_CHARS] or "[]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {_summarize(v)}" for k, v in list(value.items())[:5]) + "}"
    return str(value)[:_MAX_VALUE_CHARS]


def _collect_security_keys(data, path=""):
    """Every SECURITY_KEYS hit anywhere in a plist, including nested dicts/arrays."""
    out = []
    if isinstance(data, dict):
        for key, value in data.items():
            here = f"{path}.{key}" if path else key
            if key in SECURITY_KEYS:
                category, note = SECURITY_KEYS[key]
                if key in _SECRET_VALUE_KEYS and isinstance(value, str):
                    from .secret_intel import mask_value
                    shown, masked = mask_value(value), True
                else:
                    shown, masked = _summarize(value), False
                out.append({"key": key, "path": here, "category": category,
                            "note": note, "value": shown, "masked": masked})
            out.extend(_collect_security_keys(value, here))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            out.extend(_collect_security_keys(item, f"{path}[{i}]"))
    return out


def _privacy_manifest(data: dict) -> dict:
    """Apple privacy manifest (PrivacyInfo.xcprivacy) declarations."""
    return {
        "tracking": bool(data.get("NSPrivacyTracking")),
        "tracking_domains": list(data.get("NSPrivacyTrackingDomains") or []),
        "accessed_api_types": [e.get("NSPrivacyAccessedAPIType", "")
                               for e in (data.get("NSPrivacyAccessedAPITypes") or [])
                               if isinstance(e, dict)],
        "collected_data_types": [e.get("NSPrivacyCollectedDataType", "")
                                 for e in (data.get("NSPrivacyCollectedDataTypes") or [])
                                 if isinstance(e, dict)],
    }


# Tracker categories that plausibly constitute "tracking" under Apple's ATT definition (data
# linked to a user/device and shared with a third party for advertising or measurement).
_TRACKING_CATEGORIES = ("Analytics", "Advertising", "Attribution", "Advertising/Analytics",
                        "Advertising/Attribution")


def build_privacy_declaration_finding(results: dict) -> dict | None:
    """The INTERSECTION of two independently-gathered evidence chains:

      RUN 11 (presence) — analytics / ad-attribution trackers are demonstrably IN the app
                          (framework, endpoint and statically-linked-symbol evidence), and
      RUN 12 (absence)  — NOT ONE of the bundle's property lists declares NSPrivacyTracking,
                          any NSPrivacyTrackingDomains entry, or NSUserTrackingUsageDescription.

    Deliberately MEDIUM and worded as a DISCREPANCY FOR REVIEW, not a confirmed violation:
    on-device conversion measurement and AdServices attribution are arguably NOT "tracking"
    under Apple's definition, so an ATT prompt may not be strictly required. Asserting a
    violation here would be the same overclaim Beetle refused to copy on AdMob (RUN 11) — the
    honest output is "these two facts do not line up; check them against the developer's actual
    data practices."

    Returns None whenever either chain is missing — no trackers, or a declaration present.
    """
    pl = results.get("property_lists") or {}
    pm = pl.get("privacy_manifests") or {}
    trackers = [t for t in (results.get("trackers") or [])
                if isinstance(t, dict) and str(t.get("category", "")).startswith(_TRACKING_CATEGORIES)]
    if not trackers:
        return None                     # no tracking SDKs → nothing to declare

    # Any declaration at all defeats the discrepancy.
    if pm.get("declares_tracking") or pm.get("tracking_domains"):
        return None
    declared_att = any(k["key"] == "NSUserTrackingUsageDescription"
                       for p in (pl.get("plists") or []) for k in (p.get("security_keys") or []))
    if declared_att:
        return None

    names = sorted({t["name"] for t in trackers})
    evidence = []
    for t in trackers:
        kinds = ", ".join(sorted({e["type"] for e in (t.get("evidence") or [])}))
        evidence.append(f"{t['name']} ({t['category']}; evidence: {kinds})")

    return {
        "rule_id": "ios_privacy_declaration_discrepancy",
        "title": "Tracking SDKs Present but Not Declared in Privacy Manifest / ATT",
        "severity": "medium",
        "category": "Privacy",
        "cwe": "CWE-359", "owasp": "M1", "masvs": "MASVS-PRIVACY-1",
        "description": (
            "The app ships analytics / advertising-attribution SDKs, but none of its property "
            "lists declare them.\n\n"
            f"PRESENT ({len(trackers)} tracking SDK(s), from framework / endpoint / "
            f"statically-linked-symbol evidence):\n  - " + "\n  - ".join(evidence) + "\n\n"
            f"NOT DECLARED (across all {pl.get('count', 0)} property lists, "
            f"{pm.get('count', 0)} privacy manifests):\n"
            "  - NSPrivacyTracking is not set true in any privacy manifest\n"
            "  - no NSPrivacyTrackingDomains entries\n"
            "  - no NSUserTrackingUsageDescription, so the app shows no ATT prompt\n\n"
            "THIS IS A DISCREPANCY FOR REVIEW, NOT A CONFIRMED VIOLATION. On-device conversion "
            "measurement and AdServices attribution are arguably not 'tracking' under Apple's "
            "ATT definition, so a prompt may not be strictly required. Confirm against the "
            "developer's actual data practices: if any of this data is linked to a user or "
            "device and shared for advertising, the declaration and the ATT prompt are required."
        ),
        "recommendation": (
            "Reconcile the app's privacy manifest (PrivacyInfo.xcprivacy) and Info.plist with "
            "what these SDKs actually collect. If data is linked to the user/device for "
            "advertising, set NSPrivacyTracking, list NSPrivacyTrackingDomains, and add "
            "NSUserTrackingUsageDescription plus an ATT request. If it is not, record why."
        ),
        # The app's own configuration — not vendor code. Per RUN 9's ownership-based severity
        # this is an app-owned finding, which is precisely what makes it actionable.
        "file_path": "Info.plist",
        "snippet": "NSPrivacyTracking / NSPrivacyTrackingDomains / NSUserTrackingUsageDescription: not declared",
        "owner_type": "Application",
        "confidence": 85,
        "evidence_type": "privacy_declaration",
        "provenance": "beetle_native",
        "tracking_sdks": names,
    }


def analyze(app_bundle: str, results: dict) -> None:
    """Populate results["property_lists"]. Emits NO findings — this is a surface."""
    if not app_bundle or not os.path.isdir(app_bundle):
        return

    plists, manifests = [], []
    binary_count = 0
    for root, _dirs, files in os.walk(app_bundle):
        for fname in files:
            low = fname.lower()
            if not (low.endswith(".plist") or low.endswith(".xcprivacy")):
                continue
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, app_bundle).replace("\\", "/")
            try:
                with open(full, "rb") as f:
                    head = f.read(8)
                is_binary = head[:6] == b"bplist"
                with open(full, "rb") as f:
                    data = plistlib.load(f)     # decodes BINARY and XML transparently
            except Exception as exc:
                plists.append({"path": rel, "format": "unreadable", "key_count": 0,
                               "security_keys": [], "error": str(exc)[:120]})
                continue

            if is_binary:
                binary_count += 1
            entry = {
                "path": rel,
                "format": "binary" if is_binary else "xml",
                "key_count": len(data) if hasattr(data, "__len__") else 0,
                "security_keys": _collect_security_keys(data) if isinstance(data, dict) else [],
            }
            if low.endswith(".xcprivacy") and isinstance(data, dict):
                pm = _privacy_manifest(data)
                pm["path"] = rel
                manifests.append(pm)
                entry["privacy_manifest"] = True
            plists.append(entry)

    plists.sort(key=lambda p: (p["path"].count("/"), p["path"].lower()))

    # Roll the privacy manifests up — 26 separate files is not a readable surface.
    domains = sorted({d for m in manifests for d in m["tracking_domains"]})
    api_types, data_types = {}, {}
    for m in manifests:
        for a in m["accessed_api_types"]:
            api_types[a] = api_types.get(a, 0) + 1
        for d in m["collected_data_types"]:
            data_types[d] = data_types.get(d, 0) + 1

    results["property_lists"] = {
        "count": len(plists),
        "binary_count": binary_count,
        "xml_count": len(plists) - binary_count,
        "with_security_keys": sum(1 for p in plists if p["security_keys"]),
        "plists": plists,
        "privacy_manifests": {
            "count": len(manifests),
            "declares_tracking": any(m["tracking"] for m in manifests),
            "tracking_domains": domains,
            "accessed_api_types": sorted(api_types.items(), key=lambda kv: -kv[1]),
            "collected_data_types": sorted(data_types.items(), key=lambda kv: -kv[1]),
        },
    }
