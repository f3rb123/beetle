import re
import math
import os
from .path_utils import relativize_path

# ─── Namespace ───────────────────────────────────────────────────────────────
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def ns(attr):
    return f"{{{ANDROID_NS}}}{attr}"


# ─── Entropy ─────────────────────────────────────────────────────────────────
def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ─── Severity helpers ─────────────────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ALLOWED_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Common aliases analyzers (or imported rules) sometimes emit
_SEVERITY_ALIASES = {
    "crit": "critical",
    "severe": "critical",
    "error": "high",
    "warn": "medium",
    "warning": "medium",
    "note": "low",
    "informational": "info",
    "information": "info",
    "none": "info",
    "": "info",
}


def normalize_severity(sev) -> str:
    """Case-insensitive, alias-tolerant severity normalization.
    Always returns one of ALLOWED_SEVERITIES.
    """
    if sev is None:
        return "info"
    s = str(sev).strip().lower()
    if s in ALLOWED_SEVERITIES:
        return s
    return _SEVERITY_ALIASES.get(s, "info")


def compute_severity_summary(findings) -> dict:
    """Recompute severity_summary from a findings list. Always returns all 5 keys."""
    summary = {k: 0 for k in ALLOWED_SEVERITIES}
    for f in findings or []:
        summary[normalize_severity(f.get("severity"))] += 1
    return summary


def sort_findings(findings):
    # Normalize in-place so downstream DB + UI never see mixed case.
    for f in findings or []:
        f["severity"] = normalize_severity(f.get("severity"))
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4))


# Phase 7 Task 5 — analyst prioritization. Reachable issues lead; within a
# reachability tier, exploitability (with a severity-derived floor so a critical
# never sinks below a low) then severity then confidence decide the order.
_REACHABILITY_ORDER = {"YES": 0, "MAYBE": 1, "NO": 2}
_EXPLOIT_FLOOR = {"critical": 85, "high": 65, "medium": 40, "low": 20, "info": 5}


def sort_findings_by_priority(findings):
    """Sort by: reachability → exploitability → severity → confidence.

    Reachable findings always appear before unreachable ones of equal severity,
    so the analyst sees what is actually exploitable first (never severity alone).
    """
    for f in findings or []:
        f["severity"] = normalize_severity(f.get("severity"))

    def key(f):
        reach = _REACHABILITY_ORDER.get(str(f.get("reachability", "MAYBE")).upper(), 1)
        sev = f.get("severity", "info")
        try:
            exploit = int(f.get("exploitability") or 0)
        except (TypeError, ValueError):
            exploit = 0
        eff_exploit = max(exploit, _EXPLOIT_FLOOR.get(sev, 5))
        try:
            conf = int(f.get("confidence_score") or 0)
        except (TypeError, ValueError):
            conf = 0
        return (reach, -eff_exploit, SEVERITY_ORDER.get(sev, 4), -conf)

    return sorted(findings or [], key=key)


# ─── Confidence ──────────────────────────────────────────────────────────────
ALLOWED_CONFIDENCE = ("high", "medium", "low")


def normalize_confidence(conf) -> str:
    if conf is None:
        return "medium"
    c = str(conf).strip().lower()
    return c if c in ALLOWED_CONFIDENCE else "medium"


# ─── Evidence snippets ───────────────────────────────────────────────────────
def attach_evidence(finding: dict, file_lines, context: int = 2) -> dict:
    """Attach a short code snippet around finding['line_number'] to `finding['evidence']`.

    file_lines: pre-split list of source lines (no trailing newline).
    Mutates and returns the finding. Silently no-ops if the line number is missing.
    """
    ln = finding.get("line_number")
    if not isinstance(ln, int) or ln <= 0 or not file_lines:
        return finding
    start = max(1, ln - context)
    end   = min(len(file_lines), ln + context)
    snippet = []
    for i in range(start, end + 1):
        marker = ">" if i == ln else " "
        line = file_lines[i - 1] if i - 1 < len(file_lines) else ""
        snippet.append(f"{marker} {i:5d} | {line[:300]}")
    finding["evidence"] = "\n".join(snippet)
    return finding


# ─── Deduplication ───────────────────────────────────────────────────────────
def dedupe_findings(findings):
    """Collapse duplicate findings emitted by multiple analyzers.

    Key = (rule_id or title, title, file_path, line_number). First wins;
    subsequent copies bump a `duplicates` counter on the retained finding.

    The title participates even when a rule_id is present: since v1.3 every
    detector carries a stable rule_id, and per-instance findings of one rule
    (e.g. one exported-component finding per component, all rule_id
    ``manifest_exported_service`` at the same manifest path) must NOT collapse
    into one. For findings that never had a rule_id the key is unchanged
    (title was already the identity).
    """
    seen = {}
    result = []
    for f in findings or []:
        key = (
            f.get("rule_id") or f.get("id") or f.get("title") or "",
            f.get("title") or "",
            f.get("file_path") or f.get("file") or "",
            f.get("line_number") or 0,
        )
        if key in seen:
            seen[key]["duplicates"] = seen[key].get("duplicates", 1) + 1
            continue
        seen[key] = f
        result.append(f)
    return result


# ─── Rule identity ────────────────────────────────────────────────────────────
def rule_slug(prefix: str, text: str) -> str:
    """Stable snake_case rule_id for rule-table detectors whose rules carry a
    title but no hand-assigned id (Flutter/RN/iOS-SAST rule tuples, secret
    patterns). Derived from the rule's TITLE — never from per-match values —
    so the id is constant across scans. Changing a rule's title changes its id
    (and detaches triage state keyed on it); prefer adding explicit ids when
    rules are renamed."""
    slug = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")[:48].rstrip("_")
    return f"{prefix}_{slug or 'rule'}"


# ─── Shared file index ───────────────────────────────────────────────────────
_FILE_INDEX_CACHE = {}


def build_file_index(root: str, max_files: int = 50000) -> list:
    """Walk `root` once, return list of (abs_path, rel_path, size, ext_lower).

    Cached per root for the process lifetime — analyzers that share a root
    reuse one walk instead of calling rglob repeatedly.
    """
    key = os.path.abspath(root)
    if key in _FILE_INDEX_CACHE:
        return _FILE_INDEX_CACHE[key]
    _SKIP = {"__MACOSX", "META-INF", ".git", "node_modules", "Pods", "Carthage", "DerivedData"}
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP]
        for name in filenames:
            if len(entries) >= max_files:
                break
            abs_p = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(abs_p)
            except OSError:
                continue
            rel = os.path.relpath(abs_p, root)
            ext = os.path.splitext(name)[1].lower()
            entries.append((abs_p, rel, size, ext))
        if len(entries) >= max_files:
            break
    _FILE_INDEX_CACHE[key] = entries
    return entries


def clear_file_index(root: str = None):
    if root is None:
        _FILE_INDEX_CACHE.clear()
    else:
        _FILE_INDEX_CACHE.pop(os.path.abspath(root), None)


def _norm_identifier(s: str) -> str:
    """Lowercase, strip all non-alphanumerics — so BRIEFLY_SHOW_PASSWORD and
    brieflyShowPassword normalize to the same token for name-vs-value comparison."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _value_is_its_own_field_name(value: str, context: str) -> bool:
    """True when the value is a bare identifier that equals the assignment's constant
    NAME (case-insensitive, ignoring separators) — a preference/resource KEY string,
    not a credential: e.g. `String BRIEFLY_SHOW_PASSWORD = "brieflyShowPassword";`.

    Requires the value to be a pure identifier (letters/underscores, no digits, no
    special chars, no spaces) so a value with real entropy is never mistaken for a
    key name."""
    if not value or not re.fullmatch(r"[A-Za-z][A-Za-z_]*", value):
        return False
    val_norm = _norm_identifier(value)
    if not val_norm:
        return False
    # Constant/field names that are assigned a string literal in the surrounding code.
    for name in re.findall(r"([A-Za-z_][A-Za-z0-9_]{2,})\s*=\s*['\"]", context or ""):
        if _norm_identifier(name) == val_norm:
            return True
    return False


def _looks_like_ui_password_false_positive(value: str, context: str) -> bool:
    value_lower = (value or "").lower()
    context_lower = (context or "").lower()

    # A value that is just its own constant/field name is a preference-key string,
    # not a password (brieflyShowPassword == BRIEFLY_SHOW_PASSWORD).
    if _value_is_its_own_field_name(value, context):
        return True

    # Known UI/label words that are never real passwords
    _UI_VALUES = {
        "password", "passwd", "newpassword", "confirmpassword", "currentpassword",
        "oldpassword", "repeatpassword", "enterpassword", "yourpassword",
        "visible-password", "textpassword", "inputtypepassword",
        "hint", "placeholder", "example", "sample", "test", "dummy",
        "none", "null", "empty", "default", "required", "change", "enter",
        "forgot", "reset", "update", "new", "old", "current", "repeat",
        "retype", "again", "confirm", "the", "a", "an", "this",
    }
    if value_lower in _UI_VALUES:
        return True

    # XML inputType or hint attributes
    if re.search(r'(?:inputType|hint|contentDescription|text)\s*=', context_lower):
        return True

    # Resource file paths (drawable names, layout names, etc.)
    if re.search(r'(?:drawable|layout|menu|anim|values|raw)/', context_lower):
        return True

    ui_terms = (
        "change_password", "forgot_password", "reset_password", "password_change",
        "password_reset", "showforgotpassword", "allowchangepassword",
        "enablepassword", "disablepassword", "password_hint", "passwordlabel",
        "visible-password", "textpassword", "password_type", "input_type",
    )
    if any(term in value_lower for term in ui_terms) or any(term in context_lower for term in ui_terms):
        return True

    # All-uppercase resource constant (e.g. CHANGE_PASSWORD_ACTION)
    if re.fullmatch(r"[A-Z0-9_]{8,}", value or ""):
        return True

    if re.search(r"(action|event|screen|button|label|title|hint|flag|toggle|allow|show|hide|change|forgot|reset|visible|invisible)", context_lower):
        return True

    if re.search(r"(resource|string|translation|i18n|event_name|analytics|drawable|layout|icon|image)", context_lower):
        return True

    # camelCase UI string (e.g. visiblePassword, changePasswordLabel)
    if re.fullmatch(r"[A-Za-z]+(?:[A-Z][A-Za-z0-9]+){2,}", value or ""):
        return True

    return False


# ─── Secret patterns ─────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "category": "Cloud",
        "description": "AWS Access Key ID found. If active, allows access to AWS resources.",
        "recommendation": "Rotate immediately. Use IAM roles or secrets managers instead.",
        "check_entropy": True,
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key[\'"\s:=]+([A-Za-z0-9/+=]{40})',
        "severity": "critical",
        "category": "Cloud",
        "description": "AWS Secret Access Key potentially found in app bundle.",
        "recommendation": "Rotate immediately. Never embed AWS credentials in client apps.",
        "check_entropy": True,
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "category": "Google",
        "description": "Google API Key found. May allow unauthorized API quota usage or data access depending on key restrictions.",
        "recommendation": "Restrict key to specific APIs and Android app fingerprints. Consider moving to server-side.",
        "check_entropy": True,
    },
    {
        "name": "Firebase Realtime Database URL",
        "pattern": r"https://[a-z0-9\-]+\.firebaseio\.com",
        "severity": "medium",
        "category": "Firebase",
        "description": "Firebase Realtime Database URL found. Check for unauthenticated read/write rules.",
        "recommendation": "Audit Firebase security rules. Ensure data requires authentication.",
    },
    {
        "name": "FCM Server Key",
        "pattern": r"AAAA[A-Za-z0-9\-_]{7}:[A-Za-z0-9\-_]{140}",
        "severity": "high",
        "category": "Firebase",
        "description": "Firebase Cloud Messaging server key found. Could allow sending push notifications to all app users.",
        "recommendation": "Move server keys to backend. Never include in client app.",
        "check_entropy": True,
    },
    {
        "name": "Stripe Live Secret Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "category": "Payment",
        "description": "Stripe live secret key found. Full access to payment processing and customer data.",
        "recommendation": "Rotate immediately. Stripe keys must never be in client-side code.",
        "check_entropy": True,
    },
    {
        "name": "Stripe Publishable Key (Live)",
        "pattern": r"pk_live_[0-9a-zA-Z]{24,}",
        "severity": "low",
        "category": "Payment",
        "description": "Stripe live publishable key found. Low risk but confirms live payment integration.",
        "recommendation": "Expected in client apps, but restrict to your domains in Stripe dashboard.",
    },
    {
        "name": "Stripe Test Key",
        "pattern": r"sk_test_[0-9a-zA-Z]{24,}",
        "severity": "medium",
        "category": "Payment",
        "description": "Stripe test secret key found in app. Should never be in production builds.",
        "recommendation": "Remove test keys from production builds. Use environment-specific build configs.",
        "check_entropy": True,
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "category": "Source Control",
        "description": "GitHub PAT detected. Could allow repository access or code exfiltration.",
        "recommendation": "Revoke immediately via GitHub Settings > Developer settings.",
        "check_entropy": True,
    },
    {
        "name": "Slack OAuth Token",
        "pattern": r"xox[baprs]-(?:[0-9]{10,}|[a-zA-Z0-9\-]{24,})",
        "severity": "high",
        "category": "Communication",
        "description": "Slack OAuth token found. May allow reading messages or posting to channels.",
        "recommendation": "Revoke token in Slack app settings. Use server-side OAuth flow.",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
        "severity": "high",
        "category": "Email",
        "description": "SendGrid API key found. Allows sending emails from your domain.",
        "recommendation": "Rotate key in SendGrid dashboard. Move to server-side only.",
        "check_entropy": True,
    },
    {
        "name": "Twilio Account SID",
        "pattern": r"\bAC[a-z0-9]{32}\b",
        "severity": "medium",
        "category": "Communication",
        "description": "Twilio Account SID found. When combined with Auth Token, provides full API access.",
        "recommendation": "Rotate if Auth Token is also exposed. Use server-side Twilio integration.",
    },
    {
        "name": "Twilio Auth Token",
        "pattern": r'(?i)twilio[_\-\s]*auth[_\-\s]*token[\'"\s:=]+([a-f0-9]{32})',
        "severity": "high",
        "category": "Communication",
        "description": "Twilio Auth Token found. Full API access including sending SMS and calls.",
        "recommendation": "Rotate immediately in Twilio console.",
    },
    {
        "name": "Mapbox Token",
        "pattern": r"pk\.eyJ1[a-zA-Z0-9\.\-_]+",
        "severity": "medium",
        "category": "Maps",
        "description": "Mapbox public access token found. May allow map tile usage under your account.",
        "recommendation": "Scope token to specific URLs and services in Mapbox token settings.",
    },
    {
        "name": "Hardcoded Password",
        "pattern": r'(?i)(?:password|passwd|pwd)\s*=\s*["\']([^\s"\'\\]{8,})["\']',
        "severity": "high",
        "category": "Credentials",
        "description": "Hardcoded password string detected in app resources.",
        "recommendation": "Remove hardcoded credentials. Use secure storage or server-side auth.",
    },
    {
        "name": "Generic API Key/Secret",
        "pattern": r'(?i)(?:api[_\-]?key|api[_\-]?secret|client[_\-]?secret|app[_\-]?secret)[\'"\s:=]+([a-zA-Z0-9\-_\.]{20,})',
        "severity": "medium",
        "category": "Credentials",
        "description": "Generic API key or secret string detected. Verify if active and sensitive.",
        "recommendation": "Validate if key is active. Consider server-side credential management.",
        "check_entropy": True,
    },
    # NOTE: "JWT Token (Hardcoded)" is intentionally absent here.
    # JWTs are detected by the dedicated scan_directory_for_jwts() scanner
    # (evidence_scanner.py). Including them in SECRET_PATTERNS causes double-
    # reporting across the Secrets and JWTs sections. Leave JWTs to the
    # dedicated scanner which provides better dedup and evidence attribution.
    {
        "name": "GCP Service Account Key",
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
        "category": "Cloud",
        "description": "Google Cloud Platform service account key embedded in app. Full GCP API access.",
        "recommendation": "Remove immediately. Revoke key in GCP IAM console. Use Workload Identity.",
    },
    {
        "name": "PEM Private Key",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "category": "Cryptographic Key",
        "description": "PEM-encoded private key found embedded in the app bundle.",
        "recommendation": "Remove from app immediately. Revoke and reissue associated certificates.",
    },
    {
        "name": "Facebook App Secret",
        "pattern": r'(?i)(?:facebook|fb)[_\-]?(?:app[_\-]?)?secret[\'"\s:=]+([a-f0-9]{32})',
        "severity": "high",
        "category": "Social",
        "description": "Facebook App Secret found. Allows server-side API calls on behalf of your app.",
        "recommendation": "Rotate in Meta Developer portal. This must never be in client apps.",
    },
    {
        "name": "Basic Auth in URL",
        "pattern": r"https?://[^\s:@/]+:[^\s:@/]+@[^\s/]+",
        "severity": "high",
        "category": "Credentials",
        "description": "Credentials embedded directly in a URL found in the app.",
        "recommendation": "Remove credentials from URLs. Use Authorization headers with secure storage.",
    },
    {
        "name": "Braze/Appboy SDK Key",
        "pattern": r'(?i)(?:braze|appboy)[_\-]?(?:api[_\-]?)?key[\'"\s:=]+["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?',
        "severity": "medium",
        "category": "Marketing",
        "description": "Braze (Appboy) API key detected. Could allow sending push notifications or accessing user profiles.",
        "recommendation": "Verify key has minimal permissions. Braze client keys have limited scope.",
    },
]

# ─── Dangerous Android Permissions ───────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS":         ("high",     "Read access to all contacts"),
    "android.permission.WRITE_CONTACTS":        ("high",     "Write/modify all contacts"),
    "android.permission.READ_SMS":              ("high",     "Read all SMS messages"),
    "android.permission.SEND_SMS":              ("high",     "Send SMS without user confirmation"),
    "android.permission.RECEIVE_SMS":           ("high",     "Intercept incoming SMS messages"),
    "android.permission.READ_CALL_LOG":         ("high",     "Read full call history"),
    "android.permission.WRITE_CALL_LOG":        ("high",     "Modify call history"),
    "android.permission.PROCESS_OUTGOING_CALLS":("high",     "Intercept and redirect outgoing calls"),
    "android.permission.CALL_PHONE":            ("high",     "Initiate calls without user interaction"),
    "android.permission.RECORD_AUDIO":          ("high",     "Access microphone at any time"),
    "android.permission.CAMERA":               ("medium",   "Access device camera"),
    "android.permission.ACCESS_FINE_LOCATION":  ("medium",   "Precise GPS location access"),
    "android.permission.ACCESS_COARSE_LOCATION":("low",      "Approximate network-based location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION":("high", "Location access even when app is in background"),
    "android.permission.READ_PHONE_STATE":      ("medium",   "Read device IMEI, phone number, network info"),
    "android.permission.GET_ACCOUNTS":          ("medium",   "Enumerate all accounts on device"),
    "android.permission.MANAGE_EXTERNAL_STORAGE":("high",    "Full unrestricted access to external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE":("medium",   "Write to external storage"),
    "android.permission.READ_EXTERNAL_STORAGE": ("low",      "Read from external storage"),
    "android.permission.BODY_SENSORS":          ("high",     "Access heart rate and health sensors"),
    "android.permission.ACTIVITY_RECOGNITION":  ("medium",   "Detect physical activity (walking, running, etc.)"),
    "android.permission.BLUETOOTH_SCAN":        ("medium",   "Scan nearby Bluetooth devices (also reveals location)"),
    "android.permission.BLUETOOTH_CONNECT":     ("medium",   "Connect to paired Bluetooth devices"),
    "android.permission.USE_BIOMETRIC":         ("low",      "Use biometric authentication hardware"),
    "android.permission.READ_MEDIA_IMAGES":     ("low",      "Read photo library"),
    "android.permission.READ_MEDIA_VIDEO":      ("low",      "Read video library"),
    "android.permission.READ_MEDIA_AUDIO":      ("low",      "Read audio library"),
    "android.permission.POST_NOTIFICATIONS":    ("low",      "Send push notifications"),
    "android.permission.REQUEST_INSTALL_PACKAGES":("high",   "Install other packages silently"),
    "android.permission.SYSTEM_ALERT_WINDOW":   ("high",     "Draw over other apps (overlay attack surface)"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":("high", "Read screen content and simulate user input"),
    "android.permission.BIND_DEVICE_ADMIN":     ("high",     "Device administrator — high privilege"),
    "android.permission.CHANGE_WIFI_STATE":     ("medium",   "Connect/disconnect from Wi-Fi networks"),
    "android.permission.INTERNET":              ("info",     "Internet access (expected but noted)"),
}

# ─── SDK Signatures ──────────────────────────────────────────────────────────
SDK_SIGNATURES = {
    "com.google.firebase":              ("Firebase",                    "Analytics/Backend", "info"),
    "com.google.firebase.crashlytics":  ("Firebase Crashlytics",        "Crash Reporting",   "info"),
    "com.amplitude":                    ("Amplitude Analytics",         "Analytics",         "info"),
    "com.mixpanel.android":             ("Mixpanel",                    "Analytics",         "info"),
    "io.branch":                        ("Branch.io",                   "Attribution",       "info"),
    "com.appsflyer":                    ("AppsFlyer",                   "Attribution",       "info"),
    "com.adjust.sdk":                   ("Adjust",                      "Attribution",       "info"),
    "com.braze":                        ("Braze (Appboy)",              "Marketing/Push",    "low"),
    "com.appboy":                       ("Braze Legacy (Appboy)",       "Marketing/Push",    "low"),
    "com.onesignal":                    ("OneSignal",                   "Push Notifications","info"),
    "com.google.android.gms.ads":       ("Google AdMob",                "Advertising",       "low"),
    "com.facebook.ads":                 ("Facebook Audience Network",   "Advertising",       "medium"),
    "com.applovin":                     ("AppLovin",                    "Advertising",       "low"),
    "com.ironsource":                   ("IronSource",                  "Advertising",       "low"),
    "com.unity3d.ads":                  ("Unity Ads",                   "Advertising",       "info"),
    "com.stripe.android":               ("Stripe SDK",                  "Payments",          "low"),
    "com.braintreepayments":            ("Braintree",                   "Payments",          "low"),
    "com.paypal.android":               ("PayPal SDK",                  "Payments",          "low"),
    "com.facebook.react":               ("React Native",                "Framework",         "info"),
    "io.flutter":                       ("Flutter",                     "Framework",         "info"),
    "com.facebook":                     ("Facebook SDK",                "Social",            "medium"),
    "com.squareup.okhttp3":             ("OkHttp3",                     "Networking",        "info"),
    "retrofit2":                        ("Retrofit2",                   "Networking",        "info"),
    "io.grpc":                          ("gRPC",                        "Networking",        "info"),
    "io.realm":                         ("Realm Database",              "Database",          "info"),
    "net.sqlcipher":                    ("SQLCipher",                   "Encrypted DB",      "info"),
    "com.scottyab.rootbeer":            ("RootBeer",                    "Root Detection",    "info"),
    "io.sentry":                        ("Sentry",                      "Crash Reporting",   "info"),
    "com.bugsnag":                      ("Bugsnag",                     "Crash Reporting",   "info"),
    "com.datadog":                      ("Datadog",                     "Monitoring",        "info"),
    "com.facebook.stetho":              ("Stetho (Debug Bridge)",       "Debug Tool",        "high"),
    "com.squareup.leakcanary":          ("LeakCanary (Debug Only)",     "Debug Tool",        "medium"),
    "com.instabug":                     ("Instabug",                    "Bug Reporting",     "low"),
    "com.google.android.play.core":     ("Play Core",                   "App Updates",       "info"),
    "com.mapbox":                       ("Mapbox SDK",                  "Maps",              "info"),
}


# ─── Precompiled secret patterns (hot path) ──────────────────────────────────
_COMPILED_SECRET_PATTERNS = None


def _get_compiled_secret_patterns():
    global _COMPILED_SECRET_PATTERNS
    if _COMPILED_SECRET_PATTERNS is None:
        compiled = []
        seen_names = set()
        for p in SECRET_PATTERNS:
            try:
                compiled.append((re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE), p))
                seen_names.add(p["name"])
            except re.error:
                continue
        # Phase 1.98 consolidation (reachability): extend this scanner with the
        # unified catalog's SECRET-kind patterns from the apkleaks + coverage
        # provenances that `common` does not already define (deduped by name). This
        # makes the JS-bundle / DEX-string / no-JADX-fallback paths — which use this
        # scanner — reach the SAME secrets as the main evidence walk (e.g. AWS
        # Cognito Identity Pool in a React Native bundle), without maintaining a
        # second pattern database. `common`'s false-positive filtering still applies.
        try:
            from .secret_catalog import patterns as _catalog_patterns
            for p in _catalog_patterns("apkleaks", "coverage"):
                if p.get("kind", "secret") != "secret" or p.get("name") in seen_names:
                    continue
                try:
                    compiled.append((re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE), p))
                    seen_names.add(p["name"])
                except re.error:
                    continue
        except Exception:  # noqa: BLE001 — never let catalog wiring break the base scanner
            pass
        _COMPILED_SECRET_PATTERNS = compiled
    return _COMPILED_SECRET_PATTERNS


_HEX_BULK_RE = re.compile(r"^[0-9a-fA-F]+$")


def scan_text_for_secrets(text: str, source_file: str = "") -> list:
    """Scan text content for secret patterns. Returns list of findings."""
    found = []
    seen = set()

    # Known crypto constants to exclude (DH primes, EC params etc.)
    CRYPTO_CONSTANT_PREFIXES = (
        "FFFFFFFF", "AAAA", "MIGE", "MIIB", "MIIC",
        "sha256/", "sha1/",
    )
    # Max secret value length — anything over 200 chars is a crypto constant
    MAX_SECRET_LEN = 200
    # Min entropy for high-entropy patterns (API keys, tokens)
    MIN_ENTROPY = 3.0

    for regex, pattern_info in _get_compiled_secret_patterns():
        try:
            for match in regex.finditer(text):
                if match.groups():
                    value = next((group for group in match.groups() if group), "")
                else:
                    value = match.group(0)
                if not value:
                    continue

                # Length cap — crypto constants are huge
                if len(value) > MAX_SECRET_LEN:
                    continue

                # Skip obvious crypto constants
                if any(value.upper().startswith(p.upper()) for p in CRYPTO_CONSTANT_PREFIXES):
                    continue

                # Skip pure hex strings > 40 chars (DH params, hashes embedded in code)
                if len(value) > 40 and _HEX_BULK_RE.match(value):
                    continue

                # Skip values that are clearly i18n / localised strings (non-ASCII heavy)
                ascii_ratio = sum(1 for c in value if ord(c) < 128) / max(len(value), 1)
                if ascii_ratio < 0.5:
                    continue

                # Entropy check for patterns that should be high-entropy
                if pattern_info.get("check_entropy", False):
                    if shannon_entropy(value) < MIN_ENTROPY:
                        continue

                context_start = max(0, match.start() - 60)
                context_end = min(len(text), match.end() + 60)
                context = text[context_start:context_end]

                if pattern_info["name"] == "Hardcoded Password" and _looks_like_ui_password_false_positive(value, context):
                    continue

                key = f"{pattern_info['name']}:{value[:30]}"
                if key in seen:
                    continue
                seen.add(key)

                found.append({
                    "name":           pattern_info["name"],
                    "category":       pattern_info["category"],
                    "severity":       pattern_info["severity"],
                    "value":          value,
                    "source":         os.path.basename(source_file),
                    "full_path":      source_file,
                    "description":    pattern_info["description"],
                    "recommendation": pattern_info["recommendation"],
                })
        except re.error:
            continue

    return found


def scan_files_for_secrets(base_dir: str, extensions: list = None) -> list:
    """Walk directory and scan text files for secrets."""
    if extensions is None:
        extensions = [".xml", ".json", ".properties", ".txt", ".js",
                      ".ts", ".html", ".plist", ".yaml", ".yml", ".gradle",
                      ".java", ".kt", ".swift", ".m", ".h", ".cfg", ".config",
                      ".env", ".strings"]

    all_secrets = []
    seen_global = set()
    # Noise subtrees — skipping avoids thousands of useless reads.
    _SKIP_DIRS = {"META-INF", "_CodeSignature", "__MACOSX", "node_modules",
                  "Pods", "Carthage", ".git", "DerivedData"}
    ext_set = {e.lower() for e in extensions}
    MAX_FILE_BYTES = 5 * 1024 * 1024

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            low = fname.lower()
            if not any(low.endswith(ext) for ext in ext_set):
                continue
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            rel_path = relativize_path(fpath, base_dir)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
                for s in scan_text_for_secrets(content, rel_path):
                    key = f"{s['name']}:{s['value']}"
                    if key not in seen_global:
                        seen_global.add(key)
                        all_secrets.append(s)
            except Exception:
                continue

    return all_secrets


def extract_urls(text: str) -> list:
    """Extract URLs from text, filtering obvious false positives."""
    url_pattern = re.compile(
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
        re.IGNORECASE
    )
    urls = set()
    for match in url_pattern.finditer(text):
        url = match.group(0).rstrip("\"',;)")
        # Filter noise
        if any(skip in url for skip in [
            "schemas.android.com", "schema.org", "www.w3.org",
            "play.google.com/store", "developer.android.com",
            "xmlns", "example.com", "test.com", "localhost",
        ]):
            continue
        if len(url) > 20:
            urls.add(url)
    return sorted(list(urls))
