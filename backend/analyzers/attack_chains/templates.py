"""
Attack Chain Engine v2 — modular chain templates (Beetle 2.0, Phase 1.7).

Each template is a small, independent description of a realistic attacker journey:
its entry kind, the capability "slots" it REQUIRES (each filled by a distinct
eligible finding/component), optional SUPPORTING capabilities, the controls that
BLOCK it, and its goal/impact. The engine fills slots from the graph — there is
no giant if/else. Future engines add templates with :func:`register`.

Capabilities are deterministic tags derived by the engine from each finding
(category, taint source/sink, secret status, WebView flags, manifest flags, …).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ChainTemplate:
    id: str
    name: str
    type: str
    goal: str                       # GOAL_SEVERITY key
    summary: str
    impact: str
    entry_kind: str                 # external | distribution | device
    entry_caps: frozenset           # capabilities that count as the external entry
    entry_label: str
    required_slots: list            # list[frozenset[str]] — each slot = one required link
    slot_labels: list               # parallel human titles for each required slot
    supporting_caps: frozenset = frozenset()
    prerequisites: list = field(default_factory=list)
    mitigations: list = field(default_factory=list)
    blockers: list = field(default_factory=list)   # mitigation keys that break the chain
    priority: int = 50


def _ct(id, name, type, goal, *, summary, impact, entry_kind, entry_caps=(), entry_label="",
        required, slot_labels, supporting=(), prerequisites=(), mitigations=(),
        blockers=(), priority=50) -> ChainTemplate:
    return ChainTemplate(
        id=id, name=name, type=type, goal=goal, summary=summary, impact=impact,
        entry_kind=entry_kind, entry_caps=frozenset(entry_caps), entry_label=entry_label,
        required_slots=[frozenset(s) for s in required], slot_labels=list(slot_labels),
        supporting_caps=frozenset(supporting), prerequisites=list(prerequisites),
        mitigations=list(mitigations), blockers=list(blockers), priority=priority,
    )


_EXTERNAL = ("DEEPLINK", "EXPORTED")

TEMPLATES: list[ChainTemplate] = [
    _ct("WEBVIEW-JS-BRIDGE-RCE", "WebView JavaScript Bridge RCE", "JavaScript Interface Abuse",
        "rce", priority=100,
        summary="An externally reachable WebView with JavaScript enabled exposes a native "
                "JavaScript interface, letting attacker-controlled web content invoke app code.",
        impact="Execution of application/native methods from attacker-controlled JavaScript.",
        entry_kind="external", entry_caps=_EXTERNAL,
        entry_label="Attacker delivers a crafted URL/deep link to a browsable activity",
        required=[{"WEBVIEW_JS"}, {"JS_INTERFACE"}],
        slot_labels=["WebView enables JavaScript", "WebView exposes a native JavaScript interface"],
        supporting=("WEBVIEW_FILE", "WEBVIEW_SSL", "EXTERNAL_INPUT"),
        prerequisites=["A browsable/exported activity routes attacker input into the WebView"],
        mitigations=["Remove addJavascriptInterface or restrict to @JavascriptInterface on API 17+",
                     "Disable JavaScript unless required", "Validate/allow-list loaded URLs"]),

    _ct("DEEPLINK-WEBVIEW-FILE", "Deep Link to WebView File Disclosure", "WebView Abuse",
        "file_disclosure", priority=95,
        summary="A deep link drives a WebView that allows file access / ignores SSL errors, "
                "enabling local file disclosure or content injection.",
        impact="Disclosure of local files or injection of attacker content into app context.",
        entry_kind="external", entry_caps=("DEEPLINK",),
        entry_label="Attacker sends a crafted deep link",
        required=[{"WEBVIEW_JS", "WEBVIEW_FILE", "WEBVIEW_SSL"}],
        slot_labels=["WebView loads attacker-influenced content insecurely"],
        supporting=("WEBVIEW_FILE", "WEBVIEW_SSL"),
        mitigations=["setAllowFileAccess(false)", "Do not override onReceivedSslError",
                     "Restrict loaded origins"]),

    _ct("EXPORTED-INTENT-CMD-RCE", "Exported Component to Command Injection", "Command Injection",
        "command_injection", priority=92,
        summary="Attacker-controlled data from an exported component reaches an OS command sink.",
        impact="Arbitrary command execution in the app's context.",
        entry_kind="external", entry_caps=_EXTERNAL,
        entry_label="Malicious app/intent reaches an exported component",
        required=[{"CMD_SINK"}], slot_labels=["User-controlled data reaches a command-execution sink"],
        supporting=("EXTERNAL_INPUT",),
        mitigations=["Never pass untrusted input to Runtime.exec/ProcessBuilder",
                     "Validate and allow-list arguments"]),

    _ct("CODE-LOADING-RCE", "Dynamic Code Loading / Reflection RCE", "Dynamic Code Loading",
        "code_loading", priority=91,
        summary="Externally influenced input drives dynamic code loading or reflection.",
        impact="Loading/execution of attacker-controlled code.",
        entry_kind="external", entry_caps=("DEEPLINK", "EXPORTED", "EXTERNAL_INPUT"),
        entry_label="Attacker supplies external input",
        required=[{"CODE_LOADING"}], slot_labels=["External input drives dynamic code loading/reflection"],
        supporting=("EXTERNAL_INPUT",),
        mitigations=["Do not load classes/dex from untrusted sources", "Pin/verify loaded code"]),

    _ct("EXPORTED-INTENT-SQLI", "Exported Component to SQL Injection", "SQL Injection",
        "sql_injection", priority=90,
        summary="Attacker-controlled data from an exported component reaches a SQL query sink.",
        impact="Read/modify local database contents.",
        entry_kind="external", entry_caps=_EXTERNAL,
        entry_label="Malicious app/intent reaches an exported component",
        required=[{"SQL_SINK"}], slot_labels=["User-controlled data reaches a SQL query sink"],
        supporting=("EXTERNAL_INPUT",),
        mitigations=["Use parameterized queries", "Validate input from IPC"]),

    _ct("EXPORTED-PROVIDER-FILE", "Exported ContentProvider File Disclosure", "Content Provider Abuse",
        "file_disclosure", priority=88,
        summary="An exported ContentProvider exposes a file/path sink reachable by any app.",
        impact="Disclosure of private files via path traversal / provider queries.",
        entry_kind="external", entry_caps=("EXPORTED_PROVIDER", "EXPORTED"),
        entry_label="Malicious app queries an exported ContentProvider",
        required=[{"FILE_SINK"}], slot_labels=["Provider input reaches a file/path sink"],
        mitigations=["Set android:exported=false or enforce permissions",
                     "Canonicalize and confine file paths"]),

    _ct("CLEARTEXT-MITM-TOKEN", "Cleartext Traffic Token Theft", "Network Security",
        "token_theft", priority=85,
        summary="Cleartext HTTP (and/or disabled TLS validation) lets a network attacker read "
                "tokens/credentials in transit.",
        impact="Interception of session tokens, credentials or sensitive data.",
        entry_kind="external", entry_caps=("NETWORK",),
        entry_label="Attacker gains a network position (same Wi-Fi / MitM)",
        required=[{"CLEARTEXT"}], slot_labels=["App transmits data over cleartext HTTP"],
        supporting=("CERT_BYPASS", "SECRET", "TOKEN"),
        mitigations=["Enforce TLS via Network Security Config", "Enable certificate pinning"],
        blockers=["cert_pinning"]),

    _ct("CERT-BYPASS-MITM", "Disabled Certificate Validation MitM", "Certificate Validation",
        "mitm", priority=84,
        summary="The app disables/relaxes TLS certificate validation, enabling MitM interception.",
        impact="Man-in-the-middle interception of all 'secure' traffic.",
        entry_kind="external", entry_caps=("NETWORK",),
        entry_label="Attacker performs a man-in-the-middle on the network",
        required=[{"CERT_BYPASS"}], slot_labels=["Certificate/host validation is bypassed"],
        supporting=("SECRET", "TOKEN", "CLEARTEXT"),
        mitigations=["Use the platform TrustManager", "Enable certificate pinning"],
        blockers=["cert_pinning"]),

    _ct("HARDCODED-SECRET-ABUSE", "Hardcoded Secret / API Key Abuse", "Hardcoded Secrets",
        "credential_abuse", priority=80,
        summary="A real secret/API key is shipped in the app and is extractable by anyone who "
                "downloads it, enabling backend/API abuse.",
        impact="Unauthorized use of backend APIs / cloud resources with the leaked credential.",
        entry_kind="distribution", entry_label="Attacker downloads the distributed app and extracts strings",
        required=[{"SECRET"}], slot_labels=["A real secret is embedded in the application"],
        supporting=("API_KEY", "TOKEN"),
        prerequisites=["The app is publicly distributable (store or sideload)"],
        mitigations=["Move secrets server-side", "Use short-lived, scoped tokens", "Rotate the exposed key"]),

    _ct("INSECURE-STORAGE-THEFT", "Insecure Local Storage Theft", "Insecure Storage",
        "insecure_storage", priority=70,
        summary="Sensitive data is stored unencrypted on-device and can be read with device access.",
        impact="Theft of sensitive data from device storage.",
        entry_kind="device", entry_label="Attacker with device access (rooted / physical / malware)",
        required=[{"INSECURE_STORAGE"}], slot_labels=["Sensitive data stored without encryption"],
        supporting=("SECRET", "TOKEN"),
        prerequisites=["Rooted device, physical access, or co-resident malware"],
        mitigations=["Use EncryptedSharedPreferences / Keystore-backed encryption"]),

    _ct("BACKUP-DATA-EXTRACTION", "Backup-enabled Data Extraction", "Backup Abuse",
        "data_exposure", priority=68,
        summary="android:allowBackup permits extracting the app's private data via adb backup.",
        impact="Extraction of the app data directory without root.",
        entry_kind="device", entry_label="Attacker with ADB access runs adb backup",
        required=[{"BACKUP"}], slot_labels=["Application data is backup-eligible"],
        supporting=("INSECURE_STORAGE", "SECRET"),
        prerequisites=["USB debugging / ADB access to the device"],
        mitigations=["Set android:allowBackup=false", "Exclude sensitive data via backup rules"]),

    _ct("DEBUGGABLE-EXTRACTION", "Debuggable App Runtime Extraction", "Debuggable Abuse",
        "data_exposure", priority=66,
        summary="A debuggable build lets an attacker attach a debugger and read memory/secrets.",
        impact="Runtime inspection, memory/secret extraction, code tampering.",
        entry_kind="device", entry_label="Attacker with ADB / physical access attaches a debugger",
        required=[{"DEBUGGABLE"}], slot_labels=["Application is shipped debuggable"],
        prerequisites=["ADB / physical access"],
        mitigations=["Set android:debuggable=false in release builds"]),

    _ct("WEAK-CRYPTO-EXPOSURE", "Weak Cryptography Data Exposure", "Weak Cryptography",
        "weak_crypto", priority=60,
        summary="Sensitive data is protected with weak/broken cryptography that an attacker can defeat.",
        impact="Recovery of sensitive data protected by weak crypto.",
        entry_kind="distribution", entry_label="Attacker obtains ciphertext (from the app or storage)",
        required=[{"WEAK_CRYPTO"}], slot_labels=["Weak/broken cryptographic primitive in use"],
        supporting=("SECRET", "INSECURE_STORAGE"),
        mitigations=["Use AES-GCM / modern KDFs", "Avoid ECB/DES/MD5/SHA-1 for protection"]),
]


def register(template: ChainTemplate) -> None:
    """Register an additional chain template (future engines plug in here)."""
    TEMPLATES.append(template)
