"""
Evidence Engine — configuration (Beetle 2.0, Phase 1.5).

THE single tuning file: evidence-type/source vocabularies, the extension→type
map, per-source confidence priors, and the quality/verification thresholds. All
data, all documented. `engine.py` is logic only — adding an evidence type or
file kind is a one-line edit here.

Philosophy: *"A security finding is only as valuable as the evidence supporting
it."* These tables make evidence explainable, reproducible and verifiable.
"""
from __future__ import annotations

EVIDENCE_VERSION = "1.0.0"


# ════════════════════════════════════════════════════════════════════════════
# EVIDENCE TYPES — what kind of artifact an evidence item is
# ════════════════════════════════════════════════════════════════════════════
class EvidenceType:
    SOURCE_CODE = "SourceCode"
    DECOMPILED_JAVA = "DecompiledJava"
    KOTLIN = "Kotlin"
    SMALI = "Smali"
    SWIFT = "Swift"
    OBJC = "ObjectiveC"
    MANIFEST = "Manifest"
    INFO_PLIST = "InfoPlist"
    RESOURCE_XML = "ResourceXML"
    STRINGS_XML = "StringsXML"
    NETWORK_CONFIG = "NetworkSecurityConfig"
    JSON = "JSON"
    YAML = "YAML"
    GRADLE = "Gradle"
    CONFIGURATION = "Configuration"
    PROPERTIES = "Properties"
    DATABASE = "Database"
    SHARED_PREFERENCES = "SharedPreferences"
    ASSETS = "Assets"
    RAW_RESOURCES = "RawResources"
    BINARY = "Binary"
    MACH_O = "MachO"
    DEX = "DEX"
    NATIVE_LIBRARY = "NativeLibrary"
    JNI = "JNI"
    CERTIFICATE = "Certificate"
    CODE_SIGNATURE = "CodeSignature"
    WEBVIEW = "WebView"
    JAVASCRIPT = "JavaScript"
    HTML = "HTML"
    CSS = "CSS"
    SQL = "SQL"
    CALL_GRAPH = "CallGraph"
    TAINT_FLOW = "TaintFlow"
    DEPENDENCY = "Dependency"
    APK_METADATA = "APKMetadata"
    IPA_METADATA = "IPAMetadata"
    FLUTTER = "Flutter"
    REACT_NATIVE = "ReactNative"
    CORDOVA = "Cordova"
    CAPACITOR = "Capacitor"
    UNITY = "Unity"
    SECRET = "Secret"
    UNKNOWN = "Unknown"


# Evidence collection sources (which analyzer/technique produced the item).
class Source:
    DECOMPILER = "decompiler"        # jadx/apktool decompiled source
    MANIFEST_PARSER = "manifest_parser"
    BINARY_ANALYZER = "binary_analyzer"
    TAINT_ENGINE = "taint_engine"
    RESOURCE_PARSER = "resource_parser"
    CERT_PARSER = "cert_parser"
    SECRET_SCANNER = "secret_scanner"
    DEPENDENCY_SCANNER = "dependency_scanner"
    SEMGREP = "semgrep"
    HEURISTIC = "heuristic"
    UNKNOWN = "unknown"


# ════════════════════════════════════════════════════════════════════════════
# EVIDENCE QUALITY — how strong/verifiable the evidence is
# ════════════════════════════════════════════════════════════════════════════
class Quality:
    EXCELLENT = "Excellent"   # exact file+line+snippet+symbol; reproducible by line
    GOOD = "Good"             # exact file+line+snippet (no symbol) OR manifest line
    MODERATE = "Moderate"     # file+snippet but no line, class-level, or a taint chain
    WEAK = "Weak"             # class/heuristic reference only, no snippet
    MISSING = "Missing"       # no evidence at all


# ════════════════════════════════════════════════════════════════════════════
# VERIFICATION — how the finding can be (or was) verified
# ════════════════════════════════════════════════════════════════════════════
class Verification:
    VERIFIED = "Verified"                   # source resolved + line + snippet
    PARTIALLY_VERIFIED = "Partially Verified"
    DECOMPILER_ONLY = "Decompiler Only"
    MANIFEST_ONLY = "Manifest Only"
    BINARY_ONLY = "Binary Only"
    GENERATED = "Generated"
    NEEDS_REVIEW = "Needs Review"           # claimed evidence unresolved
    UNKNOWN = "Unknown"


# ════════════════════════════════════════════════════════════════════════════
# EXTENSION → (EvidenceType, decompiled-language?)  — file kind classification
# ════════════════════════════════════════════════════════════════════════════
EXT_TO_TYPE = {
    ".java": EvidenceType.DECOMPILED_JAVA, ".kt": EvidenceType.KOTLIN,
    ".kts": EvidenceType.KOTLIN, ".smali": EvidenceType.SMALI,
    ".swift": EvidenceType.SWIFT, ".m": EvidenceType.OBJC,
    ".mm": EvidenceType.OBJC, ".h": EvidenceType.OBJC,
    ".xml": EvidenceType.RESOURCE_XML, ".plist": EvidenceType.INFO_PLIST,
    ".json": EvidenceType.JSON, ".yaml": EvidenceType.YAML, ".yml": EvidenceType.YAML,
    ".gradle": EvidenceType.GRADLE, ".properties": EvidenceType.PROPERTIES,
    ".toml": EvidenceType.CONFIGURATION, ".ini": EvidenceType.CONFIGURATION,
    ".cfg": EvidenceType.CONFIGURATION, ".env": EvidenceType.CONFIGURATION,
    ".db": EvidenceType.DATABASE, ".sqlite": EvidenceType.DATABASE,
    ".realm": EvidenceType.DATABASE, ".so": EvidenceType.NATIVE_LIBRARY,
    ".dylib": EvidenceType.MACH_O, ".dex": EvidenceType.DEX,
    ".js": EvidenceType.JAVASCRIPT, ".jsx": EvidenceType.JAVASCRIPT,
    ".ts": EvidenceType.JAVASCRIPT, ".html": EvidenceType.HTML,
    ".htm": EvidenceType.HTML, ".css": EvidenceType.CSS, ".sql": EvidenceType.SQL,
    ".pem": EvidenceType.CERTIFICATE, ".cer": EvidenceType.CERTIFICATE,
    ".crt": EvidenceType.CERTIFICATE, ".der": EvidenceType.CERTIFICATE,
    ".p12": EvidenceType.CERTIFICATE, ".mobileprovision": EvidenceType.CODE_SIGNATURE,
}

# Special basenames / path tokens override the extension map.
BASENAME_TO_TYPE = {
    "androidmanifest.xml": EvidenceType.MANIFEST,
    "info.plist": EvidenceType.INFO_PLIST,
    "strings.xml": EvidenceType.STRINGS_XML,
    "buildconfig.java": EvidenceType.CONFIGURATION,
}
PATH_TOKEN_TO_TYPE = (
    ("network_security_config", EvidenceType.NETWORK_CONFIG),
    ("/res/raw/", EvidenceType.RAW_RESOURCES),
    ("/assets/", EvidenceType.ASSETS),
    ("/res/", EvidenceType.RESOURCE_XML),
    ("libflutter.so", EvidenceType.FLUTTER),
    ("flutter_assets", EvidenceType.FLUTTER),
    ("index.android.bundle", EvidenceType.REACT_NATIVE),
    ("/cordova", EvidenceType.CORDOVA),
    ("capacitor.config", EvidenceType.CAPACITOR),
    ("libunity.so", EvidenceType.UNITY),
    ("embedded.mobileprovision", EvidenceType.CODE_SIGNATURE),
)

# Languages that come from successful decompilation (source is human-readable).
DECOMPILED_TYPES = {
    EvidenceType.DECOMPILED_JAVA, EvidenceType.KOTLIN, EvidenceType.SWIFT,
    EvidenceType.OBJC, EvidenceType.SMALI, EvidenceType.JAVASCRIPT,
}
BINARY_TYPES = {
    EvidenceType.BINARY, EvidenceType.MACH_O, EvidenceType.DEX,
    EvidenceType.NATIVE_LIBRARY, EvidenceType.JNI,
}
MANIFEST_TYPES = {
    EvidenceType.MANIFEST, EvidenceType.INFO_PLIST, EvidenceType.NETWORK_CONFIG,
}


# ════════════════════════════════════════════════════════════════════════════
# PER-SOURCE CONFIDENCE PRIORS + EVIDENCE-ITEM SCORING (additive, capped at 100)
# ════════════════════════════════════════════════════════════════════════════
# Base credibility of an evidence item by where it came from.
SOURCE_BASE_CONFIDENCE = {
    Source.MANIFEST_PARSER: 90,    # structured, exact
    Source.CERT_PARSER: 90,
    Source.DECOMPILER: 80,         # real source, but decompilation can be lossy
    Source.TAINT_ENGINE: 78,
    Source.SEMGREP: 80,
    Source.BINARY_ANALYZER: 75,
    Source.RESOURCE_PARSER: 75,
    Source.DEPENDENCY_SCANNER: 80,
    Source.SECRET_SCANNER: 75,
    Source.HEURISTIC: 55,
    Source.UNKNOWN: 50,
}
ITEM_POINTS = {
    "line": 8,        # a precise line number
    "snippet": 8,     # the actual code/evidence text
    "symbol": 4,      # class/method/component identified
    "region": 2,      # highlighted region (end line/col)
}
ITEM_UNRESOLVED_CAP = 35   # a claimed-but-unresolved location is unreliable


# ════════════════════════════════════════════════════════════════════════════
# QUALITY THRESHOLDS — primary-item confidence → quality band (corroborated by
# the structural checks in engine.py; thresholds are the numeric backstop).
# ════════════════════════════════════════════════════════════════════════════
QUALITY_EXCELLENT_MIN = 88
QUALITY_GOOD_MIN = 72
QUALITY_MODERATE_MIN = 50
# below MODERATE_MIN → Weak (or Missing when there is no item at all)
