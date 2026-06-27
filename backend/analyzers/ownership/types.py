"""
Ownership Engine — core types (Beetle 2.0, Phase 1.2).

Defines the vocabulary (`OwnerType`), the explainable result object
(`OwnershipResult`), and the per-scan classification context
(`OwnershipContext`). These are intentionally tiny and dependency-free so every
analyzer can import them without pulling in the matching engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class OwnerType:
    """Closed vocabulary of ownership categories.

    Plain string constants (not an Enum) so they serialize directly into a
    finding dict / JSON and read identically in the UI, reports and the DB. New
    categories can be added here without touching engine logic — the engine
    treats the value as opaque data carried on each fingerprint record.
    """
    APPLICATION = "Application"
    THIRD_PARTY_SDK = "ThirdPartySDK"
    ANDROID_FRAMEWORK = "AndroidFramework"
    GOOGLE_SDK = "GoogleSDK"
    APPLE_FRAMEWORK = "AppleFramework"
    VENDOR_SDK = "VendorSDK"
    OPEN_SOURCE_LIBRARY = "OpenSourceLibrary"
    GENERATED_CODE = "GeneratedCode"
    UNKNOWN = "Unknown"

    ALL = (
        APPLICATION, THIRD_PARTY_SDK, ANDROID_FRAMEWORK, GOOGLE_SDK,
        APPLE_FRAMEWORK, VENDOR_SDK, OPEN_SOURCE_LIBRARY, GENERATED_CODE, UNKNOWN,
    )


class Stage:
    """Human-readable classification-stage labels (also stored on the finding).

    The order of the layered pipeline; each stage either classifies a finding or
    defers to the next. Stored verbatim in ``classification_stage`` so a reviewer
    can see *which* layer decided ownership.
    """
    EXACT_FINGERPRINT = "Exact Fingerprint"
    KNOWN_FRAMEWORK = "Known Framework"
    VENDOR_SDK = "Vendor SDK"
    OPEN_SOURCE = "Open Source Library"
    EMBEDDED_FRAMEWORK = "Embedded Framework"
    CLASS_SIGNATURE = "Class Signature"
    GENERATED_CODE = "Generated Code"
    APPLICATION_NAMESPACE = "Application Namespace"
    HEURISTIC = "Heuristic"
    FALLBACK = "Fallback"


# Canonical confidence anchors (see OWNERSHIP_ENGINE.md → Confidence model). Each
# decision must justify its number; these are the only values the engine assigns.
class Confidence:
    EXACT = 100          # exact SDK/library fingerprint (specific module prefix)
    FRAMEWORK = 98       # platform framework signature (android.*, Foundation, …)
    VENDOR = 95          # vendor/commercial SDK fingerprint
    OPEN_SOURCE = 95     # open-source library fingerprint
    GENERATED = 95       # unambiguous generated-code pattern (R, BuildConfig, …)
    APPLICATION = 90     # matches a declared application namespace
    EMBEDDED = 85        # bundled framework on disk, name not in DB (strong signal)
    STRONG_HEURISTIC = 80
    WEAK_HEURISTIC = 60
    FALLBACK = 30        # nothing matched — Unknown


@dataclass
class OwnershipResult:
    """The explainable outcome of classifying one finding.

    Maps 1:1 onto the ownership fields of :class:`CanonicalFinding`. Always
    carries a reason and a confidence so no decision is unexplained.
    """
    owner_type: str = OwnerType.UNKNOWN
    owner_name: str = ""
    owner_confidence: int = Confidence.FALLBACK
    owner_reason: str = ""
    matched_package_prefix: str = ""
    matched_rule: str = ""
    matched_signature: str = ""
    classification_stage: str = Stage.FALLBACK
    # Convenience derived labels (also written to the finding for downstream reuse).
    sdk_name: str = ""
    framework_name: str = ""

    def to_fields(self) -> dict:
        """The additive ownership fields to write onto a finding dict.

        Only ownership keys — never touches existing finding data. Safe to
        ``dict.update`` onto a legacy finding.
        """
        fields = {
            "owner_type": self.owner_type,
            "owner_name": self.owner_name,
            "owner_confidence": int(self.owner_confidence),
            "owner_reason": self.owner_reason,
            "matched_package_prefix": self.matched_package_prefix or None,
            "matched_rule": self.matched_rule,
            "matched_signature": self.matched_signature,
            "classification_stage": self.classification_stage,
        }
        if self.sdk_name:
            fields["sdk_name"] = self.sdk_name
        if self.framework_name:
            fields["framework_name"] = self.framework_name
        if self.matched_package_prefix:
            fields["package_prefix"] = self.matched_package_prefix
        return fields


@dataclass
class OwnershipContext:
    """Per-scan inputs that make application detection accurate.

    Beetle must NOT assume every unknown package is the application. This context
    carries every signal that identifies first-party code: the manifest package,
    iOS bundle id, extra namespaces (feature/dynamic modules, flavors, split
    APKs), and Swift/Obj-C module names. Build one per scan via
    :func:`context_from_results`.
    """
    platform: str = "unknown"               # "android" | "ios" | "unknown"
    app_packages: tuple[str, ...] = ()      # dotted application namespaces (Android)
    bundle_ids: tuple[str, ...] = ()        # iOS bundle identifiers
    app_modules: tuple[str, ...] = ()       # Swift / Obj-C module / product names
    app_name: str = ""

    # Mutable working set the engine fills with derived app-namespace variants.
    _namespaces: set = field(default_factory=set)

    def application_namespaces(self) -> set:
        """All dotted prefixes that denote first-party application code."""
        if self._namespaces:
            return self._namespaces
        ns: set[str] = set()
        for p in (*self.app_packages, *self.bundle_ids):
            p = (p or "").strip().lower()
            if p:
                ns.add(p)
        self._namespaces = ns
        return ns

    def application_modules(self) -> set:
        out = set()
        for m in (*self.app_modules, self.app_name):
            m = (m or "").strip()
            if m:
                out.add(m)
        return out
