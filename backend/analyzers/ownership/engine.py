"""
Ownership Engine — multi-stage classifier (Beetle 2.0, Phase 1.2).

Determines *who owns* the code a finding points at, with an explainable reason
and confidence, by running layered stages until one classifies:

  1. Package-prefix fingerprint  (framework / Google / OSS / vendor / Jetpack)
  2. Generated code              (R, BuildConfig, DataBinding, Dagger/Hilt, …)
  3. Application namespace        (declared app packages / manifest config)
  4. Embedded-framework path      (CocoaPods / Carthage / *.framework on disk)
  5. Class-signature             (Obj-C / Swift class prefixes — iOS)
  6. iOS application heuristic    (code under Payload/*.app, not a framework)
  7. Heuristic fallback          (obfuscation) → Unknown

Each stage either returns an :class:`OwnershipResult` or defers to the next. The
fingerprint matching is fully data-driven (``fingerprints.py``); the stage logic
here never needs editing to add an SDK.

The engine is pure and side-effect-free; :func:`annotate` is the only function
that writes back onto findings (additively).
"""
from __future__ import annotations

import logging
import os
import re

from ..canonical_finding import CanonicalFinding
from . import fingerprints as _fpdb
from .types import Confidence, OwnershipContext, OwnershipResult, OwnerType, Stage

log = logging.getLogger("cortex.ownership")

# Path root segments that prefix a decompiled package but are not part of it.
# Deliberately keeps "java"/"kotlin" (real top-level packages: java.lang, …).
_ROOT_SEGMENTS = {
    "sources", "resources", "smali", "apktool", "jadx", "apk_extract",
    "ipa_extract", "src", "main", "root", "original", "unknown", "classes",
}
_SMALI_CLASSES_RE = re.compile(r"^smali_classes\d+$")
_FRAMEWORK_PATH_RE = re.compile(r"/([A-Za-z0-9_+\-]+)\.framework/", re.I)
_POD_PATH_RE = re.compile(r"/Pods/([A-Za-z0-9_+\-]+)/", re.I)

# iOS: file extensions scanned as TEXT (real, reviewable source). Anything else in
# an .app bundle is a COMPILED binary whose reported "line" is a string-table offset,
# not a source line — so a hash/crypto/code-pattern token there is an offset-only
# match, not app source. Mirror of Android's libapp.so (Dart AOT) treatment.
_IOS_TEXT_EXTS = frozenset({
    ".swift", ".m", ".mm", ".h", ".c", ".cc", ".cpp", ".js", ".jsx", ".ts", ".tsx",
    ".json", ".plist", ".xml", ".strings", ".txt", ".html", ".css", ".storyboard", ".xib",
})
# A binary string-scan evidence path may carry a trailing ":<offset>" ("Runner:7173",
# "FirebaseCrashlytics:7173") — a string-table offset, not a source line.
_OFFSET_SUFFIX_RE = re.compile(r":\d+$")
# Dart AOT snapshot binaries (iOS Flutter): the app's compiled host executable and
# the Dart/Flutter runtime dylibs. Names are matched case-insensitively.
_IOS_AOT_BINARY_NAMES = frozenset({"libapp.dylib", "libflutter.dylib", "app"})
# Trees that are never a Java/Kotlin package root (after source roots are stripped).
# Deliberately does NOT include real package roots like "kotlin"/"okhttp3".
_NON_PACKAGE_ROOTS = {"res", "assets", "lib", "meta-inf", "build", "fabric"}

# A dotted string ending in a file extension is a FILENAME, not a class
# reference ("AndroidManifest.xml", "librdpdf.so"). Without this guard,
# _class_ref_package turned bare filenames into phantom packages
# ("AndroidManifest.xml" → package "androidmanifest.xml"), which blocked the
# application-config stage for every manifest finding.
_FILENAME_EXT_RE = re.compile(
    r"\.(?:java|kt|kts|xml|json|js|ts|smali|so|dex|txt|html|css|properties|"
    r"gradle|ya?ml|cfg|conf|config|plist|strings|swift|mm?|h|png|jpe?g|gif|"
    r"webp|pdf|bin|jar|aar|zip|apk|arsc|proto|md|dylib)$", re.I)


# ════════════════════════════════════════════════════════════════════════════
# Signal derivation
# ════════════════════════════════════════════════════════════════════════════
def _pkg_from_fqn(fqn: str) -> str:
    """Dotted package from a class FQN ('com.app.Foo$Bar' -> 'com.app')."""
    fqn = fqn.split("$", 1)[0]
    segs = [s for s in fqn.split(".") if s]
    if segs and segs[-1][:1].isupper():
        segs = segs[:-1]
    return ".".join(segs)


def _pkg_from_path(path: str) -> str:
    """Best-effort dotted package from a decompiled source path."""
    norm = path.replace("\\", "/").strip().lstrip("./")
    # JVM signature embedded as a path-ish string: Lcom/app/Foo;
    if norm.startswith("L") and "/" in norm and norm.rstrip().endswith(";"):
        return _pkg_from_fqn(norm[1:].rstrip(";").replace("/", "."))
    parts = [p for p in norm.split("/") if p]
    # Drop leading container dirs.
    i = 0
    while i < len(parts) and (parts[i] in _ROOT_SEGMENTS or _SMALI_CLASSES_RE.match(parts[i])):
        i += 1
    parts = parts[i:]
    if not parts:
        return ""
    # iOS: strip Payload/<App>.app/ wrapper before deriving.
    if parts and parts[0].lower() == "payload":
        parts = parts[1:]
        if parts and parts[0].lower().endswith(".app"):
            parts = parts[1:]
    if not parts:
        return ""
    if parts[0].lower() in _NON_PACKAGE_ROOTS:
        return ""
    # Drop trailing filename (anything with an extension).
    if "." in parts[-1]:
        parts = parts[:-1]
    return ".".join(parts)


def _class_ref_package(s: str) -> str:
    """Package from a dotted/JVM class reference, else ''."""
    t = (s or "").strip()
    if t.startswith("L") and "/" in t and t.rstrip().endswith(";"):
        return _pkg_from_fqn(t[1:].rstrip(";").replace("/", "."))
    if "/" in t or "\\" in t:
        return ""
    if _FILENAME_EXT_RE.search(t):
        return ""  # bare filename ("AndroidManifest.xml"), not a class reference
    if "." in t:
        return _pkg_from_fqn(t.rstrip(";"))
    return ""


def derive_signals(finding: CanonicalFinding) -> dict:
    """Extract the dotted identifier, simple class name and path from a finding.

    Tolerant of every signal Beetle carries: explicit package/class, file_path,
    JVM/dotted class references in taint flows, and source paths.
    """
    package = ""
    if finding.package:
        package = str(finding.package)
    elif finding.class_name and ("." in finding.class_name or "/" in finding.class_name):
        package = _class_ref_package(finding.class_name) or _pkg_from_fqn(finding.class_name)

    fpath = finding.file_path or ""
    if not package and fpath:
        package = _class_ref_package(fpath) or _pkg_from_path(fpath)
    # Last resort: a dotted class ref hiding in raw/method.
    if not package:
        for cand in (finding.raw.get("component"), finding.raw.get("class"),
                     finding.method_name):
            if cand and "." in str(cand):
                package = _class_ref_package(str(cand)) or _pkg_from_fqn(str(cand))
                if package:
                    break

    # Simple class name (original case) for class-signature / generated matching.
    class_simple = ""
    src = finding.class_name or finding.raw.get("component") or ""
    if src:
        seg = str(src).split("$", 1)[0].rstrip(";").replace("\\", "/").split("/")[-1].split(".")[-1]
        class_simple = seg
    if not class_simple and fpath:
        base = os.path.basename(fpath.replace("\\", "/"))
        class_simple = os.path.splitext(base)[0].split("$", 1)[0]
    if not class_simple and package:
        # Maybe `package` actually held a FQN whose last seg is the class.
        last = package.split(".")[-1]
        if last[:1].isupper():
            class_simple = last

    return {
        "package": package,
        "pkg_lower": package.lower(),
        "class_simple": class_simple,
        "file_path": fpath,
        "platform": (finding.platform or "unknown").lower(),
    }


# ════════════════════════════════════════════════════════════════════════════
# The engine
# ════════════════════════════════════════════════════════════════════════════
class OwnershipEngine:
    """Reusable ownership classifier. Build once, classify many."""

    def __init__(self, fingerprints: list[dict] | None = None,
                 generated_rules: list[dict] | None = None):
        records = fingerprints if fingerprints is not None else _fpdb.FINGERPRINTS
        self._generated = generated_rules if generated_rules is not None else _fpdb.GENERATED_CODE_RULES
        # Build the prefix index: (prefix_no_trailing_dot, record), longest first.
        index: list[tuple[str, dict]] = []
        self._path_records: list[dict] = []
        self._class_records: list[dict] = []
        for rec in records:
            for pref in rec.get("package_prefixes", ()):
                index.append((pref.rstrip(".").lower(), rec))
            if rec.get("path_tokens"):
                self._path_records.append(rec)
            if rec.get("class_prefixes"):
                self._class_records.append(rec)
        index.sort(key=lambda t: len(t[0]), reverse=True)  # longest-prefix wins
        self._prefix_index = index

    # ── platform gating ──────────────────────────────────────────────────────
    @staticmethod
    def _platform_ok(rec_platform: str, finding_platform: str) -> bool:
        if rec_platform == "both" or finding_platform in ("", "unknown"):
            return True
        if finding_platform in ("ios",):
            return rec_platform == "ios"
        return rec_platform in ("android",)

    # ── stage 1: package-prefix fingerprint ──────────────────────────────────
    def _match_prefix(self, sig: dict) -> OwnershipResult | None:
        pkg = sig["pkg_lower"]
        if not pkg:
            return None
        for prefix, rec in self._prefix_index:
            if not prefix:
                continue
            if (pkg == prefix or pkg.startswith(prefix + ".")) and \
                    self._platform_ok(rec["platform"], sig["platform"]):
                return self._result_from_record(rec, matched_prefix=prefix, signature=prefix)
        return None

    # ── stage 2: generated code ──────────────────────────────────────────────
    def _match_generated(self, sig: dict) -> OwnershipResult | None:
        cls = sig["class_simple"]
        pkg = sig["pkg_lower"]
        segs = set(pkg.split("."))
        path = sig["file_path"].lower()
        for rule in self._generated:
            if cls and cls in rule.get("exact_class", ()):
                return self._generated_result(rule, cls)
            for pref in rule.get("class_prefix", ()):
                if cls.startswith(pref):
                    return self._generated_result(rule, cls)
            for suf in rule.get("class_suffix", ()):
                if cls.endswith(suf):
                    return self._generated_result(rule, cls)
            for pref in rule.get("class_prefix_dollar", ()):
                # R$layout, R$string, … → still the generated R class
                if cls == pref or cls.startswith(pref + "$"):
                    return self._generated_result(rule, cls)
            if rule.get("package_segments", set()) & segs:
                return self._generated_result(rule, cls or pkg)
            for tok in rule.get("path_tokens", ()):
                if tok.lower() in path:
                    return self._generated_result(rule, tok)
        return None

    # ── stage 3: application namespace / app config ──────────────────────────
    def _match_application(self, sig: dict, finding: CanonicalFinding,
                           ctx: OwnershipContext) -> OwnershipResult | None:
        pkg = sig["pkg_lower"]
        for ns in ctx.application_namespaces():
            if pkg and (pkg == ns or pkg.startswith(ns + ".")):
                return OwnershipResult(
                    owner_type=OwnerType.APPLICATION, owner_name=ctx.app_name or "Application",
                    owner_confidence=Confidence.APPLICATION,
                    owner_reason="Package matches a declared application namespace.",
                    matched_package_prefix=ns, matched_rule="appns", matched_signature=ns,
                    classification_stage=Stage.APPLICATION_NAMESPACE)
        # Manifest / app-configuration findings are the app's own code/config.
        if not pkg and _is_app_config_finding(finding):
            return OwnershipResult(
                owner_type=OwnerType.APPLICATION, owner_name=ctx.app_name or "Application",
                owner_confidence=Confidence.APPLICATION,
                owner_reason="Application manifest / configuration finding.",
                matched_rule="app_config", matched_signature=finding.category or finding.evidence_type,
                classification_stage=Stage.APPLICATION_NAMESPACE)
        return None

    # ── stage 4: embedded framework / pods path ──────────────────────────────
    def _match_path(self, sig: dict) -> OwnershipResult | None:
        path = sig["file_path"]
        if not path:
            return None
        # iOS: a binary string-scan evidence path can be a BARE module name with an
        # offset suffix ("FirebaseCrashlytics:7173") — it has no /Pods/ or .framework/
        # context for the token matchers below. Synthesize the canonical Pods/<name>/
        # form so a known pod/framework fingerprint (Firebase, …) still matches, and
        # the generic pod fallback can name an otherwise-unknown bundled framework.
        # iOS-only + only when the path is a bare name (no separators), so Android and
        # real iOS paths are untouched.
        if sig["platform"] == "ios" and "/" not in path and "\\" not in path:
            bare = _OFFSET_SUFFIX_RE.sub("", path)
            stem, bext = os.path.splitext(bare)
            # Only a compiled/framework module normalizes to a pod — never a bare
            # SOURCE file ("Crypto.swift"), which must keep its application ownership.
            if stem and bext.lower() not in _IOS_TEXT_EXTS and stem.lower() not in ("app", "frameworks"):
                path = f"/Pods/{stem}/"
        low = path.lower()
        for rec in self._path_records:
            if not self._platform_ok(rec["platform"], sig["platform"]):
                continue
            for tok in rec["path_tokens"]:
                if tok.lower() in low:
                    return self._result_from_record(rec, signature=tok, stage=rec["stage"])
        # Unknown bundled framework / pod: clearly third-party, name from the path.
        m = _FRAMEWORK_PATH_RE.search(path) or _POD_PATH_RE.search(path)
        if m:
            name = m.group(1)
            if name.lower() not in ("app", "frameworks"):
                return OwnershipResult(
                    owner_type=OwnerType.THIRD_PARTY_SDK, owner_name=name,
                    owner_confidence=Confidence.EMBEDDED,
                    owner_reason=f"Bundled framework '{name}' present on disk (not application code).",
                    matched_rule="embedded_framework", matched_signature=m.group(0),
                    classification_stage=Stage.EMBEDDED_FRAMEWORK, sdk_name=name)
        return None

    # ── stage 5: class-signature (iOS / unknown platform only) ────────────────
    def _match_class(self, sig: dict) -> OwnershipResult | None:
        cls = sig["class_simple"]
        if not cls or sig["platform"] == "android":
            return None
        for rec in self._class_records:
            if not self._platform_ok(rec["platform"], sig["platform"]):
                continue
            for pref in rec["class_prefixes"]:
                if _class_prefix_match(cls, pref):
                    return self._result_from_record(rec, signature=pref, stage=Stage.CLASS_SIGNATURE)
        return None

    # ── stage 5.5: iOS Dart AOT / compiled-binary offset match ───────────────
    @staticmethod
    def _match_ios_binary(sig: dict) -> OwnershipResult | None:
        """A hash/crypto/code-pattern hit inside a COMPILED binary in the app bundle
        (the Dart AOT Mach-O — Payload/*.app/<exec>, libapp.dylib, App.framework/App —
        or any bundled .dylib) is an offset-only string-table match, not reviewable
        app source. Mirror Android's libapp.so treatment: classify it as a framework
        so it is demoted (INFO/library), never a HIGH application finding.

        Genuine app SOURCE (.swift/.m/.js/…) is NOT caught — it has a text extension
        and falls through to the iOS application heuristic, keeping its ownership.
        iOS-only; runs before the app-bundle heuristic. Android is never reached.
        """
        if sig["platform"] != "ios":
            return None
        raw = sig["file_path"] or ""
        if not raw:
            return None
        base = os.path.basename(_OFFSET_SUFFIX_RE.sub("", raw).replace("\\", "/"))
        ext = os.path.splitext(base)[1].lower()
        if ext in _IOS_TEXT_EXTS:
            return None  # real, reviewable source/text → keep app ownership
        low = raw.lower()
        name = base.lower()
        # Is this a compiled binary that lives in the app bundle / is a Dart-AOT dylib?
        in_app_bundle = ".app/" in low or "/payload/" in low
        is_dylib = ext in (".dylib", ".so", ".a")
        is_aot_name = name in _IOS_AOT_BINARY_NAMES
        if not (in_app_bundle or is_dylib or is_aot_name):
            return None
        aot = is_aot_name or is_dylib or "/frameworks/" in low
        owner_name = "Flutter (Dart AOT snapshot)" if (is_aot_name or "libapp" in name) \
            else ("Compiled binary" if not aot else "Bundled framework binary")
        return OwnershipResult(
            owner_type=OwnerType.OPEN_SOURCE_LIBRARY,
            owner_name=owner_name,
            owner_confidence=Confidence.EMBEDDED,
            owner_reason=("Offset-only match inside a compiled Mach-O/AOT binary "
                          "(no reviewable app source line); treated as framework, "
                          "not an application finding — mirrors the Android libapp.so "
                          "(Dart AOT) treatment."),
            matched_rule="ios_compiled_binary",
            matched_signature=base,
            classification_stage=Stage.EMBEDDED_FRAMEWORK,
            framework_name=owner_name)

    # ── stage 6: iOS application heuristic ───────────────────────────────────
    @staticmethod
    def _match_ios_app(sig: dict) -> OwnershipResult | None:
        if sig["platform"] != "ios":
            return None
        low = sig["file_path"].lower()
        if ".app/" in low and "/frameworks/" not in low and ".framework/" not in low \
                and "/pods/" not in low:
            return OwnershipResult(
                owner_type=OwnerType.APPLICATION, owner_name="Application",
                owner_confidence=Confidence.STRONG_HEURISTIC,
                owner_reason="Code located in the application bundle, not an embedded framework.",
                matched_rule="ios_app_bundle", matched_signature=".app/",
                classification_stage=Stage.HEURISTIC)
        return None

    # ── stage 7: heuristic fallback → Unknown ────────────────────────────────
    @staticmethod
    def _fallback(sig: dict) -> OwnershipResult:
        pkg = sig["pkg_lower"]
        if pkg and _looks_obfuscated(pkg):
            return OwnershipResult(
                owner_type=OwnerType.UNKNOWN, owner_name="",
                owner_confidence=Confidence.WEAK_HEURISTIC,
                owner_reason="Package appears obfuscated (R8/ProGuard); owner cannot be determined.",
                matched_signature=pkg, classification_stage=Stage.HEURISTIC)
        return OwnershipResult(
            owner_type=OwnerType.UNKNOWN, owner_name="",
            owner_confidence=Confidence.FALLBACK,
            owner_reason="No fingerprint, namespace or signature matched.",
            matched_signature=pkg, classification_stage=Stage.FALLBACK)

    # ── public classify ──────────────────────────────────────────────────────
    def classify(self, finding: CanonicalFinding, ctx: OwnershipContext | None = None) -> OwnershipResult:
        """Return the ownership of one finding. Pure — does not mutate input."""
        ctx = ctx or OwnershipContext(platform=(finding.platform or "unknown"))
        # An upstream pipeline decision outranks fingerprints: exported-component
        # findings are flagged app_owned_exposure because the EXPOSURE is declared
        # in the app's own manifest — the app owns it even when the component
        # class is implemented by a bundled SDK (android_analyzer Phase B).
        if finding.raw.get("app_owned_exposure"):
            return OwnershipResult(
                owner_type=OwnerType.APPLICATION,
                owner_name=ctx.app_name or "Application",
                owner_confidence=Confidence.APPLICATION,
                owner_reason=("Exported-component exposure declared in the application "
                              "manifest (app-owned even when the class is library code)."),
                matched_rule="app_exposure", matched_signature="app_owned_exposure",
                classification_stage=Stage.APPLICATION_NAMESPACE)
        sig = derive_signals(finding)
        for stage in (
            lambda: self._match_prefix(sig),
            lambda: self._match_generated(sig),
            lambda: self._match_application(sig, finding, ctx),
            lambda: self._match_path(sig),
            lambda: self._match_class(sig),
            lambda: self._match_ios_binary(sig),
            lambda: self._match_ios_app(sig),
        ):
            res = stage()
            if res is not None:
                return res
        return self._fallback(sig)

    def classify_package(self, package: str, platform: str = "android",
                         ctx: OwnershipContext | None = None) -> OwnershipResult:
        """Convenience: classify a bare package string (used heavily in tests)."""
        return self.classify(CanonicalFinding(title="_", package=package, platform=platform), ctx)

    # ── result builders ──────────────────────────────────────────────────────
    def _result_from_record(self, rec: dict, *, matched_prefix: str = "",
                            signature: str = "", stage: str | None = None) -> OwnershipResult:
        return OwnershipResult(
            owner_type=rec["type"], owner_name=rec["name"],
            owner_confidence=rec["confidence"], owner_reason=rec["reason"],
            matched_package_prefix=matched_prefix, matched_rule=f"fp:{rec['name']}",
            matched_signature=signature, classification_stage=stage or rec["stage"],
            sdk_name=rec.get("sdk_name", ""), framework_name=rec.get("framework_name", ""))

    @staticmethod
    def _generated_result(rule: dict, signature: str) -> OwnershipResult:
        return OwnershipResult(
            owner_type=OwnerType.GENERATED_CODE, owner_name=rule["name"],
            owner_confidence=Confidence.GENERATED, owner_reason=rule["reason"],
            matched_rule=f"generated:{rule['name']}", matched_signature=signature,
            classification_stage=Stage.GENERATED_CODE)

    # ── aggregate summary (additive, optional) ───────────────────────────────
    def summary(self, findings: list) -> dict:
        counts: dict[str, int] = {t: 0 for t in OwnerType.ALL}
        sdk_names: dict[str, int] = {}
        for f in findings or []:
            if not isinstance(f, dict):
                continue
            ot = f.get("owner_type") or OwnerType.UNKNOWN
            counts[ot] = counts.get(ot, 0) + 1
            name = f.get("owner_name")
            if name and ot not in (OwnerType.APPLICATION, OwnerType.UNKNOWN):
                sdk_names[name] = sdk_names.get(name, 0) + 1
        return {
            "by_owner_type": counts,
            "third_party_components": sorted(sdk_names.items(), key=lambda kv: -kv[1]),
            "total": sum(counts.values()),
        }


# ── module-level helpers ─────────────────────────────────────────────────────
def _class_prefix_match(class_simple: str, prefix: str) -> bool:
    """ObjC-style prefix match: prefix followed by an uppercase/digit/_ boundary.

    Case-sensitive so 'FIR' matches 'FIRApp' but never 'Firmware'.
    """
    if not class_simple.startswith(prefix):
        return False
    rest = class_simple[len(prefix):]
    return rest == "" or rest[0].isupper() or rest[0].isdigit() or rest[0] == "_"


def _looks_obfuscated(package: str) -> bool:
    """R8/ProGuard packages collapse to mostly 1-2 char segments (a.b.c.d)."""
    segs = [s for s in package.split(".") if s]
    if not segs:
        return False
    # jadx places classes stripped of their package (fully obfuscated) under a
    # synthetic `defpackage` container — that IS the obfuscation signal.
    if segs[0] == "defpackage":
        return True
    if len(segs) == 1:
        return len(segs[0]) <= 2
    short = sum(1 for s in segs if len(s) <= 2)
    return short >= max(1, (len(segs) + 1) // 2)


_APP_CONFIG_CATEGORIES = {
    "configuration", "manifest", "permissions", "network security",
    "deeplinks", "deeplink", "attack surface", "components", "component",
    "data storage", "backup", "code signing", "privacy",
    # The APK signing certificate is the application's own artifact.
    "certificate",
}


def _is_app_config_finding(finding: CanonicalFinding) -> bool:
    if (finding.evidence_type or "").lower() == "manifest":
        return True
    return (finding.category or "").lower() in _APP_CONFIG_CATEGORIES


# ── cached singleton + context builder + pipeline integration ────────────────
_ENGINE: OwnershipEngine | None = None


def get_engine() -> OwnershipEngine:
    """Process-wide engine (indices built once)."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = OwnershipEngine()
    return _ENGINE


def _derived_app_namespaces(results: dict, declared: tuple, platform: str) -> tuple:
    """Extra first-party namespaces from high-confidence manifest signals.

    Real apps routinely ship code outside the applicationId namespace (the
    Washington Post's applicationId is com.washingtonpost.android while its code
    lives in com.wapo.*). Two signals identify those namespaces with high
    confidence, and any candidate matching a known SDK/framework fingerprint is
    rejected so this can never claim library code for the app:

      1. the main/launcher activity's package — by definition the app's own
         entry point;
      2. a namespace owning a DOMINANT share of the manifest-declared
         components (>= 3 components and >= 25% of all components) — no
         bundled SDK contributes the majority of an app's manifest surface.
    """
    if platform != "android":
        return ()
    engine = get_engine()

    def _is_library(ns: str) -> bool:
        return engine._match_prefix({"pkg_lower": ns, "platform": platform}) is not None

    out: list[str] = []
    seen = {d.lower() for d in declared}

    def _accept(ns: str):
        ns = (ns or "").strip().lower()
        if ns and "." in ns and ns not in seen and not _is_library(ns):
            seen.add(ns)
            out.append(ns)

    info = results.get("app_info", {}) or {}
    main = str(info.get("main_activity") or "")
    if "." in main:
        _accept(_pkg_from_fqn(main))

    comps: list[str] = []
    surface = results.get("attack_surface") or {}
    for key in ("activities", "services", "receivers", "providers"):
        for c in surface.get(key) or []:
            name = c.get("name") if isinstance(c, dict) else c
            if name and "." in str(name):
                comps.append(str(name))
    if len(comps) >= 8:  # too few components → dominance is meaningless
        counts: dict[str, int] = {}
        for name in comps:
            segs = _pkg_from_fqn(name).split(".")
            if len(segs) >= 3:
                pref = ".".join(segs[:3]).lower()
                counts[pref] = counts.get(pref, 0) + 1
        threshold = max(3, len(comps) // 4)
        for ns, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            if n >= threshold:
                _accept(ns)
    return tuple(out)


def context_from_results(results: dict) -> OwnershipContext:
    """Build an OwnershipContext from a scan's results dict."""
    info = results.get("app_info", {}) or {}
    platform = str(results.get("platform") or info.get("platform") or "unknown").lower()
    if platform not in ("android", "ios"):
        platform = "ios" if info.get("bundle_id") else ("android" if info.get("package") else "unknown")
    app_packages = tuple(p for p in (
        info.get("package"), results.get("package"),
        *(results.get("extra_app_packages") or ()),
    ) if p)
    app_packages += _derived_app_namespaces(results, app_packages, platform)
    bundle_ids = tuple(b for b in (
        info.get("bundle_id"), info.get("bundle_identifier"),
    ) if b)
    app_name = str(results.get("app_name") or info.get("app_name") or "")
    return OwnershipContext(
        platform=platform, app_packages=app_packages, bundle_ids=bundle_ids,
        app_modules=tuple(m for m in (app_name,) if m), app_name=app_name)


def classify(finding: CanonicalFinding, ctx: OwnershipContext | None = None) -> OwnershipResult:
    """Public convenience: classify a single CanonicalFinding."""
    return get_engine().classify(finding, ctx)


# Owner types that denote library / framework / generated code — i.e. NOT the
# application's own code. Mirrors finding_model._LIB_OWNER_TYPES.
_LIBRARY_OWNER_TYPES = frozenset((
    OwnerType.THIRD_PARTY_SDK, OwnerType.ANDROID_FRAMEWORK, OwnerType.GOOGLE_SDK,
    OwnerType.APPLE_FRAMEWORK, OwnerType.VENDOR_SDK, OwnerType.OPEN_SOURCE_LIBRARY,
    OwnerType.GENERATED_CODE,
))


def is_library_owner(owner_type: str) -> bool:
    """True when an owner_type denotes library/framework/generated code (not the app)."""
    return owner_type in _LIBRARY_OWNER_TYPES


def classify_component_class(fqn: str, platform: str = "android",
                             ctx: OwnershipContext | None = None) -> OwnershipResult:
    """Ownership of a manifest component from its implementing class FQN.

    Reuses the shared engine + fingerprint DB — never a bespoke classifier — so a
    component backed by a library (androidx / io.flutter / com.google) is labeled
    identically to any other finding that points at that class.
    """
    return get_engine().classify(
        CanonicalFinding(title="_", class_name=fqn, platform=platform), ctx)


def enrich(finding: CanonicalFinding, ctx: OwnershipContext | None = None) -> CanonicalFinding:
    """Set ownership fields on a CanonicalFinding in place; returns it."""
    res = get_engine().classify(finding, ctx)
    finding.owner_type = res.owner_type
    finding.owner_name = res.owner_name
    finding.owner_confidence = res.owner_confidence
    finding.owner_reason = res.owner_reason
    finding.matched_package_prefix = res.matched_package_prefix or None
    finding.matched_rule = res.matched_rule
    finding.matched_signature = res.matched_signature
    finding.classification_stage = res.classification_stage
    if res.sdk_name:
        finding.sdk_name = res.sdk_name
    if res.framework_name:
        finding.framework_name = res.framework_name
    if res.matched_package_prefix:
        finding.package_prefix = res.matched_package_prefix
    return finding


def annotate(results: dict) -> dict:
    """Pipeline integration — enrich every finding dict with ownership metadata.

    ADDITIVE ONLY: writes the ownership fields (``owner_type``, ``owner_name``,
    …) onto each finding via dict.update; it never reads or rewrites existing
    finding data, so reports, exports and the UI are unaffected. Operates on the
    canonical model internally (dict → CanonicalFinding → classify → owner
    fields), with legacy dicts only at the edge.
    """
    ctx = context_from_results(results)
    engine = get_engine()
    enriched = 0
    for key in ("findings", "suppressed_findings"):
        for f in results.get(key) or []:
            if not isinstance(f, dict):
                continue
            cf = CanonicalFinding.from_legacy(f, platform=ctx.platform)
            f.update(engine.classify(cf, ctx).to_fields())
            enriched += 1
    results["ownership_summary"] = engine.summary(results.get("findings") or [])
    log.info("[ownership] %s | enriched %d findings | %s",
             ctx.platform, enriched, results["ownership_summary"]["by_owner_type"])
    return results
