"""
Canonical Finding Model — Beetle 2.0, Phase 1.1.

This module defines the SINGLE typed source of truth for a security finding in
Beetle. Today the scan pipeline passes plain ``dict`` findings between ~25
analyzers and a 15-stage finalize pipeline, and every producer emits a slightly
different shape (``file`` vs ``path`` vs ``file_path``; ``id`` vs ``rule_id``;
numeric ``confidence`` vs textual; ``source`` vs ``source_module``; …). That
divergence is what makes ownership, confidence, suppression, attack-chain and
report logic hard to reason about and impossible to regression-test.

`CanonicalFinding` standardizes that shape WITHOUT changing Beetle's runtime
behavior. It is introduced here as the structural foundation that later phases
(Ownership Engine, Confidence Engine, Evidence Engine, Report v2) build on.

Design decisions
----------------
* **Stdlib ``dataclass``, not Pydantic.** Pydantic 2.x ships in the backend
  image via FastAPI, but this model is meant to be imported by *every* analyzer
  and exercised by host-side sanity tests. A dependency-free dataclass behaves
  identically on the prod interpreter (3.11) and a bare dev box, adds no import
  coupling to a foundational module, and lets us express this messy domain's
  lenient coercion explicitly. The codebase has no existing Pydantic
  domain-model pattern to follow — findings are plain dicts everywhere — so a
  dataclass is the lower-risk fit. This is a reversible decision: the public
  surface (``from_legacy`` / ``to_legacy`` / ``to_dict``) is implementation
  agnostic, so a future swap to Pydantic would not ripple to callers.

* **Lossless and non-destructive.** ``from_legacy(d)`` keeps the entire original
  detector ``dict`` in ``.raw``; ``to_legacy()`` returns that original dict with
  canonical keys *added* (never overwritten). So ``to_legacy(from_legacy(d))`` is
  always a superset of ``d`` — existing readers that depend on legacy keys keep
  working, while new code can rely on canonical names. Nothing is lost.

* **Placeholders only.** Fields for later phases (``owner_type``,
  ``ownership_label``, ``exploitability``, ``sdk_name``, ``package_prefix``,
  ``framework_name``, …) exist with safe defaults. This phase populates them
  ONLY by passively carrying a value the legacy finding already had — it never
  computes them. The engines arrive in later phases.

Backward-compatibility contract
-------------------------------
* ``from_legacy`` never raises on real-world finding dicts (it coerces / falls
  back instead). Use ``CanonicalFinding.validate()`` for non-raising warnings.
* ``to_legacy`` only ADDS keys; it never removes or rewrites an existing key.
* This module is NOT yet wired into the live finalize pipeline. Introducing the
  type is this phase's scope; migrating producers/consumers to it is a later one.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field, fields
from typing import Any, Iterable

log = logging.getLogger("cortex.canonical_finding")

# ── Severity vocabulary ──────────────────────────────────────────────────────
ALLOWED_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Aliases analyzers / imported rule packs sometimes emit. Kept locally so the
# model is self-sufficient, but `normalize_severity` delegates to the canonical
# `analyzers.common.normalize_severity` when it is importable (single source of
# truth) and only falls back to this table if that import is unavailable.
_SEVERITY_ALIASES = {
    "crit": "critical", "severe": "critical",
    "error": "high",
    "warn": "medium", "warning": "medium",
    "note": "low",
    "informational": "info", "information": "info", "none": "info", "": "info",
}

# Textual confidence → numeric 0-100 (canonical confidence is an int).
_CONFIDENCE_WORDS = {
    "high": 90, "medium": 60, "moderate": 60, "low": 30,
    "informational": 20, "info": 20, "none": 0, "": 0,
}

# Default ownership classification. Filled by the Ownership Engine (Phase 1.2);
# value matches ownership.OwnerType.UNKNOWN by string (no import coupling).
OWNER_UNKNOWN = "Unknown"


# ── Normalization helpers (reusable, dependency-free) ────────────────────────
def normalize_severity(value: Any) -> str:
    """Case-insensitive, alias-tolerant severity → one of ALLOWED_SEVERITIES.

    Delegates to ``analyzers.common.normalize_severity`` when importable so the
    whole codebase shares one normalizer; degrades to the local alias table
    otherwise (keeps this foundational model importable in isolation).
    """
    try:
        from .common import normalize_severity as _common_norm  # lazy: avoid cycles/heavy import
        return _common_norm(value)
    except Exception:
        if value is None:
            return "info"
        s = str(value).strip().lower()
        if s in ALLOWED_SEVERITIES:
            return s
        return _SEVERITY_ALIASES.get(s, "info")


def normalize_confidence(value: Any) -> int:
    """Coerce any confidence representation to an int in [0, 100].

    Accepts ints/floats (clamped), numeric strings, and the textual bands
    ``high``/``medium``/``low`` (mapped to 90/60/30). Unparseable → 0.
    """
    if value is None or value == "":
        return 0
    if isinstance(value, bool):  # guard: bool is an int subclass
        return 100 if value else 0
    if isinstance(value, (int, float)):
        return max(0, min(100, int(round(value))))
    s = str(value).strip().lower()
    if s in _CONFIDENCE_WORDS:
        return _CONFIDENCE_WORDS[s]
    try:
        return max(0, min(100, int(round(float(s)))))
    except (TypeError, ValueError):
        return 0


def severity_rank(severity: str) -> int:
    """0 (critical) … 4 (info); used for ordering and merge resolution."""
    return _SEVERITY_RANK.get(normalize_severity(severity), 4)


def _as_int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    try:
        n = int(round(float(value)))
    except (TypeError, ValueError):
        return None
    # A line/column of 0 means "unknown" in the legacy producers — normalize to None.
    return n if n > 0 else None


def _as_str_list(value: Any) -> list[str]:
    """Coerce scalar-or-list-or-comma-string standards/tags into a clean list."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",")]
        return [p for p in parts if p]
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for v in value:
            if v is None:
                continue
            s = str(v).strip()
            if s and s not in out:
                out.append(s)
        return out
    return [str(value).strip()]


def _first(d: dict, *keys: str) -> Any:
    """First present, non-empty value among ``keys`` in ``d``."""
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


# ── The canonical model ──────────────────────────────────────────────────────
@dataclass
class CanonicalFinding:
    """One security finding, in Beetle's single canonical shape.

    Field groups below map 1:1 to the information Beetle already collects; the
    docstrings note which later phase consumes each placeholder. Construct from
    a legacy producer dict via :meth:`from_legacy`; emit a backward-compatible
    dict via :meth:`to_legacy`.
    """

    # ── Identity & classification ────────────────────────────────────────────
    rule_id: str = ""               # stable detector/rule identifier (``id`` legacy alias)
    title: str = ""                 # short human-readable finding name
    severity: str = "info"          # normalized to ALLOWED_SEVERITIES
    platform: str = "unknown"       # "android" | "ios" | "unknown"
    category: str = ""              # e.g. "Taint Analysis", "Certificate", "WebView"

    # ── Location / evidence anchor ───────────────────────────────────────────
    file_path: str | None = None    # decompiled/resource path the finding points at
    package: str | None = None      # dotted owning package (``owner_package`` legacy alias)
    class_name: str | None = None   # owning class, when known
    method_name: str | None = None  # owning method, when known
    line: int | None = None         # 1-based line; None = unknown (legacy 0 → None)
    column: int | None = None       # 1-based column; None = unknown
    snippet: str | None = None      # the code/evidence snippet shown to the analyst

    # ── Detection provenance ─────────────────────────────────────────────────
    evidence_type: str = ""         # "regex_match" | "taint_flow" | "semgrep" | "manifest" | …
    confidence: int = 0             # 0-100 numeric confidence (canonical; see normalize_confidence)
    source_module: str = ""         # producing analyzer/source (``source`` legacy alias)
    discovery_method: str = ""      # how it was found (regex/taint/live-probe/…); later phases enrich

    # ── Knowledge / standards mapping ─────────────────────────────────────────
    references: list[str] = field(default_factory=list)  # external URLs / advisory links
    tags: list[str] = field(default_factory=list)        # free-form labels for filtering
    cwe: str | None = None                               # CWE id(s) as emitted
    masvs: list[str] = field(default_factory=list)       # OWASP MASVS control ids
    owasp: list[str] = field(default_factory=list)       # OWASP Mobile Top 10 ids

    # ── Suppression metadata ─────────────────────────────────────────────────
    suppressed: bool = False        # hidden from the default view (data is retained)
    suppressed_reason: str = ""     # why it was suppressed (FP class / library / low-value)

    # ── Attack-chain linkage ─────────────────────────────────────────────────
    attack_chain_eligible: bool = False  # MAY participate in a chain (policy set by a later phase)
    is_attack_chain: bool = False        # this finding IS a synthesized chain
    in_attack_chain: bool = False        # this finding is a member of a chain

    # ── False-positive metadata ──────────────────────────────────────────────
    false_positive: bool | None = None   # tri-state: None=unknown, True/False=analyst/engine verdict
    false_positive_reason: str = ""      # rationale for the FP verdict

    # ── Ownership metadata (Phase 1.2 — Ownership Engine) ─────────────────────
    # Who owns the code this finding points at. Populated by the Ownership Engine
    # (analyzers.ownership); defaults are safe so a finding that never passes
    # through the engine is simply "Unknown" with zero confidence. These fields
    # are the substrate the Confidence Engine, SDK suppression, Bug Bounty Mode,
    # attack chains, the AI reviewer and the report engine will all read.
    owner_type: str = OWNER_UNKNOWN          # OwnerType value (Application/ThirdPartySDK/…)
    owner_name: str = ""                     # human SDK/framework name, e.g. "AndroidX WorkManager"
    owner_confidence: int = 0                # 0-100 explainable ownership confidence
    owner_reason: str = ""                   # human-readable why, e.g. "Matched SDK fingerprint"
    matched_package_prefix: str | None = None  # the prefix that matched, e.g. "androidx.work"
    matched_rule: str = ""                   # id of the fingerprint/rule that fired
    matched_signature: str = ""              # the concrete signal matched (prefix/class-prefix/path token)
    classification_stage: str = ""           # which stage decided, e.g. "Exact Fingerprint"

    # ── Confidence metadata (Phase 1.3 — Confidence Engine) ───────────────────
    # How much Beetle trusts this finding, broken into independent, explainable
    # dimensions (each 0-100). Populated by analyzers.confidence. These NEVER
    # touch severity/exploitability scoring or suppression — they are a separate,
    # additive trust signal future engines (Bug Bounty Mode, AI Reviewer, SDK
    # suppression, report engine, dashboard) read. The legacy `confidence` /
    # `confidence_score` fields are left untouched for backward compatibility.
    detection_confidence: int = 0        # detector identified the right issue
    ownership_confidence: int = 0        # read directly from the Ownership Engine
    evidence_confidence: int = 0         # quality/quantity of verifiable evidence
    context_confidence: int = 0          # finding sits in meaningful application context
    exploitability_confidence: int = 0   # conservative likelihood-of-exploitation (NOT severity)
    overall_confidence: int = 0          # explainable weighted roll-up of the above
    confidence_reason: str = ""          # human-readable why
    confidence_breakdown: dict = field(default_factory=dict)  # full per-dimension detail (never hidden)
    confidence_stage: str = ""           # decision path: "Weighted"|"Validated"|"Import-Only"|…
    confidence_version: str = ""         # engine config version that produced these scores

    # ── Secret intelligence (Phase 1.4 — Secret Intelligence Engine) ──────────
    # For secret-bearing findings: the full multi-stage secret assessment (type,
    # provider, status, per-dimension confidence, validation results, reasons).
    # Empty {} for non-secret findings. Nested (not ~15 flat fields) to keep the
    # canonical schema clean. Populated by analyzers.secret_intelligence.
    secret_intelligence: dict = field(default_factory=dict)

    # ── Evidence bundle (Phase 1.5 — Unified Evidence Intelligence Engine) ─────
    # The structured, aggregated, multi-source Evidence object for this finding:
    # normalized evidence items (code/manifest/binary/taint/…), quality,
    # verification status, reproduction steps, correlation and a content hash.
    # Named `evidence_bundle` so it never collides with the legacy string
    # `evidence` snippet key or the `file_evidence` list (both preserved).
    # Populated by analyzers.evidence; empty {} until then.
    evidence_bundle: dict = field(default_factory=dict)

    # ── Other future-phase placeholders (carried, never computed here) ────────
    ownership_label: str | None = None   # legacy fine-grained label (finding_model); preserved
    exploitability: int | None = None    # 0-100 exploitability — Exploitability/Reachability phase
    validation_status: str = ""          # "detected"|"valid"|"invalid"|"skipped" — Validation phase
    sdk_name: str | None = None          # detected third-party SDK name (Ownership Engine convenience)
    package_prefix: str | None = None    # owning package prefix (Ownership Engine convenience)
    framework_name: str | None = None    # RN/Flutter/Xamarin/… — Framework detection phase

    # ── Raw / debug preservation ─────────────────────────────────────────────
    file_evidence: list[dict] = field(default_factory=list)  # [{path, lines, snippet}] multi-file evidence
    metadata: dict = field(default_factory=dict)             # structured extras we want addressable
    raw: dict = field(default_factory=dict)                  # the COMPLETE original detector payload

    # Canonical fields overlaid onto the legacy dict by ``to_legacy`` (added only
    # when absent, so the merge is non-destructive and lossless).
    _OVERLAY_FIELDS = (
        "rule_id", "title", "severity", "platform", "category",
        "file_path", "package", "class_name", "method_name", "line", "column",
        "snippet", "evidence_type", "confidence", "source_module",
        "discovery_method", "owner_type", "suppressed", "suppressed_reason",
        "is_attack_chain", "in_attack_chain", "attack_chain_eligible",
        "validation_status",
        # Ownership metadata (Phase 1.2)
        "owner_name", "owner_confidence", "owner_reason", "matched_package_prefix",
        "matched_rule", "matched_signature", "classification_stage",
        # Confidence metadata (Phase 1.3)
        "detection_confidence", "ownership_confidence", "evidence_confidence",
        "context_confidence", "exploitability_confidence", "overall_confidence",
        "confidence_reason", "confidence_breakdown", "confidence_stage",
        "confidence_version",
        # Secret intelligence (Phase 1.4)
        "secret_intelligence",
        # Evidence bundle (Phase 1.5)
        "evidence_bundle",
    )

    # ── Validation / normalization ───────────────────────────────────────────
    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.platform = (str(self.platform).strip().lower() or "unknown") if self.platform else "unknown"
        self.confidence = normalize_confidence(self.confidence)
        self.line = _as_int_or_none(self.line)
        self.column = _as_int_or_none(self.column)
        self.exploitability = _as_int_or_none(self.exploitability)
        self.owner_confidence = normalize_confidence(self.owner_confidence)
        # Confidence dimensions are each clamped 0-100 (Phase 1.3).
        self.detection_confidence = normalize_confidence(self.detection_confidence)
        self.ownership_confidence = normalize_confidence(self.ownership_confidence)
        self.evidence_confidence = normalize_confidence(self.evidence_confidence)
        self.context_confidence = normalize_confidence(self.context_confidence)
        self.exploitability_confidence = normalize_confidence(self.exploitability_confidence)
        self.overall_confidence = normalize_confidence(self.overall_confidence)
        if not isinstance(self.confidence_breakdown, dict):
            self.confidence_breakdown = {}
        if not isinstance(self.secret_intelligence, dict):
            self.secret_intelligence = {}
        if not isinstance(self.evidence_bundle, dict):
            self.evidence_bundle = {}
        self.references = _as_str_list(self.references)
        self.tags = _as_str_list(self.tags)
        self.masvs = _as_str_list(self.masvs)
        self.owasp = _as_str_list(self.owasp)
        if not isinstance(self.file_evidence, list):
            self.file_evidence = []
        if not isinstance(self.metadata, dict):
            self.metadata = {}
        if not isinstance(self.raw, dict):
            self.raw = {}
        # A finding must be identifiable; never raise (preserve output) — fall back.
        if not self.title:
            self.title = self.rule_id or "Untitled Finding"
        if not self.owner_type:
            self.owner_type = OWNER_UNKNOWN

    def _is_dependency_finding(self) -> bool:
        """True for supply-chain / vulnerable-dependency findings (CVE-MAP/OSV).

        Mirrors finding_model's dependency classification so the canonical model
        treats these as evidence-backed by identity rather than a source line.
        """
        src = (self.source_module or "").upper()
        if src in ("CVE-MAP", "OSV", "CVE", "OSV-SCANNER", "NATIVE", "PACKAGES"):
            return True
        cat = (self.category or "").lower()
        return ("dependenc" in cat or "supply chain" in cat
                or "vulnerable component" in cat)

    def validate(self) -> list[str]:
        """Return a list of non-fatal data-quality warnings (does not raise).

        Intended for the future regression harness: it can assert that no
        producer emits findings missing a rule_id / title / any evidence, etc.,
        without breaking a live scan. An empty list means "clean".
        """
        warnings: list[str] = []
        if not self.rule_id:
            warnings.append("missing rule_id")
        if self.title in ("", "Untitled Finding"):
            warnings.append("missing title")
        if self.severity not in ALLOWED_SEVERITIES:
            warnings.append(f"invalid severity: {self.severity!r}")
        # Evidence notion mirrors finding_model._has_extractable_evidence so the
        # canonical model and the existing evidence gate agree: a manifest
        # finding still awaiting enforcement carries its `component` /
        # `manifest_evidence_spec` (resolved to a real line later) and counts.
        has_evidence = (
            self.snippet or self.file_evidence or self.file_path or self.is_attack_chain
            or self.raw.get("component") or self.raw.get("manifest_evidence_spec")
            or self.raw.get("call_chain") or self.raw.get("taint_flow")
            # A vulnerable-dependency / CVE finding is evidenced by its component
            # identity + CVE id, not a source line (finding_model marks these
            # source_applicable=False yet keeps them as real findings).
            or self.raw.get("cve") or self._is_dependency_finding()
        )
        if not has_evidence:
            warnings.append("no extractable evidence")
        if not (0 <= self.confidence <= 100):
            warnings.append(f"confidence out of range: {self.confidence}")
        return warnings

    # ── Adapters ─────────────────────────────────────────────────────────────
    @classmethod
    def from_legacy(cls, data: dict, *, platform: str | None = None) -> "CanonicalFinding":
        """Build a CanonicalFinding from any legacy producer dict, losslessly.

        Tolerant of the field-name variations Beetle's analyzers emit today. The
        full original dict is preserved in ``.raw`` so :meth:`to_legacy` can
        round-trip without data loss. ``platform`` may be supplied by the caller
        (it usually lives at scan level, not on each finding).
        """
        if not isinstance(data, dict):
            raise TypeError(f"from_legacy expects a dict, got {type(data).__name__}")
        d = data

        # Confidence: prefer the pipeline-computed score when it is meaningful,
        # else the analyzer-supplied confidence.
        conf_score = d.get("confidence_score")
        if isinstance(conf_score, (int, float)) and conf_score > 0:
            confidence = conf_score
        else:
            confidence = _first(d, "confidence", "confidence_score")

        # Location: tolerate file/path/file_path and nested file_evidence/files.
        file_path = _first(d, "file_path", "file", "path")
        if file_path is None:
            fe = d.get("file_evidence")
            if isinstance(fe, list) and fe and isinstance(fe[0], dict):
                file_path = fe[0].get("path")
        if file_path is None:
            files = d.get("files")
            if isinstance(files, list) and files:
                file_path = files[0]

        snippet = _first(d, "snippet", "code_context")
        ev = d.get("evidence")
        if snippet is None and isinstance(ev, str):
            snippet = ev

        return cls(
            rule_id=str(_first(d, "rule_id", "id") or ""),
            title=str(_first(d, "title", "name") or ""),
            severity=d.get("severity", "info"),
            platform=str(_first(d, "platform") or platform or "unknown"),
            category=str(d.get("category") or ""),
            file_path=str(file_path) if file_path is not None else None,
            package=_opt_str(_first(d, "package", "owner_package", "pkg")),
            class_name=_opt_str(_first(d, "class_name", "className")),
            method_name=_opt_str(_first(d, "method_name", "method")),
            line=_first(d, "line", "line_number"),
            column=_first(d, "column", "col"),
            snippet=_opt_str(snippet),
            evidence_type=str(d.get("evidence_type") or ""),
            confidence=confidence,
            source_module=str(_first(d, "source_module", "source", "module") or ""),
            discovery_method=str(d.get("discovery_method") or ""),
            references=_first(d, "references", "refs") or [],
            tags=d.get("tags") or [],
            cwe=_opt_str(d.get("cwe")),
            masvs=d.get("masvs") or [],
            owasp=d.get("owasp") or [],
            suppressed=bool(d.get("suppressed", False)),
            suppressed_reason=str(_first(d, "suppressed_reason", "suppression_reason") or ""),
            attack_chain_eligible=bool(d.get("attack_chain_eligible", False)),
            is_attack_chain=bool(d.get("is_attack_chain", False)),
            in_attack_chain=bool(d.get("in_attack_chain", False)),
            false_positive=d.get("false_positive"),
            false_positive_reason=str(d.get("false_positive_reason") or ""),
            # Ownership metadata: carried only if the legacy finding already had it
            # (the Ownership Engine populates it; from_legacy never computes it).
            owner_type=str(d.get("owner_type") or OWNER_UNKNOWN),
            owner_name=str(d.get("owner_name") or ""),
            owner_confidence=d.get("owner_confidence") or 0,
            owner_reason=str(d.get("owner_reason") or ""),
            matched_package_prefix=_opt_str(d.get("matched_package_prefix")),
            matched_rule=str(d.get("matched_rule") or ""),
            matched_signature=str(d.get("matched_signature") or ""),
            classification_stage=str(d.get("classification_stage") or ""),
            # Confidence metadata: carried only if already present (the
            # Confidence Engine populates it; from_legacy never computes it).
            detection_confidence=d.get("detection_confidence") or 0,
            ownership_confidence=d.get("ownership_confidence") or 0,
            evidence_confidence=d.get("evidence_confidence") or 0,
            context_confidence=d.get("context_confidence") or 0,
            exploitability_confidence=d.get("exploitability_confidence") or 0,
            overall_confidence=d.get("overall_confidence") or 0,
            confidence_reason=str(d.get("confidence_reason") or ""),
            confidence_breakdown=d.get("confidence_breakdown") if isinstance(d.get("confidence_breakdown"), dict) else {},
            confidence_stage=str(d.get("confidence_stage") or ""),
            confidence_version=str(d.get("confidence_version") or ""),
            secret_intelligence=d.get("secret_intelligence") if isinstance(d.get("secret_intelligence"), dict) else {},
            evidence_bundle=d.get("evidence_bundle") if isinstance(d.get("evidence_bundle"), dict) else {},
            ownership_label=_opt_str(d.get("ownership_label")),
            exploitability=d.get("exploitability"),
            validation_status=str(d.get("validation_status") or ""),
            sdk_name=_opt_str(d.get("sdk_name")),
            package_prefix=_opt_str(d.get("package_prefix")),
            framework_name=_opt_str(_first(d, "framework_name", "framework")),
            file_evidence=d.get("file_evidence") if isinstance(d.get("file_evidence"), list) else [],
            metadata=d.get("metadata") if isinstance(d.get("metadata"), dict) else {},
            raw=dict(d),  # full original payload preserved for lossless round-trip
        )

    def to_legacy(self) -> dict:
        """Return the original detector dict with canonical keys added.

        Non-destructive: a key already present in ``.raw`` is left exactly as it
        was, so this can never change existing scan output; canonical names are
        only filled in where the legacy producer did not set them. The result is
        therefore always a superset of the dict this finding was built from.
        """
        out = dict(self.raw)
        for name in self._OVERLAY_FIELDS:
            value = getattr(self, name)
            if value in (None, "", [], {}):
                continue
            out.setdefault(name, value)
        # Standardize a few well-known parallel keys the pipeline reads, additively.
        out.setdefault("confidence_score", self.confidence)
        if self.line is not None:
            out.setdefault("line_number", self.line)
        if self.cwe:
            out.setdefault("cwe", self.cwe)
        if self.masvs:
            out.setdefault("masvs", self.masvs)
        if self.owasp:
            out.setdefault("owasp", self.owasp)
        return out

    def to_dict(self, *, include_raw: bool = False) -> dict:
        """Canonical typed view as a plain dict. ``raw`` is omitted by default."""
        out = {f.name: getattr(self, f.name) for f in fields(self) if not f.name.startswith("_")}
        if not include_raw:
            out.pop("raw", None)
        return out

    def to_json(self, *, include_raw: bool = False, indent: int | None = None) -> str:
        """Serialize the canonical view to a JSON string."""
        return json.dumps(self.to_dict(include_raw=include_raw), default=str,
                          ensure_ascii=False, indent=indent)

    # ── Identity, dedup & merge ──────────────────────────────────────────────
    def identity(self) -> str:
        """Stable, rescan-coarse identity (no line numbers).

        Same logical issue keeps the same id across re-scans, so suppression /
        triage / cross-scan diffing can key on it. Mirrors the existing
        ``finding_model`` canonical-id scheme (``BEETLE-<sha1[:10]>``).
        """
        basis = "|".join((
            (self.rule_id or self.title or "finding"),
            (self.package or self.owner_type or ""),
        )).lower()
        digest = hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:10]
        return f"BEETLE-{digest}"

    def dedup_key(self) -> tuple:
        """Fine-grained key for exact-duplicate collapse within a scan.

        Mirrors the DB unique index ``(rule_id, file_path, line, title)`` so
        in-memory dedupe and the persisted uniqueness constraint agree.
        """
        return (
            self.rule_id or "",
            self.file_path or "",
            self.line or 0,
            self.title or "",
        )

    def merge(self, other: "CanonicalFinding") -> "CanonicalFinding":
        """Combine two findings describing the same issue into one.

        Keeps the higher severity and confidence, unions evidence / references /
        tags / standards, fills empty scalar fields from ``other``, and merges
        raw payloads (``other`` filling gaps). ``self``'s identity is retained.
        Pure: returns a new instance and does not mutate either input.
        """
        merged = CanonicalFinding(**self.to_dict(include_raw=True))

        # Severity: keep the more severe (lower rank).
        if severity_rank(other.severity) < severity_rank(self.severity):
            merged.severity = other.severity
        merged.confidence = max(self.confidence, other.confidence)

        # Fill empty scalars from `other`.
        for name in ("file_path", "package", "class_name", "method_name", "line",
                     "column", "snippet", "evidence_type", "source_module",
                     "discovery_method", "category", "cwe", "ownership_label",
                     "sdk_name", "package_prefix", "framework_name"):
            if getattr(merged, name) in (None, "") and getattr(other, name) not in (None, ""):
                setattr(merged, name, getattr(other, name))

        # Union list-like fields (order-preserving, de-duplicated).
        merged.references = _union(self.references, other.references)
        merged.tags = _union(self.tags, other.tags)
        merged.masvs = _union(self.masvs, other.masvs)
        merged.owasp = _union(self.owasp, other.owasp)
        merged.file_evidence = _union_evidence(self.file_evidence, other.file_evidence)

        # Boolean linkage flags are OR-ed; suppression is sticky.
        merged.is_attack_chain = self.is_attack_chain or other.is_attack_chain
        merged.in_attack_chain = self.in_attack_chain or other.in_attack_chain
        merged.attack_chain_eligible = self.attack_chain_eligible or other.attack_chain_eligible
        merged.suppressed = self.suppressed or other.suppressed
        merged.suppressed_reason = merged.suppressed_reason or other.suppressed_reason

        # Raw: keep self's, let other fill missing keys.
        raw = dict(other.raw)
        raw.update(self.raw)
        merged.raw = raw
        merged.metadata = {**other.metadata, **self.metadata}
        merged.__post_init__()  # re-normalize after mutation
        return merged


# ── Module-level convenience adapters ────────────────────────────────────────
def from_legacy(data: dict, *, platform: str | None = None) -> CanonicalFinding:
    """Functional alias for :meth:`CanonicalFinding.from_legacy`."""
    return CanonicalFinding.from_legacy(data, platform=platform)


def to_legacy(finding: CanonicalFinding) -> dict:
    """Functional alias for :meth:`CanonicalFinding.to_legacy`."""
    return finding.to_legacy()


def from_legacy_list(findings: Iterable[dict], *, platform: str | None = None) -> list[CanonicalFinding]:
    """Adapt a list of legacy finding dicts; non-dict entries are skipped."""
    out: list[CanonicalFinding] = []
    for d in findings or []:
        if isinstance(d, dict):
            out.append(CanonicalFinding.from_legacy(d, platform=platform))
    return out


def canonicalize_dict(data: dict, *, platform: str | None = None) -> dict:
    """dict → dict: add canonical field names without dropping legacy keys.

    The transition tool for migrating a producer/consumer to canonical names
    one site at a time. ``canonicalize_dict(d)`` is always a superset of ``d``.
    NOTE: not wired into the live pipeline in this phase — adopting it is a
    later, deliberate step.
    """
    return CanonicalFinding.from_legacy(data, platform=platform).to_legacy()


# ── Small internal utilities ─────────────────────────────────────────────────
def _opt_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _union(*lists: Iterable[str]) -> list[str]:
    out: list[str] = []
    for lst in lists:
        for v in _as_str_list(lst):
            if v not in out:
                out.append(v)
    return out


def _union_evidence(*lists: Iterable[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set = set()
    for lst in lists:
        for e in lst or []:
            if not isinstance(e, dict):
                continue
            key = (str(e.get("path", "")), str(e.get("lines", "")), str(e.get("snippet", ""))[:80])
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    return out
