"""
Confidence Engine — scorer (Beetle 2.0, Phase 1.3).

Computes, for every finding, five INDEPENDENT explainable confidence dimensions
and one weighted roll-up:

  detection_confidence       did the detector identify a real issue?
  ownership_confidence       read directly from the Ownership Engine
  evidence_confidence        how verifiable is the evidence?
  context_confidence         is it in meaningful application context?
  exploitability_confidence  conservative likelihood of exploitation (NOT severity)
  overall_confidence         explainable weighted combination (breakdown retained)

The engine is pure and deterministic: the same finding always yields the same
scores. It NEVER changes severity, exploitability scoring, suppression, reports
or the UI — `annotate()` only writes the confidence_* fields additively.

All constants live in `config.py`; this module is logic only.
"""
from __future__ import annotations

import logging

from ..canonical_finding import CanonicalFinding
from . import config as C

log = logging.getLogger("cortex.confidence")

_FRAMEWORK_OWNERS = {"AndroidFramework", "AppleFramework"}
_DANGEROUS_SINKS = {
    "webview", "sql", "sqlite", "exec", "execution", "command", "filesystem",
    "reflection", "network", "dynamicloading", "dynamic_loading",
}
_DANGEROUS_API_CATEGORIES = {"webview", "cryptography", "crypto", "command execution", "command"}
_EXTERNAL_SOURCES = {"user input", "intent", "contentprovider", "content provider"}


# ════════════════════════════════════════════════════════════════════════════
# Result object
# ════════════════════════════════════════════════════════════════════════════
class ConfidenceResult:
    """Explainable confidence outcome for one finding (maps onto CanonicalFinding)."""

    __slots__ = ("detection", "ownership", "evidence", "context", "exploitability",
                 "overall", "reason", "breakdown", "stage", "version")

    def __init__(self, detection, ownership, evidence, context, exploitability,
                 overall, reason, breakdown, stage, version):
        self.detection = detection
        self.ownership = ownership
        self.evidence = evidence
        self.context = context
        self.exploitability = exploitability
        self.overall = overall
        self.reason = reason
        self.breakdown = breakdown
        self.stage = stage
        self.version = version

    def to_fields(self) -> dict:
        """Additive confidence fields to write onto a finding dict (owner-safe)."""
        return {
            "detection_confidence": self.detection,
            "ownership_confidence": self.ownership,
            "evidence_confidence": self.evidence,
            "context_confidence": self.context,
            "exploitability_confidence": self.exploitability,
            "overall_confidence": self.overall,
            "confidence_reason": self.reason,
            "confidence_breakdown": self.breakdown,
            "confidence_stage": self.stage,
            "confidence_version": self.version,
        }


def _clamp(n: int) -> int:
    return max(0, min(100, int(round(n))))


# ════════════════════════════════════════════════════════════════════════════
# The engine
# ════════════════════════════════════════════════════════════════════════════
class ConfidenceEngine:
    """Deterministic, reusable confidence scorer. Stateless; build once."""

    version = C.CONFIDENCE_VERSION

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _is_validated(f: CanonicalFinding) -> bool:
        return f.validation_status == "valid" or f.raw.get("validation_status") == "valid" \
            or f.raw.get("validated") is True

    @staticmethod
    def _has_snippet(f: CanonicalFinding) -> bool:
        if f.snippet:
            return True
        for e in f.file_evidence:
            if isinstance(e, dict) and e.get("snippet"):
                return True
        return bool(f.raw.get("snippet") or f.raw.get("code_context"))

    @staticmethod
    def _is_native(f: CanonicalFinding) -> bool:
        path = (f.file_path or "").lower()
        cat = (f.category or "").lower()
        return path.endswith((".so", ".dylib")) or "binary" in cat or "native" in cat

    @staticmethod
    def _is_app_config(f: CanonicalFinding) -> bool:
        if (f.evidence_type or "").lower() == "manifest":
            return True
        cat = (f.category or "").lower()
        return cat in ("configuration", "manifest", "permissions", "network security",
                       "attack surface", "deeplinks", "data storage", "backup", "privacy")

    # ── 1. detection ─────────────────────────────────────────────────────────
    def _detection(self, f: CanonicalFinding) -> tuple[int, list[str]]:
        if self._is_validated(f):
            return C.DETECTION_VALIDATED, ["detector result live-validated"]
        cls = self._detector_class(f)
        base = C.DETECTOR_BASE_CONFIDENCE.get(cls, C.DETECTOR_BASE_CONFIDENCE["default"])
        return base, [f"{cls.replace('_', ' ')} detector"]

    @staticmethod
    def _detector_class(f: CanonicalFinding) -> str:
        for tok in ((f.evidence_type or "").lower(), (f.source_module or "").lower()):
            if tok and tok in C.DETECTOR_CLASS_BY_TOKEN:
                return C.DETECTOR_CLASS_BY_TOKEN[tok]
        cat = (f.category or "").lower()
        if cat in C.DETECTOR_CLASS_BY_CATEGORY:
            return C.DETECTOR_CLASS_BY_CATEGORY[cat]
        return "default"

    # ── 2. ownership (read straight from the Ownership Engine) ────────────────
    @staticmethod
    def _ownership(f: CanonicalFinding) -> tuple[int, list[str]]:
        conf = int(f.owner_confidence or 0)
        if conf <= 0:
            return C.OWNERSHIP_NEUTRAL_DEFAULT, ["ownership not classified"]
        label = f.owner_name or f.owner_type
        return conf, [f"ownership: {label} ({f.owner_type})"]

    # ── 3. evidence ──────────────────────────────────────────────────────────
    def _evidence(self, f: CanonicalFinding) -> tuple[int, list[str]]:
        p = C.EVIDENCE_POINTS
        score = C.EVIDENCE_BASE
        factors: list[str] = []

        def add(key, label):
            nonlocal score
            score += p[key]
            factors.append(label)

        if f.line:
            add("line", "line number")
        if self._has_snippet(f):
            add("snippet", "code snippet")
        if f.method_name:
            add("method", "method identified")
        if f.class_name:
            add("class", "class identified")
        if f.file_path:
            add("file_path", "resolvable file")
        if f.raw.get("source_resolved"):
            add("source_resolved", "decompiler resolved source")
        if (f.evidence_type or "").lower() == "manifest" or f.raw.get("manifest_evidence_spec"):
            add("manifest", "manifest-verified")
        if f.raw.get("call_chain") or f.raw.get("taint_flow"):
            add("call_chain", "taint/call chain")
        n_ev = max(len(f.file_evidence), len(f.raw.get("files") or []))
        if n_ev > 1:
            add("multiple_evidence", "multiple evidence sources")
        if self._is_native(f) and (f.raw.get("symbol") or f.raw.get("section") or f.matched_signature):
            add("binary_metadata", "binary metadata")

        score = _clamp(score)
        if f.raw.get("unresolved_evidence"):
            score = min(score, C.EVIDENCE_UNRESOLVED_CAP)
            factors.append("claimed evidence unresolved")
        return score, factors

    # ── 4. context ───────────────────────────────────────────────────────────
    def _context(self, f: CanonicalFinding) -> tuple[int, list[str]]:
        owner = f.owner_type or "Unknown"
        score = C.CONTEXT_BY_OWNER.get(owner, C.CONTEXT_DEFAULT)
        factors = [f"{owner} context"]
        if self._is_app_config(f):
            if score < C.CONTEXT_APP_CONFIG_FLOOR:
                score = C.CONTEXT_APP_CONFIG_FLOOR
                factors.append("application configuration / manifest")
        elif owner in ("Unknown",) and (f.file_path or "").lower().split("?")[0].find("/res/") >= 0:
            score = C.CONTEXT_RESOURCE
            factors.append("resource file")
        elif owner in ("Unknown",) and self._is_native(f):
            score = C.CONTEXT_NATIVE_NEUTRAL
            factors.append("native library (context depends)")
        return _clamp(score), factors

    # ── 5. exploitability (conservative) ─────────────────────────────────────
    def _exploitability(self, f: CanonicalFinding) -> tuple[int, list[str]]:
        s = C.EXPLOIT_SIGNALS
        score = C.EXPLOIT_BASE
        factors: list[str] = []
        raw = f.raw

        def add(key, label):
            nonlocal score
            score += s[key]
            factors.append(label)

        reach = str(raw.get("reachability") or "").upper()
        if reach == "YES":
            add("reachable_yes", "reachable")
        elif reach == "MAYBE":
            add("reachable_maybe", "possibly reachable")

        cat = (f.category or "").lower()
        if cat in ("attack surface", "deeplinks") or raw.get("exported"):
            add("exported_component", "attacker-reachable entry point")

        tf = raw.get("taint_flow") or {}
        src = str(tf.get("source_cat") or raw.get("source_cat") or "").lower()
        if src in _EXTERNAL_SOURCES:
            add("external_source", "externally-controlled input")
        sink = str(tf.get("sink_cat") or raw.get("sink_cat") or "").replace(" ", "").lower()
        if sink in _DANGEROUS_SINKS:
            add("dangerous_sink", "dangerous sink")
        if cat in _DANGEROUS_API_CATEGORIES:
            add("dangerous_api", "dangerous API")

        if self._is_validated(f):
            add("validated_secret", "live-validated secret")
        elif f.owner_type == "Application" and ("secret" in cat or (f.source_module or "").lower() in ("evidence", "secret")):
            add("secret_in_app", "secret in application code")

        if f.in_attack_chain or raw.get("in_attack_chain"):
            add("in_attack_chain", "part of an attack chain")
        if cat == "permissions" or raw.get("dangerous_permission"):
            add("permission_sensitive", "sensitive permission")

        score = _clamp(score)
        # Conservative caps for code that cannot meaningfully be exploited.
        if reach == "NO":
            score = min(score, C.EXPLOIT_UNREACHABLE_CAP)
            factors.append("not reachable")
        if f.owner_type == "GeneratedCode":
            score = min(score, C.EXPLOIT_GENERATED_CAP)
        elif f.owner_type in _FRAMEWORK_OWNERS:
            score = min(score, C.EXPLOIT_FRAMEWORK_CAP)
        return score, factors

    # ── multi-engine agreement (Phase 1.95) ──────────────────────────────────
    @staticmethod
    def _agreement(f: CanonicalFinding) -> tuple[int, list[str]]:
        """Bounded, explainable detection bonus from multi-engine corroboration.

        Reads the Fusion Engine's ``detection_count`` (falling back to the length
        of ``detected_by``). More independent engines ⇒ higher detection trust;
        a documented metadata conflict damps the bonus. Returns (delta, factors).
        """
        count = max(int(f.detection_count or 0), len(f.detected_by or []))
        if count <= 1:
            return 0, []
        bonus = min((count - 1) * C.AGREEMENT_PER_ENGINE, C.AGREEMENT_MAX)
        conflicts = (f.fusion or {}).get("conflicts") if isinstance(f.fusion, dict) else None
        if conflicts:
            bonus = int(round(bonus * C.AGREEMENT_CONFLICT_DAMP))
            return bonus, [f"corroborated by {count} engines (metadata conflict - corroboration damped)"]
        return bonus, [f"corroborated by {count} independent engines"]

    # ── reason synthesis ─────────────────────────────────────────────────────
    @staticmethod
    def _reason(dims: dict, stage: str) -> str:
        """Build a concise human explanation from the most salient factors."""
        ordered = []
        # Lead with context (ownership), then detection, evidence, exploitability.
        for key in ("context", "detection", "evidence", "exploitability", "ownership"):
            for fac in dims[key]["factors"]:
                if fac not in ordered:
                    ordered.append(fac)
        head = "; ".join(ordered[:6])
        if stage not in ("Weighted", ""):
            return f"{stage}: {head}" if head else stage
        return head or "scored from available signals"

    # ── public classify ──────────────────────────────────────────────────────
    def classify(self, finding: CanonicalFinding) -> ConfidenceResult:
        det, det_f = self._detection(finding)
        # Multi-engine agreement (Fusion Engine): bounded, explainable boost to the
        # detection dimension so corroboration flows into overall via the weights.
        agree_delta, agree_f = self._agreement(finding)
        if agree_delta:
            det = _clamp(det + agree_delta)
            det_f = det_f + agree_f
        own, own_f = self._ownership(finding)
        evi, evi_f = self._evidence(finding)
        ctx, ctx_f = self._context(finding)
        exp, exp_f = self._exploitability(finding)

        w = C.OVERALL_WEIGHTS
        weighted = (w["detection"] * det + w["ownership"] * own + w["evidence"] * evi
                    + w["context"] * ctx + w["exploitability"] * exp)
        overall = _clamp(weighted)

        # Decision-path short-circuits (breakdown is always retained below).
        stage = "Weighted"
        if self._is_validated(finding):
            overall = max(overall, C.OVERALL_VALIDATED_FLOOR)
            stage = "Validated"
        elif finding.is_attack_chain or finding.raw.get("is_attack_chain"):
            overall = max(overall, C.OVERALL_ATTACK_CHAIN_FLOOR)
            stage = "Correlated"
        elif finding.raw.get("unresolved_evidence"):
            overall = min(overall, C.OVERALL_UNRESOLVED_CAP)
            stage = "Unresolved-Evidence"
        overall = _clamp(overall)

        dims = {
            "detection":      {"score": det, "weight": w["detection"], "factors": det_f},
            "ownership":      {"score": own, "weight": w["ownership"], "factors": own_f},
            "evidence":       {"score": evi, "weight": w["evidence"], "factors": evi_f},
            "context":        {"score": ctx, "weight": w["context"], "factors": ctx_f},
            "exploitability": {"score": exp, "weight": w["exploitability"], "factors": exp_f},
        }
        reason = self._reason(dims, stage)
        breakdown = {
            "dimensions": dims,
            "weighted_overall": round(weighted, 2),
            "overall": overall,
            "band": C.band_for(overall),
            "stage": stage,
            "version": self.version,
        }
        return ConfidenceResult(det, own, evi, ctx, exp, overall, reason,
                                breakdown, stage, self.version)


# ── cached singleton + public API ────────────────────────────────────────────
_ENGINE: ConfidenceEngine | None = None


def get_engine() -> ConfidenceEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = ConfidenceEngine()
    return _ENGINE


def classify(finding: CanonicalFinding) -> ConfidenceResult:
    """Public convenience: confidence for a single CanonicalFinding."""
    return get_engine().classify(finding)


def enrich(finding: CanonicalFinding) -> CanonicalFinding:
    """Set confidence_* fields on a CanonicalFinding in place; returns it."""
    res = get_engine().classify(finding)
    finding.detection_confidence = res.detection
    finding.ownership_confidence = res.ownership
    finding.evidence_confidence = res.evidence
    finding.context_confidence = res.context
    finding.exploitability_confidence = res.exploitability
    finding.overall_confidence = res.overall
    finding.confidence_reason = res.reason
    finding.confidence_breakdown = res.breakdown
    finding.confidence_stage = res.stage
    finding.confidence_version = res.version
    return finding


def annotate(results: dict) -> dict:
    """Pipeline integration — enrich every finding with confidence metadata.

    ADDITIVE ONLY: writes confidence_* keys via dict.update and never reads or
    rewrites existing finding data (severity, the legacy ``confidence`` /
    ``confidence_score``, suppression, etc. are untouched). Runs AFTER the
    Ownership Engine so ``owner_*`` is available. Operates on the canonical model
    internally, with legacy dicts only at the edge.
    """
    engine = get_engine()
    bands: dict[str, int] = {}
    enriched = 0
    for key in ("findings", "suppressed_findings"):
        for f in results.get(key) or []:
            if not isinstance(f, dict):
                continue
            cf = CanonicalFinding.from_legacy(f, platform=results.get("platform"))
            res = engine.classify(cf)
            f.update(res.to_fields())
            if key == "findings":
                band = C.band_for(res.overall)
                bands[band] = bands.get(band, 0) + 1
            enriched += 1
    results["confidence_summary"] = {
        "by_band": bands,
        "version": engine.version,
        "weights": C.OVERALL_WEIGHTS,
    }
    log.info("[confidence] enriched %d findings | bands=%s | v%s",
             enriched, bands, engine.version)
    return results
