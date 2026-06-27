"""
Secret Intelligence Engine — pipeline (Beetle 2.0, Phase 1.4).

Turns a raw detected value into an explainable, multi-signal assessment so that a
value does NOT become a security finding just because it matched a regex. Stages:

  type classification → context → ownership → entropy → format → checksum →
  provider → environment → false-positive detection → confidence → final status

Deterministic and offline (no network; live probing stays in secret_validator).
It ONLY enriches — it never suppresses, re-severities, or removes a secret.

All constants live in `config.py`; type/format data in `patterns.py`.
"""
from __future__ import annotations

import logging
import os

from . import config as C
from . import patterns as P

log = logging.getLogger("cortex.secret_intel_engine")


# ════════════════════════════════════════════════════════════════════════════
# Context-kind detection (where the value lives)
# ════════════════════════════════════════════════════════════════════════════
def _context_kind(path: str) -> str:
    p = (path or "").replace("\\", "/").lower()
    if not p:
        return "unknown"
    base = os.path.basename(p)
    if "buildconfig" in base:
        return "buildconfig"
    if base == "androidmanifest.xml":
        return "manifest"
    if base == "strings.xml" or "/res/values" in p:
        return "strings_xml"
    if "/res/" in p:
        return "resources"
    if "/assets/" in p:
        return "assets"
    if any(tok in p for tok in C.FP_CONTEXT_TOKENS):
        if any(t in p for t in ("/doc", "readme", "tutorial", "javadoc", "changelog", "license")):
            return "documentation"
        if "sample" in p or "example" in p or "demo" in p or "mock" in p or "fixture" in p:
            return "sample"
        return "test"
    ext = os.path.splitext(base)[1]
    return {
        ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
        ".m": "objc", ".mm": "objc", ".h": "objc",
        ".properties": "properties", ".gradle": "gradle",
        ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".ini": "config",
        ".xml": "xml", ".plist": "xml", ".toml": "config", ".env": "config",
        ".so": "native", ".dylib": "native",
        ".dex": "binary", ".arsc": "binary", ".bin": "binary",
        ".db": "database", ".sqlite": "database", ".realm": "database",
    }.get(ext, "unknown")


# ════════════════════════════════════════════════════════════════════════════
# Assessment object
# ════════════════════════════════════════════════════════════════════════════
class SecretAssessment:
    """Explainable outcome for one candidate secret (attached as a nested dict)."""

    def __init__(self, **kw):
        self.__dict__.update(kw)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _clamp(n) -> int:
    return max(0, min(100, int(round(n))))


# ════════════════════════════════════════════════════════════════════════════
# The engine
# ════════════════════════════════════════════════════════════════════════════
class SecretIntelligenceEngine:
    """Deterministic multi-stage secret validator. Stateless; build once."""

    version = C.SECRET_INTEL_VERSION

    # ── 1. type / provider ───────────────────────────────────────────────────
    @staticmethod
    def _classify_type(value: str, name: str) -> tuple[dict | None, str, str, str]:
        rec = P.classify_value(value)
        if rec:
            return rec, rec["type"], rec["provider"], f"value matches {rec['type']} format"
        # Fall back to the detector's own name when no format matches.
        n = (name or "").strip()
        if n:
            low = n.lower()
            if "password" in low or "username" in low:
                return None, n, "GENERIC", f"detector '{n}' (weak named credential)"
            return None, n, "GENERIC", f"detector '{n}' matched (no provider format)"
        return None, "Unknown Secret", "GENERIC", "no provider format or detector name"

    # ── ownership (reuse the Ownership Engine; never duplicate logic) ─────────
    @staticmethod
    def _ownership(ctx: dict) -> str:
        if ctx.get("owner_type"):
            return ctx["owner_type"]
        try:
            from ..ownership import get_engine as _own_engine
            from ..canonical_finding import CanonicalFinding
            cf = CanonicalFinding(title="_secret", file_path=ctx.get("file_path") or "",
                                  package=ctx.get("package") or "",
                                  platform=ctx.get("platform") or "unknown")
            return _own_engine().classify(cf).owner_type
        except Exception:
            return "Unknown"

    # ── format / structure / checksum ────────────────────────────────────────
    @staticmethod
    def _validate_format(value: str, rec: dict | None) -> dict:
        kind = rec["kind"] if rec else P.KIND_WEAK
        format_valid = kind in (P.KIND_PROVIDER, P.KIND_STRUCTURED, P.KIND_PUBLIC)
        structure = rec.get("structure") if rec else None
        structure_valid = None
        detail = ""
        if structure == "jwt":
            structure_valid, detail = P.jwt_structure(value)
        elif structure in ("pem_private", "pem_public"):
            structure_valid, detail = P.pem_structure(value)
        elif structure == "hex":
            structure_valid = P.is_hex(value)
        elif structure == "base64":
            structure_valid = P.is_base64(value)
        elif structure == "uuid":
            structure_valid = P.is_uuid(value)
        checksum_valid = None
        if rec and rec.get("checksum") == "github":
            checksum_valid = P.github_checksum_valid(value)
        elif rec and rec.get("checksum") == "luhn":
            checksum_valid = P.luhn_valid(value)
        return {"format_valid": format_valid, "structure_valid": structure_valid,
                "checksum_valid": checksum_valid, "structure_detail": detail, "kind": kind}

    # ── environment ──────────────────────────────────────────────────────────
    @staticmethod
    def _environment(value: str, context_kind: str) -> str:
        low = value.lower()
        if C.is_known_example(value):
            return "example"
        if "sk_test_" in low or "pk_test_" in low or "_test_" in low or "rk_test_" in low:
            return "test"
        if context_kind in ("test", "sample", "documentation"):
            return "example" if context_kind != "test" else "test"
        if "sk_live_" in low or "pk_live_" in low or "_live_" in low or "_prod" in low:
            return "production"
        return "unknown"

    # ── false-positive detection ─────────────────────────────────────────────
    @staticmethod
    def _false_positive(value: str, rec: dict | None, context_kind: str,
                        owner_type: str) -> tuple[bool, str, str]:
        """Return (is_fp, fp_kind, reason). fp_kind drives the final status."""
        low = value.strip().lower()
        if C.is_known_example(value):
            return True, "doc_example", "matches a known documentation/example value"
        if low in C.CRYPTO_TEST_VECTORS:
            return True, "crypto_constant", "matches a known crypto test vector/constant"
        if low in C.DEGENERATE_UUIDS:
            return True, "placeholder", "degenerate/nil UUID"
        for sub in C.PLACEHOLDER_SUBSTRINGS:
            if sub in low:
                return True, "placeholder", f"contains placeholder text '{sub}'"
        if low in C.PLACEHOLDER_EXACT:
            return True, "placeholder", "value is a placeholder word"
        # Degenerate randomness: single repeated char, or strictly sequential.
        core = value.strip()
        if len(set(core)) <= 2 and len(core) >= 6:
            return True, "garbage", "near-constant low-entropy value"
        # Crypto-library / generated owners with a non-provider value are constants.
        if owner_type in ("OpenSourceLibrary",) and rec and rec["kind"] in (P.KIND_GENERIC, P.KIND_WEAK):
            return True, "crypto_constant", f"value in library code ({owner_type}) — likely a constant"
        return False, "", ""

    # ── confidence dimensions ────────────────────────────────────────────────
    def _detection(self, rec, name, validated, entropy, length) -> tuple[int, str]:
        if validated:
            return C.DETECTION_VALIDATED, "live-validated"
        if rec is None:
            if name and ("password" in name.lower() or "username" in name.lower()):
                return C.DETECTION_WEAK, "weak named credential"
            if entropy >= C.ENTROPY_STRONG and length >= C.ENTROPY_MIN_LENGTH:
                return C.DETECTION_GENERIC_HIGH_ENTROPY, "generic high-entropy token"
            return C.DETECTION_WEAK, "no provider format"
        kind = rec["kind"]
        if kind == P.KIND_PROVIDER:
            return C.DETECTION_PROVIDER_FORMAT, "provider-specific format"
        if kind == P.KIND_STRUCTURED:
            return C.DETECTION_STRUCTURED, "structured secret (JWT/PEM)"
        if kind == P.KIND_PUBLIC:
            return C.DETECTION_STRUCTURED, "public key/certificate format"
        if kind == P.KIND_GENERIC:
            base = C.DETECTION_GENERIC_HIGH_ENTROPY if entropy >= C.ENTROPY_MIN_RANDOM else C.DETECTION_WEAK
            return base, "generic token"
        return C.DETECTION_WEAK, "weak signal"

    def _validation(self, fmt: dict, entropy: float, length: int, is_fp: bool) -> tuple[int, list[str]]:
        pts = C.VALIDATION_POINTS
        score = 0
        factors = []
        if fmt["format_valid"]:
            score += pts["format_valid"]; factors.append("format valid")
        if fmt["checksum_valid"] is True:
            score += pts["checksum_valid"]; factors.append("checksum valid")
        if fmt["structure_valid"] is True:
            score += pts["structure_valid"]; factors.append("structure valid")
        if entropy >= C.ENTROPY_MIN_RANDOM and length >= C.ENTROPY_MIN_LENGTH:
            score += pts["entropy_ok"]; factors.append(f"entropy {entropy:.1f}")
        if fmt["checksum_valid"] is False:
            score = max(0, score - 20); factors.append("checksum FAILED")
        if is_fp:
            score = max(0, score - C.VALIDATION_FP_PENALTY); factors.append("false-positive signal")
        return _clamp(score), factors

    @staticmethod
    def _evidence(ctx: dict, context_kind: str) -> tuple[int, list[str]]:
        score = C.EVIDENCE_BASE
        factors = []
        p = C.EVIDENCE_POINTS
        if ctx.get("file_path"):
            score += p["file_path"]; factors.append("file")
        if ctx.get("line"):
            score += p["line"]; factors.append("line")
        if ctx.get("snippet"):
            score += p["snippet"]; factors.append("snippet")
        if ctx.get("code_context"):
            score += p["code_context"]; factors.append("code context")
        weight = C.CONTEXT_WEIGHT.get(context_kind, 0.8)
        return _clamp(score * weight), factors + [f"{context_kind} context"]

    # ── final status ─────────────────────────────────────────────────────────
    @staticmethod
    def _status(validated, fp_kind, kind, owner_type, overall) -> tuple[str, str]:
        if validated:
            return C.Status.VALIDATED, "live-validated by a provider prober"
        if kind == P.KIND_PUBLIC:
            return C.Status.PUBLIC_VALUE, "public key/certificate — not a secret"
        if fp_kind == "doc_example":
            return C.Status.DOC_EXAMPLE, "known documentation/example value"
        if fp_kind == "crypto_constant":
            return C.Status.GENERATED_CONSTANT, "crypto test vector / library constant"
        if fp_kind in ("placeholder", "garbage"):
            return C.Status.FALSE_POSITIVE, "placeholder or low-entropy non-secret"
        if owner_type == "GeneratedCode" and kind not in (P.KIND_PROVIDER, P.KIND_STRUCTURED):
            return C.Status.GENERATED_CONSTANT, "value in generated code, no provider format"
        if overall >= C.STATUS_PROBABLE_MIN:
            return C.Status.PROBABLE, "provider/format and validation signals hold in real context"
        if overall >= C.STATUS_POSSIBLE_MIN:
            return C.Status.POSSIBLE, "plausible secret but weakly evidenced/validated"
        if kind in (P.KIND_PROVIDER, P.KIND_STRUCTURED):
            return C.Status.UNKNOWN, "recognized format but low corroboration"
        return C.Status.FALSE_POSITIVE, "no provider format and weak signals"

    # ── public: assess one value ─────────────────────────────────────────────
    def assess(self, value: str, context: dict | None = None) -> SecretAssessment:
        ctx = context or {}
        value = (value or "").strip()
        name = ctx.get("name") or ctx.get("title") or ""
        validated = ctx.get("validation_status") == "valid" or ctx.get("validated") is True

        rec, secret_type, provider, why_detected = self._classify_type(value, name)
        context_kind = _context_kind(ctx.get("file_path", ""))
        owner_type = self._ownership(ctx)
        entropy = P.shannon_entropy(value)
        length = len(value)
        fmt = self._validate_format(value, rec)
        kind = fmt["kind"]
        environment = self._environment(value, context_kind)
        is_fp, fp_kind, fp_reason = self._false_positive(value, rec, context_kind, owner_type)

        det, det_reason = self._detection(rec, name, validated, entropy, length)
        own = C.OWNERSHIP_RELEVANCE.get(owner_type, C.OWNERSHIP_RELEVANCE_DEFAULT)
        val, val_factors = self._validation(fmt, entropy, length, is_fp)
        evi, evi_factors = self._evidence(ctx, context_kind)

        w = C.OVERALL_WEIGHTS
        weighted = (w["detection"] * det + w["validation"] * val
                    + w["ownership"] * own + w["evidence"] * evi)
        overall = _clamp(weighted)

        status, why_classified = self._status(validated, fp_kind, kind, owner_type, overall)
        # Overall reflects "is this a real, live secret": reject classes are low.
        if status == C.Status.VALIDATED:
            overall = 100
        elif status in (C.Status.FALSE_POSITIVE, C.Status.DOC_EXAMPLE):
            overall = min(overall, 15)
        elif status == C.Status.PUBLIC_VALUE:
            overall = min(overall, 20)
        elif status == C.Status.GENERATED_CONSTANT:
            overall = min(overall, 25)

        why_provider = (f"{provider} selected from {secret_type} format"
                        if rec else f"{provider} (generic — no provider format)")
        why_confidence = (f"detection {det} ({det_reason}); validation {val} "
                          f"[{', '.join(val_factors) or 'none'}]; ownership {own} ({owner_type}); "
                          f"evidence {evi}")
        why_rejected = fp_reason if is_fp else ""

        return SecretAssessment(
            secret_type=secret_type, provider=provider, status=status,
            detection_confidence=det, ownership_confidence=own,
            evidence_confidence=evi, validation_confidence=val,
            overall_confidence=overall,
            entropy=round(entropy, 2), length=length,
            format_valid=fmt["format_valid"], structure_valid=fmt["structure_valid"],
            checksum_valid=fmt["checksum_valid"], environment=environment,
            context=context_kind, owner_type=owner_type, false_positive=is_fp,
            reasons={
                "detected": why_detected, "classified": why_classified,
                "provider": why_provider, "confidence": why_confidence,
                "rejected": why_rejected,
            },
            version=self.version,
        )


# ── cached singleton + public API ────────────────────────────────────────────
_ENGINE: SecretIntelligenceEngine | None = None


def get_engine() -> SecretIntelligenceEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = SecretIntelligenceEngine()
    return _ENGINE


def assess(value: str, context: dict | None = None) -> SecretAssessment:
    return get_engine().assess(value, context)


_SECRET_FINDING_SOURCES = {"EVIDENCE", "SECRET", "JWT_SCANNER"}


def annotate(results: dict) -> dict:
    """Pipeline integration — assess every detected secret BEFORE masking.

    Enriches each entry in ``results['secrets']`` (and secret-bearing findings)
    with a nested ``secret_intelligence`` assessment plus flat ``secret_status`` /
    ``secret_overall_confidence`` for quick consumption. ADDITIVE ONLY: it reads
    the raw value but stores only derived, non-sensitive signals (entropy, format
    flags, status) — never the raw value — and never removes or re-severities a
    secret. Run before ``secret_intel.process_secrets`` (which masks values).
    """
    engine = get_engine()
    platform = results.get("platform")
    by_status: dict[str, int] = {}
    n = 0

    def _enrich(item: dict, value_key: str):
        nonlocal n
        value = item.get(value_key)
        if not value:
            return
        ctx = {
            "name": item.get("name") or item.get("title"),
            "file_path": item.get("file_path") or item.get("file"),
            "package": item.get("package") or item.get("owner_package"),
            "line": item.get("line") or item.get("line_number"),
            "snippet": item.get("snippet"),
            "code_context": item.get("code_context"),
            "validation_status": item.get("validation_status") or item.get("validation_result"),
            "owner_type": item.get("owner_type"),
            "platform": platform,
        }
        a = engine.assess(value, ctx).to_dict()
        item["secret_intelligence"] = a
        item["secret_status"] = a["status"]
        item["secret_overall_confidence"] = a["overall_confidence"]
        by_status[a["status"]] = by_status.get(a["status"], 0) + 1
        n += 1

    for s in results.get("secrets") or []:
        if isinstance(s, dict):
            _enrich(s, "value")
    # Secret-bearing findings (raw value still present pre-masking).
    for f in results.get("findings") or []:
        if not isinstance(f, dict):
            continue
        src = str(f.get("source") or f.get("source_module") or "").upper()
        cat = str(f.get("category") or "").lower()
        if (src in _SECRET_FINDING_SOURCES or "secret" in cat) and (f.get("value") or f.get("match")):
            _enrich(f, "value" if f.get("value") else "match")

    results["secret_intelligence_summary"] = {"by_status": by_status, "version": engine.version}
    log.info("[secret-intel] assessed %d candidate secrets | %s", n, by_status)
    return results
