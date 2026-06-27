"""
Cross-source fusion (Beetle 2.0, Phase 1.9) — Finding Fusion Engine prep.

When more than one detection source (Beetle Native, APKLeaks, …) surfaces the SAME
issue, Beetle must produce ONE finding "Detected By" all of them — never two rows
for one secret. This module is the single seam where that merge happens, and it is
deliberately small and deterministic so the upcoming Finding Fusion Engine can grow
out of it without a rewrite.

It does three jobs, all additive and side-effect-local:

1. :func:`merge_secret_streams` — fold a source's secret detections into
   ``results["secrets"]``, de-duplicating on (normalized type, value) and unioning
   ``detected_by`` / ``sources`` / evidence when a native + APKLeaks pair collide.
2. :func:`merge_finding_streams` — same idea for finding dicts, keyed on
   ``CanonicalFinding.dedup_key()`` so it agrees with the pipeline's own dedup.
3. :func:`bridge_secrets_to_findings` — the "both stream + bridge" step: after
   secrets are masked, mirror APKLeaks-attributed secrets into ``results["findings"]``
   as MASKED findings so they also traverse ownership → confidence → evidence →
   triage → attack chains → bug-bounty. Never carries a raw value.

Nothing here masks, scores, or suppresses — those remain the pipeline's job.
"""
from __future__ import annotations

import logging

from ..canonical_finding import CanonicalFinding, normalize_confidence

log = logging.getLogger("cortex.fusion")

NATIVE = "Beetle Native"


# ── helpers ──────────────────────────────────────────────────────────────────
def _secret_key(s: dict) -> tuple[str, str]:
    """Dedup key for a secret: (normalized type/name, value).

    Uses the canonical ``type`` when Secret Intelligence has already tagged it,
    else the raw detector ``name``. Value is the discriminator either way, so a
    native hit and an APKLeaks hit on the SAME literal collapse to one entry.
    """
    name = (s.get("type") or s.get("name") or s.get("title") or "").strip().lower()
    value = str(s.get("value") or s.get("masked_value") or "").strip()
    return (name, value)


def _ensure_attribution(item: dict, default_engine: str) -> None:
    """Guarantee a detection dict carries detected_by/sources (additive)."""
    db = item.get("detected_by")
    if not isinstance(db, list) or not db:
        item["detected_by"] = [item.get("source") or default_engine]
    if not isinstance(item.get("sources"), list):
        item["sources"] = [{
            "engine": item["detected_by"][0],
            "rule_id": item.get("name") or item.get("title") or "",
            "confidence": item.get("confidence"),
        }]


def _union_attribution(into: dict, frm: dict) -> None:
    """Union ``frm``'s engines + per-source detail into ``into`` (in place)."""
    _ensure_attribution(into, NATIVE)
    _ensure_attribution(frm, frm.get("source") or "Unknown")
    for eng in frm.get("detected_by", []):
        if eng not in into["detected_by"]:
            into["detected_by"].append(eng)
    seen = {(d.get("engine"), d.get("rule_id")) for d in into["sources"]}
    for d in frm.get("sources", []):
        k = (d.get("engine"), d.get("rule_id"))
        if k not in seen:
            seen.add(k)
            into["sources"].append(d)


# ── 1. secret-stream fusion ──────────────────────────────────────────────────
def merge_secret_streams(results: dict, new_secrets: list[dict]) -> dict:
    """Fold ``new_secrets`` into ``results["secrets"]`` with cross-source merge.

    Returns ``{"added", "merged"}`` stats. Existing secrets keep first-writer
    position/data; a duplicate from another source only *unions* attribution and
    fills missing evidence. Native secrets that lacked attribution are stamped
    "Beetle Native" so the UI can always show a "Detected By".
    """
    existing = results.setdefault("secrets", [])
    index: dict[tuple[str, str], dict] = {}
    for s in existing:
        if isinstance(s, dict):
            _ensure_attribution(s, NATIVE)
            index[_secret_key(s)] = s

    added = merged = 0
    for s in new_secrets or []:
        if not isinstance(s, dict):
            continue
        _ensure_attribution(s, s.get("source") or "Unknown")
        key = _secret_key(s)
        if key in index:
            cur = index[key]
            _union_attribution(cur, s)
            # Fill missing evidence fields from the newcomer (never overwrite).
            for f in ("file_path", "line", "snippet", "code_context", "cwe",
                      "masvs", "owasp", "description", "recommendation"):
                if not cur.get(f) and s.get(f):
                    cur[f] = s[f]
            merged += 1
        else:
            index[key] = s
            existing.append(s)
            added += 1

    log.info("[fusion] secrets | added=%d merged=%d total=%d", added, merged, len(existing))
    return {"added": added, "merged": merged}


# ── 2. finding-stream fusion ─────────────────────────────────────────────────
def merge_finding_streams(results: dict, new_findings: list[dict], *,
                          platform: str = "unknown") -> dict:
    """Fold ``new_findings`` into ``results["findings"]`` with cross-source merge.

    Keyed on ``CanonicalFinding.dedup_key()`` so it agrees with the pipeline's own
    ``dedupe_findings`` / DB uniqueness. Collisions union attribution via the
    canonical ``merge``; the merged legacy dict is written back in place.
    """
    existing = results.setdefault("findings", [])
    index: dict[tuple, int] = {}
    for i, f in enumerate(existing):
        if isinstance(f, dict):
            _ensure_attribution(f, NATIVE)
            index[CanonicalFinding.from_legacy(f, platform=platform).dedup_key()] = i

    added = merged = 0
    for f in new_findings or []:
        if not isinstance(f, dict):
            continue
        _ensure_attribution(f, f.get("source") or "Unknown")
        cf = CanonicalFinding.from_legacy(f, platform=platform)
        key = cf.dedup_key()
        if key in index:
            i = index[key]
            base = CanonicalFinding.from_legacy(existing[i], platform=platform)
            m = base.merge(cf)
            md = m.to_legacy()
            # to_legacy is non-destructive (never overwrites a key already in raw),
            # so the unioned attribution would otherwise be masked by the base
            # finding's original values — force the merged union through.
            md["detected_by"] = m.detected_by
            md["sources"] = m.sources
            existing[i] = md
            merged += 1
        else:
            index[key] = len(existing)
            existing.append(f)
            added += 1

    log.info("[fusion] findings | added=%d merged=%d total=%d", added, merged, len(existing))
    return {"added": added, "merged": merged}


def merge_endpoint_streams(results: dict, new_endpoints: list[str]) -> int:
    """Fold endpoint URLs into ``results["endpoints"]`` (deduplicated). Returns count added."""
    existing = results.setdefault("endpoints", [])
    seen = set(existing)
    added = 0
    for url in new_endpoints or []:
        if url and url not in seen:
            seen.add(url)
            existing.append(url)
            added += 1
    return added


# ── 3. masked secret → finding bridge ────────────────────────────────────────
# Set True to mirror EVERY secret (native + APKLeaks) into findings. Phase 1.9
# scopes the bridge to APKLeaks-attributed secrets to avoid changing how Beetle
# Native secrets are surfaced today; flipping this is the one-line broadening step.
MIRROR_ALL_SECRETS = False

# Marker key on a bridged finding so reports/UI can recognize (and avoid
# double-displaying) a secret that is already shown in the Secrets section.
BRIDGE_MARKER = "secret_bridge"


def _should_bridge(secret: dict) -> bool:
    if MIRROR_ALL_SECRETS:
        return True
    db = secret.get("detected_by") or []
    src = secret.get("source") or ""
    return ("APKLeaks" in db) or (src == "APKLeaks")


def _masked_secret_to_finding(s: dict, platform: str) -> dict | None:
    """Build a MASKED finding dict from an already-masked secret. None if unsafe.

    Guard: a secret that has not been through ``secret_intel`` masking still holds
    a raw value (no ``masked_value``); we refuse to bridge it so a raw secret can
    never leak into the findings stream.
    """
    masked = s.get("masked_value")
    if not masked:
        return None  # never bridge an unmasked secret
    path = s.get("file_path") or (s.get("evidence") or {}).get("file_path") or s.get("full_path") or ""
    line = s.get("line") or (s.get("evidence") or {}).get("line") or 0
    snippet = s.get("snippet") or (s.get("evidence") or {}).get("snippet") or ""
    name = s.get("name") or s.get("type") or "Secret"

    sid = s.get("id") or ""
    finding = {
        "title": name,
        # Bridge-unique rule_id (carries the secret id) so a bridged copy can never
        # collide with a real finding's dedup_key and never merges into one.
        "rule_id": f"APKLEAKS-SECRET-{sid or name}".upper().replace(" ", "_"),
        "severity": s.get("severity") or "medium",
        "category": s.get("category") or "Embedded Secret",
        "file_path": path,
        "line": line,
        "line_number": line,
        "snippet": snippet,
        "value": masked,                 # masked only — never the raw value
        "masked_value": masked,
        "confidence": normalize_confidence(s.get("detector_confidence") or s.get("confidence")),
        "description": s.get("description") or f"{name} detected in the application.",
        "recommendation": s.get("recommendation") or "Rotate the credential and remove it from the client.",
        "cwe": s.get("cwe") or "CWE-798",
        "masvs": s.get("masvs") or "MASVS-CRYPTO-2",
        "owasp": s.get("owasp") or "M1",
        "source_module": "APKLeaks",
        "detected_by": s.get("detected_by") or ["APKLeaks"],
        "sources": s.get("sources") or [{"engine": "APKLeaks", "rule_id": name}],
        "discovery_method": "apkleaks_regex",
        "evidence_type": "regex_match",
        # P2.5: carry the Secret Intelligence assessment so the bridged finding is
        # self-describing while it flows through the pipeline (and so an analyst
        # viewing it sees the same intelligence as in the Secrets view).
        "secret_intelligence": s.get("secret_intelligence") or {},
        BRIDGE_MARKER: True,
        "secret_id": sid,
    }
    return finding


def bridge_secrets_to_findings(results: dict, *, platform: str = "unknown") -> dict:
    """Mirror masked APKLeaks secrets into ``results["findings"]`` (the bridge).

    Runs AFTER ``secret_intel.process_secrets`` so every value is masked. Reads
    both visible and suppressed secrets (so a suppressed secret still gets the full
    finding-pipeline treatment). De-duplicated against existing findings via the
    fusion merge, so re-runs and native/APKLeaks overlap never double-count.

    Returns ``{"candidates", "bridged", "skipped_unmasked", "skipped_existing"}``.
    """
    findings = results.setdefault("findings", [])
    # Idempotency keyed on secret_id among EXISTING bridged findings only — so a
    # re-run never duplicates, and a bridged copy never merges into a real finding.
    existing = {f.get("secret_id") for f in findings
                if isinstance(f, dict) and f.get(BRIDGE_MARKER)}
    candidates = bridged = skipped_unmasked = skipped_existing = 0
    for bucket in ("secrets", "suppressed_secrets"):
        for s in results.get(bucket) or []:
            if not isinstance(s, dict) or not _should_bridge(s):
                continue
            candidates += 1
            f = _masked_secret_to_finding(s, platform)
            if f is None:
                skipped_unmasked += 1
                continue
            if f.get("secret_id") and f["secret_id"] in existing:
                skipped_existing += 1
                continue
            existing.add(f.get("secret_id"))
            findings.append(f)
            bridged += 1

    out = {
        "candidates": candidates,
        "bridged": bridged,
        "skipped_unmasked": skipped_unmasked,
        "skipped_existing": skipped_existing,
    }
    log.info("[fusion] secret->finding bridge | %s", out)
    results.setdefault("apkleaks_integration", {})["bridge"] = out
    return out


# Intelligence fields the pipeline engines write onto a finding, copied back onto
# the linked secret at reconcile so the Secrets view carries the same intelligence.
_BRIDGE_INTEL_FIELDS = (
    # Ownership (Phase 1.2)
    "owner_type", "owner_name", "owner_confidence", "owner_reason",
    "matched_package_prefix", "matched_rule", "matched_signature",
    "classification_stage", "sdk_name",
    # Confidence (Phase 1.3)
    "detection_confidence", "ownership_confidence", "evidence_confidence",
    "context_confidence", "exploitability_confidence", "overall_confidence",
    "confidence_reason", "confidence_breakdown", "confidence_stage",
    # Evidence (Phase 1.5)
    "evidence_bundle",
    # Triage (Phase 1.6)
    "triage",
    # Attack chain linkage (Phase 1.7)
    "in_attack_chain", "attack_chain_eligible",
    # Bug bounty (Phase 1.8)
    "bug_bounty",
)


def reconcile_bridged_findings(results: dict) -> dict:
    """Harvest bridged findings' intelligence onto their secrets, then drop them.

    Runs AFTER all intelligence engines. For every bridged finding it copies the
    engine-computed intelligence (ownership/confidence/evidence/triage/chain/bug
    -bounty) onto the linked secret (matched by ``secret_id``) under
    ``secret["intelligence"]`` plus a few flat conveniences, then REMOVES the
    bridged copies from ``results["findings"]``. Result: the secret appears once,
    carries its full intelligence, and never shows as a duplicate finding anywhere
    (UI / PDF / HTML / JSON / dashboard / summaries all read the cleaned list).

    Returns ``{"reconciled", "removed", "unmatched"}``.
    """
    findings = results.get("findings") or []
    secret_index: dict[str, dict] = {}
    for bucket in ("secrets", "suppressed_secrets"):
        for s in results.get(bucket) or []:
            if isinstance(s, dict) and s.get("id"):
                secret_index[s["id"]] = s

    reconciled = removed = unmatched = 0
    kept: list[dict] = []
    for f in findings:
        if not (isinstance(f, dict) and f.get(BRIDGE_MARKER)):
            kept.append(f)
            continue
        removed += 1
        sid = f.get("secret_id")
        secret = secret_index.get(sid) if sid else None
        if secret is None:
            unmatched += 1
            continue
        intel = {k: f[k] for k in _BRIDGE_INTEL_FIELDS if k in f and f[k] not in (None, "", [], {})}
        if intel:
            secret["intelligence"] = intel
            # Flat conveniences for views that show a column without unpacking.
            for k in ("owner_type", "owner_name", "overall_confidence", "triage", "bug_bounty"):
                if k in intel:
                    secret.setdefault(k, intel[k])
            reconciled += 1

    results["findings"] = kept
    out = {"reconciled": reconciled, "removed": removed, "unmatched": unmatched}
    log.info("[fusion] bridge reconcile | %s", out)
    results.setdefault("apkleaks_integration", {})["reconcile"] = out
    return out
