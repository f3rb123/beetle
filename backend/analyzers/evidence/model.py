"""
Evidence Engine — the unified evidence model (Beetle 2.0, Phase 1.5).

`EvidenceItem` is one concrete piece of evidence (a code location, a manifest
entry, a binary symbol, a taint step …). `Evidence` is the aggregated, multi-
source bundle attached to a finding: items + quality + verification +
reproduction + correlation + a content hash.

Both are plain dataclasses with `to_dict()` so they serialize cleanly into the
finding's `evidence_bundle` and round-trip through JSON/DB/reports unchanged.
The model is intentionally extensible: long-tail locators live in the `locator`
dict and free-form extras in `metadata`, so new fields never break compatibility.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields


@dataclass
class EvidenceItem:
    """One verifiable piece of evidence for a finding."""

    id: str = ""
    type: str = "Unknown"            # EvidenceType
    source: str = "unknown"          # Source (collection technique)
    confidence: int = 0              # 0-100 strength of THIS item

    # Location
    file_path: str = ""
    relative_path: str = ""
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str = ""

    # Status
    decompiler_status: str = ""      # succeeded | smali | decoded | binary | unavailable
    source_availability: str = ""    # available | binary-only | unavailable
    generated_code: bool = False

    # Named locators (class/method/package/namespace/component/permission/uri/
    # sink/source/native_library/swift_module/objc_class/jni_library/resource/…).
    # A dict so the long, sparse list of locator kinds stays extensible.
    locator: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {f.name: getattr(self, f.name) for f in fields(self)}
        # Drop empty locator/metadata keys for a compact, stable representation.
        out["locator"] = {k: v for k, v in self.locator.items() if v not in (None, "", [], {})}
        out["metadata"] = {k: v for k, v in self.metadata.items() if v not in (None, "", [], {})}
        return out


@dataclass
class Evidence:
    """The aggregated evidence bundle for a finding (stored as `evidence_bundle`)."""

    evidence_id: str = ""
    version: str = ""
    items: list = field(default_factory=list)        # list[dict] (serialized EvidenceItem)
    primary: dict = field(default_factory=dict)      # the strongest item
    evidence_types: list = field(default_factory=list)
    sources: list = field(default_factory=list)

    quality: str = "Missing"
    quality_reason: str = ""
    verification_status: str = "Unknown"
    verification_reason: str = ""
    source_availability: str = ""
    generated_code: bool = False
    reproducible: bool = False

    # Rich structures.
    reproduction: dict = field(default_factory=dict)     # how to reproduce
    correlation: list = field(default_factory=list)      # relationships between items
    data_flow: dict = field(default_factory=dict)        # taint path, if any
    cross_references: list = field(default_factory=list) # other locations referencing this

    # Links to sibling engines' metadata (not duplicated — summarized).
    ownership: dict = field(default_factory=dict)
    confidence: dict = field(default_factory=dict)
    secret: dict = field(default_factory=dict)

    content_hash: str = ""
    timestamp: str = ""
    item_count: int = 0
    location_count: int = 0

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}
