"""
Attack Chain Engine v2 — graph + chain model (Beetle 2.0, Phase 1.7).

A chain is represented internally as a small typed graph (nodes + relationship
edges) AND as a rich, analyst-facing :class:`AttackChain`. Both serialize to
plain dicts so they round-trip through JSON/reports unchanged and a future UI can
visualize the graph without any backend change.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields


class NodeType:
    ENTRY_POINT = "EntryPoint"
    FINDING = "Finding"
    ACTIVITY = "Activity"
    SERVICE = "Service"
    RECEIVER = "Receiver"
    PROVIDER = "Provider"
    PERMISSION = "Permission"
    INTENT = "Intent"
    SECRET = "Secret"
    CERTIFICATE = "Certificate"
    ENDPOINT = "Endpoint"
    RESOURCE = "Resource"
    NATIVE_LIBRARY = "NativeLibrary"
    WEBVIEW = "WebView"
    DEEP_LINK = "DeepLink"
    GOAL = "Goal"


class EdgeRelation:
    USES = "uses"
    REQUIRES = "requires"
    EXPOSES = "exposes"
    CALLS = "calls"
    DEPENDS_ON = "depends_on"
    LEADS_TO = "leads_to"
    PROTECTS = "protects"
    WEAKENS = "weakens"


@dataclass
class ChainNode:
    id: str
    type: str
    label: str
    ref: str = ""                 # finding canonical_id / component name
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}


@dataclass
class ChainEdge:
    source: str
    target: str
    relation: str
    label: str = ""

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}


@dataclass
class ChainGraph:
    nodes: list = field(default_factory=list)   # list[ChainNode]
    edges: list = field(default_factory=list)   # list[ChainEdge]

    def add_node(self, node: ChainNode) -> ChainNode:
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)
        return node

    def add_edge(self, edge: ChainEdge) -> None:
        self.edges.append(edge)

    def to_dict(self) -> dict:
        return {"nodes": [n.to_dict() for n in self.nodes],
                "edges": [e.to_dict() for e in self.edges]}


@dataclass
class AttackChain:
    """A realistic attacker journey, evidence-backed and explainable."""
    id: str = ""
    name: str = ""
    type: str = ""
    summary: str = ""
    goal: str = ""
    prerequisites: list = field(default_factory=list)
    entry_point: dict = field(default_factory=dict)
    steps: list = field(default_factory=list)
    required_findings: list = field(default_factory=list)
    supporting_findings: list = field(default_factory=list)
    blocked_by: list = field(default_factory=list)
    mitigations: list = field(default_factory=list)
    blocked: bool = False

    # How the chain's external reachability is justified:
    #   proven        — a taint flow links external input to the matching sink in an
    #                    application-owned class reachable from the entry component.
    #   heuristic      — an injection/RCE template matched on capability co-occurrence
    #                    only; no dataflow proof. Severity capped at MEDIUM (RUN 25),
    #                    confidence below 60.
    #   manifest-only  — a non-injection template resting on manifest/config/
    #                    distribution/device evidence, which makes no dataflow claim.
    reachability_proof: str = "manifest-only"

    overall_confidence: int = 0
    overall_evidence_quality: str = "Missing"
    overall_exploitability: int = 0
    overall_impact: str = ""
    severity: str = "medium"
    # Set when a rule deliberately caps this chain's severity (e.g. a heuristic co-occurrence
    # chain capped to MEDIUM), so the UI/report can explain WHY it is not higher. "" otherwise.
    severity_reason: str = ""

    affected_components: list = field(default_factory=list)
    affected_files: list = field(default_factory=list)
    affected_classes: list = field(default_factory=list)
    affected_methods: list = field(default_factory=list)
    evidence_references: list = field(default_factory=list)

    triage_summary: dict = field(default_factory=dict)
    ownership_summary: dict = field(default_factory=dict)
    confidence_explanation: dict = field(default_factory=dict)
    narrative: list = field(default_factory=list)
    graph: dict = field(default_factory=dict)
    version: str = ""

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}
