"""
Attack Chain Engine v2 — engine (Beetle 2.0, Phase 1.7).

Builds realistic, evidence-backed, explainable attacker journeys by:
  1. tagging every active finding with deterministic capabilities,
  2. deciding each finding's chaining role from Triage / Secret Intelligence
     (SAFE CHAINING — framework noise / suppressed / FP secrets / generated code
     are never required links),
  3. filling each template's required capability slots from the eligible findings
     (and entry points from the manifest attack surface),
  4. scoring the chain from the prior engines' outputs (no arbitrary numbers),
  5. emitting a graph, an analyst narrative and a full explanation.

Additive and non-destructive: writes `results["attack_chains_v2"]`; the legacy
chain output is untouched. Deterministic and modular (templates + capabilities).
"""
from __future__ import annotations

import hashlib
import logging
import re

from .. import security_controls
from ..ownership import OwnerType, context_from_results, get_engine as _get_ownership_engine
from . import config as C
from . import templates as T
from .model import (
    AttackChain, ChainEdge, ChainGraph, ChainNode, EdgeRelation, NodeType,
)

log = logging.getLogger("cortex.attack_chains_v2")

# Owners that are NOT the application. A manifest component owned by any of these
# is library/framework/generated code and must never anchor a chain as its entry
# node (Flaw A): on a Flutter app the first exported component is androidx
# ProfileInstallReceiver, which used to anchor a fabricated "Intent -> SQLi" chain.
# APPLICATION and UNKNOWN are allowed — an unfingerprinted custom component is the
# app's own code far more often than a library's.
_NON_APP_OWNERS = frozenset((
    OwnerType.THIRD_PARTY_SDK, OwnerType.ANDROID_FRAMEWORK, OwnerType.GOOGLE_SDK,
    OwnerType.APPLE_FRAMEWORK, OwnerType.VENDOR_SDK, OwnerType.OPEN_SOURCE_LIBRARY,
    OwnerType.GENERATED_CODE,
))

# ── Reachability gate (Flaw B) ───────────────────────────────────────────────
# Injection/RCE sink capabilities. A template requiring any of these asserts that
# attacker input reaches a dangerous sink — a claim that must be backed by an
# actual taint flow, not mere co-occurrence of an exported component and a sink.
_GATED_SINK_CAPS = frozenset(("SQL_SINK", "CMD_SINK", "FILE_SINK", "CODE_LOADING", "JS_INTERFACE"))

# Gated sink capability -> taint-engine sink categories (lowercased) that satisfy it.
# CODE_LOADING has no corresponding taint sink category today, so a code-loading
# chain is always heuristic — correctly, since we cannot prove the dataflow.
_SINK_CAP_TAINT_CATS = {
    "SQL_SINK":     frozenset(("sqlite", "sql")),
    "CMD_SINK":     frozenset(("execution", "command")),
    "FILE_SINK":    frozenset(("filesystem", "file")),
    "CODE_LOADING": frozenset(("reflection", "dynamicloading", "dynamic_loading")),
    "JS_INTERFACE": frozenset(("webview",)),
}

# Taint source categories that count as attacker-controllable external input.
_EXTERNAL_SOURCE_CATS = frozenset(("user input", "intent", "contentprovider", "content provider"))

PROOF_PROVEN, PROOF_HEURISTIC, PROOF_MANIFEST = "proven", "heuristic", "manifest-only"

_LAUNCHER_ACTION = "android.intent.action.main"
_LAUNCHER_CATEGORY = "android.intent.category.launcher"


def _is_launcher_only_activity(c: dict) -> bool:
    """An exported activity whose ONLY intent-filter action is MAIN (the home-screen
    launcher entry). Such an activity is reachable from the launcher, NOT
    attacker-deliverable IPC — a malicious app cannot 'send it an intent' as an
    injection entry point, so it must not satisfy an EXPORTED/DEEPLINK entry cap.

    A MAIN activity that ALSO exposes a deep link (browsable / a scheme / a non-MAIN
    action) is genuinely reachable and is NOT treated as launcher-only."""
    if not isinstance(c, dict):
        return False
    if c.get("browsable") or c.get("schemes") or c.get("deeplinks"):
        return False
    actions = {str(a).strip().lower() for a in (c.get("actions") or []) if str(a).strip()}
    if actions:
        return not (actions - {_LAUNCHER_ACTION})   # only MAIN → launcher-only
    # No declared action, but flagged with the LAUNCHER category → still launcher-only.
    cats = {str(x).strip().lower() for x in (c.get("categories") or []) if str(x).strip()}
    return _LAUNCHER_CATEGORY in cats


# ════════════════════════════════════════════════════════════════════════════
# Capability tagging (deterministic) + eligibility
# ════════════════════════════════════════════════════════════════════════════
def _blob(f: dict) -> str:
    return " ".join(str(f.get(k) or "") for k in
                    ("title", "category", "description", "snippet", "rule_id")).lower()


def _secret_status(f: dict) -> str:
    si = f.get("secret_intelligence") or {}
    return si.get("status") or f.get("secret_status") or ""


_STRUCTURAL_CAPS = frozenset(("WEBVIEW", "WEBVIEW_JS", "JS_INTERFACE", "WEBVIEW_FILE",
                              "WEBVIEW_SSL", "EXPORTED", "DEEPLINK", "EXPORTED_PROVIDER",
                              "NATIVE", "NETWORK"))


# CERT_BYPASS requires POSITIVE evidence of actually-disabled TLS validation. A
# method that merely forwards a passed-in factory (setSSLSocketFactory / setSSLContext
# pass-through) is NOT a bypass, so neither the bare setter token nor a generic
# "certificate validation" mention qualifies.
_CERT_BYPASS_RULE_IDS = frozenset((
    "android_webview_ignore_ssl",             # onReceivedSslError → handler.proceed()
    "android_trust_all_certs",                # custom X509TrustManager accepts all
    "android_trust_manager_accept_all",       # empty checkServerTrusted body
    "android_allow_all_hostname",             # AllowAllHostnameVerifier
    "android_smali_insecure_hostname_verifier",
))
_CERT_BYPASS_TOKENS = (
    "allowallhostnameverifier", "allow_all_hostname", "nullhostnameverifier",
    "trustallcerts", "trust all cert", "trust-all", "trustall",
    "accepts all cert", "accept all cert", "nooptrustmanager",
    "onreceivedsslerror", "setdefaulthostnameverifier",
)


def tag_capabilities(f: dict, results: dict | None = None) -> set:
    """Deterministic capability tags for a finding (the chaining vocabulary).

    ``results`` (when supplied) lets state-dependent caps consult the authoritative
    ``security_controls`` resolution — e.g. CLEARTEXT is never tagged when cleartext
    is resolved to ``blocked``."""
    caps: set = set()
    cat = (f.get("category") or "").lower()
    blob = _blob(f)
    rule_id = str(f.get("rule_id") or f.get("id") or "")
    tf = f.get("taint_flow") or {}
    sink = str(tf.get("sink_cat") or "").replace(" ", "").lower()
    src = str(tf.get("source_cat") or "").lower()

    # Entry / surface
    if cat == "attack surface" or f.get("exported"):
        caps.add("EXPORTED")
    if cat in ("deeplinks", "deeplink") or f.get("browsable"):
        caps.add("DEEPLINK")
    if "content provider" in blob or "contentprovider" in blob:
        caps.add("EXPORTED_PROVIDER")
    # WebView
    if cat == "webview" or "webview" in blob:
        caps.add("WEBVIEW")
        if "javascript" in blob or "setjavascriptenabled" in blob:
            caps.add("WEBVIEW_JS")
        if "addjavascriptinterface" in blob or "javascriptinterface" in blob:
            caps.add("JS_INTERFACE")
        if "allowfileaccess" in blob or "file access" in blob or "file://" in blob:
            caps.add("WEBVIEW_FILE")
        if "ssl" in blob or "onreceivedsslerror" in blob:
            caps.add("WEBVIEW_SSL")
    # Injection sinks (taint or title)
    if sink in ("sqlite", "sql") or "sql injection" in blob:
        caps.add("SQL_SINK")
    if sink in ("execution", "command") or "command injection" in blob or "os command" in blob:
        caps.add("CMD_SINK")
    if sink in ("filesystem", "file") or "path traversal" in blob:
        caps.add("FILE_SINK")
    if sink in ("reflection", "dynamicloading", "dynamic_loading") or "dexclassloader" in blob \
            or "dynamic code" in blob or "reflection" in blob:
        caps.add("CODE_LOADING")
    if src in ("user input", "intent", "contentprovider", "content provider"):
        caps.add("EXTERNAL_INPUT")
    # Secrets (only REAL secrets qualify)
    if _secret_status(f) in C.REAL_SECRET_STATUSES or (
            cat == "secrets" and _secret_status(f) not in C.REJECT_SECRET_STATUSES
            and (f.get("secret_intelligence") or f.get("value"))):
        caps.add("SECRET")
        st = ((f.get("secret_intelligence") or {}).get("secret_type") or "").lower()
        if "api" in st or "key" in st or "aws" in st or "google" in st or "stripe" in st:
            caps.add("API_KEY")
        if "token" in st or "jwt" in st or "bearer" in blob or "session" in blob:
            caps.add("TOKEN")
    # Network / crypto / cert
    # CLEARTEXT only when cleartext is ACTUALLY permitted: never when the
    # authoritative resolution says it's blocked, and only for a finding that
    # ASSERTS it's permitted (not one that says it's disabled, and not a mere
    # mention). Reuses the security_controls negation guard.
    if "cleartext" in blob:
        blocked = results is not None and security_controls.state_of(results, "cleartext") == "blocked"
        if not blocked and security_controls.finding_asserts_absent(f, "cleartext"):
            caps.add("CLEARTEXT")
    # CERT_BYPASS requires POSITIVE evidence of disabled validation (a trust-all
    # TrustManager, an allow-all HostnameVerifier, an onReceivedSslError that
    # proceeds, …) — a pass-through setSSLSocketFactory/setSSLContext does not qualify.
    if rule_id in _CERT_BYPASS_RULE_IDS or any(t in blob for t in _CERT_BYPASS_TOKENS):
        caps.add("CERT_BYPASS")
    if cat == "network security":
        caps.add("NETWORK")
    if (cat in ("cryptography", "crypto")) and any(w in blob for w in
            ("weak", "insecure", "ecb", "md5", "sha-1", "sha1", "des", "rc4", "static iv")):
        caps.add("WEAK_CRYPTO")
    # Storage / manifest posture
    if cat == "data storage" or "sharedpreferences" in blob or "insecure storage" in blob \
            or "world readable" in blob or "world writable" in blob:
        caps.add("INSECURE_STORAGE")
    if "allowbackup" in blob or "backup enabled" in blob or "backup allowed" in blob:
        caps.add("BACKUP")
    # DEBUGGABLE only when the app is ACTUALLY debuggable — never from a textual
    # mention (e.g. a "not declared" breadcrumb). Absent android:debuggable
    # defaults to false. Mirrors the allowBackup discipline: real =true only,
    # resolved from the authoritative manifest_security state, not the blob.
    _dbg_state = ""
    if results is not None:
        _dbg_state = str(
            ((results.get("manifest_security") or {}).get("debuggable") or {}).get("state") or ""
        ).lower()
    if rule_id == "manifest_debuggable" or ("debuggable" in blob and _dbg_state == "true"):
        caps.add("DEBUGGABLE")
    if cat == "binary hardening" or str(f.get("file_path") or "").endswith((".so", ".dylib")):
        caps.add("NATIVE")
    if "jni" in blob:
        caps.add("JNI")
    return caps


# Legacy finding_model ownership labels (uppercase) that mean library/framework code —
# the counterpart to the OwnerType constants in _NON_APP_OWNERS.
_NON_APP_LABELS = frozenset((
    "THIRD_PARTY_LIBRARY", "THIRD_PARTY_SDK", "ANDROID_FRAMEWORK", "GOOGLE_SDK",
    "APPLE_FRAMEWORK", "VENDOR_SDK", "OPEN_SOURCE_LIBRARY", "GENERATED_CODE",
    "FIREBASE", "JETPACK",
))


def _finding_is_library_owned(f: dict) -> bool:
    """Whether a finding's RESOLVED ownership is a library/framework/generated owner.

    Reads the ownership the pipeline already attached (owner_type from the Ownership
    Engine, ownership_label from finding_model) — never recomputes it."""
    ot = str(f.get("owner_type") or "")
    if ot in _NON_APP_OWNERS:
        return True
    return str(f.get("ownership_label") or "").upper() in _NON_APP_LABELS


# Defensive controls that are IN USE — never a step in a weakness chain. A finding
# marked security_control, or asserting one of these controls without a weakness
# qualifier, is positive evidence, not an attack step.
_POSITIVE_CONTROL_TOKENS = (
    "encryptedsharedpreferences", "encrypted shared preferences", "encrypted storage",
    "flutter secure storage", "flutter_secure_storage", "androidx.security.crypto",
    "androidx.security", "masterkey", "sqlcipher", "keystore-backed", "keychain",
    "secure storage", "secure enclave",
)
_CONTROL_WEAKNESS_TOKENS = (
    "no ", "not ", "missing", "without", "insecure", "weak", "plaintext",
    "unencrypted", "world readable", "world writable", "cleartext", "disabled",
)


def _is_positive_control(f: dict) -> bool:
    """A defensive control that is PRESENT/in use — must never be listed as a step in
    a weakness chain (e.g. Flutter Secure Storage / EncryptedSharedPreferences in an
    Insecure-Storage or Weak-Crypto chain)."""
    if f.get("security_control"):
        return True
    blob = _blob(f)
    if not any(tok in blob for tok in _POSITIVE_CONTROL_TOKENS):
        return False
    # A control token present WITHOUT a weakness qualifier → the control is in use.
    return not any(neg in blob for neg in _CONTROL_WEAKNESS_TOKENS)


def chain_role(f: dict) -> str:
    """required | supporting | excluded — SAFE CHAINING from Triage + Secret status +
    resolved ownership."""
    if _secret_status(f) in C.REJECT_SECRET_STATUSES:
        return "excluded"
    tri = f.get("triage") or {}
    decision = tri.get("decision", "")
    if decision in C.EXCLUDED_DECISIONS:
        return "excluded"
    if f.get("suppressed"):
        # Suppressed findings may only lend structural context.
        return "supporting" if (tag_capabilities(f) & _STRUCTURAL_CAPS) else "excluded"
    if decision in C.SUPPORTING_ONLY_DECISIONS:
        return "supporting"
    # Ownership enforcement (Fix 2): a library/framework/generated-owned finding is
    # NOT the application's vulnerability. It can never be a REQUIRED link — at most
    # supporting context when it carries a structural cap (e.g. a framework WebView).
    if _finding_is_library_owned(f):
        return "supporting" if (tag_capabilities(f) & _STRUCTURAL_CAPS) else "excluded"
    vis = tri.get("visibility", "")
    if vis == "HiddenByDefault":
        return "supporting" if (tag_capabilities(f) & _STRUCTURAL_CAPS) else "excluded"
    return "required"


# ════════════════════════════════════════════════════════════════════════════
# Context
# ════════════════════════════════════════════════════════════════════════════
class ChainContext:
    def __init__(self, results: dict):
        self.results = results
        self.platform = results.get("platform") or "android"
        self.surface = results.get("attack_surface") or {}
        self.findings = [f for f in (results.get("findings") or []) if isinstance(f, dict)]
        self.mitigations = _detect_mitigations(results)

        # Ownership: used to reject library/framework components as entry nodes and
        # to require the proven taint sink to live in application code.
        self._own_engine = _get_ownership_engine()
        self._own_ctx = context_from_results(results)
        self._own_cache: dict[str, str] = {}

        # Independent taint evidence for the reachability gate: the taint engine's
        # own flow list, plus any finding that carries a taint_flow. Never derived
        # from chain membership.
        self.taint_flows: list[dict] = self._collect_taint_flows(results)

        # Launcher-only (MAIN/LAUNCHER) activities are the home entry, not
        # attacker-deliverable IPC — never an injection/RCE external entry.
        self._launcher_only_names = {
            c.get("name") for c in (self.surface.get("activities") or [])
            if isinstance(c, dict) and c.get("name") and _is_launcher_only_activity(c)
        }

        # Tag + role each finding once (deterministic).
        self.tagged: list[dict] = []
        for f in self.findings:
            role = chain_role(f)
            if role == "excluded":
                continue
            self.tagged.append({"f": f, "caps": tag_capabilities(f, results), "role": role,
                                "id": _finding_id(f)})
        # Stable ordering: strongest first (confidence, then evidence), then id.
        self.tagged.sort(key=lambda t: (-_conf(t["f"]), C.EVIDENCE_RANK.get(_equality(t["f"]), 4), t["id"]))

    def _collect_taint_flows(self, results: dict) -> list[dict]:
        """Gather taint flows from the taint engine's list and any finding carrying
        a taint_flow, normalized to {source_cat, sink_cat, class}. Deterministic."""
        flows: list[dict] = []
        seen: set = set()

        def _add(source_cat, sink_cat, cls):
            source_cat = str(source_cat or "").strip().lower()
            sink_cat = str(sink_cat or "").replace(" ", "").strip().lower()
            key = (source_cat, sink_cat, str(cls or ""))
            if not source_cat or not sink_cat or key in seen:
                return
            seen.add(key)
            flows.append({"source_cat": source_cat, "sink_cat": sink_cat, "class": str(cls or "")})

        for tf in results.get("taint_flows") or []:
            if isinstance(tf, dict):
                _add(tf.get("source_cat"), tf.get("sink_cat"), tf.get("class_name") or tf.get("class"))
        for f in self.findings:
            tf = f.get("taint_flow")
            if isinstance(tf, dict):
                _add(tf.get("source_cat"), tf.get("sink_cat"),
                     tf.get("class_name") or tf.get("class") or f.get("file_path"))
        flows.sort(key=lambda x: (x["source_cat"], x["sink_cat"], x["class"]))
        return flows

    def _owner_of(self, name: str) -> str:
        """Ownership type of a class/package FQN, cached. '' when unclassifiable."""
        if not name:
            return ""
        if name not in self._own_cache:
            try:
                res = self._own_engine.classify_package(name, platform=self.platform, ctx=self._own_ctx)
                self._own_cache[name] = res.owner_type or ""
            except Exception:  # noqa: BLE001 — ownership must never break chaining
                self._own_cache[name] = ""
        return self._own_cache[name]

    def _is_app_entry(self, name: str) -> bool:
        """True unless the component is owned by a known library/framework/generated
        source. APPLICATION and UNKNOWN pass; library owners are rejected (Flaw A)."""
        return self._owner_of(name) not in _NON_APP_OWNERS

    def _is_app_owned_class(self, name: str) -> bool:
        """Strict: the class must classify as APPLICATION. Used to require the proven
        taint sink to live in application code, not a bundled SDK."""
        return self._owner_of(name) == OwnerType.APPLICATION

    def entry_point(self, template) -> tuple[dict | None, str]:
        """Return (entry_dict, reach_key) or (None, '') when no entry exists."""
        if template.entry_kind in ("distribution", "device"):
            return ({"label": template.entry_label, "kind": template.entry_kind,
                     "reachable": True, "component": ""},
                    "distribution" if template.entry_kind == "distribution" else "device")
        # external — need an APPLICATION-owned structural entry. A library component
        # must never become an entry node, so if none exists this template does not
        # emit an "external_reachable" chain.
        comp = self._surface_entry(template.entry_caps)
        if comp:
            return ({"label": template.entry_label, "kind": "external",
                     "component": comp["name"], "reachable": True}, "external_reachable")
        ft = self._first_with_caps(template.entry_caps)
        if ft:
            comp_name = ft["f"].get("component") or ft["f"].get("title", "")
            # Reject a launcher-only activity here too: it is not attacker-deliverable
            # IPC even when a finding references it (Part B).
            if (self._is_app_entry(comp_name)
                    and ft["f"].get("component") not in self._launcher_only_names
                    and not _is_launcher_only_activity(ft["f"])):
                reach = str(ft["f"].get("reachability") or "").upper()
                key = "external_reachable" if reach == "YES" else "external"
                return ({"label": template.entry_label, "kind": "external",
                         "component": comp_name,
                         "reachable": reach in ("YES", "MAYBE", "")}, key)
        return None, ""

    def _surface_entry(self, caps: frozenset) -> dict | None:
        """First APPLICATION-owned exported manifest component satisfying ANY
        requested entry cap. Library/framework components (androidx.*, com.google.*,
        …) are skipped — they are not the app's declared attack surface (Flaw A)."""
        want_provider = "EXPORTED_PROVIDER" in caps
        want_deeplink = "DEEPLINK" in caps
        want_exported = "EXPORTED" in caps
        for key in ("providers", "activities", "services", "receivers"):
            for c in sorted(self.surface.get(key) or [], key=lambda x: str(x.get("name", ""))):
                if not c.get("exported"):
                    continue
                name = c.get("name", key)
                if not self._is_app_entry(name):
                    continue
                # A launcher-only activity (MAIN/LAUNCHER) is the home entry, not
                # attacker-deliverable IPC — it never satisfies an injection/RCE
                # EXPORTED/DEEPLINK entry (Part B). Skip it as a candidate entry.
                if key == "activities" and _is_launcher_only_activity(c):
                    continue
                if want_provider and key == "providers":
                    return {"name": name, "type": key}
                if want_deeplink and (c.get("browsable") or c.get("schemes")):
                    return {"name": name, "type": key}
                if want_exported:
                    return {"name": name, "type": key}
        return None

    def reachability_proof(self, template, entry: dict) -> str:
        """proven | heuristic | manifest-only for `template` given `entry` (Flaw B).

        Non-injection templates make no dataflow claim → 'manifest-only'. An
        injection/RCE template is 'proven' only when a taint flow links external
        input to the template's sink category in an application-owned class;
        otherwise 'heuristic'.
        """
        gated = _template_sink_caps(template)
        if not gated:
            return PROOF_MANIFEST
        wanted_sinks: set = set()
        for cap in gated:
            wanted_sinks |= _SINK_CAP_TAINT_CATS.get(cap, frozenset())
        for tf in self.taint_flows:
            if (tf["source_cat"] in _EXTERNAL_SOURCE_CATS
                    and tf["sink_cat"] in wanted_sinks
                    and self._is_app_owned_class(tf["class"])):
                return PROOF_PROVEN
        return PROOF_HEURISTIC

    def _first_with_caps(self, caps: frozenset) -> dict | None:
        for t in self.tagged:
            if t["caps"] & caps:
                return t
        return None

    def supporting(self, caps: frozenset, used: set) -> list[dict]:
        """Distinct, deterministically-ranked, capped supporting findings for a chain.

        Excludes positive controls (a defensive control is never an attack step),
        deduplicates by (title, file:line) and (rule_id, file, line) so one library
        string can't render ~40 times, then keeps the strongest MAX_SUPPORTING by
        severity, then evidence quality, then id."""
        cand = []
        for t in self.tagged:
            if t["id"] in used:
                continue
            if not (t["caps"] & caps):
                continue
            if _is_positive_control(t["f"]):
                continue
            cand.append(t)

        # Deterministic strongest-first ordering before dedup, so the row kept for a
        # duplicate location is the highest-severity / best-evidenced one.
        cand.sort(key=lambda t: (C.sev_rank(t["f"].get("severity", "info")),
                                 C.EVIDENCE_RANK.get(_equality(t["f"]), 4), t["id"]))

        out, seen = [], set()
        for t in cand:
            f = t["f"]
            fp, line = _finding_location(f)
            loc = f"{fp}:{line}" if fp else ""
            title = str(f.get("title") or "").strip().lower()
            rid = str(f.get("rule_id") or f.get("id") or "")
            keys = ((title, loc), (rid, fp, line))
            if any(k in seen for k in keys):
                continue
            for k in keys:
                seen.add(k)
            out.append(t)
            if len(out) >= C.MAX_SUPPORTING:
                break
        return out


# Chain blocker key -> the security control that implements it.
_MITIGATION_CONTROLS = (
    ("cert_pinning", "cert_pinning"),
    ("root_detection", "root_detection"),
    ("attestation", "safetynet_play_integrity"),
)


def _detect_mitigations(results: dict) -> set:
    """Which chain blockers the app actually implements.

    Read from the resolved security controls rather than re-derived. The old
    substring scan blocked a MitM chain whenever any finding title contained
    "certificate pinning" — including *"No Certificate Pinning Configured"*, which
    is the reason to run the chain, not to suppress it. It also mixed in
    `results["score"]["bonuses"]`, which is always empty here because chains are
    built before scoring.

    A `partial` control does not block: pinning that `debug-overrides` can switch
    off, or that covers one domain out of five, is not a barrier an attacker meets.
    """
    return {blocker for blocker, control in _MITIGATION_CONTROLS
            if security_controls.is_present(results, control)}


# ── small accessors ──────────────────────────────────────────────────────────
def _template_sink_caps(template) -> frozenset:
    """Gated injection/RCE sink capabilities this template requires (possibly empty)."""
    caps: set = set()
    for slot in template.required_slots:
        caps |= (set(slot) & _GATED_SINK_CAPS)
    return frozenset(caps)


def _coerce_int(v, default: int) -> int:
    try:
        return int(round(float(v)))
    except (TypeError, ValueError):
        return default


def _conf(f: dict) -> int:
    for key in ("overall_confidence", "confidence_score", "confidence"):
        v = f.get(key)
        if v not in (None, ""):
            return max(0, min(100, _coerce_int(v, 50)))
    return 50


def _equality(f: dict) -> str:
    return ((f.get("evidence_bundle") or {}).get("quality")) or "Missing"


def _finding_id(f: dict) -> str:
    return f.get("canonical_id") or f.get("rule_id") or f.get("id") or \
        ("F-" + hashlib.sha1(str(f.get("title", "")).encode("utf-8", "replace")).hexdigest()[:8])


# ════════════════════════════════════════════════════════════════════════════
# Scoring (from prior-engine outputs only)
# ════════════════════════════════════════════════════════════════════════════
def _evidence_quality(findings: list[dict]) -> str:
    if not findings:
        return "Missing"
    worst = max(C.EVIDENCE_RANK.get(_equality(f), 4) for f in findings)
    return C.EVIDENCE_BY_RANK[worst]


def _chain_confidence(required: list[dict], reach_key: str) -> tuple[int, dict]:
    mean_conf = sum(_conf(f) for f in required) / len(required)
    mean_ev = sum(C.EVIDENCE_SCORE.get(_equality(f), 10) for f in required) / len(required)
    blend = (C.CONFIDENCE_BLEND["member_confidence"] * mean_conf
             + C.CONFIDENCE_BLEND["member_evidence"] * mean_ev)
    mult = C.ENTRY_REACH_MULTIPLIER.get(reach_key, 0.85)
    score = max(0, min(100, round(blend * mult)))
    return score, {"mean_member_confidence": round(mean_conf), "mean_member_evidence": round(mean_ev),
                   "entry_reach_multiplier": mult, "formula": "0.55*conf + 0.45*evidence, scaled by reachability"}


def _chain_exploitability(required: list[dict], reach_key: str, app_control: bool,
                          blocked: bool) -> tuple[int, dict]:
    base = C.EXPLOIT_BASE.get(reach_key, 55)
    expl_conf = [_coerce_int(f.get("exploitability_confidence"), 0) for f in required]
    avg_expl = round(sum(expl_conf) / len(expl_conf)) if expl_conf else 0
    # Blend the entry-kind base with the members' own exploitability confidence.
    score = round((base + avg_expl) / 2) if avg_expl else base
    if app_control:
        score += C.EXPLOIT_APP_CONTROL_BONUS
    if blocked:
        score -= C.EXPLOIT_BLOCKED_PENALTY
    score = max(0, min(100, score))
    return score, {"entry_base": base, "avg_member_exploitability": avg_expl,
                   "app_control_bonus": C.EXPLOIT_APP_CONTROL_BONUS if app_control else 0,
                   "blocked_penalty": C.EXPLOIT_BLOCKED_PENALTY if blocked else 0}


def _chain_severity(goal: str, exploitability: int, blocked: bool) -> str:
    rank = C.sev_rank(C.GOAL_SEVERITY.get(goal, C.GOAL_SEVERITY["default"]))
    if exploitability < C.SEVERITY_DOWNGRADE_EXPLOIT:
        rank += 1
    if blocked:
        rank += 1
    return C.sev_by_rank(rank)


# ════════════════════════════════════════════════════════════════════════════
# Chain assembly
# ════════════════════════════════════════════════════════════════════════════
def _selection_primary(f: dict):
    """The Evidence Selection primary location, if present. Lazy import avoids any
    import cycle and keeps attack chains independent when selection didn't run."""
    try:
        from ..evidence_selection import primary_location
        sel = f.get("evidence_selection")
        if isinstance(sel, dict) and sel.get("primary"):
            return primary_location(f)
    except Exception:  # noqa: BLE001
        pass
    return "", 0, ""


def _finding_location(f: dict) -> tuple[str, int]:
    """(file, line) for a finding — the corrected Evidence Selection primary when
    present, else the evidence-bundle primary / legacy fields."""
    sel_file, sel_line, _ = _selection_primary(f)
    if sel_file:
        return sel_file, int(sel_line or 0)
    prim = (f.get("evidence_bundle") or {}).get("primary") or {}
    fp = prim.get("relative_path") or prim.get("file_path") or f.get("file_path") or ""
    line = prim.get("line") or f.get("line") or f.get("line_number") or 0
    return fp, int(line or 0)


def _aggregate_evidence(findings: list[dict]):
    files, classes, methods, refs = [], [], [], []
    ref_seen: set = set()
    for f in findings:
        eb = f.get("evidence_bundle") or {}
        prim = eb.get("primary") or {}
        # Phase 1.97: prefer the Evidence Selection primary (application-owned, not a
        # framework/library file) so chains never present a library-only node as
        # proof. Falls back to the evidence bundle / file_path when selection is absent.
        sel_file, sel_line, _sel_snip = _selection_primary(f)
        # File AND line must come from the SAME source: when selection corrected the
        # file, its line must accompany it (the bundle line belongs to the old file).
        # This is what lets "view code" on a chain land on the exact evidence line.
        if sel_file:
            fp, line = sel_file, sel_line
        else:
            fp = prim.get("relative_path") or prim.get("file_path") or f.get("file_path")
            line = prim.get("line") or f.get("line") or f.get("line_number")
        if fp and fp not in files:
            files.append(fp)
        loc = prim.get("locator") or {}
        if loc.get("class") and loc["class"] not in classes:
            classes.append(loc["class"])
        if loc.get("method") and loc["method"] not in methods:
            methods.append(loc["method"])
        # Emit a reference whenever we have a proof file so the chain carries a
        # per-member (file, line) the viewer can jump to. When no line is known,
        # carry None so the frontend omits the jump gracefully rather than opening
        # at the top with no indication.
        if fp:
            ref_key = (fp, line or None)
            if ref_key not in ref_seen:
                ref_seen.add(ref_key)
                refs.append({"finding": _finding_id(f),
                             "evidence_id": eb.get("evidence_id") or f"EV-{_finding_id(f)}",
                             "file": fp, "line": (line or None)})
    return files, classes, methods, refs


def _build_graph(entry: dict, required: list[dict], supporting: list[dict],
                 goal_label: str, mitigations: list[str]) -> ChainGraph:
    g = ChainGraph()
    en = g.add_node(ChainNode(id="entry", type=NodeType.ENTRY_POINT,
                              label=entry.get("label", "Entry"),
                              ref=entry.get("component", ""),
                              metadata={"kind": entry.get("kind")}))
    if entry.get("component"):
        cn = g.add_node(ChainNode(id="component", type=NodeType.ACTIVITY,
                                  label=entry["component"], ref=entry["component"]))
        g.add_edge(ChainEdge(en.id, cn.id, EdgeRelation.EXPOSES, "exposes"))
        prev = cn.id
    else:
        prev = en.id
    for i, f in enumerate(required):
        nid = f"req{i}"
        g.add_node(ChainNode(id=nid, type=NodeType.FINDING, label=f.get("title", "finding"),
                             ref=_finding_id(f),
                             metadata={"owner": f.get("owner_type"),
                                       "confidence": f.get("overall_confidence"),
                                       "evidence": (f.get("evidence_bundle") or {}).get("quality")}))
        g.add_edge(ChainEdge(prev, nid, EdgeRelation.LEADS_TO, "enables"))
        prev = nid
    for i, f in enumerate(supporting):
        nid = f"sup{i}"
        g.add_node(ChainNode(id=nid, type=NodeType.FINDING, label=f.get("title", "finding"),
                             ref=_finding_id(f), metadata={"role": "supporting"}))
        g.add_edge(ChainEdge(nid, prev, EdgeRelation.WEAKENS, "supports"))
    goal = g.add_node(ChainNode(id="goal", type=NodeType.GOAL, label=goal_label))
    g.add_edge(ChainEdge(prev, goal.id, EdgeRelation.LEADS_TO, "achieves"))
    for m in mitigations:
        mn = g.add_node(ChainNode(id="mit-" + hashlib.sha1(m.encode()).hexdigest()[:6],
                                  type=NodeType.RESOURCE, label=m, metadata={"role": "mitigation"}))
        g.add_edge(ChainEdge(mn.id, goal.id, EdgeRelation.PROTECTS, "mitigates"))
    return g


def _build_narrative(template, entry: dict, required: list[dict], goal_label: str) -> list[dict]:
    steps = [{"order": 1, "title": "Entry point", "description": entry.get("label", ""),
              "finding": "", "evidence": entry.get("component", "")}]
    for i, f in enumerate(required):
        # Per-step evidence targets THIS step's own file:line, from the same
        # (corrected) Evidence Selection primary the aggregated references use — so a
        # step's "view code" lands on its exact line, not a stale bundle location.
        sel_file, sel_line, _ = _selection_primary(f)
        if sel_file:
            ev = f"{sel_file}:{sel_line}" if sel_line else sel_file
        else:
            eb = f.get("evidence_bundle") or {}
            prim = eb.get("primary") or {}
            ev = ""
            fp = prim.get("relative_path") or prim.get("file_path") or f.get("file_path")
            if fp:
                ln = prim.get("line") or f.get("line") or f.get("line_number")
                ev = f"{fp}:{ln}" if ln else fp
        label = template.slot_labels[i] if i < len(template.slot_labels) else f.get("title", "")
        steps.append({"order": i + 2, "title": label, "description": f.get("title", ""),
                      "finding": _finding_id(f), "evidence": ev})
    steps.append({"order": len(required) + 2, "title": "Objective achieved",
                  "description": goal_label, "finding": "", "evidence": ""})
    return steps


_ALLOW_BACKUP_TRUE_RE = re.compile(r'allowbackup\s*=\s*"(?:true|1)"')


def _allow_backup_true(results: dict) -> bool:
    """Whether android:allowBackup is actually true (manifest / manifest_security, or a
    genuine allowBackup finding derived from the manifest). The BACKUP chain's premise
    is this flag; without it there is no backup path — and a debuggable finding, which
    never asserts allowBackup, can never stand in for it."""
    mx = str(results.get("manifest_xml") or "").lower()
    if _ALLOW_BACKUP_TRUE_RE.search(mx):
        return True
    ms = results.get("manifest_security") or {}
    ab = ms.get("allow_backup", ms.get("allowBackup"))
    if isinstance(ab, dict):
        ab = ab.get("state", ab.get("value"))
    if str(ab).strip().lower() in ("true", "1", "enabled"):
        return True
    # A finding that genuinely asserts allowBackup is enabled (manifest-derived).
    for f in results.get("findings") or []:
        if not isinstance(f, dict):
            continue
        blob = " ".join(str(f.get(k) or "") for k in ("title", "description", "rule_id")).lower()
        if "allowbackup" in blob.replace(" ", "") and not any(
                neg in blob for neg in ("false", "disabled", "not ", "= \"false\"")):
            return True
    return False


def _template_suppressed_by_controls(tmpl, results: dict) -> bool:
    """Authoritative-state veto: a template must never be emitted when the state it
    depends on contradicts it.

    * CLEARTEXT-MITM-TOKEN cannot exist when cleartext is resolved to ``blocked``.
    * BACKUP-DATA-EXTRACTION requires android:allowBackup="true"; without it there is
      no backup path (and a debuggable finding must never stand in as its entry)."""
    if tmpl.id == "CLEARTEXT-MITM-TOKEN":
        return security_controls.state_of(results, "cleartext") == "blocked"
    if tmpl.id == "BACKUP-DATA-EXTRACTION":
        return not _allow_backup_true(results)
    return False


def _summary_counts(findings: list[dict], key_path) -> dict:
    out: dict = {}
    for f in findings:
        v = key_path(f)
        if v:
            out[v] = out.get(v, 0) + 1
    return out


# ════════════════════════════════════════════════════════════════════════════
# The engine
# ════════════════════════════════════════════════════════════════════════════
class AttackChainEngine:
    version = C.CHAIN_VERSION

    def __init__(self, templates: list | None = None):
        tmpl = templates if templates is not None else T.TEMPLATES
        self._templates = sorted(tmpl, key=lambda t: (-t.priority, t.id))

    def build_chains(self, results: dict) -> list[dict]:
        ctx = ChainContext(results)
        chains: list[AttackChain] = []
        emitted_member_sets: list[frozenset] = []

        for tmpl in self._templates:
            if _template_suppressed_by_controls(tmpl, results):
                continue
            entry, reach_key = ctx.entry_point(tmpl)
            if entry is None:
                continue
            # Constrained slot matching: fill the most-constrained slot (fewest
            # candidate findings) first, so a versatile finding that matches
            # several slots is not greedily consumed by an earlier one.
            slots = list(enumerate(tmpl.required_slots))
            cand = {i: [t for t in ctx.tagged if t["role"] == "required" and (t["caps"] & s)]
                    for i, s in slots}
            used: set = set()
            assign: dict = {}
            ok = True
            for i, _s in sorted(slots, key=lambda x: (len(cand[x[0]]), x[0])):
                pick = next((t for t in cand[i] if t["id"] not in used), None)
                if pick is None:
                    ok = False
                    break
                used.add(pick["id"])
                assign[i] = pick
            if not ok:
                continue
            required_t = [assign[i] for i, _ in slots]
            required = [t["f"] for t in required_t]
            member_set = frozenset(_finding_id(f) for f in required)
            # Avoid "finding soup": skip if these required findings are already
            # fully represented by a higher-priority chain.
            if any(member_set <= prev for prev in emitted_member_sets):
                continue

            support_t = ctx.supporting(tmpl.supporting_caps, used) if tmpl.supporting_caps else []
            supporting = [t["f"] for t in support_t]
            chains.append(self._assemble(tmpl, entry, reach_key, required, supporting, ctx))
            emitted_member_sets.append(member_set)

        chains.sort(key=lambda c: (C.sev_rank(c.severity), -c.overall_confidence, c.id))
        return [c.to_dict() for c in chains]

    def _assemble(self, tmpl, entry, reach_key, required, supporting, ctx) -> AttackChain:
        blocked_by = [b for b in tmpl.blockers if b in ctx.mitigations]
        blocked = bool(blocked_by)
        app_control = any((f.get("owner_type") == "Application") for f in required)

        confidence, conf_expl = _chain_confidence(required, reach_key)
        exploitability, expl_expl = _chain_exploitability(required, reach_key, app_control, blocked)
        evidence_q = _evidence_quality(required)
        severity = _chain_severity(tmpl.goal, exploitability, blocked)

        # Reachability gate (Flaw B): an injection/RCE chain with no taint flow from
        # external input to the matching sink is heuristic — it may exist, but it is
        # capped below CRITICAL and below 60 confidence so it can never present as a
        # proven critical finding on co-occurrence alone.
        proof = ctx.reachability_proof(tmpl, entry)
        if proof == PROOF_HEURISTIC:
            if C.sev_rank(severity) < C.sev_rank("high"):
                severity = "high"
            confidence = min(confidence, C.HEURISTIC_CONFIDENCE_CAP)
            conf_expl = {**conf_expl, "reachability_cap": C.HEURISTIC_CONFIDENCE_CAP,
                         "reachability_proof": proof}

        files, classes, methods, refs = _aggregate_evidence(required + supporting)
        components = [entry["component"]] if entry.get("component") else []

        members = required + supporting
        chain = AttackChain(
            id=self._chain_id(tmpl, required),
            name=tmpl.name, type=tmpl.type, goal=tmpl.summary,
            summary=tmpl.summary,
            prerequisites=list(tmpl.prerequisites),
            entry_point=entry,
            steps=_build_narrative(tmpl, entry, required, tmpl.impact),
            required_findings=[_finding_id(f) for f in required],
            supporting_findings=[_finding_id(f) for f in supporting],
            blocked_by=blocked_by, mitigations=list(tmpl.mitigations), blocked=blocked,
            reachability_proof=proof,
            overall_confidence=confidence, overall_evidence_quality=evidence_q,
            overall_exploitability=exploitability, overall_impact=tmpl.impact,
            severity=severity,
            affected_components=components, affected_files=files,
            affected_classes=classes, affected_methods=methods,
            evidence_references=refs,
            triage_summary=_summary_counts(members, lambda f: (f.get("triage") or {}).get("decision")),
            ownership_summary=_summary_counts(members, lambda f: f.get("owner_type")),
            narrative=_build_narrative(tmpl, entry, required, tmpl.impact),
            graph=_build_graph(entry, required, supporting, tmpl.impact, tmpl.mitigations).to_dict(),
            version=self.version,
        )
        chain.confidence_explanation = {
            "why_exists": f"Required links for '{tmpl.name}' are all present with a real entry point "
                          f"({entry.get('kind')}).",
            "why_members": [{"finding": _finding_id(f), "title": f.get("title"),
                             "owner": f.get("owner_type"),
                             "evidence": (f.get("evidence_bundle") or {}).get("quality"),
                             "triage": (f.get("triage") or {}).get("decision")} for f in required],
            "why_supporting": [_finding_id(f) for f in supporting],
            "why_confidence": conf_expl,
            "why_exploitability": expl_expl,
            "why_blocked": (f"Mitigation(s) {blocked_by} break this chain." if blocked
                            else "No blocking mitigation detected."),
        }
        return chain

    @staticmethod
    def _chain_id(tmpl, required) -> str:
        basis = tmpl.id + "|" + "|".join(sorted(_finding_id(f) for f in required))
        return "CHAIN-" + hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:10]


# ── cached singleton + public API ────────────────────────────────────────────
_ENGINE: AttackChainEngine | None = None


def get_engine() -> AttackChainEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = AttackChainEngine()
    return _ENGINE


def build_chains(results: dict) -> list[dict]:
    return get_engine().build_chains(results)


def annotate(results: dict) -> dict:
    """Pipeline integration — emit `results['attack_chains_v2']` (+ summary).

    ADDITIVE and NON-DESTRUCTIVE: it reads the enriched findings and writes a new
    key; the legacy chain output, findings, severity, reports and UI are
    untouched. Runs after Triage (the final quality gate). Deterministic.
    """
    engine = get_engine()
    chains = engine.build_chains(results)
    by_type: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for c in chains:
        by_type[c["type"]] = by_type.get(c["type"], 0) + 1
        by_sev[c["severity"]] = by_sev.get(c["severity"], 0) + 1
    results["attack_chains_v2"] = chains
    results["attack_chains_v2_summary"] = {
        "count": len(chains), "by_type": by_type, "by_severity": by_sev,
        "blocked": sum(1 for c in chains if c["blocked"]), "version": engine.version,
    }
    log.info("[attack_chains_v2] %d chains | severity=%s", len(chains), by_sev)
    return results
