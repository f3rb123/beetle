"""Per-binary protection table for iOS (RUN 9) — main executable + every framework.

THIS IS THE FALSE-POSITIVE RUN. MobSF flags "missing stack canary" and "missing ARC" as HIGH
on App.framework/App. That binary is the Dart AOT snapshot: the app's OWN compiled Dart code,
the iOS twin of Android's libapp.so. It is emitted by the Dart compiler, not clang, so it has
no stack canary and no ARC by construction — those are clang/Objective-C features. Flagging it
is a false positive, and NOT copying it is the core Beetle-beats-MobSF differentiator.

Two suppression classes, both decided from CONTENT (never from a filename):

  1. Dart-AOT blob  — identified by its exported snapshot symbols (_kDartVmSnapshotInstructions
     et al). Missing canary/ARC on it is expected and is never a finding.
  2. Pure C library — a binary with ZERO Objective-C runtime imports (e.g. nanopb) cannot have
     ARC, because ARC *is* the ObjC runtime. "Missing ARC" is a meaningless claim about it.

Everything else — a genuine native framework with real ObjC/C code — IS flagged when a
protection is absent. Suppression is narrow and evidence-driven, not a blanket exemption.
"""
from __future__ import annotations

# Order of the table columns, so every renderer agrees.
COLUMNS = ("binary", "kind", "nx", "pie", "stack_canary", "arc", "code_signature",
           "encrypted", "symbols_stripped", "rpaths", "insecure_apis")

KIND_MAIN = "main executable"
KIND_DART_AOT = "Dart AOT (app code)"
KIND_PURE_C = "native library (no ObjC)"
KIND_FRAMEWORK = "native framework"


def _kind(b: dict, is_main: bool) -> str:
    if b.get("is_dart_aot"):
        return KIND_DART_AOT
    if is_main:
        return KIND_MAIN
    if not b.get("objc_import_count"):
        return KIND_PURE_C
    return KIND_FRAMEWORK


def build_table(binaries: list, main_binary: str = "", owner_of=None) -> list[dict]:
    """One row per Mach-O — the main executable FIRST, then frameworks alphabetically.

    ``owner_of(relative_path) -> owner_type`` is the shared Ownership Engine (the same one RUN 8
    fixed so the app's main executable resolves to APPLICATION instead of being mistaken for a
    CocoaPod). Severity below keys off THAT decision rather than inventing a second heuristic.
    """
    rows = []
    for b in binaries or []:
        if not isinstance(b, dict):
            continue
        rel = b.get("binary") or ""
        is_main = bool(main_binary) and rel.replace("\\", "/") == main_binary
        owner = ""
        if owner_of:
            try:
                owner = str(owner_of(rel) or "")
            except Exception:
                owner = ""
        rows.append({
            "owner_type": owner,
            "binary": rel,
            "kind": _kind(b, is_main),
            "nx": bool(b.get("has_nx_stack", True)),
            # PIE is only meaningful for the main executable; a dylib/framework is position
            # independent by definition, so reporting "no PIE" for one is noise.
            "pie": bool(b.get("has_pie")) if is_main else None,
            "stack_canary": bool(b.get("has_stack_canary")),
            "arc": bool(b.get("has_arc")),
            "code_signature": bool(b.get("has_code_signature")),
            "encrypted": bool(b.get("is_encrypted")),
            "symbols_stripped": bool(b.get("symbols_stripped")),
            "rpaths": len(b.get("rpaths") or []),
            "insecure_apis": sorted((b.get("api_scan") or {}).get("insecure") or []),
            "objc_import_count": int(b.get("objc_import_count") or 0),
            "is_dart_aot": bool(b.get("is_dart_aot")),
        })
    rows.sort(key=lambda r: (r["kind"] != KIND_MAIN, r["binary"].lower()))
    return rows


def _suppression_reason(row: dict, protection: str) -> str:
    """Why a missing protection on THIS binary is not a finding — or '' if it IS one."""
    if row["is_dart_aot"]:
        return ("Dart AOT snapshot (the app's own compiled Dart code, the iOS twin of Android's "
                "libapp.so). Emitted by the Dart compiler, not clang, so it has no stack canary "
                "and no ARC by construction. MobSF reports this as HIGH; it is a false positive.")
    if protection == "arc" and row["objc_import_count"] == 0:
        return ("No Objective-C runtime imports — a pure C/Swift library cannot use ARC, "
                "which IS the ObjC runtime. 'Missing ARC' is not a meaningful claim here.")
    return ""


APPLICATION_OWNER = "Application"


def _is_app_owned_native(row: dict) -> bool:
    """The missing protection is in code the APP ITSELF ships as native code.

    Keyed on the Ownership Engine's verdict (the field RUN 8 fixed), not a new heuristic. The
    Dart-AOT blob is excluded even though it is the app's own code: it is a Dart snapshot, not
    clang-compiled native code, so a canary was never applicable to it — that is the whole point
    of the guard.
    """
    if row.get("is_dart_aot"):
        return False
    return str(row.get("owner_type") or "") == APPLICATION_OWNER


def build_findings(rows: list) -> tuple[list, dict]:
    """(findings, suppressed) — consolidated findings, split by OWNERSHIP.

    Consolidated, not one-per-binary: a per-binary explosion would swamp the report (RUN 8's
    lesson).

    SEVERITY IS OWNERSHIP-BASED:
      * MEDIUM for a THIRD-PARTY/vendor framework — a real hardening gap in someone else's code,
        not a directly exploitable weakness in the app. MobSF calls these HIGH; that overstates
        them, and a defensible score is the point (RUN 15).
      * HIGH only when the missing protection is in the APP'S OWN native code (owner ==
        APPLICATION, and not the Dart-AOT blob) — there the app itself shipped unhardened
        native code and owns the fix.
    """
    findings, suppressed = [], {"stack_canary": [], "arc": []}
    # protection -> {"app": [...], "vendor": [...]}
    missing = {"stack_canary": {"app": [], "vendor": []},
               "arc": {"app": [], "vendor": []}}

    for row in rows:
        for protection in ("stack_canary", "arc"):
            if row.get(protection):
                continue                       # protection present — nothing to report
            reason = _suppression_reason(row, protection)
            if reason:
                suppressed[protection].append({"binary": row["binary"], "reason": reason})
            else:
                bucket = "app" if _is_app_owned_native(row) else "vendor"
                missing[protection][bucket].append(row["binary"])

    specs = {
        "stack_canary": {
            "rule_id": "macho_missing_stack_canary",
            "title": "Framework Binaries Without Stack Canary",
            "cwe": "CWE-693", "owasp": "M7", "masvs": "MASVS-CODE-8",
            "text": ("These binaries were built without stack-protector, so a stack buffer "
                     "overflow in them is not detected at return."),
            "fix": "Rebuild the affected frameworks with -fstack-protector-strong.",
        },
        "arc": {
            "rule_id": "macho_missing_arc",
            "title": "Framework Binaries Without ARC",
            "cwe": "CWE-401", "owasp": "M7", "masvs": "MASVS-CODE-8",
            "text": ("These Objective-C binaries were built without Automatic Reference "
                     "Counting, so memory is managed manually — a use-after-free / double-free "
                     "risk."),
            "fix": "Enable ARC (-fobjc-arc) for the affected frameworks.",
        },
    }

    for protection, spec in specs.items():
        for bucket, severity in (("app", "high"), ("vendor", "medium")):
            bins = sorted(missing[protection][bucket])
            if not bins:
                continue
            owned = (" in the application's own native code" if bucket == "app"
                     else " in bundled third-party frameworks")
            findings.append({
                "rule_id": spec["rule_id"] + ("_app" if bucket == "app" else ""),
                "title": spec["title"] + (" (Application Code)" if bucket == "app" else ""),
                "severity": severity,
                "category": "Binary Hardening",
                "cwe": spec["cwe"], "owasp": spec["owasp"], "masvs": spec["masvs"],
                "description": (f"{spec['text']}{owned}\n\nAffected binaries ({len(bins)}): "
                                f"{', '.join(bins)}"),
                "recommendation": spec["fix"],
                "file_path": bins[0],
                "snippet": ", ".join(bins),
                "affected_binaries": bins,
                "owner_class": bucket,
                "confidence": 95,         # structural fact from the symbol table, not a guess
                "evidence_type": "binary_protection",
                "provenance": "beetle_native",
            })
    return findings, suppressed
