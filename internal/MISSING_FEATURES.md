# Beetle — Missing Features & Gap Analysis (Phase 12)

**Author:** Reverse-engineering upgrade pass
**Basis:** MobSF 4.4.6 source (`Mobile-Security-Framework-MobSF-4.4.6(1).zip`, same
directory) read module-by-module, against a full read of the Beetle backend
(`backend/analyzers/*`, `decompiler.py`, `main.py`) and frontend source viewer.
**Method:** Concept study, not code reuse. Magic constants and algorithm ideas
are public format/spec knowledge; no MobSF source was copied.

> TL;DR — Beetle is **not** behind MobSF on most dimensions. It already has
> Info.plist parsing, ATS, embedded-framework detection, LIEF Mach-O/ELF
> checksec, CVE+KEV, secret intelligence, taint/attack-chains, and a full
> triage/suppression/RBAC collaboration layer that MobSF lacks. The real gaps
> are concentrated in **source-viewer fidelity**, **per-artifact binary
> presentation**, and **Objective-C/Swift reconstruction**. The highest-value
> defect (binary bytes rendered as garbage in "View code") is **fixed in this
> pass** — see "Shipped in this pass".

---

## 1. How MobSF's iOS pipeline is structured (the "why")

From `mobsf/StaticAnalyzer/views/ios/` + `views/common/binary/`:

| MobSF module | Responsibility | Why it exists |
|---|---|---|
| `ipa.py` / `static_analyzer.py` | Orchestration: unzip → locate `.app` → run each stage | One pass produces the whole report |
| `plist_analysis.py` | Info.plist → bundle id, versions, ATS, URL schemes, perms, capabilities | iOS apps declare their attack surface in the plist |
| `app_transport_security.py` | Parse `NSAppTransportSecurity` into per-domain verdicts | ATS exceptions are the #1 iOS transport finding |
| `binary/macho.py` (`MachOChecksec`) | LIEF `checksec`: PIE/NX/canary/ARC/rpath/encrypted/stripped/code-sign | Binary hardening posture |
| `binary_analysis.py` | Walk the bundle, run checksec on **every** Mach-O (app + frameworks + dylibs) | Per-artifact protections, not just the main image |
| `binary_rule_matcher.py` | Regex/symbol rules over the binary (`strcpy`, `NSLog`, `random`, …) | "Low-hanging fruit" insecure-API surface |
| `classdump.py` (`jtool2`/`class-dump`) | Dump ObjC classes/methods/selectors from the Mach-O | Readable structure from a stripped binary |
| `dylib.py` / framework handling | Treat each `.framework`/`.dylib` as its own analysis unit | Third-party SDK posture (Realm/Parse/Bolts…) |
| `strings.py` + `entropy.py` | `strings`-on-binary + Shannon entropy for secret-likeness | Recover URLs/keys from compiled code |
| `firebase.py` | Probe Firebase URLs found in strings | Public-DB exposure |
| `icon_analysis.py` | Locate the app icon (asset catalog / plist) | Report polish |
| `views/view_source.py` | Render a file: **allow-list of text extensions only** (`m/xml/plist/db/txt`); plist → JSON | **Never feeds a compiled binary to the text viewer** |
| `common/suppression.py` | Per-rule suppression by hash | Triage hygiene |

**Key architectural lesson borrowed:** MobSF's source viewer renders only an
*allow-list* of text types and converts plist→JSON; it never attempts to decode
an arbitrary binary as text. Beetle's viewer did the opposite (`read_text` on
anything), which is the root cause of the `@##c#h###` garbage. We adopt the
"classify-then-render" principle natively.

---

## 2. Capability matrix (MobSF vs Beetle)

Legend: ✅ present · 🟡 partial · ❌ missing

| # | Capability | MobSF | Beetle (before) | Gap | Priority |
|---|---|:---:|:---:|---|:---:|
| 1 | APK decompile (jadx/apktool) | ✅ | ✅ | — | — |
| 2 | Info.plist → metadata (id/version/ATS/schemes/perms/min-iOS) | ✅ | ✅ `ios_analyzer._parse_info_plist` | — | — |
| 3 | **Raw Info.plist viewer (beautified XML/JSON) in UI** | ✅ | ❌ | No dedicated plist workspace panel | **P1** |
| 4 | Mach-O checksec (PIE/NX/canary/ARC/sign/encrypt/strip/rpath) | ✅ | ✅ `lief_analyzer.analyze_macho` | ARC + stripped flags thin | P2 |
| 5 | **Per-framework protections table** (Realm/Parse/Bolts…) | ✅ | 🟡 data via `analyze_all_macho`, **no UI section** | Surface as its own panel | **P1** |
| 6 | Insecure-API symbol scan (`strcpy`/`NSLog`/`random`…) w/ count·risk·MASVS·CWE | ✅ | 🟡 `lief` risky-imports (no counts/table) | Dedicated symbol table | P2 |
| 7 | Frida/instrumentation dylib detection | ✅ | ✅ `_INSTRUMENTATION_DYLIBS` | present as metadata, not garbage | ✅ (this pass) |
| 8 | **ObjC/Swift class-dump → pseudo-source** | ✅ (`jtool2`) | ❌ | No class/selector/method extraction | **P1** |
| 9 | Source-tree nav (files/classes/methods/imports/strings/secrets) | 🟡 | 🟡 Code Browser (files only) | Add class/method/import facets | P2 |
| 10 | Secret detection (Google/AWS/Azure/JWT/Stripe/Twilio/GitHub/keys) | ✅ | ✅ `secret_intel` + `secret_validator` | entropy+validation already present | — |
| 11 | String intelligence (URLs/domains/IPs/emails/trackers) | ✅ | ✅ `string_analyzer` + `tracker_db` | jump-to-source for strings 🟡 | P3 |
| 12 | CVE intel (OSV/NVD/KEV) | 🟡 (no KEV) | ✅ `cve_mapper`+`osv_scanner`+KEV | **Beetle ahead** | — |
| 13 | Binary protections explained | ✅ | 🟡 | wording per-flag thin | P2 |
| 14 | Finding evidence model (file/func/line/snippet/view-code/MASVS/CWE) | 🟡 | ✅ `finding_model`+`evidence_scanner` | **View-code reliability** was broken | ✅ (this pass) |
| 15 | False-positive / accepted-risk / status / audit | 🟡 (suppress only) | ✅ `collaboration.py` state machine | **Beetle ahead** | — |
| 16 | Roles & collaboration (comments/assign/triage) | ❌ (single user) | ✅ RBAC + assignee + comments | **Beetle ahead**; add Reviewer role | P3 |
| 17 | UI polish (alignment/overflow/icons/responsive) | n/a | 🟡 | ongoing; Users page fixed Phase 11.991 | P2 |
| 18 | Icon extraction (APK manifest / IPA asset catalog) | ✅ | 🟡 | asset-catalog (`.car`) fallback weak | P2 |
| 19 | Exact line mapping (never blank lines) | 🟡 | ✅ `resolveEvidenceLines` (deterministic) | strong; depends on real source (fixed) | ✅ (this pass) |
| 20 | Report depth (exec/CISO/MASVS/chains/score) | 🟡 | ✅ | **Beetle ahead** | — |
| — | **Source viewer renders binary as garbage** | ✅ avoids it | ❌ **bug** | root cause: `read_text(errors=replace)` | **P0 → FIXED** |

---

## 3. The real gaps, ranked

### P0 — Source viewer shows binary garbage  → **FIXED THIS PASS**
`decompiler.get_file_content` decoded any file (incl. Mach-O/`.dylib`/`.dex`) as
text. Now classified first; binaries return structured metadata, never bytes.

### P1 — Objective-C / Swift reconstruction (Part 8)
No class/method/selector extraction today. MobSF shells out to `jtool2`/
`class-dump`. **Implementation idea:** add `analyzers/macho_classdump.py` using
LIEF (already a dependency) to read the `__objc_classlist`/`__objc_methname`
sections and Swift `__swift5_types`, emitting `{classes:[{name,methods[],
properties[]}], selectors[], imports[]}`. Render as readable pseudo-ObjC; when
LIEF can't resolve (fully stripped), show "Source unavailable — available
metadata: symbols, imports, strings" (no bytes). Reuses the binary-card UI built
this pass.

### P1 — Per-framework binary protections panel (Part 5)
`lief_analyzer.analyze_all_macho` already produces per-binary data; it just isn't
surfaced as its own section. **Idea:** new workspace panel "Binary Analysis"
with one row per Mach-O (main + each `.framework`/`.dylib`): PIE/NX/Canary/ARC/
Encrypted/Signed/RPATH columns + explanation tooltips. Pure frontend + a results
key rollup; no new heavy compute.

### P1 — Raw Info.plist workspace (Part 3)
Data is parsed but there is no "open the plist" view. **Idea:** `/file` already
returns text for `.plist`; add a dedicated panel that pretty-prints the plist
(XML or binary→XML via `plistlib`) with the key/value summary above it
(bundle id, version, ATS verdicts, URL schemes, capabilities, associated
domains, min iOS) — all of which `ios_analyzer` already computes.

### P2 — Insecure-API symbol table (Part 6)
Extend `lief_analyzer` to count occurrences of a curated symbol set
(`strcpy/sprintf/printf/scanf/memcpy/malloc/fopen/random/NSLog`) and emit
`{symbol, count, risk, masvs, cwe}` rows rather than a single lumped finding.

### P2 — ARC / stripped-symbols fidelity (Part 4/13)
Add `has_arc` (presence of `_objc_release`/`_objc_retain` imports) and
`is_stripped` (no debug symbols) to `analyze_macho`, with per-flag explanations.

### P2 — Icon extraction fallback (Part 18)
IPA asset-catalog (`Assets.car`) icons aren't extracted. **Idea:** fall back to
the largest `AppIcon*.png` in the bundle, then `CFBundleIcons` plist keys.

### P3 — String/secret jump-to-source, Reviewer role, more nav facets.

---

## 4. Shipped in this pass (fixes first, per Part 22)

1. **`backend/analyzers/binary_inspector.py` (new)** — content-first binary
   detection (Mach-O incl. fat, ELF, DEX, ZIP/APK/JAR/AAR/IPA, Java class, PE,
   images, PDF) via magic bytes + non-printable-ratio sniff, plus `describe()`
   producing `{kind,label,name,size,arch,protections[],linked_libraries[],
   rpaths[],recoverable[],note}`. Best-effort LIEF enrichment; never raises.
2. **`decompiler.py`** — extracted `resolve_source_path`; `get_file_content` now
   guards binaries (returns a clean notice, **never** decoded bytes) for *every*
   caller; new `inspect_file` returns a `text`/`binary` envelope.
3. **`main.py` `/api/scans/{id}/file`** — returns a JSON binary envelope for
   compiled artifacts, plain text for source (backward compatible).
4. **`lief_analyzer.py`** — PIE finding downgraded to `info` for `.dylib`/
   `.framework` (matches the documented MobSF rationale), killing the noisy
   "Not Position-Independent" false positives on embedded libraries (Part 4).
5. **Frontend** — `CodeBlockViewer` renders a premium dark "compiled binary"
   card (type, arch, size, protection chips, recoverable-metadata chips, linked
   libraries) instead of garbage; `Results.openCode` content-negotiates the
   JSON envelope. Build green.

**Net effect:** Parts 2 & 7 satisfied; Parts 1/8/14/19 root cause removed
(viewer never shows garbage; evidence lands on real source). Remaining P1/P2
items above are the next implementation tranche.
