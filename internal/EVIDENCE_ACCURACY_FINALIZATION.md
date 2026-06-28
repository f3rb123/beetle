# Evidence Accuracy Finalization & Proof Validation (Beetle 2.0 — Phase 1.997)

Phase 1.96/1.97 made evidence selection ownership-aware and corrected the rendered
location across reports. This phase eliminates the final evidence-quality edge cases
so framework code never misleadingly headlines a finding, certificate findings name
a real artifact, and manifest/chain evidence is focused and authoritative.

## Root-cause analysis

The reported bug — *Broken Crypto / Hardcoded Key → `androidx.appcompat…AppCompatDelegateImpl.java`* — has **two distinct causes**, found by reproducing both empirically:

1. **SAST aggregation defaults `file_path` to the alphabetically-first match**
   (`code_analyzer._run_rules_per_file` sorts files by path → `androidx/…` sorts
   before app packages). **When an application match also exists**, Evidence
   Selection already re-promotes the app file (verified — *not* the live bug after
   1.97).
2. **Framework-only findings** — a SAST rule (e.g. ECB) that matched **only** in
   framework code (`androidx.appcompat`) produces a finding whose **only** candidate
   is framework. The engine legitimately keeps it (the "no application evidence
   exists" exception), but it was presented as if it were ordinary proof. *This* is
   the residual issue.

The root cause is therefore **not** evidence generation, fusion, ownership or
rendering ranking (all correct) — it is the **absence of an explicit policy for
framework-only findings**, plus two presentation gaps (certificates, manifest
verbosity). No upstream engine needed redesign; the fix lives entirely in the
Evidence Selection Engine + its render view.

## Scoring refinements (Evidence Selection Engine)

- **Framework path-prefix gate** (`_framework_path_signal`, file-scope, −45): a
  deterministic second gate keyed on the *path* (`androidx/`, `com/google/`,
  `kotlin/`, `okhttp3/`, `retrofit/`, `glide/`, `coil/`, `material/`, `compose/`,
  `firebase/`, `support/`, …). It deprioritizes framework files **even when
  ownership returns Unknown** (obfuscated / not-yet-fingerprinted), guaranteeing an
  application/manifest proof always outranks framework.
- **Manifest authority** raised (`MANIFEST_DECLARATION_BONUS` 45→80) so manifest
  findings prefer `AndroidManifest.xml` even over an application source candidate.
- **Manifest-derived detection tightened**: only `evidence_type=="manifest"`, a
  strict declaration category set, or *a manifest already among the candidates*.
  Ambiguous categories ("Network Security", "Configuration") no longer force a
  manifest candidate onto a *code* finding (e.g. a TrustManager).

## Framework suppression behaviour

Framework code becomes Primary Evidence **only** when no application-owned proof
exists. When that happens the finding is flagged `evidence_view.framework_only =
true` with an honest reason ("No application-owned proof was detected…") and the UI
shows a note — it is never dressed up as application proof. Framework matches that
lost to an app proof remain available as **hidden library evidence** (not dropped).

## Attack-chain evidence policy

In chain mode (`is_attack_chain`/`in_attack_chain`) selection follows: **Manifest →
application business logic → configuration → resources → supporting → framework**
(`_chain_priority_signal` + an extra framework penalty). Chains therefore lead with
the declaration/config evidence an analyst acts on, and every chain exposes the same
evidence metadata (primary/supporting/detection-sources/reason/ownership/confidence)
through the shared `evidence_view`.

## Certificate evidence policy

Certificate / signing findings (category `Certificate`) have no decompiled source.
The view now renders the **real artifact** instead of "Unknown file": `Signing
Certificate`, `APK Signature Block`, `Certificate Chain` or `APK Metadata` (chosen
from the finding title), marked `artifact:true` with language `Signing Metadata`. The
analyst immediately understands why there is no Java file; the card offers Copy
(no View Source/Smali for an artifact).

## Manifest evidence presentation

Manifest snippets are reduced to the **security-relevant `android:*` attribute(s)**
(`debuggable`, `usesCleartextTraffic`, `allowBackup`, `exported`, …) via an
allowlist; benign attributes (`label`/`icon`/`theme`/`name`) are dropped, so the
card shows `android:debuggable="true"` rather than a long `<application …>` excerpt.

## Regression strategy

`backend/tests/test_evidence_accuracy.py` (12 tests) locks every guarantee and the
named report cases: Broken Crypto, Hardcoded Key, UploadService, Debuggable, Backup,
Cleartext, Exported Components, Certificate, WebView, Secrets — plus app-outranks-
obfuscated-framework, framework-only flagging, manifest focused snippet, and chain
manifest-first. Frontend model parity is covered by the existing Node tests.

## Performance

No new evidence pass. Everything reuses the single Evidence Selection pass
(`evidence_selection.annotate`) and the precomputed `evidence_view`; the added
signals are O(candidates) string checks. Rendering only reads precomputed data.

## Files modified

- `analyzers/evidence_selection/config.py` — framework prefixes + penalty, chain
  policy constants, certificate/artifact + security-manifest-attr data, manifest
  bonus 45→80, strict manifest categories.
- `analyzers/evidence_selection/scoring.py` — `_framework_path_signal`,
  `_chain_priority_signal`, `chain` context field.
- `analyzers/evidence_selection/engine.py` — chain mode, `framework_only` detection
  + reason, manifest-derived "manifest-is-a-candidate" rule.
- `analyzers/evidence_selection/view.py` — certificate artifact view, focused
  manifest snippet, `framework_only` exposure.
- `frontend/.../evidence-model.js` + `panels.jsx` + `workspace.css` — surface
  `framework_only`, certificate artifact (no Source/Smali), focused snippet.
- Tests: `backend/tests/test_evidence_accuracy.py`.
