# Evidence UI & Analyst Workspace (Beetle 2.0 — Phase 1.99)

The backend already produces far more intelligence than the UI exposed — Primary /
Supporting / Hidden-library evidence, evidence score + selection reason, ownership,
detection sources, fusion metadata, confidence explanation, reachability, attack
chains. This phase surfaces all of it in an analyst-first finding workspace. It is a
**frontend-only** phase: no backend changes, no recomputation — the UI consumes the
fields the pipeline already emits.

## Data flow

```
GET /api/scans/{id} ──► results (safe_results)
   findings[].{ evidence_view, evidence_selection, detected_by, fusion, fusion_score,
                detection_count, confidence_breakdown, overall_confidence,
                reachability, owner_type, file_evidence, … }
        │
        ▼
evidence-model.js  (pure, React-free, unit-tested)
   getEvidenceView · detectionSources · trustScore · confidenceContributions ·
   reachabilityLabel · languageOf · matchesFilters
        │
        ▼
panels.jsx components ──► rendered in Workspace.jsx
```

`evidence-model.js` is the single adapter between backend shapes and the UI. It
prefers `evidence_view` (Report Accuracy engine), falls back to `evidence_selection`,
then to legacy `file_evidence`/`file_path` — so old and new scans both render. Being
React-free it runs under plain Node for tests.

## Component hierarchy

```
Workspace.jsx
├─ FindingsPanel                         (list + analyst filters)
│  ├─ toolbar: search · severity chips · App-owned · state
│  ├─ toolbar--filters: Category · Detected By · Ownership · Framework · Trust ≥
│  └─ FindingRow[]                       (+ "N engines" badge)
├─ FindingDrawer                         (finding details)
│  ├─ IntelStrip                         Severity·Confidence·Trust·Evidence·Fusion·Ownership·Reachability·Chain
│  ├─ DetectedByBadges                   ✓ Beetle Native ✓ APKLeaks … (future engines auto-appear)
│  ├─ CollabBlock                        (existing — state/assignment/comments)
│  ├─ AI Analysis                        (existing)
│  ├─ PrimaryEvidenceCard                large card: file·line·language·reason·ownership·source
│  │     buttons: View Source · View Smali · Copy Path · Copy Snippet
│  ├─ SupportingEvidence                 (collapsible)
│  ├─ HiddenLibraryEvidence              (collapsed; capped at 50; explains why hidden)
│  ├─ ConfidencePanel                    overall + why-high/low bars + fusion/evidence/ownership contributions
│  └─ Remediation / References           (existing)
└─ ChainsPanel                           (steps with a file are click-to-jump)
```

## Components

**Created** (`panels.jsx`, all presentation-only): `IntelStrip`, `DetectedByBadges`,
`PrimaryEvidenceCard`, `SupportingEvidence`, `HiddenLibraryEvidence`,
`ConfidencePanel`, `FilterSelect`; plus the pure module `evidence-model.js`.

**Reused**: `Block`, `SoftTag`, `SeverityTag`, `EmptyState`, `ownershipLabel`,
`confidenceLabel`, `buildEvidence`, `EvidenceLocations` (legacy fallback),
`CollabBlock`, the AI drawer, and the host `onOpenCode(path, lines, ctx)` source hook.

## API usage

No new endpoints. The drawer reads only fields already serialized by
`safe_results()`. `detected_by` drives the Detected-By badges, so **future detection
engines appear automatically** with zero UI changes. `evidence_view` drives the
Primary/Supporting/Hidden split; `confidence_breakdown` drives the confidence bars;
`fusion_score`/`detection_count` drive trust + fusion contribution.

## Source-explorer integration (next phase)

`View Source` and `View Smali` both call the existing `onOpenCode(path, lines, ctx)`
with `ctx.view = 'java' | 'smali'`. No duplicate viewer is built — when the Reverse
Engineering Workspace lands it consumes the same hook (and the `view` hint); until
then `View Smali` opens the resolved source as a graceful placeholder.

## Performance

* Hidden library evidence is **collapsed by default** and **capped at 50** rendered
  rows (`+N more hidden`), so an app with thousands of SDK files never renders them.
* Supporting evidence is collapsed until opened.
* The findings list keeps its existing incremental `limit` paging.
* `evidence-model` helpers are pure and cheap; the drawer computes the view once per
  open.

## Visual design

Neutral ink-based palette on the existing `ws-*` tokens (no new brand colors). The
Primary card is the one highlighted element; everything secondary is muted or
collapsed to keep the view readable and analyst-focused.

## Tests

`frontend/src/components/workspace2/__tests__/evidence-model.test.mjs` (13 tests, run
with `node …/evidence-model.test.mjs`): language mapping, evidence-view normalization
(modern + evidence_selection + legacy fallback), detection sources (incl. unknown
future engines + legacy inference), trust score blend, confidence contributions,
reachability, filter composition, and an API-compatibility sweep proving mixed
old/new finding shapes never throw. The full app also `vite build`s cleanly.

## Analyst Workstation foundation (extensibility)

This phase is not just new widgets — it lays the architecture so the upcoming
roadmap (Source Explorer, Smali Explorer, Jump-to-Source/Smali, cross-navigation,
decompiled viewer, side-by-side comparison, AI Reviewer, Security Controls,
Flutter/RN views) slots in **without a shell rewrite**. Four seams were added:

### 1. Panel registry (component hierarchy) — `workspace-registry.js`
A pure, declarative catalog of every panel: `{id,label,group,icon,status}`. The
shell derives its nav and dispatch from it. Roadmap panels are **declared now** with
`status:'planned'` under new groups (`Source`, `Reviewer`) and are already navigable
— they route to a `ComingSoonPanel`. Shipping one is: flip `status:'ready'` + add a
renderer case. No hardcoded nav array, no edits to unrelated code.

### 2. Navigation/intent context (routing + state) — `workspace-context.jsx`
`WorkspaceProvider` centralizes workspace state (`section`, `finding`, `comparison`)
and exposes ONE intent API: `openSection · openFinding · closeFinding · openSource ·
openSmali · addToComparison/clear`. Components call **intents**, not specific
viewers. `comparison` (holds up to two findings) is the state foundation for
side-by-side. The `useWorkspaceNav()` hook is provider-optional (returns a no-op nav)
so components stay unit-testable.

### 3. The source seam (Jump to Source / Smali / cross-navigation)
`openSource`/`openSmali` are the single definition of "go to code". Today they
delegate to the host `onOpenCode` modal with a forward-compatible `view:'java'|'smali'`
hint. The Source Explorer will **re-target these same intents** into a docked pane —
`PrimaryEvidenceCard`, chain steps and finding rows already speak `nav.openSource`,
so zero call sites change. That is what makes Jump-to-Source/Smali and
finding↔source cross-navigation a later wiring change, not a refactor.

### 4. Layout regions (layout) — `ws-workspace` / `ws-region`
The content area is wrapped in a region container with a `--primary` region (used
today) and a reserved, CSS-collapsed `--secondary` region. **Why a new layout:** the
Source Explorer and side-by-side comparison need a persistent second pane beside the
finding context (a drawer/modal can't host a tree+code+evidence triptych). Adding the
container now — collapsed to zero so single-pane behavior is unchanged — means the
roadmap mounts its pane into `--secondary` and toggles `.is-split` (already styled)
instead of restructuring the shell.

### How each roadmap item slots in

| Roadmap item | Slots into |
|---|---|
| Java / Smali Source Explorer | registry panels `source-java`/`source-smali` (declared) → render into `--secondary`; fed by `nav.openSource/openSmali` |
| Jump to Source / Smali | already routed through `nav.openSource/openSmali` (re-target the seam) |
| Cross-nav findings ↔ source | `nav.openFinding` + `openSource` already centralized; explorer reads `comparison`/`finding` from context |
| Decompiled code viewer | replaces/augments the `onOpenCode` host hook behind the same seam |
| Side-by-side evidence comparison | `comparison` state + `--secondary` region + `evidence-compare` panel (declared) |
| AI Reviewer panel | `ai-reviewer` panel (declared) + a future drawer-section; consumes the same evidence-model |
| Security Controls dashboard | `security-controls` panel (declared); rolls up coverage + findings |
| Flutter / React Native views | `framework-view` panel (declared); `evidence-model` already exposes `framework` filtering |

Implemented as foundations only — the roadmap panels render placeholders. Existing
components were **extended, not replaced** (the drawer, finding rows and chains now
speak the nav seam; the shell kept all panel prop wiring).

## Remaining UI limitations

* `View Smali` is a hook/placeholder until the Reverse Engineering Workspace ships.
* Attack-chain interactivity jumps to source for steps that carry a file; steps that
  are pure narrative (no file) are not clickable.
* No component-level DOM tests (the repo has no React test runner); the testable
  logic was extracted to `evidence-model.js` and covered under Node instead.
