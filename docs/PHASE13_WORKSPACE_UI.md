# Phase 13 — Explainable Security Workspace (UI)

> Frontend + UX only. No backend logic or detections were changed. The redesign
> is namespaced under `.ws` and reuses the already-loaded `results` blob and the
> host's `openCode` / export / CI plumbing.

## What changed

The workspace route (`/scans/:scanId/:sectionId`) now renders a new
information-architecture: a 7-section workspace instead of the ~24-item legacy
sidebar + table-heavy `SectionViews`. `Results.jsx` keeps data loading and the
code-viewer / export / CI-gate modals; everything visual is the new `Workspace`.

## New component tree

```
src/main.jsx
  └─ imports styles/workspace.css            (design system, namespaced .ws)
src/pages/Results.jsx                         (data load + modals, unchanged logic)
  └─ <Workspace results onOpenCode actions>   src/components/workspace2/Workspace.jsx
       ├─ Sidebar (7 sections + counts)
       ├─ Topbar (Home · title · ⌘K search · Export · user)
       ├─ SearchPalette                       (⌘K / Ctrl-K global search)
       ├─ panels.jsx
       │    ├─ OverviewPanel    (identity, metric strip, risk summary,
       │    │                     top risks, most-exploitable chain, MASVS posture,
       │    │                     recent findings)
       │    ├─ FindingsPanel     (filterable finding cards + "show more")
       │    ├─ ChainsPanel       (vertical attack-path timeline)
       │    ├─ SecretsPanel      (Pairs / Credentials / Cloud Exposure / Suppressed)
       │    ├─ MasvsPanel        (recharts radar + coverage cards + maturity)
       │    ├─ FilesPanel        (evidence files → openCode)
       │    └─ ExportsPanel      (PDF / SBOM / SARIF / CI Gate)
       ├─ FindingDrawer          (side panel: Summary · Evidence · Why it matters ·
       │                          Attack scenario · Prerequisites · Impact ·
       │                          Remediation · FP notes · Confidence · References · Code)
       └─ ui.jsx                 (SeverityTag, SoftTag, Metric, EmptyState, helpers)
```

## Information architecture (Task 1)

`Overview · Findings · Attack Chains · Secrets · MASVS Coverage · Files · Exports`
— sections are switched client-side (no full reload, scroll reset on switch).

## Design system (Task 9)

Tokens live in `src/styles/workspace.css` under `.ws`:

- **White-first, neutral palette.** Ink `#18181b` / `#52525b` / `#8a8a93`, lines
  `#ececf0`. The accent is ink-based — **no brand neon, no gradients, no
  glassmorphism**.
- **Severity is the only saturated color**, applied exactly as specified:
  Critical `#7f1d1d` (dark red) · High `#dc2626` (red) · Medium `#ea8600` (orange)
  · **Low `#3b82f6` (blue)** · Info `#6b7280` (gray).
- **Typography-first.** System UI stack, tight tracking on headings, 14px body,
  uppercase 11–13px section labels.
- **Rounded cards** (`12–16px`), **subtle shadows** (1–3px), **Apple-like spacing**
  (18–30px rhythm).

## Finding details drawer (Task 7)

A right-side panel (no modal popups), driven entirely by the backend
`analyst_explanation`: Summary → Evidence (with **View Code**) → Attack Scenario →
Prerequisites → Impact → Remediation (MASVS/OWASP/CWE) → False-Positive Notes →
Confidence reasoning → References. Esc / backdrop closes it; the underlying list
scroll position is preserved.

## Search (Task 8)

`⌘K` / `Ctrl-K` opens a command palette indexing Findings, Files, Packages,
Secrets, MASVS categories, and Chains. Selecting a finding jumps to Findings and
opens its drawer.

## Performance notes (Task 11)

- **No heavy re-renders:** section switching is local state; filters use
  `useMemo`; the drawer/search are conditionally mounted.
- **Large lists are capped, not dumped:** Findings render 60 at a time with a
  "show more" control; Files cap at 300 rendered rows. (A windowing lib like
  `react-window` is the next step if a corpus exceeds a few thousand findings.)
- **No layout shift:** the drawer is an overlay (fixed), not an inline expansion;
  opening it does not reflow the list.
- Production build: 2319 modules, ~7s, single CSS+JS bundle (recharts is the main
  weight — candidate for code-splitting later).

## Before vs after

| | Before (legacy) | After (Phase 13) |
|--|------------------|------------------|
| Sidebar | ~24 mixed sections | 7 analyst-workflow sections |
| Findings | dense tables / mixed cards | uniform cards + side drawer + filters |
| Explanation | description + recommendation | full analyst narrative (why / attack / FP / confidence) |
| Attack chains | list section | vertical timeline with confidence + impact |
| Secrets | one flat list | grouped: Pairs / Credentials / Exposure / Suppressed (masked only) |
| MASVS | finding flags | radar + coverage cards + maturity labels |
| Search | none | global ⌘K palette |
| Palette | green neon + gradients | white-first, neutral, severity-only color |

## Validation (Task 12)

- **Builds clean:** `npm run build` — 2319 modules transformed, no errors.
- **Data contract verified** against real `analyze` output (DVBA) via the offline
  harness: every field the panels read is present — `trust_score`,
  `resolution_scores`, `analyst_summary` (5 top risks), `masvs_summary` (8 radar
  points), per-finding `analyst_explanation` (all sub-fields), and secrets carry
  `masked_value` (no raw values reach the UI). InsecureShop / WaPo share the same
  schema.
- **Screenshots:** not captured in this environment (no browser/headless Chrome on
  the build host). To view: `cd frontend && npm run dev` with the backend running,
  then open a completed scan. The drawer, radar, timeline, and palette are all
  driven by the data fields validated above.

## Backend untouched

No files under `backend/` were modified in this phase.
