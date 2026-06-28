# Engineering Workspace (Beetle 2.0 — Phase 2.0)

> An architectural expansion of the launcher (`pages/Home.jsx`) into a **scalable
> module workspace** that is the central entry point for current and future Beetle
> capabilities. **Not** a redesign: it is purely additive. The existing Android/iOS
> upload + analysis workflow, the dashboard, the colors and the design language are
> all unchanged.

---

## 1. Workspace architecture

The Engineering Workspace is a new section rendered at the **top** of the launcher's
main column, above the existing upload card:

```
ws-home__main
 ├─ <EngineeringWorkspace>        ← NEW (module launcher grid)
 │     Available:  Android · iOS
 │     Coming soon: Flutter · React Native · Semgrep · CI/CD · AI · Plugin SDK · Enterprise
 ├─ upload card (existing, unchanged)
 ├─ recent scans (existing, unchanged)
 └─ footer (existing, unchanged)
```

Files:

| File | Role |
|---|---|
| `src/lib/engineering-modules.js` | **Configuration model** — the single source of truth for all modules (data only). |
| `src/components/EngineeringWorkspace.jsx` | Presentational grid + `ModuleCard`; a pure projection of the config. |
| `src/pages/Home.jsx` | Renders the workspace, owns `selectedModule`, and the `launchModule` handler. |
| `src/styles/auth.css` | `.ew*` styles, using only the existing `--auth-*` tokens. |

The grid hardcodes **no** module and **no** navigation — it iterates the config and
dispatches purely on each module's `status`.

---

## 2. Module configuration

Every capability is one object in `ENGINEERING_MODULES`:

```js
{
  id, name, icon,            // identity (icon is a lucide-react component)
  status,                    // MODULE_STATUS.AVAILABLE | COMING_SOON
  description,               // card one-liner
  capability,                // planned/primary capability (Coming Soon cards)
  eta,                       // expected status text (Coming Soon cards)
  accept,                    // upload filter for Available modules (".apk" / ".ipa")
  platform,                  // "android" | "ios" — upload hint
}
```

Today: **Android** and **iOS** are `AVAILABLE` (with `accept`/`platform`); the seven
future modules — **Flutter, React Native, Semgrep, CI/CD, AI Security Intelligence,
Plugin SDK, Enterprise Dashboard** — are `COMING_SOON` (visually complete, with a
description, planned capability, and expected status, but non-functional).

---

## 3. Navigation model

A single status-based handler (`EngineeringWorkspace.handleSelect`) drives behavior:

* **Available** → calls `onLaunch(module)`. In `Home.jsx`, `launchModule` sets the
  selected module, scrolls to and highlights the **existing** upload card, and
  pre-filters the file dialog to the module's package type. **The scan workflow
  itself — `startScan` → `/api/analyze` → SSE/poll → `navigate('/scans/:id/dashboard')`
  — is byte-for-byte unchanged.** `pickFile` still accepts both `.apk` and `.ipa`, so
  nothing about the current behavior regresses; the module selection only narrows the
  OS dialog and updates the card's hint.
* **Coming Soon** → does **not** navigate. It toggles an inline
  "**Available in a future release**" message on the card. The cards are visually
  marked unavailable (muted, dashed border, "Coming Soon" badge) and carry
  `aria-disabled="true"`.

No `react-router` routes were added or changed.

---

## 4. Card design

Each `ModuleCard` shows: **module icon**, **status badge** (Available / Coming Soon),
**module name**, **short description**, and — for Coming Soon — **planned capability**
+ **expected status**. Available cards lift on hover (matching the upload-card depth
language) and show an active state when selected; Coming Soon cards are static and
muted. Layout is a responsive CSS grid (`repeat(auto-fill, minmax(240px, 1fr))`,
collapsing to one column under 560px). Consistent spacing and the existing radius/
shadow tokens are reused throughout.

**Colors / theming.** Every rule uses the existing `--auth-*` CSS variables (no new
hues, no hardcoded theme colors), so the workspace inherits the app theme and is
**dark-mode-ready by construction** — if a dark palette is ever defined for the
`--auth-*` variables, the cards adapt with zero changes here.

---

## 5. Future extensibility

**Enabling a future module is a one-field config change** — no component, navigation,
layout, or CSS edits:

```js
// To ship Semgrep, in engineering-modules.js:
{ id: 'semgrep', name: 'Semgrep Integration', icon: ScanSearch,
  status: MODULE_STATUS.AVAILABLE,        // ← was COMING_SOON
  description: '…', accept: '.apk,.ipa', platform: 'android' }   // launch descriptor
```

The module immediately renders under **Available** and becomes launchable through the
same handler. Modules that are not upload-based can instead carry a `route` (or any
launch descriptor) and have `launchModule` dispatch on it — the grid and card code do
not change. This keeps the workspace scalable across Beetle's roadmap while preserving
the existing experience.

---

## 6. Testing / verification

* **Production build passes** (`npm run build` — 2330 modules transformed, no errors).
* **Android & iOS workflows unchanged** — the `Home.jsx` diff touches no scan-workflow
  code (`startScan` / `streamScan` / `pollScan` / `navigate` / `/api/analyze` /
  `pickFile` are untouched); only additive state + rendering was added.
* **Responsive** — grid auto-fills and collapses to one column on small screens.
* **Dark-mode compatible** — variable-driven colors only.
* **No regressions** — additive section; no routes, components, or existing styles
  were modified.
