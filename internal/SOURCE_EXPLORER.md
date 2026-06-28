# Universal Source Explorer & Security Explorer (Beetle 2.0 — Phase 2.3)

> The central investigation workspace — a professional file **tree** + code viewer with
> intelligence **badges**, plus a **Security Explorer** that filters the tree by security
> category — built entirely on **existing** metadata. No new extraction, no parallel
> pipeline. It replaces the former flat "Code Browser" and works identically across
> Android, iOS, Flutter and React Native.

---

## 1. Architecture

```
backend (overlay, no extraction)
  analyzers/source_explorer.py  annotate(results) → results["source_explorer"]
        file_index      path → { max_severity, counts, categories, findings, secret/network/cert/component }
        security_index  category → [paths]            (Secrets/Crypto/Network/Storage/…/IPC)
        project_structure  (reused from Flutter / React Native metadata)
  runs late in android_analyzer + ios_analyzer finalize (after fusion/evidence selection)

frontend (the investigation UI)
  source-explorer-model.js   pure tree + overlay helpers (framework-free, unit-tested)
  SourceExplorer.jsx         tree + Security Explorer pane + viewer wiring
  workspace-context.jsx      explorerTarget seam (finding → tree jump)
  registered as the 'codebrowser' workspace section (replaces the flat Code Browser)
```

The file **listing** comes from the existing `GET /api/scans/{id}/files`; the file
**content** from the existing `GET /api/scans/{id}/file?path=`; the **code viewer**
(syntax highlight, line numbers, in-file search, copy, highlighted lines) is the
existing `CodeBlockViewer` reached through `onOpenCode`. This phase adds only the
**tree**, the **Security Explorer**, the **badge overlay** and the **jump seam**.

---

## 2. How the explorer consumes existing metadata

`source_explorer.annotate` is a pure projection of streams the analyzers already
produced: `results["findings"]` (file_path / severity / category / cwe / evidence_view /
file_evidence), `results["secrets"]`, `results["ips"]`, and the Flutter/RN
`project_structure`. It parses nothing. Findings are mapped to security categories by a
deterministic keyword/CWE table (e.g. CWE-327 → Crypto, "Network Security"/CWE-319 →
Network, "Insecure Storage"/CWE-312 → Storage, "Native Bridge"/"Platform Channel"/CWE-749
→ IPC). A finding may belong to several categories; secrets always flag **Secrets** and
IPs flag **Network**. Because Flutter/RN findings are already in `results["findings"]`,
they are covered automatically.

---

## 3. Tree model

`buildTree(paths)` turns the flat `/files` manifest into a nested
`{ name, path, dir, children }` tree (directories first, then files, alphabetical).
`buildOverlay(file_index)` builds the badge lookup and **aggregates folder severity** by
propagating each annotated file's worst severity and flags up to every ancestor folder.
Manifest paths are prefixed by their source root (`jadx/`, `apktool/`, `apk_extract/`,
`ipa_extract/`, `payload/`); `normalizePath` strips that prefix to match the
finding/secret paths in the overlay.

Tree features: expand/collapse, **persisted expanded state** (sessionStorage per scan),
file/language **icons**, severity **badges** + 🔐 secret / 🌐 network / 📜 certificate /
📱 component markers, **breadcrumb** of the selected file, and **file search** (name/path).

---

## 4. Security Explorer

A second pane lists the 12 categories (Secrets, Crypto, Network, Storage, Components,
Permissions, Certificates, Native, Authentication, Authorization, IPC) with counts from
`security_index`. Selecting a category **filters the tree** to that category's files
(via `categoryPathSet` + `nodePasses`, which keeps the matching files and their ancestor
folders). Empty categories are disabled.

### Quick Filters

A convenience row at the top of the explorer (All Files · Findings · Secrets · Network ·
Certificates · Native · Modified* · Favorites*) drives the **same** `activeCat` selection
as the Security Explorer pane — it is **not** a second filtering system. The row and the
pane stay in sync because both read/write one state value; `filterPathSet(activeCat, …)`
resolves it (`'all'` → no filter, `'findings'` → every annotated file, else the security
category set). `Modified` and `Favorites` are reserved seams, rendered disabled. Both the
filters (`QUICK_FILTERS`) and the resolver live in the testable `source-explorer-model.js`.

---

## 5. Finding → source jump

The workspace navigation context (`workspace-context.jsx`) gained an `explorerTarget`
seam. Every existing `nav.openSource` / `nav.openSmali` call (finding rows, evidence
cards, chain steps — unchanged) now also records the target; `openInExplorer(path)`
additionally switches to the explorer section. The Source Explorer subscribes to
`explorerTarget`: on a new token it resolves the finding path to the manifest path
(`resolveManifestPath`), **expands the ancestor folders** (`ancestorsOf`), selects the
file, and the existing viewer jumps to the exact line + highlights the snippet. Works for
Android / iOS / Flutter / React Native because every finding carries `file_path`/`line`.

---

## 6. Lazy loading & performance

The manifest is fetched once (capped at 10k files by `list_source_files`). The tree
**renders lazily** — only the children of *expanded* folders are mounted, so a large APK
/ Flutter / RN project never renders the full tree at once. File content is fetched only
on selection, and `CodeBlockViewer` virtualizes line rendering. Backend per-directory
pagination is a documented future seam (the current cap makes one fetch sufficient).

---

## 7. Engineering Workspace

Two new `AVAILABLE` cards — **Source Explorer** and **Security Explorer** — were added to
the Engineering Workspace via the Phase 2.0 config model. They are *navigation* modules
(a `nav: 'codebrowser'` descriptor rather than `accept`/upload): clicking opens the most
recent scan's explorer, or guides the user to run a scan first when there is no history.
No workspace redesign.

---

## 8. Future extensibility

* **Regex / structured search** — the search box is a single seam; a regex toggle and the
  class/method/variable/secret/URL/IP/package search modes plug into `nodePasses` /
  the global palette without touching the tree.
* **Backend directory pagination** — `list_source_files` can grow a `dir=` parameter; the
  tree already lazy-renders, so only the fetch changes.
* **New platforms** — any future analyzer that emits canonical findings + a
  `project_structure` is covered automatically by `source_explorer.annotate`.
* **Docked viewer pane** — the workspace already reserves a secondary region; the viewer
  can dock beside the tree without changing the model.

### Extension points (future-ready seams — no implementation yet)

`EXPLORER_EXTENSIONS` (in `source-explorer-model.js`) is a data-only registry of planned
investigation features — **Bookmarks, Notes, Compare Scans, AI Review, Semgrep Results**
— rendered today as disabled affordances in the Quick Filters row, mirroring the
Engineering Workspace's planned-module pattern. Enabling one is a two-step, no-redesign
change: flip its `status` to `available` and pass a handler via the panel's optional
`extensions` prop (`<SourceExplorerPanel extensions={{ bookmarks: fn, notes: fn, … }} />`),
which is invoked with `{ scanId, results, selected }`. `Favorites` (Quick Filters) is the
UI entry point reserved for the Bookmarks seam; `Modified` is reserved for a future VCS/
diff signal. No behavior is attached in this phase.

---

## 9. Testing

* **Backend** `backend/tests/test_source_explorer.py` (9 tests): Android / iOS / Flutter /
  React Native overlays, secrets + IPs reuse, badge **severity aggregation**, finding →
  file mapping (incl. evidence_view + file_evidence) for the **source jump**, bridged-
  finding exclusion, security-category mapping (**Security filtering**), and empty-safety.
* **Frontend** `…/__tests__/source-explorer-model.test.mjs` (12 tests): tree build (folders/
  files, lazy shape), path normalization, folder **badge aggregation**, category **filtering**,
  **file search**, and **source-jump** path resolution + ancestor expansion.
* Full backend suite **349 passed**; existing frontend model test **13/13**; production
  build green. No regression to Android/iOS/Flutter/RN or the rest of the app.
