# 21. Source Explorer

The Source Explorer is Beetle's central investigation workspace — a professional file **tree**
+ code viewer with intelligence **badges**, plus a **Security Explorer** that filters the tree
by security category. It is built entirely on metadata the analyzers already produced; there
is no new extraction and no parallel pipeline. It works identically across Android, iOS,
Flutter, React Native and CI/CD.

---

## 21.1 What it replaces and why

The Source Explorer replaces the former flat "Code Browser." A flat file list answers "what
files are there?"; the Source Explorer answers "*where is the risk, and let me read the exact
code*" — with the tree, security badges, category filtering, and a finding → source jump all
in one surface.

```mermaid
flowchart LR
    subgraph Backend (overlay, no extraction)
      SE[source_explorer.annotate] --> FI[file_index<br/>path → severity, counts, categories, flags]
      SE --> SI[security_index<br/>category → paths]
      SE --> PS[project_structure -reused from Flutter/RN-]
    end
    subgraph Frontend
      FI & SI & PS --> T[file tree + badges]
      T --> SX[Security Explorer pane]
      T --> CV[Code viewer -CodeBlockViewer-]
    end
```

`source_explorer.annotate` runs late in finalize (after fusion/evidence selection) and is a
**pure projection** of existing streams — `findings` (file_path/severity/category/cwe/
evidence), `secrets`, `ips`, and the Flutter/RN `project_structure`. It parses nothing.

---

## 21.2 The file tree

- **Build.** `buildTree(paths)` turns the flat `/files` manifest into a nested
  `{name, path, dir, children}` tree (directories first, then files, alphabetical).
- **Badge overlay.** `buildOverlay(file_index)` builds a per-file badge lookup and
  **aggregates folder severity** — each annotated file's worst severity propagates up to
  every ancestor folder, so a folder's badge tells you the worst thing inside it.
- **Path normalization.** Manifest paths are prefixed by source root (`jadx/`, `apktool/`,
  `apk_extract/`, `ipa_extract/`, `payload/`); `normalizePath` strips the prefix to match
  finding/secret paths.
- **Markers.** Severity badges plus 🔐 secret · 🌐 network · 📜 certificate · 📱 component
  markers on the files that carry them.
- **UX.** Expand/collapse with **persisted expanded state** (sessionStorage per scan), file/
  language icons, a **breadcrumb** of the selected file, and **file search** by name/path.

---

## 21.3 The Security Explorer

A second pane lists 12 security categories with counts from `security_index`:

> Secrets · Crypto · Network · Storage · Components · Permissions · Certificates · Native ·
> Authentication · Authorization · IPC

Selecting a category **filters the tree** to that category's files (keeping the matching files
and their ancestor folders). Empty categories are disabled. Findings are mapped to categories
by a deterministic keyword/CWE table (e.g. CWE-327 → Crypto; "Network Security"/CWE-319 →
Network; "Insecure Storage"/CWE-312 → Storage; "Native Bridge"/"Platform Channel"/CWE-749 →
IPC). A finding can belong to several categories; secrets always flag **Secrets** and IPs flag
**Network**. Because Flutter/RN findings are already in `results["findings"]`, they're covered
automatically.

### Quick Filters

A convenience row at the top — *All Files · Findings · Secrets · Network · Certificates ·
Native · Modified\* · Favorites\** — drives the **same** selection state as the Security
Explorer pane (it is not a second filtering system; both read/write one value). `Modified` and
`Favorites` are reserved seams (future VCS/diff and bookmarks), rendered disabled.

*Insert screenshot of the Source Explorer with the Security Explorer pane and a category
filter active here.*

---

## 21.4 Finding → source jump

The flagship workflow that ties findings to code:

1. Any `View Code` / `View Smali` action (finding rows, evidence cards, **chain steps**)
   records an `explorerTarget` and switches to the explorer.
2. The explorer resolves the finding path to the tree's manifest path
   (`resolveManifestPath`), **expands the ancestor folders** (`ancestorsOf`), and selects the
   file.
3. The code viewer jumps to the exact **line** and **highlights the snippet** (with a
   highlighted region when start/end lines are known).

It works for Android / iOS / Flutter / React Native / CI-CD because every finding carries
`file_path`/`line` and flows through the same backend resolver ([Ch 11](11-source-resolution.md)).

---

## 21.5 The code viewer

The viewer (`CodeBlockViewer`, reached via `onOpenCode`) provides syntax highlighting, line
numbers, in-file search, copy, and highlighted lines. File **content** comes from the existing
`GET /api/scans/{id}/file?path=`; the file **listing** from `GET /api/scans/{id}/files`. The
Source Explorer adds only the tree, the Security Explorer, the badge overlay and the jump seam
on top of these existing endpoints.

---

## 21.6 Performance

- The manifest is fetched once (capped at ~10k files by `list_source_files`).
- The tree **renders lazily** — only the children of *expanded* folders are mounted, so a
  large APK / Flutter / RN project never renders the whole tree at once.
- File content is fetched only on selection, and the viewer **virtualizes** line rendering.
- Backend per-directory pagination is a documented future seam (the current cap makes one
  fetch sufficient).

---

## 21.7 Engineering Workspace integration

Two "AVAILABLE" cards — **Source Explorer** and **Security Explorer** — appear in the
Engineering Workspace as *navigation* modules (a `nav: 'codebrowser'` descriptor rather than
an upload). Clicking opens the most recent scan's explorer, or guides the user to run a scan
first.

---

## 21.8 Extensibility (reserved seams)

`EXPLORER_EXTENSIONS` is a data-only registry of planned investigation features —
**Bookmarks, Notes, Compare Scans, AI Review, Semgrep Results** — rendered today as disabled
affordances. Enabling one is a two-step, no-redesign change: flip its `status` to `available`
and pass a handler (`extensions={{ bookmarks: fn, … }}`) invoked with
`{ scanId, results, selected }`. The search box is a single seam ready for a regex toggle and
class/method/variable/secret/URL/IP/package search modes. New platforms are covered
automatically: any future analyzer emitting canonical findings + a `project_structure` is
overlaid with no explorer change.

---

## 21.9 How analysts use it

- **Start from a category.** Open the Security Explorer, pick *Crypto* (or *Secrets*,
  *Network*), and the tree collapses to exactly the files implicated — a fast way to audit one
  control area.
- **Read folder badges top-down.** Aggregated severity tells you which package/module
  concentrates the risk before you open a single file.
- **Pivot from a finding.** From the Findings view, `View Code` drops you on the exact line in
  context — then explore neighboring files in the same module.
- **Follow a chain.** Each attack-chain step's evidence reference jumps here, so you can walk
  the chain through real code.

---

*Next: [Chapter 22 — AI](22-ai.md).*
