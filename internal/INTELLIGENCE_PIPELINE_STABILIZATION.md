# Intelligence Pipeline Final Stabilization (Beetle 2.0 — Phase 1.998)

The final backend quality phase before Phase 2.0 (Reverse Engineering Workspace). No
new engine — this phase makes the existing engines agree on **one source of truth**
for secrets, evidence, manifest snippets, attack-chain proof and detection
attribution, and closes the last three reported inconsistencies.

## Architecture audit

Every finding-evidence consumer was traced. After this phase they all read the
Evidence Selection Engine's output (`build_evidence_view` / `primary_location`):

| Surface | Evidence source | Status |
|---|---|---|
| REST / JSON | corrected `file_path` + `evidence_view` | ✓ (1.97) |
| PDF / SARIF / Developer Guide | `build_evidence_view` / `primary_location` | ✓ (1.97) |
| **Attack chains** (`workspaces.enrich_chains`) | **was reading raw `file_path`** → now `primary_location`/`build_evidence_view` | ✓ **fixed here** |
| Analyst Workspace / Finding details | `evidence-model.js` over `evidence_view` | ✓ (1.99) |

The one remaining independent selector — attack-chain `chain_evidence` — was the
root of Issue 2.

## Coverage audit & secret benchmark

Secret scanning paths and whether they use the unified catalog
(`secret_catalog.combined()` = beetle_native + apkleaks + coverage):

| Path | Uses unified catalog? |
|---|---|
| Evidence Scanner (main decompiled walk) | ✓ |
| Java / Smali / Resource / Manifest / Config (same walk, by extension) | ✓ |
| DEX-string / JS-bundle / no-JADX fallback (`common.scan_text_for_secrets`) | ✓ (folded in 1.98) |
| APKLeaks | ✓ (catalog provenance) |

**Benchmark (vs MobSF / APKLeaks) — the missed AWS secret.** Root cause: every
catalog matched **only the `AKIA` prefix**. AWS issues access-key ids with many
prefixes — `ASIA` (STS/temporary), `AROA/AIDA/AGPA/…` (IAM principals) — which
MobSF's broader regex catches. This was a genuine gap, not a copy: the *reason*
Beetle missed it is the narrow prefix. Closed by adding (to the **coverage**
provenance of the one catalog, no duplicate matcher):

* **AWS STS Temporary Access Key** — `ASIA[0-9A-Z]{16}` (high; a live credential).
* **AWS IAM Unique ID** — `(?:AROA|AIDA|AGPA|AIPA|ANPA|ANVA)[0-9A-Z]{16}` (low; recon).
* **AWS CloudFront Distribution** — `*.cloudfront.net` (low; footprint).

The rest of the brief's list (AWS Access/Secret/Identity-Pool/Cognito, Firebase,
Google Maps via AIza, Azure, Stripe, Twilio, Slack, Discord, GitHub/GitLab, JWT,
OAuth/GOCSPX, PEM/SSH keys, OpenAI/Anthropic/Gemini-via-AIza/HuggingFace, Supabase,
S3 buckets) was already covered by native/apkleaks/coverage — verified, not
duplicated.

## Evidence synchronization

Attack chains no longer pick proof independently. `workspaces.enrich_chains` now
resolves each member's evidence via `primary_location()` + `build_evidence_view()`,
so a chain shows the SAME application-owned primary the finding shows, plus the
member's `ownership`, `detection_sources` and selection reason. A regression test
asserts finding-details and chain render an identical primary.

## Manifest snippet engine

The old focuser filtered `android:*` attributes but could not fix a snippet that
captured the **wrong manifest line** (Issue 3: a Debuggable finding whose stored
snippet was a `<permission android:name=…>` line). The new XML-aware selector is
**finding-aware**: it maps the finding (by title/rule) to the EXACT attribute it
triggers (`MANIFEST_FINDING_ATTRS`), extracts that attribute from the snippet, and —
when the captured snippet grabbed the wrong line — **synthesizes** the triggering
attribute (`android:debuggable="true"`). It understands the security attributes of
the application/activity/service/receiver/provider/permission/intent-filter nodes.

## Attack-chain synchronization

Chains consume Evidence Selection output and never silently promote framework code.
When a member has only framework evidence, the chain entry is flagged
`framework_only` with the reason *"No application-owned implementation was found."* —
honest, not hidden. (Selection itself already runs in chain mode: Manifest → app
logic → config → resources → supporting → framework, Phase 1.997.)

## Exported components (Part D)

Exported component findings prioritize **Manifest → application component → supporting
code → library implementation** (manifest authority bonus, Phase 1.997). Verified by
regression so UploadService/exported activities/receivers/providers reference the
manifest declaration, not the SDK class.

## Performance

No new evidence pass. Secrets ride the existing single combined walk; chain
enrichment and snippet focusing read the **precomputed** `evidence_view`. The added
work is O(candidates) string checks. Scan performance is unchanged.

## Lessons learned

* "Evidence correctness" is only as good as its *least-synchronized consumer* — the
  chain `chain_evidence` builder silently diverged for phases. A single
  `build_evidence_view`/`primary_location` seam + a synchronization regression test
  is the durable fix.
* A snippet captured at detection time can be wrong; the renderer must be able to
  derive the correct attribute from the finding's identity, not trust the snippet.
* Coverage gaps are usually a *narrow pattern* (AKIA-only), not a missing engine —
  benchmark to find the reason, then widen the one catalog.

## Remaining technical debt

* `common.SECRET_PATTERNS` still physically exists (it now *consumes* the unified
  catalog for reachability, but its own ~30 patterns overlap native). Full physical
  consolidation is a follow-up.
* Framework-only SAST findings are flagged, not suppressed — whether to hide
  library-internal code-quality findings is a triage-policy decision, not evidence.
* Manifest snippet synthesis covers the common security attributes; rarer custom
  attributes fall back to the security-attribute filter.

## Regression suite

`backend/tests/test_pipeline_stabilization.py` (12 tests): AWS STS/IAM/CloudFront
detection + AKIA non-regression + common-scanner reachability; manifest exact-attr
(incl. the wrong-captured-line case); attack-chain app-primary + framework-only
labeling + ownership/detection-source exposure + finding↔chain agreement. Plus the
Phase 1.997 `test_evidence_accuracy.py`. Run:

```
cd backend && python -m tests.test_pipeline_stabilization
```
