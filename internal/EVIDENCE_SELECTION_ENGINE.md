# Intelligent Evidence Selection & Proof Validation Engine (Beetle 2.0 — Phase 1.96)

A finding often has several candidate proof files — the application package,
AndroidX, Google Play Services, generated code, a binary string-dump. Until now the
"primary" proof was chosen by **raw confidence only** (`evidence/engine.py`:
`primary = max(items, key=confidence)`), so a library file could win over the real
application code. The Evidence Selection Engine fixes this: for every finding it
selects the **strongest, most reportable, application-relevant** proof an analyst
should review, explains why, and demotes the rest — so reports stop drowning users
in irrelevant SDK files.

> **Quality over quantity.** One excellent, application-owned, reachable proof beats
> ten weak SDK proofs.

```
… Ownership → Confidence → Evidence Intelligence → Triage → Attack Chains →
   Bug Bounty → Fusion(reconcile) → ★ EVIDENCE SELECTION ★ → analyst/MASVS/reports
```

## Architecture

A dedicated, modular package — selection logic lives in one place and **reuses**
existing engines instead of re-deriving them.

```
analyzers/evidence_selection/
  __init__.py   public API: annotate(results, platform=…), select(finding, ctx),
                register_contributor(fn, scope=…)
  config.py     the scoring model as DATA (owner deltas, bonuses, penalties, bug-bounty)
  library.py    per-FILE owner/library classifier — wraps ownership.classify()
  scoring.py    pluggable SIGNAL CONTRIBUTORS + score() (the extensibility seam)
  snippet.py    pure snippet-quality toolkit (import-only/method/call/relevance/refine)
  engine.py     candidate gather → classify → score → primary/supporting/rejected
  view.py       the single rendering model every report surface consumes
```

It runs as a **late, additive pipeline stage** (`annotate`) in both analyzers, after
ownership / confidence / reachability / attack-chains / bug-bounty / fusion-reconcile
— so every signal is available and the transient secret-bridge findings are already
gone. It writes a new `evidence_selection` block and a flat `primary_evidence`
convenience onto each finding; the existing `file_path` / `file_evidence` /
`evidence_bundle` are left untouched for backward compatibility.

## Scoring model

Each candidate proof file is scored by independent **signal contributors**; the score
is the sum of their deltas and the explanation is their reasons. All weights are data
in `config.py`. Contributors carry a **scope**:

- **File scope** — intrinsic to the file (ownership, generated, binary-dump,
  multi-engine corroboration, already-selected-elsewhere). The file-intrinsic score
  drives **ranking and the reject decision**.
- **Finding scope** — finding-wide corroboration (reachability, attack-chain,
  validation). Raises the displayed total but **never rescues** a library/framework
  file from rejection.

| Signal | Δ | Scope |
|---|---:|---|
| Application-owned file | **+40** | file |
| Application business logic (real code line) | +20 | file |
| Developer source code | +10 | file |
| Unattributed (possibly app) code | +8 | file |
| Open-source library | −25 | file |
| Third-party / vendor SDK | −30 | file |
| Android/Apple framework | −30 | file |
| Generated code | −30 | file |
| **AndroidX** / Google Play Services / Firebase | **−40** | file (name override) |
| Binary string-dump (`*.dex/.so`) | −15 | file |
| Corroborated by ≥2 detection engines | +15 | file |
| Already another finding's primary | −25 | file |
| Snippet shows the flagged value / variable / API | **+10** | file |
| Snippet includes the enclosing method signature | +6 | file |
| Snippet shows an API call (usage / call proximity) | +5 | file |
| Snippet is only imports / comments / braces | −8 | file |
| No code snippet captured | −4 | file |
| Validated finding | +30 | finding |
| Reachable (`YES` / `MAYBE`) | +25 / +8 | finding |
| Referenced by an attack chain | +20 | finding |
| App code but unreachable (likely dead code) | −20 | finding |
| Specific, high-confidence detection rule | +6 … +16 | finding |

Ranking: total score desc → file-intrinsic score → application-owned → has-line →
path. A candidate whose **file-intrinsic** score is below `REJECT_BELOW` (0) is
**rejected** (kept for transparency, not shown as proof) unless it is the only
candidate — a finding always keeps one primary.

### Snippet quality & code relevance (Phase 1.96)

Selecting the right proof *file* is only half of report quality — the proof *snippet*
must show the code that actually triggered the finding, not a block of imports or an
unrelated line. `snippet.py` is a small, pure, deterministic toolkit used by both the
scoring contributors and the engine:

- **Quality signals (file scope, small).** A snippet that is only imports / comments /
  braces — or blank — is penalized; one carrying the enclosing **method signature** or
  an **API call** is rewarded. The deltas are intentionally small (app base +40 ≫ them)
  so they reorder candidates **within** a file without ever rejecting application code
  ("reject weak relevance *unless there is no better alternative*").
- **Relevance signal (file scope).** The strongest snippet signal: the candidate
  snippet actually contains the **flagged value / variable / API** (`relevant_tokens`
  derives these from the finding's matched value and API-looking title identifiers).
  Its absence is precisely what marks a snippet as "unrelated code".
- **Snippet refinement.** The chosen primary's displayed snippet is refined to the
  single most relevant line — flagged-token > real API call > method signature > plain
  code, never an import/comment/brace — using the finding's richer `code_context` when
  the primary is the detection site. It never blanks a snippet (falls back to the
  original). So an `import javax.crypto.Cipher;` capture becomes
  `Cipher c = Cipher.getInstance("AES/ECB");`.

**Rule specificity** (`finding` scope) raises the displayed score for findings from
precise, high-confidence rules (detector confidence + a specific, non-broad CWE). Being
finding-wide, it never changes *which* file wins — only the score shown.

## Library identification

`library.classify_file(path)` **reuses the Ownership Engine** (`analyzers.ownership`,
data-driven `fingerprints.py`) to classify each candidate file: AndroidX, Google Play
Services, Firebase, OkHttp, Retrofit, Compose, Kotlin stdlib, BouncyCastle, Apache
Commons, Facebook, Cordova, React Native, Flutter, advertising / analytics / crash
SDKs, generated code, … are all recognized through the **one** existing catalog. No
second signature database is maintained — **add an SDK to the ownership fingerprints
and both ownership and evidence selection benefit.** The app's own packages/bundle id
flow in via `OwnershipContext` so application code is correctly recognized.

## Application ownership influence

Application-owned files get the dominant positive weight and, because the reject
decision is on the file-intrinsic score, an SDK/framework/generated file is demoted
to *rejected* whenever any application proof exists — exactly the brief's intent
("avoid selecting SDK internals … unless no better evidence exists"). When the only
candidate is a library file, it is still kept as the primary (a finding never loses
its single proof) but its negative file-score is visible.

## Proof selection output

Every finding exposes `evidence_selection`:

```jsonc
{
  "primary":    { "file_path": "…/PaymentCrypto.java", "line": 12, "score": 115,
                  "file_score": 70, "owner_type": "Application",
                  "selected_because": ["Application-owned", "Reachable from an entry point",
                                       "Referenced by an attack chain", …] },
  "supporting": [ … up to MAX_SUPPORTING app/unknown proofs … ],
  "rejected":   [ { "file_path": "…/androidx/…", "file_score": -40,
                    "rejected_because": ["AndroidX AppCompat library/framework"] }, … ],
  "reason": "Selected from 3 candidate proof file(s): Application-owned; …",
  "candidate_count": 3, "bug_bounty_mode": false
}
```

Cross-finding de-noise: `annotate` processes findings in severity order, so the
strongest finding claims a shared file first and later findings are penalized for
reusing it (`ALREADY_SELECTED_PENALTY`).

## Bug Bounty Mode

Auto-detected from `results["options"]["bug_bounty_mode"]`, `results["bug_bounty_mode"]`,
or `CORTEX_BUG_BOUNTY_MODE=1`. When on it sharpens toward reportable, exploitable,
application-owned proof: non-application penalties are amplified
(`×BUG_BOUNTY_NONAPP_MULTIPLIER`), reachable findings get an extra bonus, and
unreachable findings take a penalty.

## Report improvements

Reports read `evidence_selection` to render three clearly separated sections —
**Primary Proof**, **Supporting Evidence**, **Additional/Rejected References** — each
with its "selected because / rejected because" rationale, instead of a flat list of
dozens of files. The finding's loose `file_path` is preserved, so existing report
paths keep working while new ones can adopt the richer selection.

## Future extensibility

New scoring inputs plug in with **no architecture change** — register a contributor:

```python
from analyzers.evidence_selection import scoring

def ai_reviewer_vote(candidate, ctx):
    # e.g. an AI reviewer that judges which file is the true proof
    return [(40, "AI reviewer: strongest proof")] if _looks_like_real_proof(candidate) else []

scoring.register_contributor(ai_reviewer_vote, scope=scoring.FILE_SCOPE)
```

The same seam accommodates **runtime analysis**, **dynamic instrumentation**,
**user feedback**, **deeper reachability**, and **CVE correlation** — each becomes a
contributor returning `(delta, reason)` pairs. File-scope contributors influence
ranking/rejection; finding-scope contributors add corroboration without rescuing weak
files.

## Tests

`backend/tests/test_evidence_selection.py` (21 tests): application-beats-library,
AndroidX/GMS rejection, finding-signals-don't-rescue-libraries (scope separation),
generated-code demotion, single-candidate, score boosts, multi-engine bonus,
cross-finding de-noise, Bug Bounty Mode (amplify/reward/detection), contributor
extensibility, additive/non-destructive, malformed-input safety, and the Phase 1.96
snippet-quality work (import-only snippet demoted, primary snippet refined from
code_context, relevant-token usage-site selection, rule specificity raises score but
not selection, weak snippet never rejects app code). Run:

```
cd backend && python -m tests.test_evidence_selection
```
