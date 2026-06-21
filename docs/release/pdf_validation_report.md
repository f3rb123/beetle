# PDF Export Validation — Tier-1 Corpus

> Phase 11.5. **The PDF render itself was NOT executed on this validation host**
> because `reportlab` is a container-only dependency. This report is a rigorous
> **static** review of the export code path plus the data fed to it from the three
> Tier-1 results. Render-time confirmation must be re-run in Docker.

## Verdict (static): PASS with one low-risk hardening item

| Check | Result | Basis |
|-------|:------:|-------|
| No secret leaks | ✅ (credentials) | Secrets table renders the **masked** `value` field only |
| No malformed HTML (secrets/findings) | ✅ | `_safe()` / `escape()` on all dynamic text (21 escape sites) |
| No encoding failures | ✅ | `str()` coercion + `escape()`; reportlab Paragraph is Unicode-safe |
| No crashes | ⚠ unverified | render not run here — re-confirm in container |
| Strings-section escaping | ⚠ hardening | "Sample Values" path should route through `_safe()` |

## Secret leakage (the key safety check)

- `backend/report/pdf_generator.py:_secrets_section` renders
  `escape(str(s.get("value", "")))` — and `value` is **masked** by `secret_intel`
  before serialization. So the PDF secrets table shows masked values only
  (`AKIA****MPLE`, `<REDACTED PRIVATE KEY>`, …).
- Confirmed against all three Tier-1 results: **0 credential/key/token raw values**
  in the serialized data the PDF consumes.
- **Firebase database URLs** appear (unmasked) inside finding **evidence snippets**
  (e.g. "Firebase Realtime Database — Unauthenticated Access Risk"). A Firebase URL
  is a public network endpoint (also listed under `endpoints`), **not** a
  credential. This is consistent with showing code evidence and is not a key leak.

## Malformed-HTML / encoding safety

- reportlab parses `Paragraph` content as XML, so raw `<`, `>`, `&` in snippets
  would abort generation. `_safe(text) = escape(str(text)).replace("\n","<br/>")`
  neutralizes this and is applied across findings, permissions, behavior, strings,
  and titles.
- The secrets value cell and finding snippets are escaped; non-ASCII is coerced via
  `str()` and rendered by reportlab's Unicode-capable Paragraph.

## Hardening item (LOW)

- The **Strings** section "Sample Values" / category cells
  (`pdf_generator.py` ~lines 1210–1225) build `samples`/`cat` and render them
  without an explicit `_safe()` wrap. String-analyzer values are arbitrary and
  could contain `<`/`&`. **Recommendation:** wrap those cells in `_safe()` to
  guarantee no malformed-HTML abort on exotic strings. Low risk (string values are
  short/truncated) but cheap to close. Tracked in `technical_debt.md`.

## Required container confirmation

```bash
# in the container, after a real scan of each Tier-1 app:
python -c "from report.pdf_generator import build_pdf; ..."  # render + open
```
Confirm: (1) renders without exception for all three, (2) secrets table shows
masked values, (3) no XML parse abort on any snippet.
