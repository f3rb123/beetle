# RUN 19 — regex_sast base-rule audit (MEASURE ONLY, no behavior change)

**Scope:** `backend/analyzers/code_rules.py` — `CODE_RULES` (Android, 55) + `IOS_CODE_RULES` (iOS, 26)
= **81 base regex rules.** (`backend/analyzers/sast/` is the Semgrep adapter, not regex rules —
out of scope.) Evidence = match breadth (`merged_locations`) and final finding count/severity/owner
observed on the current iOS (14 findings) and Android (46 findings) scans.

## Method
Pattern-shape heuristics over-flag (e.g. `Cipher.getInstance("AES")` is precise, not broad), so the
ranking below is **empirical**: how many source locations each rule actually matched on this corpus,
plus the final severity and ownership of the finding it produced. A rule that matches hundreds of
lines across framework/library code is over-broad regardless of its pattern's look.

Note: the score is unaffected by these — all the over-broad rules end up INFO and library-owned
after the RUN 15 library-noise demotion. The cost is **evidence noise** (huge `merged_locations`,
quality-scoring overhead) and, for `android_obfuscation_missing`, it is the carrier of the L4
jadx line-drift. So this is a signal-quality cleanup, not a scoring fix.

## The over-broad rules (ranked by match breadth on this corpus)

| rule | rule sev | final sev | match locs | owner | why over-broad |
|---|---|---|---|---|---|
| `android_reflection` | low | info | **228** | AndroidFramework | `.invoke(` / `.getMethod(` appear in nearly all framework+library code; reflection is ubiquitous and not itself a vuln |
| `android_log_debug` | low | info | **181** | AndroidFramework | `\bLog\.(d\|v\|i\|e\|w\|wtf)\(` matches every log call in the app AND every bundled library |
| `android_obfuscation_missing` | info | info | **125** | ThirdPartySDK | `R\.id\.`/`R\.layout\.`/`R\.string\.` occur in essentially every Android UI class; a whole-app posture proxy implemented as a per-file regex that accumulates 125 locations |
| `android_process_death` | medium | info | **41** | ThirdPartySDK | bare `Serializable`/`Parcelable` match any class implementing those interfaces; ALSO an id/pattern mismatch (see below) |
| `android_insecure_random` | medium | info | **26** | ThirdPartySDK | bare `java\.util\.Random` matches the import ref everywhere; `Math.random()` is usually non-security (UI/animation) |
| `android_print_stack_trace` | low | info | 12 | AndroidFramework | `printStackTrace()` / `System.out.print` are pervasive and low value |
| `android_content_provider_no_permission` | low | info | 10 | ThirdPartySDK | detects `contentResolver.query(` USAGE, not a missing-permission condition (see below) |
| `ios_jailbreak_detection` | info | info | 10 | GoogleSDK | `substrate`, `/bin/bash`, `fileExists.*Applications` are broad and match library code |

## Proposed changes — PROPOSALS ONLY, NOT APPLIED

For each, the intent is fewer matches with the same true-positive coverage. None of these is applied
in RUN 19.

1. **`android_reflection`** (`java\.lang\.reflect\.|\.getMethod\(|\.invoke\(|\.getDeclaredMethod\(|\.getDeclaredField\(`)
   - Drop the bare `\.invoke\(` and `\.getMethod\(` alternatives (they match Retrofit, RxJava,
     lifecycle, mockito, etc.). Keep `java\.lang\.reflect\.`, `getDeclaredMethod`, `getDeclaredField`.
   - Restrict to app-owned code (skip `androidx/`, `com/google/`, `kotlin/`), OR require a
     dynamic-load context (`Class\.forName` / `DexClassLoader` near the reflection call).
   - Reflection presence alone is not a finding; this should be INFO evidence, not a per-file match.

2. **`android_log_debug`** (`\bLog\.(d|v|i|e|w|wtf)\(`)
   - Only flag when the logged argument looks sensitive (`password|token|secret|key|pin|cvv|jwt|
     Authorization`) — that is the actual CWE-532 risk. A bare log call is not a finding.
   - Restrict to app-owned code. This alone would cut ~90% of the 181 matches.

3. **`android_obfuscation_missing`** (`BuildConfig|R\.layout\.|R\.id\.|R\.string\.`)
   - This is a WHOLE-APP posture check ("is the app obfuscated?"). It should be computed ONCE
     (presence/absence of unobfuscated app class names) and emit a single finding with ONE
     representative location — not a per-file regex that accrues 125 `merged_locations`.
   - Bonus: this retires the L4 jadx line-drift residual, which rides entirely on this rule's
     per-file locations in AndroidX code.

4. **`android_process_death`** (`ObjectInputStream|readObject\(\)|Serializable|Parcelable.*readFromParcel`)
   - CORRECTNESS, not just breadth: the id says "process death" but the pattern is
     insecure-deserialization. Rename to `android_insecure_deserialization`.
   - Drop bare `Serializable` and `Parcelable` (implementing an interface is not a vuln). Keep
     `ObjectInputStream` + `readObject()` (the real untrusted-deserialization sink).

5. **`android_insecure_random`** (`new Random\(\)|Math\.random\(\)|java\.util\.Random`)
   - Drop the bare `java\.util\.Random` import ref. Keep `new Random()` / `Math.random()`.
   - Ideally gate on a security context (seed/key/token/IV/nonce nearby) so UI/animation RNG is
     not flagged. Restrict to app-owned code.

6. **`android_print_stack_trace`** — restrict to app-owned code; consider merging into a single
   "verbose error output" evidence rather than a standalone finding. Very low value.

7. **`android_content_provider_no_permission`** — CORRECTNESS: the pattern detects
   `contentResolver.query()` usage, which is not evidence of a *missing* permission. Either
   rename to reflect "content-provider access" or gate it on an actually-exported provider with no
   `android:permission` in the manifest. As-is it is a usage detector mislabeled as a config gap.

8. **`ios_jailbreak_detection`** (`cydia|substrate|...|fileExists.*Applications|/bin/bash`)
   - Tighten `fileExists.*Applications` (matches any file-existence check mentioning "Applications")
     to specific JB paths (`/Applications/Cydia.app`, `/bin/bash`, `/etc/apt`, `/private/var/lib/apt`).
   - `substrate` alone is broad; require `MobileSubstrate`/`CydiaSubstrate`.

## Rules my shape-heuristic flagged but that are ACTUALLY FINE (not over-broad)
Recorded so a follow-up run does not "fix" precise rules:
`android_aes_ecb_default` (`Cipher\.getInstance\("AES"\)` — exact), `android_weak_cipher_des/ecb/rc4`
(exact `getInstance("...")`), `ios_hardcoded_credentials`
(`(?:password|secret|token|api.?key)\s*=\s*"[^"]{6,}"` — scoped), `android_runtime_exec`
(`Runtime.exec(` — precise sink). These matched the crude heuristic only because they contain a
common token inside an otherwise precise pattern.

## Two id/pattern MISMATCHES found (correctness, worth a follow-up regardless of breadth)
- `android_process_death` — id implies process-death handling; pattern is deserialization.
- `android_content_provider_no_permission` — id implies a missing-permission config; pattern is
  content-resolver usage.

## Summary
- 81 base regex rules; **8 empirically over-broad** on this corpus (2 of them also mislabeled).
- All 8 currently land INFO/library-owned, so they do NOT inflate the score — the cost is evidence
  noise and (rule 3) the L4 jadx line-drift carrier.
- Highest-value follow-ups: rule 3 (retires L4 residual + kills 125 locations), rules 1 & 2 (409
  combined matches), rules 4 & 7 (correctness mislabels).
- NOTHING APPLIED. Proposals for a future run to pick from.
