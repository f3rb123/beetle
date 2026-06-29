# 24. FAQ

Answers to the questions analysts ask most, with pointers to the chapter that covers each in
depth.

---

## Scores & interpretation

### Why is my Security Score low?
The score starts at 100 and deducts for findings (critical −15, high −8, medium −3, low −1,
with diminishing returns capped at 3× per severity class), secrets, and a correlated-risk
penalty for attack chains (+5 each, cap 20) and high exploitability (up to +10). Open the
**Score** breakdown to see the exact deductions and which factors (chains, secrets, cleartext,
exported components) drove it. The fastest way back up: eliminate a *critical-class* issue,
*break an attack chain*, or *bank a control bonus* (e.g. certificate pinning +5). See
[Ch 9](09-security-score.md).

### Why is my Trust Score high (or low)?
Trust Score answers *"can I trust these findings?"* — not how secure the app is. It's 35%
evidence quality + 30% source resolution + 20% ownership certainty + 15% chain confidence.
**High** means strong evidence and good attribution. **Low** usually means heavy obfuscation
(lots of "Unknown" ownership) or weak evidence — not that findings are wrong. Reachability is
deliberately excluded. See [Ch 8](08-trust-score.md).

### My Security Score is high but Trust Score is low — what does that mean?
The most important quadrant: *few issues found, but coverage/evidence was poor.* Treat the
"clean" result with caution — Beetle is telling you it couldn't see much (often obfuscation).
Add coverage (deobfuscate, dynamic analysis, manual review) before declaring the app safe. See
[Ch 6 §6.3](06-scoring-systems.md).

### Why does a critical finding have low confidence?
Severity and confidence are independent axes ([Ch 6 §6.2](06-scoring-systems.md)). A
high-severity pattern Beetle can't prove (unresolved evidence, no pinned line) gets low
confidence and a "Needs Review" verification status — it's a *verify-this-manually* item, not
a dismissal. Open the confidence breakdown to see which dimension capped it. See
[Ch 10](10-finding-confidence.md).

### What's the difference between all these numbers?
Security Score (how secure), Trust Score (how much to believe the report), Confidence
(per-finding sureness), Severity (how bad if true), Exploitability/Reachability (how
exploitable), Reportability (worth reporting), MASVS coverage (how mature). They're kept
separate on purpose — see the master table in [Ch 6 §6.1](06-scoring-systems.md).

### "Trust Score", "Trust" and "Confidence" all appear — are they the same?
No, and this is the most common first-time confusion. There are **three** numbers: the
report-level **Trust Score** card (can I trust this report?), a per-finding **Trust** chip
(a 0–100 at-a-glance composite of confidence + fusion + evidence, also driving the "Trust ≥"
filter), and a per-finding **Confidence** score (the explainable 5-dimension reliability of
one finding). Same-sounding, different formulas, different scopes. The disambiguation table is
[Ch 6 §6.10](06-scoring-systems.md).

---

## Findings, evidence & source

### Why wasn't the source resolved for a finding?
Either it's a kind that legitimately has no code line (native/binary, certificate metadata,
manifest entry, taint chain — these are fully resolved *for their kind*), or the claimed
location couldn't be resolved (shown as "Needs Review," which caps confidence at 35). Beetle
flags the difference rather than guessing. Obfuscated apps still resolve source — only the
*owner* is uncertain. See [Ch 11](11-source-resolution.md).

### Why does one finding list multiple engines ("Detected By: Beetle · Semgrep · APKLeaks")?
That's **Finding Fusion**: several detectors found the same logical issue (same CWE +
location), so Beetle collapsed them into one finding and credited all of them. Multi-engine
agreement also raises the finding's confidence (+12/engine, cap +24). You never see the same
issue twice just because two engines found it. See [Ch 15](15-finding-fusion.md).

### Why is a finding "hidden by default"?
Triage decided it lacks meaningful security value *right now* — typically framework/SDK noise,
generated code, a documentation example, or a confirmed false positive. **It is not deleted** —
reveal hidden findings with the Findings filter. Note the rule: Beetle suppresses for *lack of
value*, never for "it's a library" — a real secret inside an SDK stays visible. See
[Ch 4 §4.17](04-intelligence-engines.md).

### A finding is in a third-party SDK. Should I care?
Usually it's lower priority (you can't fix someone else's SDK), which is why Ownership marks it
and Triage may hide it. But check: if it's a *real secret*, a *vulnerable dependency* (update
it), or a *supporting link in an attack chain*, it matters. See [Ch 14](14-ownership-engine.md).

### Why was a "secret" classified as a false positive / documentation example?
The Secret Intelligence engine validates every candidate with deterministic signals (format,
checksums like GitHub CRC32, entropy, ownership) and recognizes known non-secrets — famous
docs/example keys, NIST test vectors, placeholders, public keys, crypto-library constants. *A
value isn't a secret just because it matches a regex.* See [Ch 4 §4.6](04-intelligence-engines.md).

### Why did a secret get bumped to critical?
The live secret validator confirmed it's an *active* credential (`severity_bumped=True`), which
also floors its confidence at 95. Make sure you're authorized to probe the app's services —
live validation makes real API calls. See [Ch 4 §4.4](04-intelligence-engines.md).

---

## Attack chains

### What does an Attack Chain mean?
A chain is a *realistic attacker journey* — an entry point (e.g. an exported component) +
required findings (e.g. a WebView JS bridge) + supporting context, leading to a goal (e.g.
code execution). It's evidence-backed end-to-end (each step links to `file:line`). It explains
how individually-medium findings combine into a critical, reachable risk. See
[Ch 12](12-attack-chains.md).

### How do I fix / break a chain?
A chain needs *all* its required links, so fix **any one** required link to break it — pick the
cheapest. Breaking a chain also removes the Security-Score chain penalty. A *blocked* chain
(a mitigation is present) is shown but downgraded. See [Ch 12 §12.8](12-attack-chains.md).

### Why isn't every high-severity finding a chain?
By design (SAFE-CHAINING + finding-soup avoidance): a single unrelated finding never becomes a
chain; templates require specific *combinations*, and subset chains are de-duplicated.
Framework/SDK noise can only be *supporting*, never required. See [Ch 12 §12.6](12-attack-chains.md).

---

## Prioritization & workflow

### How should I prioritize findings?
Rank by **severity × confidence × reachability**, application-owned first, then use **Bug
Bounty reportability** (`review_priority` P1–P4) and the **Most Exploitable Chain** to decide
what's worth a write-up. The Findings filter (severity + "Trust ≥" + ownership +
reachability) does this directly. See [Ch 7 §7.8](07-risk-rating.md), [Ch 10 §10.8](10-finding-confidence.md).

### What's the fastest triage path?
Overview → read the headline trio → start at the Most Exploitable Chain → in Findings, set
severity ≥ High, "Trust ≥" high, ownership = Application → reproduce via evidence → use AI
*verify* on anything uncertain. See [Ch 5](05-dashboard-guide.md).

### Can I verify a finding with AI?
Yes — the AI *verify* action gives an *advisory* assessment grounded in the evidence, but it
never auto-marks a finding as a false positive (that's your call). Every AI answer is tagged
`llm` or `deterministic`. See [Ch 22](22-ai.md).

---

## Platforms & coverage

### Does Beetle support Flutter / React Native?
Yes, as first-class platforms — detected inside the APK/IPA scan and analyzed by dedicated
sub-analyzers whose findings flow through the same pipeline (so they show Detected By, Owner,
Confidence, Evidence, Chains, Source like native findings). There's no separate "Flutter
target"; you upload the APK/IPA. See [Ch 19](19-framework-intelligence.md).

### Can Beetle scan a repository / CI-CD config?
Yes — upload a `.zip` repository archive. The CI/CD Security Intelligence engine finds pipeline
misconfigurations (mutable action refs, `curl|bash`, over-privileged tokens, `docker.sock`
mounts, …) and they run the same finalize pipeline. See [Ch 3 §3.5](03-scan-targets.md).

### Why is taint analysis missing on my iOS scan?
Taint analysis uses the androguard DEX call graph and is **Android-only**. iOS analysis is
binary/plist/entitlement-centric. See [Ch 19 §19.3](19-framework-intelligence.md).

### Why does the MASVS "Compliance PDF" say "pass" for something I'm not sure about?
The Compliance PDF mapping is static: "pass" means *no failing evidence found*, not *verified
compliant*. Read it alongside MASVS **coverage maturity**, which is explicit about what was and
wasn't checked. See [Ch 16 §16.4](16-reports.md), [Ch 17](17-masvs-coverage.md).

---

## Operations

### Why did my large APK's progress bar stop but the scan kept running?
The live SSE stream has a 6-minute cap; large APKs continue in the background after it closes.
The UI falls back to polling — refresh or re-open the scan to get the final result. See
[Ch 2 §2.3](02-system-architecture.md).

### Are my app binaries uploaded anywhere?
No. Analysis is local; the artifact and source never leave your infrastructure. A few
*optional* integrations make outbound calls (VirusTotal hash lookups, OSV/CVE feeds, AI
provider, domain geo, live secret/cloud probing) — all disableable
(`CORTEX_DISABLE_LIVE_CHECKS=1`, no provider keys). See [Ch 1 §1.1](01-introduction.md),
[Ch 2 §2.12](02-system-architecture.md).

### How do I gate a CI pipeline on Beetle results?
Use the CI/CD policy gate endpoint with per-severity thresholds; it returns
`{pass, violations[]}`. Combine with the SARIF export for GitHub Code Scanning. See
[Ch 16 §16.8](16-reports.md).

### Source files aren't available on an old scan — why?
Decompiled trees are cleaned up after the scan TTL (default 24 h). Re-scan to restore View
Code. See [Ch 2 §2.11](02-system-architecture.md).

---

*Next: [Chapter 25 — Glossary](25-glossary.md).*
