# Beetle Scoring

Beetle reports four numbers. They answer two different questions, and it's important not to
confuse them:

| Score | Answers | High is… |
| ----- | ------- | -------- |
| **Security Score** | *How secure is the app?* | **bad** (high score = fewer/less-severe issues; a low score means an insecure app) |
| **Trust Score** | *How much can I trust this report?* | **good** (findings are well-evidenced and traceable) |
| **Source Resolution** | *Are findings located in real code?* | **good** |
| **View Code** | *Can I click through to the actual code?* | **good** |

A strong result looks like a **low Security Score** paired with **high Trust / Source Resolution /
View Code** — i.e. *"this app has real problems, and every one of them is backed by evidence you
can open and verify."*

---

## Security Score — "how secure is the app?"

Reported as a number `0–100` and a letter grade `A–F`. It is computed in two stages.

### 1. The number

Starts at **100** and subtracts deductions:

- **Per-severity deductions** for each finding tier (CRITICAL / HIGH / MEDIUM / LOW), applied
  with **diminishing returns** — each additional finding of the same tier costs less than the
  previous one. (Ten HIGHs is worse than one HIGH, but not ten times worse.)
- **Attack-chain penalty** — correlated, evidence-backed attack paths carry an additional
  deduction, because a chain is more dangerous than its isolated parts.
- **Good-practice bonuses** — a small credit for positive controls actually detected in the app
  (e.g. root/tamper detection).

The result is clamped to `0–100`.

### 2. The grade (semantic ceiling)

The grade is **not** just the number mapped to a letter. It is the **worse of two things**:

1. the band the number falls in, and
2. a **semantic ceiling** based on what the app actually ships:

| App ships… | Grade cannot exceed |
| ---------- | ------------------- |
| any **CRITICAL or HIGH** finding | **C** (Fair) |
| any **MEDIUM** finding | **B** |
| any **LOW** finding | **B** |
| nothing above **INFO** | **A** (clean bill) |

The ceiling only ever **lowers** the grade. This is deliberate: a good-looking number can never
earn an **A** while the app still ships a real, evidence-backed weakness. An **A** means a clean
bill — no finding above informational.

> Example: an app scoring 38/100 with 3 CRITICAL and 8 HIGH findings grades **F** — here the
> number is already below the CRITICAL/HIGH ceiling, so the number is the binding constraint.

---

## Trust Score — "can I trust this report?"

Reported as `0–100` and a rating (**HIGH / MEDIUM / LOW**). This measures the **quality of the
analysis**, not the security of the app. It is a weighted average of four factors, each `0–100`:

| Factor | Weight | Measures |
| ------ | :----: | -------- |
| **Evidence quality** | 35% | Average strength of the evidence backing each finding |
| **Source resolution** | 30% | Share of findings resolved to a concrete file and line |
| **Ownership certainty** | 20% | Share of findings with a known application-vs-library owner |
| **Chain confidence** | 15% | Average confidence of correlated attack chains (100% if none) |

```
Trust Score = 0.35·evidence + 0.30·source + 0.20·ownership + 0.15·chain
```

**Rating:** `≥ 75` → HIGH · `≥ 50` → MEDIUM · else LOW.

**Reachability is deliberately excluded.** Whether an attacker can *exploit* a finding is a
separate question (surfaced through Beetle's reachability / exploitability signals) and is not part
of report trust. Trust Score answers only: *are these findings evidenced, located, and correctly
attributed?*

> **Note:** a high Trust Score means findings are *well-evidenced and traceable* — not that every
> finding is *correct*. A false positive with a real file:line and viewable code would still score
> high on trust. Trust measures traceability; correctness is a separate concern validated against
> ground-truth reference apps.

---

## Source Resolution — "findings located"

The share of findings that resolved to an exact **file and line** in the decompiled source.

```
Source Resolution = (findings with a resolved source location) / (applicable findings) × 100
```

Some findings legitimately have no source line (manifest-level, certificate, or binary findings),
so this is measured over the applicable set.

---

## View Code — "clickable to real code"

The share of findings for which Beetle can render the **actual source** in its code viewer — i.e.
you can click a finding and read the exact code that produced it.

```
View Code = (findings with viewable code) / (applicable findings) × 100
```

This tracks Source Resolution closely: a finding that is located is usually also viewable.

---

## MASVS Coverage — "how mature is each security area?"

[OWASP MASVS](https://mas.owasp.org/MASVS/) (Mobile Application Security Verification Standard) is
the industry standard for what a secure mobile app should do. Beetle maps its findings and detected
controls onto the **eight MASVS categories** and scores each one `0–100` with a maturity label, so
you can say "this app's **Cryptography** posture is weak but its **Resilience** is moderate" rather
than reading a flat list.

### The eight categories

| Category | Covers |
| -------- | ------ |
| **MASVS-STORAGE** | Local data storage and leakage |
| **MASVS-CRYPTO** | Cryptographic primitives and key management |
| **MASVS-AUTH** | Authentication and session handling |
| **MASVS-NETWORK** | Network communication security |
| **MASVS-PLATFORM** | Platform interaction (WebViews, components, deep links) |
| **MASVS-CODE** | Code quality and input handling |
| **MASVS-RESILIENCE** | Anti-tampering and reverse-engineering resistance |
| **MASVS-PRIVACY** | Data minimization and permissions |

### How each category is scored

Each category's `0–100` score combines two halves — **do the expected controls exist**, and **is
the code clean of weaknesses** in that area:

```
category score = control_score + hygiene

control_score = (controls present / controls expected) × 60      # up to 60 pts
hygiene       = 40 − severity_penalty                            # up to 40 pts
```

- **Control score (up to 60)** — Beetle checks for **positive controls** it can actually detect in
  the app for that category (e.g. Certificate Pinning and No Cleartext Traffic for MASVS-NETWORK;
  Keystore-backed Keys and No Hardcoded Keys for MASVS-CRYPTO). The more of the expected controls
  are present, the higher this half.
- **Hygiene (up to 40)** — starts at 40 and subtracts a **severity penalty** for findings in that
  category (a HIGH crypto flaw drags MASVS-CRYPTO down). The penalty is capped so one bad category
  can't go infinitely negative.

The two halves are added and clamped to `0–100`, then mapped to a **maturity** label
(e.g. *weak / moderate / strong*). Each category also carries a **confidence** (HIGH / MEDIUM / LOW)
based on how many signals — findings plus detected controls — informed it: more signals, more
confidence.

### What it's used for

- **A posture map, not just a list.** It turns hundreds of findings into eight readable scores, so
  an analyst or an engineering lead can see *where* the app is weakest at a glance.
- **Standards-aligned reporting.** MASVS is what auditors and mobile security programs measure
  against, so the coverage view maps directly to compliance and remediation planning.
- **Missing-control visibility.** Each category also lists the expected controls that were **not**
  detected — a concrete "here's what to add" checklist, not only "here's what's wrong."

> Like the other scores, MASVS coverage reflects what Beetle can **detect and evidence**. A control
> Beetle cannot observe statically is reported as missing rather than assumed present — an honest
> floor, not an optimistic guess.

---

## Summary

- **Security Score** grades the **app**. Low is bad.
- **Trust Score, Source Resolution, View Code** grade the **report**. High is good.
- The Security **grade** can never be papered over by a good number — a single real finding caps
  it, by design.
- Trust is about **evidence and traceability**, not exploitability and not correctness — each of
  those is handled separately.
- **MASVS Coverage** grades the **app** per security area — a posture map across the eight OWASP
  MASVS categories, each combining detected controls with code hygiene.
