# Network Intelligence — IP Address Discovery (Beetle 2.0 — Phase 1.99)

> Restores and **improves** the IP-address discovery capability from the original
> Cortex, as a single canonical model shared by the Android and iOS pipelines. It
> **complements** the existing URL extraction — it never touches `results["endpoints"]`,
> the URL/host/domain rendering, or any URL logic.

The original `evidence_scanner.scan_directory_for_ips` only surfaced **IPv4**, collapsed
everything to `public`/`private` (dropping loopback/link-local/multicast/reserved/
broadcast/documentation), never attributed an owner, used a hardcoded confidence, and
missed Swift/ObjC sources (so iOS source IPs were lost). This phase replaces that with
`analyzers/network_intel.py`.

---

## 1. Detection architecture

Two stages, mirroring the other intelligence engines, so it integrates without
disrupting anything:

```
decompiled tree
  → network_intel.extract_ips(base_dir, extra_dirs)      [parallel scan pool]
        IPv4 + IPv6, broad source/resource/config extensions (Swift/ObjC/plist incl.)
        reuse evidence-scanner smali/version/binary-dump filters
        → raw hits: {ip, file_path, line, snippet}        (one per distinct occurrence)
  → network_intel.annotate(results, platform)            [after manifest/plist parse]
        classify → owner-attribute → suppress → MERGE → confidence → intelligence
        → results["ips"]  (enriched, backward-compatible)
        → results["ip_intelligence"]  (summary)
```

* **Android** (`android_analyzer.py`): `extract_ips` runs in the existing parallel
  string pool; `annotate` runs immediately after that phase — **before** the
  "Hardcoded Public IP Addresses" finding, `network_workspace`, and the UI.
* **iOS** (`ios_analyzer.py`): identical — `extract_ips` in the scan pool, `annotate`
  right after `results["ips"]` is assigned, before the iOS public-IP finding.

Both call the **same** module with the **same** logic → full Android/iOS parity. The
only platform input is `platform=` (chooses the Ownership context and is recorded in
the summary).

### Extraction details
* **IPv4** reuses the evidence scanner's strict `IP_PATTERN`.
* **IPv6** uses a permissive candidate regex (hex groups + colons, allowing a mid-address
  `::` like `2606:4700:4700::1111`) that is then **validated by `ipaddress`** — so times
  (`12:30:45`), version strings and malformed groups are rejected.
* Extensions cover Java/Kotlin, **Swift/ObjC/`.m`/`.h`/`.plist`** (iOS parity), XML,
  JSON, properties, gradle, YAML, `.conf/.cfg/.ini/.env`, `.strings`, HTML. Smali is
  excluded (hex/`const-wide` false-positive goldmine); binary string-dumps are skipped.
* Inherited noise filters: smali opcode tokens, `_VERSION_DECL_RE`, file-size/file-count
  caps (`CORTEX_EVIDENCE_MAX_*`).

---

## 2. Classification rules

Every IP is classified into the full taxonomy via the `ipaddress` stdlib (authoritative),
checked in this order (documentation ranges first, since they otherwise look public/private):

| Class | Rule |
|---|---|
| `documentation` | RFC 5737 (`192.0.2/24`, `198.51.100/24`, `203.0.113/24`), RFC 6598 (`100.64/10`), RFC 3849 (`2001:db8::/32`) |
| `unspecified` | `0.0.0.0` / `::` |
| `loopback` | `127/8`, `::1` |
| `link_local` | `169.254/16`, `fe80::/10` |
| `multicast` | `224/4`, `ff00::/8` |
| `broadcast` | `255.255.255.255` |
| `private` | RFC1918 (`10/8`, `172.16/12`, `192.168/16`), ULA `fc00::/7` |
| `reserved` | other reserved / non-global |
| `public` | globally routable |
| `unknown` | not a valid IP literal |

`type` (legacy) is preserved as `public`/`private`/`internal` so the existing Android &
iOS public-IP findings and the UI keep working unchanged. Each entry also carries
`classification`, `classification_label` ("Private (RFC1918)" …) and `version` (4/6).

---

## 3. Ownership integration

`annotate` reuses the **Ownership Engine** (no second SDK database): it builds the
`OwnershipContext` from the app's package/bundle id (`context_from_results`) and calls
`evidence_selection.library.classify_file(path, ctx)` on each IP's source file. The
result is mapped to a display owner — **Application**, **Third-party SDK**, **Framework**,
**Generated Code** — exactly as elsewhere in Beetle. Application-owned IPs score higher
confidence; framework/SDK/generated IPs are demoted.

---

## 4. Suppression logic

Quality over noise — but **nothing is dropped**; suppressed IPs are kept and counted for
auditability and only hidden by default.

* **Merge.** Repeated occurrences of one literal collapse into a single canonical entry
  carrying `occurrences` and `merged_files` (every source file it appeared in).
* **Suppress-by-default** when an IP is noise *and* has no promoting intelligence tag:
  a known placeholder (`8.8.8.8`, `1.1.1.1`, `10.0.2.2`, `255.255.255.255`, …), a
  documentation/framework-test range, or a non-endpoint class (link-local / multicast /
  reserved / broadcast / unspecified / documentation / unknown).
* **Promotion.** Strong context overrides suppression: any intelligence tag (e.g. a
  loopback used as a real dev backend) keeps the IP visible.

The UI shows visible IPs by default and offers a "Show N suppressed (noise)" toggle.

---

## 5. Confidence calculation

An explainable 5–99 score (not a constant): base 50, `+20` routable endpoint / `−30`
non-endpoint range / `−10` loopback; `+20` application-owned, `−25` framework-SDK,
`−15` generated; `+12` when the snippet shows network-assignment context
(`http`/`url`/`host`/`endpoint`/`://`/…); `+6` for ≥3 occurrences. The reason string
(`confidence_reason`) records every contribution.

---

## 6. Intelligence (highlighted cases)

`intelligence` tags surface interesting IPs: **Hardcoded Internal IP** (private in app
code), **Private IP in Release Build** (private + app + non-debuggable build), **Loopback
Reference**, **Development Environment** (dev/stage/test/qa/uat/debug/internal/local in the
snippet), **Embedded Backend Address** (routable, app-owned, network context), **Multiple
IP References** (≥3 occurrences).

---

## 7. Reporting

`results["ips"]` per entry (backward-compatible **plus** enriched):

```
ip, type(legacy), version, classification, classification_label,
owner_type, owner, owner_name, confidence, confidence_label, confidence_reason,
file_path, line, snippet, file_evidence, occurrences, merged_files,
intelligence[], reason, suppressed
```

`results["ip_intelligence"]` summary: `total`, `visible`, `suppressed`,
`by_classification`, `public`, `private`, `ipv6`, `with_intelligence`, `platform`.

The Network UI (`NetworkPanel`, IPs tab only — the URL section is untouched) renders each
IP with its **Classification**, **Owner** (color-coded), **Confidence %**, **source
file\:line**, occurrence count and **intelligence tags**, matching the spec's report
fields (IP / Classification / Source / Evidence / Owner / Confidence / Reason).

---

## 8. Tests

`backend/tests/test_network_intel.py` (12 tests): full classification taxonomy, IPv4 and
IPv6 (incl. compressed `::`) extraction, time/version rejection, public/private visibility
with owner + confidence, loopback reference, reserved/noise suppression (kept + counted),
owner attribution (Application vs SDK), duplicate occurrence merge, placeholder
suppression, **Android == iOS parity** (incl. Swift-source extraction), and
backward-compatible legacy fields. Run:

```
cd backend && python -m tests.test_network_intel
```

---

## 9. What is intentionally untouched

URL extraction (`_extract_endpoints`, `results["endpoints"]`), the URL/host/domain
rendering, the Network section layout, and all other intelligence engines. This phase
adds IP discovery beneath the existing URL section and changes nothing about URLs.
