# BEETLE_PROGRESS.md — Live Execution Tracker
Claude Code: read this FIRST every session (see CLAUDE.md). Work the first non-[x] run. Update after each run and before stopping.

Status key:  [ ] TODO   [~] IN-PROGRESS   [x] DONE   [!] BLOCKED (needs human)

Baseline before start: iOS grade A 97/100 (0/0/0); MobSF 50/100 grade B. Target: correct + beats MobSF, Android unchanged.

═══════════════ METHODOLOGY — READ BEFORE ANY SHARED-FILE RUN ═══════════════

*** SECRET-MASKING RULE (durable — 3 confirmed bypasses: RUN 12, 13, 21) ***
ANY new output surface that renders bundle-derived strings — PDF (pdf_generator.py), a UI
panel, a JSON/API export, SARIF, anything — MUST route every rendered value through
secret_intel.mask_value (or strings_section.redact, which wraps it). The masking pipeline only
protects the fields explicitly passed to it: a NEW surface that reads results[...] and prints
raw values bypasses it silently and leaks credentials. History:
  RUN 12 — Property Lists printed the Firebase API key in plaintext.
  RUN 13 — the Strings section printed base64 "Potential Secret" blobs raw.
  RUN 21 — the PDF's _string_analysis_section printed those same base64 values raw.
Each was a DIFFERENT output path with its own read of the raw data. When adding or reviewing
any surface: grep it for direct results[...] value rendering and confirm each credential-class
value is masked. A green test does not prove this — only reading the rendered artifact does.

(applies to RUN 13, 15, 16, 17 and every future shared-file change)

*** CONSUMER-FIELD RULE (durable — RUN 20 set the right field, the UI read a different one) ***
When correcting evidence DATA (a line, a snippet, a path), fix the field the RENDERER actually
reads — not just the field you first think of. RUN 20 correctly remapped a plist finding's
top-level f["line"] to the decoded-XML line (32), but the frontend's buildEvidence (ui.jsx) reads
file_evidence[*].lines FIRST, which still held the raw-bplist artifact [3] — so View Code kept
scrolling to the wrong line and RUN 20 "passed" its one-finding check while the bug was live.
RUN 24 fixed the consumed field (file_evidence) and generalized it. GENERALIZES: before claiming
an evidence fix works, TRACE which field the consumer (frontend buildEvidence / resolveEvidenceLines,
PDF _findings_section, SARIF, source_explorer._finding_paths) actually reads, and correct THAT.
A finding often carries the same location in several fields (line / file_evidence / merged_locations /
evidence_view); correcting one and not the rest leaves a silent mismatch.

THE ANDROID GUARD IS ORDER-INSENSITIVE ON SET-DERIVED FIELDS.
Byte-equality is the right test ONLY for fields that are already deterministically ordered:
    endpoints, ips, findings, severity_summary, secrets   -> compare byte-for-byte.
Fields backed by a Python set are NOT stably ordered across processes — their order changes
on every backend restart even with byte-identical code (see L3: androguard's
apk.get_permissions() at android_analyzer.py:1353). Compare these as SETS / multisets:
    permissions (all / classified / dangerous), and any other set-derived collection.
Concretely:  sorted(json.dumps(x, sort_keys=True) for x in lst)  on both sides, then compare.

ALSO MASK VOLATILE FIELDS before any byte-compare (all construction-varying, NOT analysis
nondeterminism): timestamp / scan_time / generated_at / created_at / updated_at; scan-id UUIDs
in filesystem paths (/tmp/cortex/scans/<uuid>/...); and TIMING metrics
(duration_ms / total_duration_ms / parallel_phase_ms).

*** UPDATED AT RUN 16 — the byte-identical guarantee is now STRONG, with ONE narrow tolerance ***
After RUN 16 fixed L3 (permission order), Android is byte-stable EXCEPT:
  TOLERATE: +/-1 line drift on REJECTED (non-primary) LIBRARY-candidate evidence, and ONLY there.
    Cause: jadx decompiles the same APK to byte-different source across runs (proven: two
    ViewPager2.java decompiles had different md5 AND different line counts, 1121 vs 1122), so a
    match lands on line 428 vs 429. Out of Beetle's control.
  *** UPDATED AT RUN 23 — the obfuscation-finding carrier of this drift is RETIRED. *** RUN 23
    collapsed android_obfuscation_missing to a single app-owned representative, so ViewPager2.java
    (and 124 other library locations) are no longer candidates on that finding — its +/-1 drift is
    gone for good. BUT the tolerance STAYS: the SAME jadx mechanism rides on OTHER over-broad rules
    that still carry rejected AndroidX candidates — CONFIRMED on android_log_debug
    (AppCompatTextViewAutoSizeHelper.java 60<->61) and android_reflection. It is intermittent
    (a given scan pair may show 0 drift leaves). L4 is REDUCED, not resolved; full closure needs the
    RUN 19 breadth fixes (proposals 1 & 2: restrict reflection/log_debug to app-owned code).
    READ THIS RIGHT (do NOT mark L4 done): obfuscation FINDING's drift = RETIRED; the jadx
    byte-different-decompilation ROOT CAUSE = STILL OPEN — it affects ANY finding with rejected
    AndroidX library candidates, and stays out of scope for the SAME reason as RUN 16 (not fixable
    Beetle-side). RUN 23 removed one carrier, not the mechanism.
    UPDATED RUN 25: android_reflection (103 androidx) + android_log_debug (112 androidx) carriers
    also RETIRED (restricted to app-owned code). Still 17 findings carry androidx candidates
    (insecure_deserialization 26, print_stack_trace 14, implicit_intent_sensitive 14, ...). L4 is
    REDUCED to 17 residual carriers, STILL NOT closed. Root cause unchanged.
  NEW at RUN 23 — L5 (separate, pre-existing): taint_flows list ORDER is nondeterministic
    run-to-run (e.g. the WebView2Activity flow and the CustomReceiver flow swap positions). This is
    an ordering issue, NOT jadx line-drift; sorting taint_flows order-insensitively makes the diff
    empty. Unrelated to RUN 23. Logged for a later determinism pass; do NOT let it mask a real diff.
  NEW at RUN 24 — L6 (test-coverage gap, NOT a runtime bug): the frontend has NO test infra
    (no test script in frontend/package.json), so the view-code line-resolution / autoscroll path
    (Results.jsx resolveEvidenceLines + buildEvidence + CodeBlockViewer) is verified only by build +
    data-level simulation, never an automated regression test. This is the SECOND scroll/remap
    regression in this exact area (RUN 20 then RUN 24); without a test it can regress a third time.
    A future frontend-test effort MUST cover: (a) declared line out of range -> falls through, never a
    phantom row; (b) a plist finding scrolls to its decoded-XML value line; (c) an absence-finding
    (no anchor) renders + highlights nothing. Not broken today — a durable safety net is missing.
  MUST STAY BYTE-STABLE (tolerance does NOT extend here): primary evidence, finding identities,
    severity_summary, score, grade, and permissions. If any of THOSE move, it is a real bug.
  iOS has an analogous ENVIRONMENTAL variance: domain_intel geo (live DNS/geo of CDN IPs, e.g.
    Mountain View vs Bangkok) — same class as jadx, network-driven, not analysis. Exclude
    domain_intel city/country/geo from iOS byte-diffs; iOS analysis output (findings/score/
    primaries) is otherwise fully deterministic (no jadx on the iOS path).

WHY THIS RULE EXISTS: RUN 6's Android diff reported "permissions identical: False" and it was
a PHANTOM failure — same 5 permissions, different order, cause proven pre-existing (3 container
restarts, no rebuild, 3 different orders). Without this rule RUN 13/15/16 will chase the same
ghost, or worse, "fix" a regression that was never there.

DO NOT paper over a real diff with this rule: first prove the difference is order-only
(content equal as a multiset), THEN prove the cause is pre-existing (restart the container with
NO code change and show the order moves on its own). Only then is it safe to pass.

═══════════════ TIER 1 — CORRECTNESS ═══════════════

[x] RUN 1 — iOS URLs & IPs reach Discovered Endpoints (SHARED: endpoints/ips)  DONE
    Files changed:
      backend/analyzers/ios_analyzer.py    — import printable_text (was MISSING: see below);
        _scan_binary_strings rewritten to walk EVERY Mach-O (magic-byte detect: main +
        Frameworks/*.framework/* + *.dylib, cap 40) and harvest secrets + URLs + IPs;
        merge binary IPs into results["ips"] BEFORE network_intel.annotate and binary URLs
        into results["endpoints"] after extract_endpoints; _extract_endpoints now passes
        verbose=True (iOS-only, no-source-context mode); domain_intel key initialized and
        domain_analyzer.check_domains wired in (iOS never called it — see below).
      backend/analyzers/endpoint_intel.py  — NEW extract_urls_from_text() (additive; Android
        never calls it).
      backend/analyzers/network_intel.py   — NEW extract_ips_from_text() + _has_network_context()
        FP gate (additive; Android never calls them).
    Android diff (must be empty): CLEAN. InsecureShop.apk rescanned on the edited tree vs the
      pre-change baseline: endpoints 1 -> 1 BYTE-IDENTICAL (["https://com.insecureshop"]),
      ips 0 -> 0, findings 45 -> 45, secrets 1 -> 1, severity_summary identical
      (C1/H11/M7/L4/I22). No regression.
    Acceptance (domains + IP 192.168.161.138 + Domain Intel): PASS — all four criteria.
      iOS testapp.ipa BEFORE -> AFTER:  endpoints 0 -> 78 | ips 1 -> 1 | domain_intel 0 -> 30
      | findings 82 -> 82 (unchanged).
      WHAT RUN 1 ACTUALLY FIXED (be honest with yourself next session):
        endpoints  0 -> 78   <-- the real win
        domain_intel 0 -> 30 <-- the real win (section was never wired on iOS at all)
        ips        1 -> 1    <-- NOT A FIX. 192.168.161.138 was ALREADY surfacing before
                                 any edit (it sits in a text asset network_intel already
                                 scanned). RUN 1 did not make it appear; it only had to
                                 avoid breaking it — and avoid the FP it nearly added.
        PASS  firebase*.googleapis.com, httpbin.org, filesamples.com, pub.dev, github.com
        PASS  IPs section shows 192.168.161.138  (pre-existing — see above, not a RUN 1 fix)
        PASS  Domain Intelligence populates (30 domains)
        PASS  no binary-IP false positive (see FP note)
    Commit-ready: Y  (NOT committed, nothing staged — human commits)
    Tests: 780 passed, 11 skipped (backend/tests, local).

    THREE PROMPT FACTS WERE WRONG — corrected against live source before editing:
      FACT 1 — CONFIRMED. Only the main Runner binary was string-scanned.
      FACT 2 — WRONG. _scan_binary_strings never extracted URLs/IPs at all (secrets only),
        and string_analyzer._collect_files reads only text exts + .dex/.so, so extension-less
        Mach-O strings NEVER entered results["string_analysis"]. There was nothing
        binary-derived to bridge; "Do" step 2 as written would have bridged an empty set.
        Implemented the human-approved correction: extract URLs/IPs directly in
        _scan_binary_strings and merge into endpoints/ips.
      ROOT CAUSE (not in the prompt): printable_text was NEVER IMPORTED into ios_analyzer.py,
        yet _scan_binary_strings called it inside a bare `except Exception: pass`. The
        function raised NameError and silently did nothing on EVERY iOS scan since it was
        written — it had never contributed a single binary string. Fixed by importing it.
      IP PREMISE — WRONG. Proven by a real pre-change iOS scan: 192.168.161.138 was ALREADY
        surfaced (1 IP) before any edit — it lives in a TEXT file
        (App.framework/flutter_assets/assets/cfg/app_settings.json), which network_intel
        already scans. It was never being dropped. RUN 1's real win is endpoints 0 -> 78.
      DOMAIN INTEL — GAP NOT IN THE PROMPT. ios_analyzer never referenced domain_analyzer and
        never initialized results["domain_intel"], so Domain Intelligence could not populate
        no matter how many endpoints were found. Wired check_domains into the iOS path (after
        all endpoint contributors). Android's _add_domain_intel_summary FINDING is
        deliberately NOT mirrored, so iOS finding count is unchanged (82 -> 82).

    FP GUARD (self-caught): the first cut of binary IP extraction added a false positive —
      1.3.0.1 from Flutter.framework/Flutter (an OID/version fragment; syntactically valid
      IPv4). Binary string tables are dense with dotted-quad lookalikes and have no code
      context to judge by. Added _has_network_context(): a binary IP is kept only when it
      appears as a URL host (//1.2.3.4) or with a port (1.2.3.4:8080) — how a real embedded
      backend appears, never how an OID/version does. Verified: 1.3.0.1 gone, the real
      192.168.161.138 (which the app uses as http://192.168.161.138:8080/) retained.

[x] RUN 1.1 — endpoint-noise cleanup (binary-strings artifacts)  DONE
    Files changed: backend/analyzers/endpoint_intel.py (extract_urls_from_text only — the
      binary-path fn Android never calls; text/called-only path untouched by construction).
      - _ABUTTED_SPLIT_RE: a binary string table has no delimiters, so adjacent literals abut
        and the URL regex swallows them as one token. Split before every embedded scheme.
      - _FMT_PLACEHOLDER_RE: drop runtime-assembled HOST templates (%@, %s, %1$s, {…}, ${…}).
        Checked against the HOST ONLY — a placeholder in the PATH still has a real,
        reportable host (https://api.real.com/v1/%@/log is kept).
    Acceptance: PASS. iOS endpoints 78 -> 77 (net -1: 3 junk removed, 2 real URLs recovered).
      REMOVED: https://%@.app-analytics-services.com/a
               https://%@.app-analytics-services-att.com/a
               the 160-char abutted blob (…/legacy/batchttps://crashlyticsreports-pa…)
      RECOVERED from that blob: https://firebaselogging.googleapis.com/…/legacy/batc
                                https://crashlyticsreports-pa.googleapis.com/…/legacy/bbatc
      All 5 named domains still present; IP 192.168.161.138 still present; domain_intel 30;
      findings 82 (unchanged).
    Android diff: BYTE-IDENTICAL. endpoints 1->1, ips 0->0, findings 45->45, severity identical.
    Commit-ready: Y
    KNOWN RESIDUAL (not fixed, out of scope): the two recovered URLs keep trailing truncation
      noise from the string table ("…/legacy/batc", "…/legacy/bbatc" — the real paths are
      /batch). A binary literal has no terminator, so the tail of one string runs into the
      next. Harmless for domain/host intelligence (host is exact); only the path tail is off.
      Fixing it needs Mach-O __cstring section parsing (real string boundaries) rather than a
      printable-strings dump — worth considering if a later run touches binary strings.

[x] RUN 2 — CISO must not headline a LOW (SHARED: report_summaries.py, cross-platform)  DONE
    Files changed: backend/report/report_summaries.py (build_ciso_summary, most-critical block).
      Verified prompt fact first: lines 99-111 set most_critical from chains[0] OR the top
      ranked finding with NO severity check — CONFIRMED, both branches affected.
      Restructured to pick (top, top_sev) once — chain branch reads top["severity"], finding
      branch reads _sev_of(top) — then applies ONE guard to both: if the selected item ranks
      below HIGH, emit "No critical or high-severity issues. Most notable: <title> (<SEV>)."
      instead of presenting it as the critical issue.
    Android diff (only intended reword): NO DELTA AT ALL. InsecureShop's top item is a HIGH+
      attack chain, so the guard correctly does not fire: ciso_summary byte-identical
      (0 keys differ), most_critical unchanged ("Deep Link to WebView File Disclosure — …"),
      endpoints 1->1, ips 0->0, findings 45->45, severity identical (C1/H11/M7/L4/I22).
      The reword is available to Android but only triggers when its top item is <HIGH.
    Acceptance: PASS. iOS report (0 critical / 0 high / 0 medium; 36 low / 46 info):
      BEFORE: "Firebase Storage Bucket Reference — ilogistics-check-in.appspot.com — Exposed
               cloud storage configuration lets an attacker probe the bucket…"  (a LOW,
               presented as the Most Critical Issue)
      AFTER:  "No critical or high-severity issues. Most notable: Firebase Storage Bucket
               Reference — ilogistics-check-in.appspot.com (LOW)."
    Commit-ready: Y
    Tests: 780 passed, 11 skipped.

[x] RUN 3 — Google API key surfaces as INFO (SHARED: secret pipeline)  DONE
    Files changed: backend/analyzers/ios_analyzer.py ONLY (_extract_firebase_plist_config
      dedupe + new _secret_has_evidence helper). The shared secret pipeline (secret_intel.py,
      secret_intelligence/engine.py) was NOT modified — see below.
    Drop point found (file:line): backend/analyzers/secret_intel.py:747-748
        path, line, snippet = _evidence(secret)
        if not (path and line and snippet):
            return None   # Task 4 — no evidence, no finding.
    THE PROMPT'S PREMISE WAS WRONG. It said the key is "extracted then removed downstream"
      by visibility/status masking in process_secrets:846 / engine.annotate:510. It is not.
      Proven chain (each step verified live, not assumed):
        1. GoogleService-Info.plist is a BINARY plist. The generic scanners DO find the AIza
           value but cannot quote a source line, so they emit it with an EMPTY snippet
           (evidence_scanner: path + line=3, snippet ''; legacy common.py: no path/line/snippet).
        2. Those evidence-less copies land in results["secrets"] BEFORE the iOS Firebase
           extractor runs.
        3. _extract_firebase_plist_config then saw the value already present and SKIPPED it as
           a duplicate — so the ONE copy with real evidence (its own, with a snippet) was never
           added. Confirmed by results["scan_metrics"]["firebase_plist_secrets"] being ABSENT.
        4. process_secrets -> _build_canonical -> the evidence gate at secret_intel.py:747
           dropped all 3 evidence-less copies silently (secrets_summary.dropped_no_evidence = 3).
           They never reach suppressed_secrets, which is why the iOS report showed
           0 visible AND 0 suppressed secrets.
      FIX: the evidence gate is CORRECT ("no evidence, no finding") and was left alone. Instead
      the iOS extractor's dedupe now keeps a generic hit that HAS evidence, but REPLACES
      evidence-less duplicates that could not survive the gate anyway. iOS-only file, so the
      shared pipeline and Android are untouched by construction.
    Android diff: BYTE-IDENTICAL. InsecureShop.apk secrets 1->1 identical, suppressed_secrets
      11->11 identical, secrets_summary identical, endpoints 1->1, ips 0->0, findings 45->45,
      severity identical.
      HONEST CAVEAT: InsecureShop contains NO Firebase/AIza key, so the prompt's claim that
      "Android already shows the same AIza key as INFO" could NOT be demonstrated on this
      corpus. What IS proven is that Android's secrets output did not change at all.
    Acceptance: PASS. iOS Hardcoded Secrets table, visible secrets 0 -> 3, all INFO:
        Google API Key         AIza*******************************88rI   (= MobSF's AIzaSy…88rI)
        Google OAuth Client ID 8728****…apps.googleusercontent.com
        Firebase App ID        1:87*********************************a129
      dropped_no_evidence 3 -> 0. findings 82 -> 82 (unchanged).
    Commit-ready: Y
    Tests: 780 passed, 11 skipped.
    EVIDENCE CONFIRMED (all 3, not just the API key — none rides through on a relaxed rule):
      each carries path + line + snippet and passes the real secret_intel.py:747 gate —
      Google API Key ("API_KEY = AIzaSy…"), OAuth Client ID ("CLIENT_ID = 872846…"),
      Firebase App ID ("GOOGLE_APP_ID = 1:8728…"), all at Runner.app/GoogleService-Info.plist.
      NUANCE: line=1 is NOMINAL — a binary plist has no "line 1". The snippet is genuine
      (key-derived), but the line number is a placeholder. Same class as RUN 4's
      "offset must not render as a source line" problem — carried into RUN 4.

[x] RUN 4 — View-Code correct evidence location (iOS-only)  DONE
    Files changed:
      backend/analyzers/ios_analyzer.py            — _record_binary_format_files(): records
        every bundle file that is binary-format BY MAGIC BYTES (Mach-O magic / bplist00)
        into results["binary_evidence_files"]. Content-detected, not extension-guessed —
        an IPA's Info.plist may be XML or binary.
      backend/analyzers/evidence_selection/view.py — _is_binary_evidence() + _as_binary_evidence():
        a binary primary is re-rendered as BINARY evidence — line is ZEROED, the bogus number
        moves to string_index, artifact=True (the UI already hides View Source/View Smali for
        artifacts), language = "Mach-O Binary" | "Binary Property List".
      backend/analyzers/evidence_selection/engine.py — threads platform + binary_files into
        build_evidence_view. Both new params default to None => Android behaviour byte-identical
        by construction (gated on platform == "ios").
      frontend/.../evidence-model.js, panels.jsx, styles/workspace.css — binary-evidence panel:
        shows the matched symbol + "string #N", and an explicit note that a compiled binary has
        no source line. Source snippet <pre> is suppressed for binary primaries.
    WHAT THE "LINE" ACTUALLY WAS (verified, not assumed): code_analyzer._collect_ios_files:552-557
      does NOT read a Mach-O as source — it replaces the content with _extract_strings(raw)
      (printable runs joined by newlines). So "Runner:8731" is the INDEX OF A STRING in that
      synthetic listing. It is neither a source line NOR a byte address. The prompt asked for an
      "address"; there is no address to show without re-parsing the Mach-O, so the panel names the
      artifact honestly (symbol + string index) rather than inventing a plausible-looking offset.
      -> Candidate follow-up (NOT done): compute true __cstring byte offsets. Same root cause as
         RUN 1.1's residual path truncation. Would need Mach-O section parsing.
    Acceptance: PASS (iOS report regenerated; iOS-only run, no Android diff required).
      - 7 findings previously rendered a strings index AS A SOURCE LINE (Runner:8731 MD5,
        Runner:8620 Keychain, Runner:8732 SHA-1, FirebaseCrashlytics:7184, …). Now all
        line=0, string_index preserved, "Mach-O Binary" + binary panel, no View Source.
      - THE BINARY-PLIST CLASS (the one the human flagged): the ONLY file-resolved finding was
        "Firebase Storage Bucket Reference" at GoogleService-Info.plist:3 WITH AN EMPTY SNIPPET —
        a BINARY plist, so line 3 was a parse artifact, not a source line. Now rendered as
        "Binary Property List", line=0. This is the same class as RUN 3's nominal line=1.
      - 0 binary findings render a source line (asserted).
      - 0 findings lost a real source line without being marked binary (asserted).
      - Every binary-marked path is in the content-detected binary set (no path-heuristic
        over-reach). 81 findings marked binary = 7 strings-index + ~74 binary-hardening
        findings on framework executables (which already had line=0).
      - findings 82 -> 82, severity unchanged.
    HONEST GAP: the acceptance clause "the file-resolved finding highlights the correct line"
      has NO positive case in this app — a Flutter release IPA ships no text source, so there is
      no genuine source-line finding to highlight. The only file-resolved finding WAS the binary
      plist, now correctly binary. No line-remapping bug was found or fixed; the wrong line was
      the binary-plist artifact. Re-test this clause on an app with real Swift/ObjC source.
    Commit-ready: Y
    Tests: backend 780 passed / 11 skipped; frontend build OK; evidence-model test passed.

[x] RUN 5 — iOS app icon fallback (iOS-only)  DONE
    Files changed: backend/analyzers/ios_analyzer.py (_extract_ios_app_icon + new
      _iter_png_chunks / _is_cgbi_png / _unfilter_scanlines / _decode_cgbi_png /
      _renderable_icon_bytes; imports io + zlib).
    THE PROMPT'S PREMISE WAS WRONG — no fallback was missing.
      Prompt said: "_extract_ios_app_icon carves the icon from Assets.car, fails, no fallback.
      Add the CFBundleIcons/CFBundleIconFiles -> AppIcon*.png fallback."
      Reality: that fallback ALREADY EXISTED as step (2) of a 5-step chain (iTunesArtwork ->
      CFBundleIcons -> appiconset -> heuristic walk -> Assets.car carve LAST, not first). And
      it WORKED: the pre-change report already had icon_data, icon_path
      "AppIcon76x76@2x~ipad.png", icon_source "ipa". Adding the prompt's fallback would have
      changed NOTHING.
    ACTUAL ROOT CAUSE (found by decoding the bytes, not by reading filenames): the extracted
      icon is an APPLE CgBI PNG. Chunks were ['CgBI','IHDR','iDOT','IDAT','IDAT','IEND'] —
      Xcode rewrites every bundled PNG into this crushed form: IDAT is RAW DEFLATE (no zlib
      header), channels are byte-swapped to BGRA, alpha is premultiplied. It is NOT a standard
      PNG: Pillow fails with "broken data stream" and every browser refuses it. So icon_data
      was present but the <img> was a broken image => "no app logo renders".
    FIX: _decode_cgbi_png() reverses pngcrush exactly — raw-deflate inflate (negative wbits),
      PNG scanline un-filtering (Sub/Up/Average/Paeth), BGRA->RGBA, un-premultiply alpha, then
      re-encode a standard PNG via Pillow. Candidates are now judged BY CONTENT: every one is
      decoded and scored by real pixel dimensions (square, >=20px), and the largest that
      actually decodes wins — filename and file size are never trusted. A candidate that
      cannot be decoded is skipped instead of being emitted as a broken image.
    Acceptance: PASS (iOS report regenerated).
      BEFORE: 5715 bytes, chunks ['CgBI','IHDR','iDOT','IDAT'...], DECODES = NO (broken image)
      AFTER : 7187 bytes, chunks ['IHDR','IDAT','IEND'],           DECODES = YES, 152x152 RGBA
      Visually inspected the decoded PNG: correct teal check-in glyph (hand + checkmark),
      which also proves the BGRA swap / un-premultiply are right — a wrong channel order would
      render the teal as orange.
      findings 82 -> 82, severity unchanged.
    REGRESSION CAUGHT + FIXED DURING THE RUN: the first rewrite collapsed the Assets.car
      diagnosis into a generic "unavailable", breaking
      test_assets_car_without_png_records_reason (which asserts icon_source ==
      "assets_car_unsupported" + a note when Assets.car exists but has no carveable PNG). That
      test encodes intended behaviour — "record WHY the icon is missing" — so the distinction
      was restored rather than the test changed.
    Commit-ready: Y
    Tests: 780 passed, 11 skipped (incl. all 8 icon tests).

[x] RUN 5.1 — lift the CgBI decoder into a SHARED helper (placement only, no behaviour change)
    WHY: every PNG in a shipped iOS bundle is CgBI-crushed, so the app icon is NOT the only
      consumer — RUN 12 (Property Lists) and any future image-rendering path hit the identical
      broken-image bug. Burying the reversal inside _extract_ios_app_icon would guarantee the
      next image surface re-introduces it.
    Files changed: NEW backend/analyzers/apple_png.py (public API: PNG_SIG/PNG_END,
      is_cgbi_png, decode_cgbi_png, renderable_image_bytes, png_dimensions, iter_png_chunks,
      iter_carved_pngs, best_icon_png_from_assets_car). ios_analyzer.py now imports it and
      keeps zero private PNG helpers. NEW backend/tests/test_apple_png.py (4 tests).
      backend/tests/test_ios_report_fixes_abcd.py: one reference updated
      ios._png_dimensions -> ios.png_dimensions (pure symbol move; the assertion is unchanged).
    THE GATE TO USE: renderable_image_bytes(raw) is the ONE call every image path should make
      before shipping bytes to a report — standard PNG/JPEG passes through, CgBI is converted,
      and anything undecodable returns None so the caller picks another candidate instead of
      emitting a broken image. Never base64 raw bundle PNG bytes into a report again.
    Tests: 784 passed, 11 skipped. The new tests encode the RUN 5 lesson: one asserts the
      decoded pixel is still TEAL (0,179,179) — a missed BGRA swap decodes fine but renders
      orange, so only a pixel assertion actually proves correctness.

[x] RUN 6 — Info.plist section label + render (iOS-only)  DONE
    Files changed:
      backend/analyzers/ios_analyzer.py    — permissions now keep the developer's OWN purpose
        string from Info.plist (usage_description + reason_declared); new app_info.ats_state.
      backend/report/pdf_generator.py      — permissions table appends the declared reason when
        present. Android entries have no usage_description key => Android PDF unchanged.
      frontend workspace-registry.js       — labelByPlatform + panelLabel(); navGroups(platform).
      frontend Workspace.jsx / panels.jsx  — nav + launcher label resolve per platform.
      frontend panels2.jsx                 — iOS panel title "Info.plist & Entitlements"; usage
        descriptions rendered with the declared reason; ATS shows the true state.
    WHAT WAS ALREADY THERE (prompt partly stale): an IosApplicationConfig panel already existed,
      platform-guarded, rendering ATS + entitlements + URL schemes + permissions. The section
      BODY was never "Android-only". What was NOT platform-aware was the LABEL (registry +
      launcher) and the panel <h1> ("Application Configuration").
    ANDROID LABEL — DISCREPANCY, LEFT UNTOUCHED ON PURPOSE: the prompt/human said Android
      "stays" AndroidManifest. It does NOT say that today — Android's label is "Manifest"
      (workspace-registry.js) and its panel <h1> is "Manifest". Renaming it would be an
      unrequested Android-visible change, so Android's wording is left EXACTLY as-is (zero
      delta) and only iOS gets an override. If "AndroidManifest" is genuinely wanted, that is a
      separate one-line registry change — ask first.
    TWO CONTENT-NOT-GUESS FINDINGS (read the real Info.plist, did not assume the standard set):
      1. The 3 usage-description KEYS were already parsed, but their VALUES were thrown away:
         the report showed Beetle's static label ("Camera access") and never the developer's
         actual reason. MobSF shows the reason. Now captured verbatim.
      2. This app has NO NSAppTransportSecurity KEY AT ALL — so ats == {} was CORRECT, not a
         parsing bug. An absent key is NOT the same as false: iOS enforces ATS by default, so
         "not declared" is the SECURE state. ats_state now says which of
         default / enforced / exceptions / disabled applies, instead of implying the app
         configured something it never configured.
    Acceptance: PASS (iOS report regenerated).
      NSMicrophoneUsageDescription  HIGH   "iLogistics Check-in App dependant library use microphone"
      NSCameraUsageDescription      MEDIUM "iLogistics Check-in App uses your camera for taking photos."
      NSPhotoLibraryUsageDescription LOW   "iLogistics Check-in App uses your library for choosing photos."
      ATS state: "Not declared — ATS enforced by default (HTTPS required)."  (declared=false)
      iOS section label + panel title: "Info.plist & Entitlements". findings 82 -> 82.
    Android diff: CONTENT-IDENTICAL. endpoints 1->1, ips 0->0, findings 45->45, secrets identical,
      severity identical, NO ats_state key on Android, NO usage_description leaked into Android
      permissions. Permissions differ in ORDER ONLY — and that is PRE-EXISTING nondeterminism,
      NOT caused by RUN 6. See L3.
    Commit-ready: Y
    Tests: 784 passed, 11 skipped; frontend build OK.

[x] RUN 7 — SDK categories, no more 39×unknown (iOS-only)  DONE
    Files changed: backend/analyzers/ios_analyzer.py (_KNOWN_FRAMEWORKS extended,
      new _FRAMEWORK_PREFIXES family fallback + _classify_framework(); call site uses it).
      NEW backend/tests/test_ios_framework_categories.py (4 tests).
    Acceptance: PASS. iOS sdks/embedded_frameworks categories: unknown 39 -> 0.
      backend 7 | platform 5 | utility 5 | media 4 | analytics 4 | storage 3 | security 2 |
      network 2 | runtime 2 | logging 2 | nfc 1 | scanning 1 | webview 1
      findings 82 -> 82 (unchanged), severity unchanged.
    READ THE BUNDLE, NOT THE PROMPT (the prompt's pod list was partly wrong for this app):
      Named in the prompt but NOT PRESENT in this IPA: screen_protector, ScreenProtectorKit,
        ScreenPreventerKit, snowfinch_security_ios. Not mapped — mapping a pod that is not
        there would be inventing coverage.
      PRESENT but NOT named in the prompt: flutter_jailbreak_detection_plus,
        path_provider_foundation, shared_preferences_foundation, IOSSecuritySuite, and 8 more
        Firebase modules (Core/CoreInternal/CoreExtension/SharedSwift/Installations/
        RemoteConfig/RemoteConfigInterop/ABTesting/Sessions). All mapped from the real list.
    TWO JUDGEMENT CALLS:
      1. "App" and "Flutter" are NOT third-party SDKs — "App" is the app's OWN Dart AOT blob
         and "Flutter" is the engine. Listing them as unknown third-party dependencies
         misattributes the app's own code to a vendor. Categorised as "runtime".
      2. EVERY framework added here is severity "info" ON PURPOSE. _analyze_embedded_frameworks
         emits a FINDING for any known framework at medium/high, so assigning severities while
         categorising would have INVENTED findings about dependencies that were previously
         silent. Categorising a dependency must not create a claim about it. findings 82 -> 82
         proves it.
    "unknown" IS STILL REACHABLE (verified by test): an unrecognised pod returns "unknown" with
      known=False. A Firebase/Google module we never enumerated falls to the family prefix
      rather than "unknown", but a novel vendor pod stays honestly unknown.
    Commit-ready: Y
    Tests: 788 passed, 11 skipped.

═══════════════ TIER 2 — PARITY + DIFFERENTIATORS ═══════════════

[x] RUN 8 - Binary insecure-API + logging + malloc scan (iOS-only)  DONE
    Files changed:
      NEW backend/analyzers/binary_api_scan.py - symbol sets + match_symbols() + build_findings()
        (ONE consolidated finding per class listing matched symbols; MobSF's format).
      backend/analyzers/lief_analyzer.py - scans the FULL uncapped import list at parse time;
        records imported_syms_total / imported_syms_truncated. Mach-O ONLY (ELF path untouched).
      backend/analyzers/ios_analyzer.py - emits the 3 findings + results["binary_api_scan"];
        records lief_macho.truncated_symbol_lists.
    THE 2000 CAP *WAS* TRUNCATING - AND IT MATTERED (why the prompt's "use imported_syms" fails):
      webview_flutter_wkwebview imports 2432 symbols; only 2000 were kept. _fopen, _malloc,
      _sscanf, _strlen appear ONLY PAST INDEX 2000 in that framework - scanning the capped field
      would have MISSED ALL FOUR. The scan runs against the full uncapped list at parse time; the
      cap is kept for display and truncation is now recorded, never silent.
    Acceptance part 1 - FINDINGS SHOWN: PASS. findings 82 -> 85 (+3, all real; each traced to a
      symbol genuinely in the import table; confidence 95, evidence_type "imported_symbol").
        Binary Imports Insecure C APIs         10 symbols, 29 binaries  CWE-676/M7/MASVS-CODE-8
          _fopen _memcpy _printf _sprintf _sscanf _strcat _strcpy _strlen _strncpy _vsnprintf
        Binary Imports Uncontrolled Allocation  _malloc, 27 binaries    CWE-789/M7/MASVS-CODE-8
        Binary Imports Logging API (NSLog)      _NSLog,   6 binaries    CWE-532/M9/MASVS-STORAGE-3
    MobSF CROSS-CHECK: MATCHED AND EXCEEDED. Every MobSF symbol found (_fopen _memcpy _printf
      _sscanf _strlen _strncpy _vsnprintf / _NSLog / _malloc), NOTHING missed, plus 3 that MobSF
      MISSED: _sprintf, _strcat, _strcpy.
    Acceptance part 2 - "MASVS-CODE moves off 0/100": NOT ACHIEVED, AND THE CLAUSE IS BACKWARDS.
      masvs_intel.build_coverage:159-163 => score = (controls_present/expected)*60 + (40 - penalty).
      FINDINGS ARE PENALTIES, NOT CONTROLS. MASVS-CODE was ALREADY 0 before RUN 8 (0 controls
      detected, 74 category findings, penalty already capped at 40). Adding 3 more findings can
      only hold it at 0 - it can never raise it. Moving MASVS-CODE off 0 requires DETECTING
      CONTROLS ("Safe Input Handling", "Up-to-date Dependencies") in _detect_controls - a
      different feature. NOT hand-tuned: CLAUDE.md forbids tuning to hit a number, and score
      realism is RUN 15's job.
    Android diff: CONTENT-IDENTICAL (guard applied per METHODOLOGY). endpoints 1->1, ips 0->0,
      secrets identical, severity identical (C1/H11/M7/L4/I22), permissions content-identical,
      finding identities identical, NO binary_api_scan key and NO api_scan on any ELF binary.
      Residual byte deltas = a scan timestamp + the L4 rejected-candidate jitter, PROVEN
      pre-existing by scanning the same APK twice on the same build.
    DECISION 1 - RESOLVED (human approved): import-table evidence exempted from the
      compiled-binary demotion, narrowly and with a locking test.
      TWO REAL BUGS were behind the INFO severity, and the first one was NOT where I first
      looked (_match_ios_binary was never even reached):
        BUG A - ownership/engine.py:296 synthesises "/Pods/<stem>/" for ANY bare, extension-less
          iOS filename. So file_path "Runner" - the app's OWN main executable - matched the
          embedded_framework rule and was classified ThirdPartySDK. FIX: attribute with the full
          bundle-relative path ("Payload/Runner.app/Runner"), which the iOS app-bundle stage then
          correctly classifies as APPLICATION.
        BUG B - the demotion is NOT in the ownership engine at all: finding_model.
          demote_library_noise:936-963 demotes any library-owned finding whose rule_id starts with
          "ios_" to INFO. With ownership fixed to APPLICATION, it no longer fires for these.
      THE EXEMPTION (ownership/engine.py): sig now carries evidence_type, and _match_ios_binary
      returns None for evidence_type == "imported_symbol" only - a one-member frozenset
      (_AUTHORITATIVE_BINARY_EVIDENCE), NOT "any high-confidence binary finding". An import-table
      entry proves the binary LINKS that function; it is a structural fact, not the offset-only
      string-table coincidence the guard exists to suppress.
      LOCKING TEST: backend/tests/test_ios_binary_evidence_ownership.py (6 tests), BOTH directions:
        (a) imported_symbol on a compiled Mach-O stays app-owned / not demoted;
        (b) the Dart-AOT FP class is STILL demoted - missing canary + ARC on App.framework/App,
            libapp.so, AND the RUN 4 string-index class (code_pattern on a Mach-O) - plus an
            explicit test that the exemption is keyed on evidence KIND, never on confidence.
            If anyone widens the exemption, direction (b) fails. RUN 9/15 guard is protected.
    VERIFIED ON THE REGENERATED iOS REPORT:
      Binary Imports Insecure C APIs         MEDIUM  owner=Application  library_noise=False
      Binary Imports Uncontrolled Allocation MEDIUM  owner=Application  library_noise=False
      Binary Imports Logging API (NSLog)     INFO    owner=Application  (correctly stays INFO)
      findings still 85; severity 0/0/2/36/47. FP GUARD INTACT: 0 HIGH and 0 CRITICAL findings
      in the whole report - the Dart-AOT class is not inflated.
    Android: CONTENT-IDENTICAL (timestamps masked, set-derived fields order-insensitive).
      endpoints/ips/secrets identical, severity identical, finding identities identical,
      permissions content-identical, and library_noise demotions unchanged at 13 = 13 (proving
      the ownership change did not leak into Android's demotion behaviour).
    DECISION 2 - RESOLVED: the MASVS-CODE clause is unachievable as written and was NOT faked.
      Findings are PENALTIES, not controls (build_coverage:159-163). Superseded by RUN 8.1, which
      implements real control DETECTION. Must land before RUN 15.
    Commit-ready: Y
    Tests: 794 passed, 11 skipped (incl. the 6 new ownership FP-guard tests).

[x] RUN 8.1 - MASVS control DETECTION (iOS-only)  DONE - BUT THE PREMISE WAS LARGELY FALSE
    THE PREMISE WAS WRONG: control detection ALREADY EXISTED AND ALREADY WORKED.
      Checked the reports generated BEFORE any masvs_intel edit (RUN 6, RUN 7, RUN 8):
        MASVS-RESILIENCE = 60, controls_present = ['Root/Tamper Detection']   <- already there
        MASVS-STORAGE    = 67, controls_present = ['Encrypted Storage']       <- already there
      IOSSecuritySuite was already being credited (via the security_controls authority) and
      Encrypted Storage was already credited (via a kSecAttrAccessible snippet in the corpus).
      So the controls the human named as examples were NOT missing.
    WHAT I ACTUALLY CHANGED (masvs_intel._SIGNALS): broadened the EVIDENCE for two controls so
      they are credited from the pod name alone, for apps that do not happen to carry the
      snippet signal this app carries:
        Root/Tamper Detection <- iossecuritysuite, flutter_jailbreak_detection, jailbreakdetection
        Encrypted Storage     <- flutter_secure_storage (Keychain-backed by construction)
      Evidence route: results["sdks"] (populated by RUN 7 from the REAL Frameworks/ directory)
      feeds security_controls.positive_corpus, so a control is credited only when the framework
      binary is PHYSICALLY IN THE BUNDLE. Never assumed.
      HONEST DELTA ON THIS APP: ZERO. Scores unchanged (RESILIENCE 60, STORAGE 67, overall 43).
      The additions are redundant here and only broaden coverage for other apps.
    MASVS-CODE IS STILL 0 - AND THAT IS THE CORRECT ANSWER, NOT A GAP:
      Its two controls are "Safe Input Handling" and "Up-to-date Dependencies".
        Safe Input Handling  -> GENUINELY ABSENT. RUN 8 proved this app imports _strcpy, _strcat,
          _sprintf, _sscanf, _gets-class APIs. Crediting the control would contradict Beetle's
          own finding.
        Up-to-date Dependencies -> CANNOT be claimed yet. The only available signal is "the CVE
          scan found nothing", which is ABSENCE OF EVIDENCE, not evidence of absence. RUN 14 is
          the run that verifies OSV/CVE coverage is real; until it does, crediting this control
          would be exactly the score-inflation the guard forbids.
      So MASVS-CODE = 0 is a true statement about this app. NOT tuned, NOT faked.
    GUARD + TESTS: backend/tests/test_masvs_control_detection.py (6 tests) locks the discipline -
      a control with NO evidence stays ABSENT; an empty app is credited with NO controls at all;
      and a control's score lift must come from the CONTROL term, not from dropping penalties.
    Files changed: backend/analyzers/masvs_intel.py (_SIGNALS only);
      NEW backend/tests/test_masvs_control_detection.py.
    Android diff: CONTENT-IDENTICAL. endpoints/ips/secrets identical, severity identical, finding
      identities identical, and MASVS coverage (scores + controls_present) BYTE-IDENTICAL - the
      new patterns are iOS pod names, which an Android corpus can never contain.
    Commit-ready: Y
    Tests: 800 passed, 11 skipped.
    -> RUN 15 (score calibration) now has a WORKING control signal to calibrate against, and a
       documented reason why MASVS-CODE legitimately reads 0 for this app.

[x] RUN 9 - Per-binary protection table (iOS-only) - FP GUARD on App.framework/App  DONE
    Files changed:
      NEW backend/analyzers/binary_protections.py - build_table() + build_findings() with the
        two suppression classes; NEW backend/tests/test_binary_protections.py (8 tests).
      backend/analyzers/lief_analyzer.py - _protection_flags(): per-binary canary / ARC /
        objc_import_count / encrypted / symbols_stripped / is_dart_aot, from the FULL symbol
        tables at parse time. Mach-O only (ELF untouched).
      backend/analyzers/ios_analyzer.py - results["binary_protections"] (table) +
        results["binary_protections_suppressed"] (what was suppressed AND WHY) + findings.
    THE TABLE: 40 rows, main executable FIRST then frameworks alphabetically. Columns: kind, NX,
      PIE (main only - a dylib is position-independent by definition, so "no PIE" on a framework
      is noise), Stack Canary, ARC, Code Signature, Encrypted, Symbols Stripped, RPATH count,
      and the RUN 8 insecure-API count.
    THE FP GUARD - VERIFIED IN THE REGENERATED REPORT:
      App.framework/App  kind="Dart AOT (app code)"  canary=N  arc=N  objc_imports=0
      -> findings referencing App.framework/App: 0
      -> report contains ZERO HIGH and ZERO CRITICAL findings
      -> suppressed WITH A REASON (not silently dropped), recorded in the report itself.
    DART-AOT DETECTED BY CONTENT, NOT BY FILENAME: keyed on the exported snapshot symbols
      (_kDartVmSnapshotInstructions / _kDartIsolateSnapshotInstructions / ...Data). This matters:
      Flutter.framework/Flutter exports ObjC classes named FlutterDartProject, so a naive "Dart"
      SUBSTRING match would have suppressed a REAL native framework. Test locks this.
    SECOND FP CLASS FOUND (not in the prompt): ARC is the Objective-C runtime, so a binary with
      ZERO ObjC imports (nanopb, FirebaseCoreExtension) CANNOT have ARC - "missing ARC" is a
      meaningless claim about a pure C/Swift library. Suppressed with reason. MobSF flags both
      as HIGH; both are false positives.
    MobSF CROSS-CHECK - MobSF's 8 missing-canary HIGHs and 3 missing-ARC HIGHs, adjudicated:
      CANARY:
        connectivity_plus            CONFIRMED missing (genuine native ObjC framework) -> flagged
        battery_plus                 CONFIRMED missing -> flagged
        FirebaseRemoteConfigInterop  CONFIRMED missing -> flagged
        FirebaseCoreExtension        CONFIRMED missing -> flagged
        flutter_timezone             CONFIRMED missing -> flagged
        App                          MobSF FALSE POSITIVE - Dart AOT blob. SUPPRESSED.
        nanopb                       MobSF FALSE POSITIVE - the canary IS present (it imports
                                     ___stack_chk_fail). Beetle says present; MobSF is wrong.
        ScreenProtectorKit           NOT IN THIS BUNDLE AT ALL - MobSF flagged a framework this
                                     app does not ship (same error class as RUN 7's pod list).
      ARC:
        App                          MobSF FALSE POSITIVE - Dart AOT. SUPPRESSED.
        FirebaseCoreExtension        MobSF FALSE POSITIVE - 0 ObjC imports, ARC N/A. SUPPRESSED.
        nanopb                       MobSF FALSE POSITIVE - 0 ObjC imports, ARC N/A. SUPPRESSED.
        => Beetle emits NO missing-ARC finding at all: not one binary in this app is a genuine
           ObjC framework that lacks ARC. All 3 of MobSF's ARC HIGHs are FPs.
      BEETLE FOUND 2 THAT MobSF MISSED: flutter_jailbreak_detection_plus, path_provider_foundation
        (both genuinely lack a stack canary).
    Acceptance: PASS. Table renders (40 rows); NO HIGH FP on App.framework/App (no finding at all).
      findings 85 -> 86 (+1: ONE consolidated missing-canary finding naming 7 binaries - not one
      finding per binary, per RUN 8's lesson). severity 0/0/3/36/47.
    SEVERITY IS OWNERSHIP-BASED (refined on human review; keyed off the Ownership Engine field
      RUN 8 fixed, NOT a new heuristic):
        MEDIUM - missing protection in a VENDOR/third-party framework (someone else's code; a
                 real hardening gap but not a directly exploitable app weakness). MobSF calls
                 these HIGH, which overstates them.
        HIGH   - missing protection in the APP'S OWN native code (owner == APPLICATION and NOT
                 the Dart-AOT blob): the app shipped unhardened native code and owns the fix.
      NO OUTPUT CHANGE FOR THIS APP (verified): every flagged binary is a vendor framework, and
      Runner has both canary and ARC, so there is nothing app-owned to flag. findings 86 -> 86,
      severity identical (0 crit / 0 HIGH / 3 med / 36 low / 47 info), same consolidated
      missing-canary finding naming the same 7 vendor binaries. The report still carries ZERO
      HIGHs - every one of MobSF's 11 HIGHs here is either an FP (5) or an overstatement (6).
    A DEAD-CODE BUG CAUGHT WHILE DOING THIS (would have silently broken rule (b)): in the LIVE
      pipeline the main binary Runner classified as OpenSourceLibrary, not APPLICATION, because
      RUN 8's exemption only covered evidence_type == "imported_symbol" - so a protection-flag
      finding on a compiled Mach-O was still demoted, and the HIGH branch could NEVER have fired.
      The unit test passed only because it stubbed the owner lookup. FIX: added
      "binary_protection" to _AUTHORITATIVE_BINARY_EVIDENCE - both members are STRUCTURAL FACTS
      read out of the Mach-O (import table / load commands + symbol table), not the offset-only
      string-table coincidence the demotion suppresses. Still keyed on evidence KIND, never on
      confidence: the RUN 4 string-index class (code_pattern in a Mach-O) is STILL demoted, and
      test_exemption_is_narrow_not_confidence_based still locks that. Safe for the Dart-AOT class
      because that is suppressed BY CONTENT one layer earlier, so no App.framework/App finding
      exists to be re-promoted. Two new tests assert Runner -> APPLICATION and
      connectivity_plus -> library through the REAL engine (not a stub).
    Tests locking severity from BOTH sides (as with the RUN 8 exemption):
      (a) vendor-framework missing protection is MEDIUM and never HIGH;
      (b) an app-own NATIVE binary (owner==APPLICATION, non-Dart-AOT) missing a canary IS HIGH
          (synthetic fixture - this app ships no such binary);
      plus: Dart-AOT is never promoted to HIGH even though it IS the app's own code, because it
      is a Dart snapshot, not clang-compiled native code.
    Android diff: CONTENT-IDENTICAL. endpoints/ips/secrets identical, severity identical
      (C1/H11/M7/L4/I22), finding identities identical (45->45), permissions content-identical,
      MASVS coverage identical, no binary_protections key and no macho_* findings on Android.
    Commit-ready: Y
    Tests: 808 passed, 11 skipped (incl. 8 new FP-guard tests, from the PROTECTION-FLAG angle -
      complementing RUN 8's import-symbol angle on the same guard).

[x] RUN 10 - Dedicated ATS section (iOS-only)  DONE
    Files changed:
      backend/analyzers/ios_analyzer.py - ats_state extended: global_flags (all four ATS keys,
        each named with its own severity + meaning), per-exception-domain rows, enforced flag,
        posture string.
      frontend workspace-registry.js - NEW iOS-ONLY panel { id: 'ats', platforms: ['ios'] } +
        panelAppliesTo(); panels2.jsx - NEW AtsPanel; Workspace.jsx - route; workspace.css.
      NEW backend/tests/test_ios_ats_section.py (7 tests).
    THE POINT OF THIS SECTION (carried from RUN 6): iOS enforces ATS BY DEFAULT, so an app that
      never declares NSAppTransportSecurity is in the SECURE state, not an unconfigured one.
      MobSF shows an EMPTY TABLE here, which reads like a gap when it is the opposite. Beetle
      states the posture plainly: "ATS enforced" with a green verdict card.
    Acceptance: PASS (iOS report regenerated).
      posture  = "ATS enforced"   enforced = True   declared = False   state = "default"
      summary  = "Not declared - ATS enforced by default (HTTPS required)."
      Global Settings: all four keys listed, each "not set" + what that means:
        NSAllowsArbitraryLoads / ...InWebContent / ...ForMedia / NSAllowsLocalNetworking
      Exception Domains: 0 - "none declared; every connection must satisfy ATS"
      findings 86 -> 86 UNCHANGED - the ATS section is a SURFACE, not a new finding.
    GRADED, NOT COLLAPSED: a WebContent/Media relaxation is NOT reported as "ATS disabled" - it
      is narrower (the app's own requests stay protected), so it is MEDIUM and named
      individually. The report says WHICH door is open. Per-domain severity is keyed on what the
      exception actually relaxes: cleartext HTTP -> HIGH; TLS floor lowered to 1.0/1.1 -> MEDIUM;
      forward secrecy disabled -> MEDIUM; exception that relaxes nothing -> INFO. Worst domain
      listed first. All locked by tests.
    Android: UNAFFECTED BY CONSTRUCTION - the ATS panel is registry-gated to platforms:['ios'].
      Verified against the real registry: ATS visible on iOS = true, on Android = false, and the
      rest of Android's nav is unchanged (ATS is an Info.plist concept; Android's counterpart is
      the Network Security Config, already in the Network panel).
    Commit-ready: Y
    Tests: 820 passed, 11 skipped.

[x] RUN 11 - iOS tracker detection  DONE  ("one-line wire-up" -> it was NOT one line)
    THE PREMISE WAS FALSE. detect_trackers(package_names) matches TRACKER_SIGNATURES with
      `p.startswith(pkg)`, and ALL 73 signatures are ANDROID PACKAGE PREFIXES
      ("com.google.firebase.crashlytics"). An iOS app has no Java packages. Passing pod names to
      it matches NOTHING - locked by test_android_detector_cannot_see_ios_pods. iOS needed its
      own identifier path.
    Files changed: backend/analyzers/tracker_db.py (IOS_TRACKER_SIGNATURES, detect_trackers_ios,
      ios_tracker_markers - all ADDITIVE; Android's detect_trackers untouched);
      backend/analyzers/ios_analyzer.py (marker capture in the existing binary string walk +
      the call, placed AFTER _analyze_embedded_frameworks);
      NEW backend/tests/test_ios_tracker_detection.py (10 tests).
    THREE EVIDENCE SIGNALS, never an inference:
      pods    - a framework physically in the bundle (RUN 7's real Frameworks/ walk)
      domains - an endpoint the app actually contains (RUN 1)
      markers - a string statically linked into a Mach-O (reuses RUN 8's string walk; no extra pass)
      A tracker with NO matching evidence is not reported (test_tracker_with_no_evidence...).
    THE MARKER SIGNAL IS NOT OPTIONAL: Firebase Analytics ships NO framework in this app - it is
      linked straight into Runner (35 "FirebaseAnalytics" + 9 "GoogleAppMeasurement" strings). A
      framework-only check reports it ABSENT. 3 of the 9 trackers are statically linked and
      would have been missed by a pod-only check.
    ORDERING BUG CAUGHT AND FIXED: the call was initially placed BEFORE
      _analyze_embedded_frameworks (which is what populates results["sdks"]), so the pod list was
      EMPTY and every tracker fell back to marker evidence - FirebaseCrashlytics, which plainly
      ships FirebaseCrashlytics.framework, was reported as "statically linked, no framework".
      Moved after it; regression test added. (Same class as the RUN 9 stub-hid-the-bug lesson:
      the unit tests passed while the live report was wrong.)
    Acceptance: PASS AND EXCEEDED. iOS trackers 0 -> 9 (MobSF found 2).
      framework-backed (6): Crashlytics, Performance Monitoring, Remote Config, A/B Testing,
        Sessions, DataTransport
      statically linked (3): Firebase Analytics, Google Ads On-Device Conversion,
        Apple AdServices (Attribution)
      Crashlytics MATCHED (MobSF parity). 7 trackers MobSF MISSED.
    AdMob - MobSF SAYS YES, BEETLE SAYS NO, AND BEETLE IS RIGHT: this app ships NO
      GoogleMobileAds framework and NO GADMobileAds symbol in any binary. The only "admob" string
      is an `admob_app_id` KEY inside GoogleAppMeasurement - attribution plumbing, not the
      ad-serving SDK. Beetle reports what is ACTUALLY there instead: "Google Ads On-Device
      Conversion" (GoogleAdsOnDeviceConversion symbol + googleadservices.com +
      odm.app-ads-services.com endpoints). Two tests lock this: AdMob is NOT claimed from
      Firebase evidence, and IS reported when the real GoogleMobileAds SDK is present.
    findings 86 -> 86 (trackers are intelligence, not findings). severity unchanged.
    Android diff: CONTENT-IDENTICAL. trackers 0 -> 0 identical, endpoints/ips/secrets identical,
      severity identical, finding identities identical. detect_trackers() and its 73 signatures
      were not touched; the iOS path is a separate additive function.
    UI: no registry work needed - the existing panel already renders results["trackers"]
      platform-neutrally, so populating it was enough.
    Commit-ready: Y
    Tests: 830 passed, 11 skipped.

[x] RUN 12 - Property Lists section (iOS-only)  DONE
    Files changed: NEW backend/analyzers/ios_plists.py; ios_analyzer.py (one call);
      frontend workspace-registry.js (iOS-gated panel), panels2.jsx (PropertyListsPanel),
      Workspace.jsx (route); NEW backend/tests/test_ios_plists.py (9 tests).
    Acceptance: PASS. 95 property lists enumerated (69 .plist + 26 .xcprivacy):
      67 BINARY (bplist00) / 28 XML - ALL decoded via plistlib, ZERO unreadable, ZERO text reads.
      findings 86 -> 86 UNCHANGED, severity unchanged (enumeration surface, not a detector).
    RULE 1 - plistlib everywhere: 67 of 69 plists are BINARY. RUN 3 and RUN 4 both traced real
      bugs to binary plists treated as text (empty snippet -> the Firebase key was silently
      dropped; a "line 3" that does not exist). One read path, no garbage.
    RULE 2 - raw bytes NEVER emitted: a data value is summarised ("<data: N bytes>") and anything
      image-like goes through RUN 5.1's renderable_image_bytes() gate, so a CgBI PNG can never
      reach a report as a broken image. This bundle happens to carry ZERO data-bearing plists, so
      the guard is locked by TEST (a synthetic CgBI PNG in a plist) rather than by luck.
    RULE 3 - cross-links, does not re-report: ATS -> RUN 10's section; Firebase API_KEY/CLIENT_ID/
      GOOGLE_APP_ID -> already INFO secrets from RUN 3; usage descriptions -> RUN 6. No findings.
    *** SECRET LEAK CAUGHT AND FIXED (found only in the REGENERATED report, 4th time) ***
      The first cut printed the Firebase API key IN PLAINTEXT
      ("AIzaSyCw2rXeRTyaNxZ3cBm3gUip5sfZ1fW88rI"). RUN 3 deliberately MASKS it, and
      secret_intel's cross-scrub only purges raw values from the secrets it knows about - it has
      never heard of results["property_lists"]. Enumerating a plist had become a way to leak the
      exact secret the rest of the pipeline is careful to mask.
      FIX: credential-valued keys are masked with secret_intel.mask_value (ONE masking
      implementation, not a second that drifts). Verified in the live report:
        API_KEY = AIza*******************************88rI   (matches RUN 3 exactly)
      and the raw key appears NOWHERE in the entire report. Locked by test.
    BONUS SURFACE (not in the prompt): 26 Apple PRIVACY MANIFESTS (PrivacyInfo.xcprivacy) rolled
      up - declares_tracking=false, tracking domains: NONE declared, accessed API categories
      (UserDefaults 6x, FileTimestamp 3x, DiskSpace 1x, SystemBootTime 1x), collected data types
      (OtherDiagnosticData 4x, CrashData 1x). MobSF does not show this at all.
    HONEST "ABSENT" REPORTING (RUN 10 discipline): NSAppTransportSecurity, CFBundleURLTypes/
      CFBundleURLSchemes, LSApplicationQueriesSchemes, NSUserTrackingUsageDescription and
      UIFileSharingEnabled are ALL GENUINELY ABSENT from this bundle. The section says so rather
      than implying a gap. The ONLY plist with security keys is GoogleService-Info.plist.
[x] RUN 12.1 - privacy-declaration discrepancy finding (HUMAN-APPROVED; findings 86 -> 87)
    THE FINDING IS AN INTERSECTION OF TWO INDEPENDENT EVIDENCE CHAINS, and says so explicitly:
      PRESENCE (RUN 11): 4 tracking SDKs proven in the app - Apple AdServices, Google Ads
        On-Device Conversion, Firebase Analytics, Firebase Sessions - each with its evidence
        kinds cited (binary_symbol / endpoint / framework).
      ABSENCE (RUN 12): across all 95 property lists and 26 privacy manifests, NOT ONE declares
        NSPrivacyTracking, any NSPrivacyTrackingDomains entry, or NSUserTrackingUsageDescription
        (so the app shows no ATT prompt).
    SEVERITY MEDIUM, WORDED AS A DISCREPANCY FOR REVIEW - NOT A VIOLATION. The text says so in
      capitals: on-device conversion measurement and AdServices attribution are arguably NOT
      "tracking" under Apple's ATT definition, so a prompt may not be strictly required.
      Asserting HIGH/violation would be the SAME OVERCLAIM Beetle refused to copy on MobSF's
      AdMob (RUN 11). Consistency matters more than a scary number.
    owner_type = Application (the app's own config, not vendor code) -> per RUN 9's
      ownership-based severity it is a real app-owned finding, and library_noise did NOT demote it.
    Verified in the regenerated report: findings 86 -> 87, severity 0/0/4/36/47, the discrepancy
      is the ONLY delta, and the report still carries 0 HIGH / 0 CRITICAL.
    ORDERING TRAP HIT AGAIN (same class as RUN 11): the check first ran inside the plist block,
      which executes BEFORE tracker detection - so results["trackers"] was empty and the finding
      never fired, while all 14 unit tests stayed green. Caught by the regenerated report (5th
      time). Moved to after BOTH chains exist.
    Tests: 5 more, both directions - trackers-present + declarations-absent -> emitted;
      no-tracking-SDKs / declares_tracking / tracking_domains / ATT-string-present -> NOT emitted.
    Tests: 844 passed, 11 skipped.
    Android: registry-gated to platforms:['ios'] - verified against the real registry (visible on
      iOS = true, Android = false). property_lists key absent on Android; endpoints/ips/secrets/
      severity/finding-identities all identical.
    Commit-ready: Y
    Tests: 839 passed, 11 skipped.

[x] RUN 13 - Strings section + email FP filter (SHARED: both platforms)  DONE
    Files changed: NEW backend/analyzers/strings_section.py (shared by both analyzers);
      ios_analyzer.py (binary email harvest in the existing string walk + section);
      android_analyzer.py (section); frontend registry/panels2/Workspace (Strings panel, BOTH
      platforms - no gate); NEW backend/tests/test_strings_section.py (12 tests).
    *** THE SECRET GATE (the RUN 12 lesson, one level worse) ***
      This is the highest secret-leak-risk surface in the product: it shows the STRINGS
      THEMSELVES. Every value passes strings_section.redact() BEFORE it can reach the report.
      TWO triggers, because one was not enough:
        1. the secret CATALOG matches the value (scan_text_for_secrets) -> mask via
           secret_intel.mask_value (the SAME masking the secrets table uses - one impl);
        2. the value sits in a category that IS a credential class ("Base64 Encoded String
           (Potential Secret)"). CAUGHT IN THE REGENERATED REPORT: the first cut printed all 10
           of those base64 blobs RAW (masked_count = 0) because the catalog does not match a bare
           base64 blob. The section was literally saying "this may be a secret" and then showing
           it. Now masked_count = 10, and the raw blob appears nowhere.
      Verified: no raw Firebase key anywhere in the report; no raw base64 candidate in the section.
    EMAIL FP FILTER - MobSF's ~95% garbage, quantified: the raw regex yields 48 hits on this app;
      47 are dropped, 1 real address survives.
        DROPPED: 44 Dart runtime symbols (_AnonymousRestorationInformation@133124995.
          fromSerializableData) - already killed by string_analyzer._is_real_email;
          2 format-string hosts (%@.app-analytics-services.com) - RUN 1.1's class, needed a new
          rule because the local part is bare "%";
          1 library-internal address (appro@openssl.org) - real, but OpenSSL's, not the app's.
        KEPT: service.coord@cvx.com - the one genuine address (MobSF found it too, buried in
          95% noise). VERIFIED against the bundle: it lives in the Dart AOT blob App.framework/App.
    iOS section: 3 categories / 34 matches / 10 masked / 77 URLs / 1 IP + the emails.
    Android diff (SHARED FILE - methodology applied: timestamps masked, set-derived fields
      order-insensitive): endpoints / ips / secrets / string_analysis / severity_summary all
      IDENTICAL; finding identities identical (45 -> 45); permissions content-identical.
      INTENDED DELTA (the prompt asks for both platforms): Android GAINS results["strings"]
      (10 categories, 28 matches, 0 masked, 0 emails). Its existing fields are untouched.
    findings 87 -> 87 (surface, not a detector). severity 0/0/4/36/47.
    *** BUG CAUGHT BY THE REGENERATED REPORT (6th time) ***: my inserted block dedented, so the
      privacy-discrepancy check ended up nested INSIDE the strings block's `except` handler - it
      only ran if the strings section THREW. It did not throw, so the RUN 12.1 finding silently
      VANISHED (87 -> 86) while all 854 tests stayed green. Fixed the block structure; findings
      back to 87. A unit test could not have caught this: the code was live-reachable only on an
      exception path.
    Commit-ready: Y
    Tests: 856 passed, 11 skipped.

[x] RUN 14 - Vulnerable components VERIFY (SHARED: cve_mapper)  DONE
    *** THE ANSWER IS NO: "39 detected / 0 CVEs" WAS AN EMPTY PASS. ***
    PROVEN, not assumed, by a live experiment from inside the container:
      1. THE SCANNER WORKS. OSV.dev is reachable and returns REAL advisories:
           npm  lodash@4.17.15  -> 6 vulns
           PyPI django@2.2.0    -> 65 vulns
           Pub  http@0.13.0     -> 1 vuln
         So the pipeline is not dead and the network is not blocked.
      2. BUT OSV HAS NO CocoaPods ECOSYSTEM. Every CocoaPods query returns 0 - including
         Alamofire@4.0.0. ALL 39 of this app's dependencies are CocoaPods, so all 39 queries
         return empty BY CONSTRUCTION. The zero was structural, not a real negative.
      3. AND 17 OF THE 39 VERSIONS ARE PLACEHOLDERS. A Flutter plugin's framework Info.plist
         carries CFBundleShortVersionString "0.0.1" (not its real pub version), so even in a
         SUPPORTED ecosystem those 17 could never match an advisory.
    WHAT I BUILT (not a fix for OSV's ecosystem list - an honest instrument):
      cve_mapper.assess_coverage() + ecosystem_answers() - a CANARY test. Rather than trust a
      hardcoded ecosystem list (which drifts, and which I would be asserting from memory), it
      queries a KNOWN-VULNERABLE canary per ecosystem AT SCAN TIME. If the canary comes back
      empty, that ecosystem is not answering and its components are marked UNASSESSABLE. The
      scanner now reports whether it COULD have found something, not just that it didn't.
    IN THE REGENERATED iOS REPORT:
      cve_stats.cves_assessable = FALSE
      coverage.verdict = "no_coverage" | components_total 39 | assessable 0 | UNASSESSABLE 39
        | placeholder_versions 17
      ecosystem CocoaPods: osv_answers = False, reason = "OSV returned no advisories for a
        known-vulnerable canary ... a zero result here is NOT a clean bill of health."
    RUN 8.1's DEFERRED QUESTION, NOW ANSWERED: "Up-to-date Dependencies" STAYS UNCREDITED.
      MASVS-CODE remains 0, controls_present []. Coverage is 'no_coverage', so crediting the
      control would be exactly the "absence of evidence = evidence of absence" error RUN 8.1
      forbade. VERIFIED in the live report, not just asserted.
    POSITIVE CONTROL LOCKED BY TEST: inject a package@version with a known advisory and the
      scanner MUST flag it (test_the_scanner_is_not_dead_it_flags_a_known_vulnerable_package).
      So a future zero is a real zero, not a broken pipeline. Plus tests that an
      ecosystem-that-answers makes real versions assessable, and that a placeholder version is
      NEVER assessable even in a supported ecosystem.
    HONEST STANDING vs MobSF: MobSF has NO dependency analysis at all, so Beetle's 39 detected
      components (with real versions for 22 of them) is still a win. But the CVE result must be
      read as "not assessable", NOT as "no known vulnerabilities" - and the report now says so.
    FUTURE WORK (not done, out of scope): real coverage for iOS deps needs either (a) an OSV
      ecosystem that covers CocoaPods/SwiftPM, or (b) resolving Flutter plugin pods to their PUB
      package + real version (OSV's Pub ecosystem DOES answer - proven above), which needs a
      version source better than the framework Info.plist.
    (b) App Store metadata: SKIPPED - explicitly optional/low-priority, and it would add a
      network dependency and scope for no security value.
    Android diff (SHARED FILE): endpoints / ips / secrets / components / cve_stats / severity /
      finding identities ALL IDENTICAL. Android's cve_mapper path (native .so libs) is untouched;
      assess_coverage is called only from the iOS analyzer.
    findings 87 -> 87. severity unchanged.
    Commit-ready: Y
    Tests: 861 passed, 11 skipped.

═══════════════ TIER 3 — SCORE CALIBRATION ═══════════════

[x] RUN 15 - Score model realism (SHARED: scoring/lief) - FP GUARD  DONE  -> iOS 89/100 grade B
    I CHANGED NO WEIGHTS, NO CAPS, NO GRADE BANDS. The score is an OUTPUT. The only change was
    removing two FALSE-POSITIVE CLASSES, both keyed on the Mach-O FILE TYPE (content, not path -
    the RUN 9 discipline):
      macho_no_pie x39      - emitted at INFO on EVERY framework, with a description that
        literally said "expected and not a hardening gap". A finding that says it is not a
        problem is not a finding. MH_PIE applies ONLY to the main executable image; a dylib
        relocates regardless. SUPPRESSED (recorded, auditable).
      macho_multiple_rpaths x35 -> x1 - one row per vendor framework. @executable_path/
        @loader_path RPATHs are exactly what Xcode emits for a bundled framework. The
        dylib-hijacking surface that matters is the MAIN EXECUTABLE's search path, which is
        still assessed (Runner keeps its LOW). SUPPRESSED for libraries.
    FINDINGS 87 -> 14. 74 of the 87 were noise. THAT is the real result.
    THE LEDGER (every point traced to a real finding):
      MEDIUM x4 = 12 raw -> CAPPED at 9 -> DEDUCTED 9
        - Tracking SDKs Present but Not Declared   Info.plist            [Application]  (RUN 12.1)
        - Framework Binaries Without Stack Canary  FirebaseCoreExtension [GoogleSDK]    (RUN 9)
        - Binary Imports Insecure C APIs           Runner                [Application]  (RUN 8)
        - Binary Imports Uncontrolled Allocation   Runner                [Application]  (RUN 8)
      LOW x2 = 2 raw -> DEDUCTED 2 (uncapped)
        - Firebase Storage Bucket Reference        GoogleService-Info.plist [Application]
        - Multiple @-Relative RPATHs Set (2)       Runner (main executable only)
      SECRETS 0 (the 3 Firebase keys are INFO client keys -> weight 0). CHAINS 0. BONUSES +0.
      TOTAL DEDUCTED 11  =>  SCORE 100 - 11 = 89  (grade B "Good")
    FP GUARD HOLDS: ZERO deductions trace to App.framework/App (Dart-AOT canary/ARC) or to a
      string-index (RUN 4) finding. Suppressions recorded and auditable in lief_macho.
      suppressed_rules: macho_no_pie x39, macho_multiple_rpaths x34; binary-protection
      suppressions: canary x1, arc x3.
    THE HONEST SURPRISE - THE SCORE WENT *UP*, 88 -> 89. Reported, not massaged. The LOW cap was
      already binding (36 lows -> 3 pts), so removing 34 FP lows recovered only 1 point. The win
      is not the number: it is that all 14 remaining findings are REAL.
    MASVS-CODE 0 -> 16, and the reason matters: controls_present is STILL [] - NO control was
      credited. The rise is pure PENALTY REDUCTION (74 FP findings left the category, so the
      capped 40-pt penalty fell). RUN 14's rule holds: "Up-to-date Dependencies" stays
      UNCREDITED because dependency coverage is not assessable.
    STRUCTURAL DEFECT FOUND, NOT ACTED ON (would have been the forbidden move): the model caps
      each severity at 3x its weight, so MEDIUM deducts at most 9 points NO MATTER HOW MANY
      mediums exist - 4 mediums and 40 mediums score identically. This app's profile therefore
      FLOORS at 89. Raising that cap would move the score toward MobSF's 50, which is exactly
      the reverse-engineering CLAUDE.md forbids, so I STOPPED and flagged it. -> RUN 15.1.
    Android diff (SHARED FILE): SCORE 33/F -> 33/F, score dict BYTE-IDENTICAL. endpoints / ips /
      secrets / severity_summary / masvs_coverage / components / finding identities / permissions
      ALL IDENTICAL. macho_* rules are Mach-O only; Android's native path is analyze_elf.
    vs MobSF: Beetle 89/B on 14 evidence-backed findings. MobSF 50/B - but RUN 9 proved 5 of its
      11 HIGHs are outright FPs and 6 more are overstatements. A defensible 89 beats an FP-driven 50.
    Commit-ready: Y
    Tests: 866 passed, 11 skipped (incl. 5 new: file-type beats path, path fallback).

[x] RUN 15.1 - graduated (diminishing-marginal) score contribution (SHARED: scoring)  DONE
    THE DEFECT (found in RUN 15): the model capped each severity at 3x its weight - a CLIFF.
      Full weight for the first three findings, then NOTHING. 4 MEDIUMs and 40 MEDIUMs scored
      IDENTICALLY. The same flattening bit on LOW (36 lows -> 3 pts).
    THE FIX: the i-th finding of a severity deducts weight/i (harmonic). CHOSEN BY SHAPE, not by
      output. Applied UNIFORMLY to every tier AND to secrets (the defect was uniform).
    WHY HARMONIC and not a gentler curve: property 1 (volume never overtakes severity) must hold
      at ANY count. Harmonic's sum grows like ln(n): 1000 LOWs = 7.49 pts < one CRITICAL (15).
      A weight/sqrt(i) curve FAILS this - 56 LOWs would already outweigh a CRITICAL. Harmonic is
      the only candidate that holds property 1 AND fixes property 2.
    PROPERTIES PROVEN + LOCKED (tests, both directions):
      1. 40 INFO -> 100 vs 1 CRITICAL -> 85; 1000 LOW deduction 7.49 < 15. Volume never wins.
      2. 4 MEDIUM -> 94, 40 MEDIUM -> 87 (old cap: BOTH 91). Accumulation now registers.
      3. INFO weight 0 -> 500 INFO deduct 0. The Dart-AOT/string-index FP classes contribute
         ZERO regardless of curve.
    HONEST OUTPUT (target-blind, reported not massaged):
      iOS: 89 -> 92. The harmonic curve DISCOUNTS FROM THE 2ND finding (3+1.5+1+0.75=6.25),
        where the old cap gave the first THREE full weight (=9), so a FEW-findings app scores
        HIGHER. New ledger: MEDIUM x4 -> 6.25, LOW x2 -> 1.5, total 7.75 -> 92. This crosses
        B->A, which was flagged to the human BEFORE commit; grade-band redesign is RUN 15.2.
      Android: 33 -> 35 (grade F UNCHANGED). Documented consequence of a UNIFORM formula on a
        shared file: highs 24->24.16, mediums 9->7.78, lows 3->2.08; total 74->72.02. All
        content (findings/severity/secrets/permissions) byte-identical - only score arithmetic.
    FP GUARD holds: 0 deductions from Dart-AOT/string-index. MASVS-CODE still 16 (penalty-only;
      RUN 14 rule holds, controls_present []).
    Files: backend/analyzers/scoring.py (graduated_deduction + uniform application);
      pdf_generator.py ("diminishing returns" label replaces "capped at 3x");
      NEW backend/tests/test_score_graduated.py (11 tests); updated test_report_quality_v26.py.
    Commit-ready: Y
    Tests: 877 passed, 11 skipped.

[x] RUN 15.2 - semantic grade bands (SHARED: scoring)  DONE  -> iOS 92/B, Android 35/F
    THE GRADE IS A MEANING LABEL ON THE HONEST SCORE. Architecture: final grade = WORSE of
    (score-band grade, semantic ceiling). The ceiling can only LOWER a grade, never raise it.
    Numeric thresholds UNCHANGED (A>=90 B>=75 C>=60 D>=40 F>=0) - the semantic definition adds a
    ceiling GATE, it does not move the boundaries.
    SEMANTIC CEILING (gate = LOW+, per human decision - a LOW is a real evidence-backed issue):
      A / Excellent = clean bill: NO finding or secret ABOVE INFO (a single LOW bars it).
      B / Good      = has LOW and/or MEDIUM findings, nothing HIGH/CRITICAL.
      C / Fair      = has HIGH/CRITICAL (ceiling; the score may push lower - it never lifts up).
    WHY LOW+ not MEDIUM+ (human, target-blind): under MEDIUM+, 60 real LOWs graded A/Excellent -
      the exact accumulation-blindness RUN 15.1's harmonic curve killed on the SCORE side. It
      must not survive on the GRADE side. LOW+ closes it (60 lows -> B).
    THE SCORE IS NEVER TOUCHED - only the label mapping. iOS score stayed 92, Android 35.
    iOS: score 92, grade A -> B/Good. Reason: "Score 92 would place this in the Excellent band,
      but capped at B/Good: a clean bill (Excellent) requires no finding above INFO - this app
      has 4 real MEDIUM finding(s) and 2 LOW." Grade reason cites the gating findings. This app
      lands B BECAUSE it has 4 real MEDIUMs, not because a threshold was chosen to catch it -
      identical under MEDIUM+ or LOW+ (the mediums already cap it).
    Android: score 35, grade F -> F UNCHANGED. Ceiling for high/critical is C; min(F-band, C)=F -
      the ceiling did not raise it. score dict identical apart from the new grade_reason field;
      endpoints/ips/secrets/severity/finding-identities all identical.
    MUST-HOLDS LOCKED (both directions, LOW+ reading):
      1. zero findings above INFO -> A/Excellent
      2. one real LOW (no mediums) -> cannot be A, grades B (score 99 -> B). CHANGED assertion.
      3. this app (4 MEDIUM, 2 LOW, 92) -> B/Good, reason cites the mediums (+ notes the lows)
      4. Android grade unchanged (F)
      plus: ceiling only lowers (a high/critical D-band app is not lifted to its C ceiling);
      an INFO client-key secret does NOT gate; a LOW/MEDIUM secret DOES.
    Files: backend/analyzers/scoring.py (_apply_semantic_ceiling + grade_reason);
      NEW backend/tests/test_grade_semantics.py (13 tests).
    vs MobSF: Beetle scores 92 but grades B/Good - honest: a strong app that still ships 4 real
      evidence-backed issues is not "Excellent". MobSF 50/B rests on mediums RUN 9 proved are
      mostly framework-canary FPs.
    Commit-ready: Y
    Tests: 889 passed, 11 skipped.

═══════════════ TIER 4 — PENDING ANDROID + WEB/PDF ═══════════════

[x] RUN 16 - Android determinism + verbose gate (SHARED; 3 intended changes, one review)  DONE
    INVERTED-GUARD DISCIPLINE (Android output is SUPPOSED to change): wrote the expected delta
    per change BEFORE regenerating; every byte of Android movement had to map to the list.
    CHANGE 1 - verbose_only gate (report_summaries.py _real_findings). verbose_only findings
      (JNI inventory, shallow iOS taint) no longer leak into the DEFAULT CISO/developer summaries
      (the PDF already excluded them). EXPECTED + OBSERVED delta: ZERO on both platforms - neither
      app produces a verbose_only finding, so the gate is defensive (0 to gate here).
    CHANGE 2 - L3 sorted(perms) at android_analyzer.py:1363. *** THE HEADLINE RESULT ***
      permissions.all/classified/dangerous are now BYTE-STABLE across two same-build scans
      (previously flipped on every restart - PYTHONHASHSEED set iteration). VERIFIED byte-identical
      run-to-run. L3 RESOLVED.
    CHANGE 3 - L4 candidate sort in _candidates_from_finding (engine.py). Correct + safe, but
      INSUFFICIENT - and the inverted guard CAUGHT that:
      *** L4's LOGGED ROOT CAUSE WAS WRONG. *** Not candidate ordering. PROVEN root: jadx
      decompiles the same APK to BYTE-DIFFERENT source across runs - two ViewPager2.java
      decompiles had different md5 AND different line counts (1121 vs 1122), so a match lands on
      line 428 vs 429. No Beetle-side sort can fix the underlying line DATA. I did NOT claim the
      byte-equality payoff for the part that is not achievable.
    RECLASSIFIED L4: jadx decompiler nondeterminism, out of scope; candidate sort kept as the
      correct partial mitigation (removes candidate-ORDER nondeterminism).
    PRECISE ANDROID SCOPE (2 same-build runs, uuid+timestamp masked): 28 differing leaves =
      24 timing metrics (duration_ms etc - construction-varying) + 1 rejected-candidate LINE
      (android_obfuscation_missing / ViewPager2.java 428 vs 429, jadx). Finding identities,
      severity_summary, score (35/F), permissions, primary evidence: ALL byte-stable.
    METHODOLOGY UPDATED (narrowed, not loose): Android diffs EXCLUDE timestamps + scan-id UUIDs +
      timing metrics; TOLERATE +/-1 line drift on REJECTED library-candidate evidence ONLY;
      everything that affects a finding must stay byte-stable. L3 retired the permission-order
      workaround; the jadx tolerance is the one narrow residual.
    iOS HELD (L4 sort is in SHARED engine.py - proven not to shift iOS): 14 findings, 92/B, every
      finding's PRIMARY evidence (file+line+snippet+binary) unchanged, evidence_selection content
      identical (order-insensitive). iOS domain_intel geo (Mountain View vs Bangkok for CDN IPs)
      is pre-existing live-DNS/geo variance - environmental, same class as jadx, untouched by
      these changes.
    Files: backend/report/report_summaries.py, backend/analyzers/android_analyzer.py,
      backend/analyzers/evidence_selection/engine.py.
    Commit-ready: Y
    Tests: 889 passed, 11 skipped.

[x] RUN 17 — Android 5.1b: surface the storage taint finding (Android)  DONE
    Prompt referenced a 'prior session spec' that did not exist; PAUSED and asked the human
    (CLAUDE.md hard rule). Decision: surface flow #1 (Intent.getStringExtra -> SharedPrefs.putString)
    as a finding at its CALIBRATED LOW — 'promote' = make visible, NOT raise severity; do NOT
    touch the calibration rule.
    CHANGE (surgical): removed 'storage' from finding_model._LOW_VALUE_TAINT_SINKS
      ({'logging','intent','storage'} -> {'logging','intent'}). A taint flow that PERSISTS
      user-controlled data to SharedPrefs is a real MASVS-STORAGE data-handling signal, so it is
      no longer pruned as low-value. Logging + Intent with non-PII source stay suppressed.
      The taint SEVERITY model (taint_analyzer._calibrate_severity) is UNTOUCHED — the flow is
      LOW because the model calibrates it LOW, not because anyone assigned it.
    INVERTED-GUARD RESULT (delta = exactly the human's expected list):
      findings 45 -> 46; severity LOW 4 -> 5, all other severities unchanged; grade F -> F.
      NEW: TAINT-STORAGE, LOW, owner=Application, evidence Intent.getStringExtra ->
        SharedPreferences.putString at com.insecureshop.PrivateActivity.onCreate.
      flow #3 (TAINT-INTENT) STILL suppressed. iOS BYTE-IDENTICAL (14 findings, 92/B).
    ONE SECONDARY EFFECT — STOPPED AND REPORTED, then human-ratified as in-scope: the new finding
      was absorbed as a SUPPORTING member of existing chain CHAIN-84d4e33c83 ('Backup-enabled Data
      Extraction'), members 2 -> 3. Verified invariants: chain COUNT 6 -> 6, all chain rule_ids
      and severities identical, this chain stays MEDIUM, no new chain, no severity movement. A
      real finding SHOULD participate in correlation — correct behaviour, not a regression.
    Every byte of Android movement traced to the one finding: the finding (+1 LOW), its chain
      supporting-membership, and +1 in evidence_summary.by_quality. Nothing unexplained.
    Files: backend/analyzers/finding_model.py; NEW backend/tests/test_taint_storage_promotion.py.
    Commit-ready: Y
    Tests: 893 passed, 11 skipped.

[x] RUN 18 — Web/PDF parity (frontend; presentation only)  DONE
    PRESENTATION-ONLY: only frontend/panels2.jsx changed. No analyzer/report file touched, so
    findings (46 Android / 14 iOS) and scores (35/F, 92/B) CANNOT have moved (verified by git
    diff scope). Frontend build passes; evidence-model tests pass (0 fail).
    P1 — taint-card verifiability:
      VERIFIED the new RUN 17 TAINT-STORAGE card renders correctly from taint_graph: severity
        LOW (calibrated), title 'User Input -> Storage', timeline Source=Intent.getStringExtra /
        Sink=SharedPrefs.putString, call chain PrivateActivity.onCreate -> SharedPreferences$
        Editor.putString. A reader can verify the flow.
      FIXED a latent verifiability bug in the taint_flows FALLBACK path: it computed
        `risk: t.sink_sev || t.risk`, preferring the RAW sink severity over the CALIBRATED risk.
        calibrate_flow_severity is explicit that every consumer reads flow.risk. Proven on live
        data: getString->startActivity is sink_sev=medium but calibrated risk=low — the fallback
        would show MEDIUM while the model says LOW. Now `t.risk || t.sink_sev` (calibrated first).
        No CURRENT render change: taint_graph is populated on this app and already carries the
        correct calibrated risk (sink_sev=None), so the buggy fallback was not exercised — the
        fix hardens it so both paths agree.
    P2 — verbose toggle: CONFIRMED already-correct, no change needed. panels.jsx:323 gates
      `f.verbose_only` — the SAME class elf_analyzer/ios_analyzer set and RUN 16's backend gate
      excludes from the default summaries. Hidden by default, shown in the expanded/Suppressed
      view — mirrors the backend's two-tier (default vs full) model exactly. Did NOT invent
      speculative UI against the absent 'prior session spec' (anti-over-build).
    No registry change; TaintFlowPanel is platform-neutral, so no cross-platform leak.
    NOTE: frontend change needs a `docker compose build frontend` to go live (baked, not mounted).
    Commit-ready: Y
    Tests: frontend build OK; evidence-model tests pass.

[x] RUN 19 — Hygiene: regex_sast base audit (MEASURE ONLY)  DONE — REPORT ONLY, no code change
    Deliverable: <scratchpad>/RUN19_regex_sast_audit.md (report artifact; NOT committed to repo).
    Scope: code_rules.py CODE_RULES (55 Android) + IOS_CODE_RULES (26 iOS) = 81 base regex rules.
      (backend/analyzers/sast/ is the Semgrep adapter — not regex rules, out of scope.)
    METHOD: empirical, not pattern-shape — ranked by ACTUAL match breadth (merged_locations) on the
      live iOS(14)/Android(46) scans, since shape heuristics over-flag precise rules.
    8 EMPIRICALLY OVER-BROAD rules (all currently INFO/library-owned after RUN 15 demotion, so they
      do NOT inflate the score — cost is EVIDENCE NOISE + the L4 jadx carrier):
        android_reflection (228 locs), android_log_debug (181), android_obfuscation_missing (125),
        android_process_death (41), android_insecure_random (26), android_print_stack_trace (12),
        android_content_provider_no_permission (10), ios_jailbreak_detection (10).
    2 ID/PATTERN MISMATCHES (correctness): android_process_death (pattern is deserialization),
      android_content_provider_no_permission (pattern is usage, not a missing-permission gap).
    Proposals written per rule (tighten/boundary/app-code-only/rename) — PROPOSALS ONLY, not applied.
      Highest-value: obfuscation_missing (retires L4 residual + kills 125 locs); reflection+log_debug
      (409 combined matches); the 2 mislabels.
    Also recorded the rules the shape-heuristic flagged that are ACTUALLY FINE (precise cipher/exec/
      credential rules) so a follow-up does not 'fix' them.
    NO BEHAVIOR CHANGE: no rule/pattern/finding touched. git working tree CLEAN except this progress
      line. Findings unchanged: Android 46, iOS 14; scores 35/F, 92/B (verified — nothing regenerated,
      no analyzer code touched).
    Commit-ready: N/A (report only; nothing to commit but this note). Human to pick follow-up rules.

[x] RUN 20 — iOS view-code regression: decodable binary plists shown as binary card  DONE
    VERIFIED FIRST (not assumed): swept ALL 330 bundle files through the file server — ZERO
    viewable-text files wrongly carded; inspect_file/_maybe_decode_plist was already correct
    (plists->XML text, Mach-O->card). The bug was in the FINDING evidence path.
    ROOT CAUSE (hypothesis 1 — content-detection too aggressive): RUN 4's
      _record_binary_format_files flagged EVERY bplist (magic bytes) as binary_evidence, so a
      finding on a DECODABLE plist showed the "Binary Property List" card and hid View Source.
      Reproduced: cloud_firebase_storage_bucket on GoogleService-Info.plist had evidence
      binary=True/artifact=True — but that plist decodes to viewable XML.
    LINE DRAWN (matches human guidance): decodable bplist -> source; non-decodable blob
      (embedded.mobileprovision CMS/PKCS#7) and Mach-O -> card. Same "viewable" definition the
      file server uses, so card and viewer never disagree.
    FIX (ios_analyzer.py only, iOS-scoped):
      1. _record_binary_format_files adds a bplist ONLY if plistlib CANNOT decode it (Mach-O
         always). binary_evidence_files 107 -> 40 (67 decodable plists removed).
      2. NEW _remap_decodable_plist_finding_lines: a plist finding's raw-bplist line is a parse
         artifact meaningless for the decoded XML; remap to the decoded-XML line of the finding's
         value. cloud_firebase line 3 -> 32 (the STORAGE_BUCKET value line).
    BEFORE->AFTER (cloud_firebase): binary True->None, artifact True->None (shows SOURCE); line
      3->32; snippet now the real XML key line. Still correctly carded: Runner / webview Mach-O /
      embedded.mobileprovision (proved via the new scan's file server). ios_md5_hash on Runner
      keeps binary=True.
    INVARIANTS: iOS 14->14, score 92/B held. ONE finding reclassified (cloud_firebase binary
      -> source) — a legitimate evidence-type correction, flagged; no severity/owner/count change.
    ANDROID UNAFFECTED (iOS-only fns; view.py untouched): 46->46, 35/F, endpoints/ips/secrets/
      severity/permissions/components/finding-identities all identical.
    L1 CROSS-CHECK: iOS side of L1's binary-evidence edge cases (decodable-plist edge). Android
      L1 (.dex/.arsc string-index) remains open.
    Files: backend/analyzers/ios_analyzer.py; NEW backend/tests/test_ios_decodable_plist_viewable.py.
    Commit 176ce7b. Tests: 897 passed, 11 skipped.

[x] RUN 21 — PDF export completeness audit + fill real gaps (PDF-only)  DONE
    ANSWER TO THE QUESTION: the PDF was shorter than MobSF NOT because MobSF's length is
    legitimate padding-only — it was because MANY RUN 1-20 sections landed UI-ONLY and the
    reportlab PDF generator (which predates most of the RUN work) never got renderers for them.
    MEASURED FIRST (grep each RUN-feature results-key in pdf_generator.py): missing keys were
    trackers, property_lists, binary_protections, ats_state, cve_stats.coverage, grade_reason,
    results["strings"]; and _binary_section rendered the empty Android "binaries" list, not the
    iOS binary_protections.
    GAPS FILLED (new PDF sections, each self-gating so Android is unaffected):
      RUN 9  Binary Protections — the per-binary Mach-O table (40 rows) + the suppressed-FP note
             (App.framework/App Dart-AOT never a HIGH). MobSF's single biggest section; now in PDF.
      RUN 11 Trackers — 9, each with evidence type + linkage.
      RUN 12 Property Lists — security keys + privacy-manifest rollup.
      RUN 6+10 Info.plist & Entitlements — ATS posture, usage-description reasons, entitlements.
      RUN 1  Hardcoded IPs added to the Endpoints section (192.168.161.138).
      RUN 14 OSV coverage VERDICT ("Not assessable — 0 CVEs is NOT a clean bill").
      RUN 15.2 grade_reason (why 92 is capped to B).
    TWO CORRECTNESS FIXES:
      RUN 13 — _string_analysis_section rendered the RAW string_analysis, printing the
        "Base64 (Potential Secret)" values UNMASKED — a real secret leak in the PDF (RUN 12 class).
        Now renders the MASKED results["strings"] + the FP-filtered emails. Verified: raw base64
        candidate and raw Firebase key are NOT in the PDF; masked AIza**** marker is.
      RUN 20 follow-through — _findings_section recomputed build_evidence_view WITHOUT platform,
        dropping the iOS binary treatment. Now prefers the stored platform-aware finding
        ["evidence_view"]. Verified: cloud_firebase shows the DECODED bucket line
        (ilogistics-check-in.appspot.com), not the raw-bplist artifact line 3.
    DID NOT PAD: no 41x-repeated table, no FP emails. Density over length.
    RESULT: iOS PDF 19 pages, ALL 14 audited sections present (verified via pypdf text
      extraction). Shorter than MobSF's padded 57 = CORRECT (completeness, not length).
      Android PDF 29 pages, iOS-only sections correctly ABSENT, strings section present.
    DISCIPLINE: pdf_generator.py only (no analyzer change) — iOS 14/92/B, Android 46/35/F
      unchanged (verified). 897 tests pass. No pdf skill at /mnt/skills (reportlab, code-based).
    Files: backend/report/pdf_generator.py.
    Commit-ready: Y

[x] RUN 22 — fix the two regex_sast MISLABELS from the RUN 19 audit  DONE
    Both were id/pattern mismatches: the rule asserted something the pattern never checks. Per the
    audit (proposals 4 & 7) the honest fix for BOTH is RELABEL, not narrow — the patterns detect
    real things, they were just named for the wrong thing.
    FIX 1 — android_process_death -> android_insecure_deserialization.
      The pattern (ObjectInputStream|readObject()|Serializable|Parcelable...) is deserialization;
      the title "Object Deserialization", CWE-502 and description were ALREADY correct — only the id
      lied ("process death"). id-only rename; pattern/title/severity unchanged.
    FIX 2 — android_content_provider_no_permission -> android_content_provider_query.
      Pattern is getContentResolver().query() — a USAGE detector, not a missing-permission check.
      Old title "ContentProvider Query Without Permission Check" claimed a gap the rule never
      verifies. Relabeled id + title ("ContentProvider Query") + description (now: usage detected,
      review that the provider is permission-guarded — not itself a finding of a missing permission).
      Pattern/severity unchanged.
    Chose RELABEL over NARROW for both: narrowing changes match breadth/coverage (a separate
    signal-quality concern, deferred with the rest of the RUN 19 breadth proposals); the mislabel
    is purely a correctness/honesty defect, and relabel fixes exactly that with zero coverage change.
    ITEMIZED EXPECTED DELTA (stated before regenerating): only the 2 rule_ids change (+1 title);
    count 46 unchanged; severity_summary unchanged; score 35/F unchanged; iOS untouched.
    PROVED (android_R21 vs android_R22, neutralizing ONLY the 2 intended relabels):
      exactly 2 old ids removed / 2 new ids added; ALL other finding identities byte-identical;
      count 46->46; severity_summary {crit1,high11,med7,low5,info22} unchanged; score 35/F unchanged;
      both findings stay INFO (library-owned, RUN 15 demotion). iOS 14/92/B unchanged.
    No external refs to the old ids (only code_rules.py + the RUN 19 doc, which is a historical
    record and left as-is). 897 tests pass. Analyzer change only.
    Files: backend/analyzers/code_rules.py.
    Commit-ready: Y

[x] RUN 23 — tighten android_obfuscation_missing (whole-app posture collapse)  DONE
    AUDIT VERIFIED (proposal 3): the rule is a WHOLE-APP posture proxy (is the app obfuscated?)
    implemented as a per-file regex on R.id./R.layout./BuildConfig, which matched every UI class and
    accrued 125 evidence locations. The audit's honest fix = compute ONCE, emit a single finding with
    ONE representative location. It was ALSO the observed carrier of the L4 jadx line-drift.
    HOW (3 files, minimal):
      1. code_rules.py — added "posture": True to the rule + honest posture-wording description.
         Pattern/severity/coverage UNCHANGED (still the same detection; only breadth changes).
      2. code_analyzer.py — emit copies posture flag onto the finding ONLY when true (never stamps
         ordinary findings, so no report-wide field churn).
      3. evidence_selection/engine.py — new _collapse_posture_finding(), called from annotate AFTER
         select() has scored the FULL candidate set and picked the app-owned primary. It preserves
         that primary and collapses the WHERE-fields to it: file_evidence/files/file_count=1,
         evidence_selection.supporting/rejected=[] candidate_count=1, and merged_locations +
         fusion.merged_locations = [primary]. STRENGTH-fields (detection_count, evidence_count,
         fusion score) are untouched — so the finding's strength and the app score cannot move.
      Design note: collapse is POST-selection (not at emit) precisely so the app-owned primary
      (AboutUsActivity.java:53) still wins over the alphabetical-first androidx candidate. Emit-time
      collapse would have starved selection and changed the primary.
    ITEMIZED EXPECTED DELTA (breadth fix — count changes are the POINT, unlike RUN 22's relabel):
      obf finding: file_count 125->1, candidate_count 125->1, rejected 120->0, supporting 4->0,
      merged_locations 125->1, +posture flag, +posture description; PRIMARY held. Report: one
      consequent file_index drop + one summary counter. Everything else byte-identical.
    PROVED (R22 baseline vs R23; taint sorted, timing/uuid masked) — 0 UNEXPLAINED leaves:
      * obf finding: collapsed exactly as itemized; PRIMARY = AboutUsActivity.java:53 UNCHANGED;
        ViewPager2 GONE from the finding entirely (was in merged_locations/fusion/evidence_view).
      * source_explorer.file_index: -1 file = sources/androidx/.../ActionBarDrawerToggleHoneycomb.java
        (deterministic, R23==R23b). TRACED: it was the obf finding's pre-collapse file_evidence[0]
        (an AndroidX file the posture regex matched); no other finding references it, so it correctly
        drops. stats.annotated_files 38->37, by_severity.info 26->25 — same one file.
      * evidence_selection_summary.multi_candidate_findings 25->24 (obf no longer multi-candidate).
      * NOTHING ELSE. All 45 other findings byte-identical.
    INVARIANTS: findings COUNT 46->46 (posture collapses LOCATIONS, not the finding);
      severity_summary {C1,H11,M7,L5,I22} unchanged; score 35/F unchanged; iOS 14 findings / 92 / B
      unchanged, no iOS finding carries the posture flag (IOS_CODE_RULES has none). 897 tests pass.
    L4 RE-SCOPED HONESTLY (do NOT overclaim):
      * obfuscation finding: L4 carrier RETIRED — ViewPager2 drift candidate no longer exists.
      * L4 broader: STILL OPEN. Same jadx byte-different-decompilation root cause rides on ANY
        finding with rejected AndroidX library candidates — CONFIRMED on android_log_debug
        (AppCompatTextViewAutoSizeHelper.java 60<->61) and android_reflection. Intermittent. Same
        out-of-scope conclusion as RUN 16. Full closure = RUN 19 breadth proposals 1 & 2.
      * L5 NEW (separate, pre-existing): taint_flows run-to-run ORDER swap — logged for a later
        determinism pass, NOT touched here.
    Files: backend/analyzers/code_rules.py, backend/analyzers/code_analyzer.py,
      backend/analyzers/evidence_selection/engine.py.
    Commit-ready: Y  (committed 1e9cabd; pushed to origin/v1.3-dev)

[x] RUN 24 — iOS view-code: generalize the plist line-remap + frontend autoscroll safety  DONE
    VERIFIED FIRST (all facts held): backend file-serving is CORRECT (decompiler._maybe_decode_plist
      decodes bplist AND round-trips XML plists via plistlib.dumps(FMT_XML), line 455) — NOT touched.
      Mach-O + non-decodable blobs correctly card. The bugs were exactly as the prompt described.
    ROOT CAUSES (two, both confirmed against live source + a live scan):
      Bug B (backend, the real one): RUN 20's _remap_decodable_plist_finding_lines fixed only
        f["line"], leaving file_evidence[*].lines at the RAW-bplist artifact (cloud_firebase: f.line
        was 32 but file_evidence.lines was [3]). ui.jsx buildEvidence() reads file_evidence BEFORE the
        top-level location, so the DEFAULT "View Code" entry pointed at line 3 = the `<plist>` header,
        not the bucket at line 32. Also the remap only decoded bplist magic, not XML plists (which the
        file server canonicalizes) — so an XML-plist finding would render canonical XML never remapped.
      Bug A (frontend safety net): resolveEvidenceLines() (Results.jsx) trusted declared lines with NO
        range check — an out-of-range artifact line targets a nonexistent row (silent no-scroll).
    FIX (ios_analyzer.py + Results.jsx only):
      * _remap: _xml_lines now mirrors _maybe_decode_plist EXACTLY (bplist OR .plist round-trip), and
        the remap rewrites EVERY plist file_evidence entry to its own decoded-XML line (or clears it to
        [] when no anchor), and overwrites the raw-bplist snippet with the decoded line. Generalized
        from "one finding" to all plist findings + all their plist evidence entries.
      * resolveEvidenceLines: keep only IN-RANGE declared lines; if none survive, fall through to the
        existing snippet/token/line-1 chain. Never targets a nonexistent row.
    PLIST-FINDING TABLE (every decodable-plist finding in the app — there are 2):
      cloud_firebase_storage_bucket / GoogleService-Info.plist (bplist): BEFORE file_evidence.lines=[3]
        -> View Code landed on line 3 (`<plist version="1.0">`). AFTER f.line=32, file_evidence.lines=
        [32], snippet=`<string>ilogistics-check-in.appspot.com</string>`. Simulated frontend: default
        View Code -> focus line 32 = the bucket. FIXED. (Legit location correction: file_evidence 3->32;
        NOT a finding/severity/score change — f.line was already 32 from RUN 20.)
      ios_privacy_declaration_discrepancy / Info.plist (bplist): f.line=None, file_evidence.lines=[]
        (the NSPrivacyTracking keys are ABSENT — that IS the finding, nothing to anchor). Stays
        approximate -> renders Info.plist, resolves to line 1, never a nonexistent row. CORRECT.
    BROAD PROOF: 40 Mach-O binary_evidence_files still card (App.framework/App Dart-AOT, FBLPromises,
      Firebase*), ZERO decodable plists wrongly carded. PDF follow-through (RUN 21): the decoded bucket
      value is in the PDF, raw `bplist00` does NOT leak.
    INVARIANTS: iOS 14->14 findings, 92/B, severity_summary identical. Android BYTE-STABLE at the
      finding level (46->46, 35/F, severity + all finding identities identical) — iOS-analyzer + a
      presentation-only frontend guard; Android never calls the remap. 897 backend tests pass
      (incl. the 4 plist tests); no frontend test infra (verified via build + data-level simulation).
    Files: backend/analyzers/ios_analyzer.py, frontend/src/pages/Results.jsx.
    LESSONS LOGGED: L6 (frontend view-code/scroll has NO regression test — 2nd regression here,
      RUN 20 then RUN 24) + the CONSUMER-FIELD RULE in the methodology (fix the field the renderer
      reads, not just the one you set — RUN 20's exact miss).
    ALL live user-facing bugs now CLOSED: view-code #1/#2 (RUN 20+24), short-PDF #4 (RUN 21),
      CISO #3 (was already correct). Remaining work is optional polish only: RUN 19 breadth 1&2
      (also broadly retires L4), L1 Android, L2 (blocked on a Swift/ObjC source app), OSV coverage, L5.
    Commit-ready: Y  (committed 12facac; pushed to origin/v1.3-dev)

[x] RUN 25 — restrict android_reflection + android_log_debug to app-owned code (audit 1&2)  DONE
    VERIFIED FIRST: audit proposals 1&2 = restrict these two over-broad rules to APP-OWNED code
    (reflection 228 locations / 227 library; log_debug 181 / 180 library). Confirmed app-owned uses
    the EXISTING signal classify_file(path,ctx).is_application (RUN 8/9/15), not a new heuristic; the
    manifest package is set at _parse_manifest (line 421) BEFORE SAST (524), so context_from_results
    is valid at emit time. Guard list respected (cipher/exec/credential rules untouched).
    IMPLEMENTATION (code_rules.py + code_analyzer.py):
      Added "app_owned_only": True to both rules; in _run_rules_per_file the emit filters each such
      rule's file matches to is_application files (cached), and does NOT fire the finding if none
      remain. Gating at EMIT means fusion / merged_locations / ownership / evidence_selection all see
      only app-owned files — no downstream surgery, and no library candidate can carry L4 drift.
    BOTH FINDINGS SURVIVE (they had an app-owned match): reflection -> LoginActivity.java:107,
      log_debug -> LoginActivity.java:84; file_count 228->1 and 181->1; primary UNCHANGED.
    *** THE INVERTED GUARD CAUGHT A CASCADE — stopped, investigated, human-ratified. ***
      Un-demotion: both were INFO only because RUN 15 demoted them as LIBRARY-owned. Now app-owned,
      they are no longer demoted -> keep rule severity LOW (correct: real Log/reflection in app code).
      Revealed chain: reflection being a real app finding made it chain-eligible, and the correlation
      engine emitted a NEW "Dynamic Code Loading / Reflection RCE" finding.
      INVESTIGATION (human asked: earned HIGH or co-occurrence?): the chain is HEURISTIC, not proven.
      engine.reachability_proof: CODE_LOADING has no taint sink category, so a code-loading chain can
      NEVER be taint-proven -> always PROOF_HEURISTIC. Its own check "Reachability proven by data-flow
      (taint)" = false. It was wired from capability co-occurrence (exported InsecureShopProvider + an
      app-owned reflection finding), NO dataflow linking provider input to the reflection sink.
    CHAIN-ENGINE FIX (attack_chains/engine.py + model.py + bridge.py) — general, keyed on proof type:
      Found + fixed an INVERSION: heuristic chains were being FORCED UP to HIGH (`if sev_rank<high:
      severity=high`). Now a heuristic (co-occurrence) chain CAPS at MEDIUM — real, worth review, not
      proven exploitable (same bar as RUN 9 canary / RUN 12.1 discrepancy MEDIUMs). proven chains stay
      HIGH; manifest-only (structural) chains are untouched. Added chain.severity_reason ("capabilities
      co-occur but reachability not proven — heuristic linkage") surfaced on the finding. sev_rank is
      INVERTED (critical=0..info=4) — cap condition is sev_rank(sev) < sev_rank("medium").
      TEST LOCKS BOTH DIRECTIONS: test_heuristic_injection_chain_caps_at_medium (heuristic SQLi ->
      MEDIUM + severity_reason) alongside the existing proven-SQLi -> HIGH test. 898 tests pass.
    FULL ATTRIBUTION (R24 baseline vs R25) — the ENTIRE delta is 3 things, nothing else:
      android_reflection info->low; android_log_debug info->low; NEW chain_CHAIN-7a268fef60 MEDIUM
      (heuristic). 0 other finding severities changed; the 6 pre-existing chains byte-identical.
      count 46->47; severity_summary {C1,H11,M8,L7,I20}; score 35->34/F (grade HELD). Every deduction
      traces to a REAL finding: 2 genuine app-owned LOWs (were mislabeled library INFO) + 1 genuine
      MEDIUM co-occurrence chain. NO unproven HIGH. The chain's HIGH->MEDIUM cap is why score is 34
      not something worse — the unearned HIGH does not stand.
    L4 (honest): reflection (103 androidx) + log_debug (112 androidx) drift carriers RETIRED. But L4 is
      NOT closed — 17 findings STILL carry androidx library candidates (android_insecure_deserialization
      26, print_stack_trace 14, implicit_intent_sensitive 14, content_provider_query 10, behavior_*).
      Same jadx root cause; only the two biggest carriers removed. Full closure needs restricting those
      too, or a systemic androidx-candidate strip — out of RUN 25 scope.
    iOS UNTOUCHED (chain-engine change is SHARED but proven not to shift iOS): 14 findings, 92/B,
      severity_summary identical.
    Files: backend/analyzers/code_rules.py, backend/analyzers/code_analyzer.py,
      backend/analyzers/attack_chains/engine.py, backend/analyzers/attack_chains/model.py,
      backend/analyzers/attack_chains/bridge.py, backend/tests/test_chain_reachability.py.
    Commit-ready: Y  (committed 8c48657; pushed to origin/v1.3-dev)

[x] RUN 26 — L1: Android .dex/.arsc string-index-as-source-line (twin of RUN 4/20)  DONE
    VERIFIED FIRST (heeded the CONSUMER-FIELD rule — did NOT assume the file-server): traced the
    whole path against live source. string_analyzer._collect_files dumps .dex/.so printable strings
    ONLY when no decompiled source exists (has_source=False); a match's "line" is then the index in
    that strings dump, not a source line. The file-server ALREADY cards binaries on click, and
    finding_model marks .dex/.so/.arsc paths unresolved — so the real gap was elsewhere:
    *** ROOT CAUSE: evidence_selection/view.py build_evidence_view carded binary-primary findings
        ONLY when platform=="ios" (lines 292 & 343, via _is_ios_binary_path). An Android finding
        whose primary is a .dex/.so/.arsc rendered its string-index as a misleading file:line in the
        EVIDENCE VIEW — the field the PDF (RUN 21), UI panels and SARIF all read. The iOS RUN 4/20
        carding was never extended to Android. This is exactly the consumer-field lesson: fix the
        field the renderer reads (evidence_view), not the file-server (which was already correct).
    FIX (view.py only): added _ANDROID_BINARY_SUFFIXES (.dex/.so/.arsc/.odex/.vdex/.oat + .dex.txt/
      .so.txt/.arsc.txt) + _is_android_binary_path; made _is_binary_evidence platform-aware; removed
      the iOS-only gate at both call sites so an Android binary primary is carded (artifact=True,
      line=0, string_index preserved) — the same treatment iOS Mach-O/bplist gets. iOS path
      unchanged (platform=="ios" -> _is_ios_binary_path, identical).
    TEST: test_android_binary_evidence_carding.py (4 cases) — .dex/.so/.arsc/.dex.txt primary carded;
      a real .java primary NOT carded (line preserved); iOS Mach-O still carded (regression). 902 pass.
    ARTIFACT PROOF (shared-file run -> regenerated BOTH):
      Android R25->R26: count 47->47, score 34/F, severity identical; ZERO findings carded (InsecureShop
        has jadx source, so NO binary-primary finding exists -> the new carding is correctly DORMANT).
        After L5 taint-order + L4 jadx-line tolerances: 0 other differing leaves. Byte-clean.
      iOS R25->R26: 14/92/B unchanged; findings carded as binary 11->11 (iOS carding preserved).
    LIMITATION (transparent): L1 only manifests on a NO-SOURCE / packed APK (the .dex/.so fallback).
      No such APK is available (InsecureShop has full source; testapp.ipa is iOS). So the fix is
      verified by code trace + unit test + zero-regression on both apps, but NOT by a live end-to-end
      repro on a real no-source APK. Same blocker class as L2. Offer: full validation if a
      packed/obfuscated Android sample is provided. L1 status -> FIXED (code+test), live-repro DEFERRED.
    Files: backend/analyzers/evidence_selection/view.py; NEW backend/tests/test_android_binary_evidence_carding.py.
    L1 STATUS: FIXED (code trace + unit test + zero-regression on both apps); NOT live-validated
      (no packed/no-source Android APK in the corpus). "Verified correct, not verified live." The
      carding being DORMANT on InsecureShop (which has source) is itself evidence the gate is right —
      it only fires when there is no source. Live repro deferred, same blocker class as L2.
    Commit-ready: Y  (committed b870836; pushed to origin/v1.3-dev)

[x] RUN 27 — iOS Source Explorer file-click shows cards / empty tree (SEPARATE from view-code)  DONE
    VERIFIED FIRST against the REAL endpoints (not simulation — the user noted sims passed while the
    UI failed). Traced the Source Explorer click: SourceExplorerPanel.open -> onOpenCode -> the SAME
    openCode -> /api/scans/{id}/file -> inspect_file. Probed inspect_file on every iOS file: it is
    CORRECT (all plists -> decoded XML text; Runner/frameworks/embedded.mobileprovision -> binary
    card). So the file-server was NOT the bug (consumer-field rule again).
    *** ROOT CAUSE: the file-TREE, not the file-server. /api/scans/{id}/files -> list_source_files
        (decompiler.py) enumerated jadx/apktool/apk_extract/repo but NEVER ipa_extract (where iOS
        bundles are persisted). Confirmed live: the endpoint returned {} for the iOS scan. The iOS
        Source Explorer tree therefore fell back to sparse finding-evidence paths — mostly Mach-O
        framework binaries that correctly card — so viewable bundle files (plists/JSON/config) were
        simply MISSING and the tree looked like "everything is a card." ***
    FIX (decompiler.py list_source_files only): added an ipa_extract branch listing VIEWABLE files
      (.plist/.strings/.json/.txt/.xml/.html/.js/.css/.md/.mobileconfig/.entitlements/.xcconfig/
      .properties/.yaml/.cfg/.config/.storyboard/.modulemap). Compiled binaries (Mach-O, .dylib,
      embedded.mobileprovision, .car) are EXCLUDED — they only card. Paths are served exactly like
      Android's (flattenManifest prefixes "ipa_extract/…"; resolve_source_path already resolves it).
      No frontend change needed — the frontend was already correct (Android proves it); the bug was
      the empty backend manifest.
    VERIFIED IN THE REAL UI PATH (the exact HTTP calls the UI makes):
      /files: iOS tree 0 -> 80 viewable files (69 plists, 8 JSON incl. login_config.json/app_settings.json,
        css, js, modulemap, storyboard Info.plists, AssetManifest.json).
      /file on the PREFIXED tree path ("ipa_extract/Payload/…"): ALL 80 files -> CONTENT (plists
        decode to XML), 0 cards, 0 errors. Mach-O Runner + embedded.mobileprovision (finding paths)
        -> CARD, correct and untouched.
    NO REGRESSION: Android /files still {jadx:2222, apktool:464, apk_extract:955}, NO ipa_extract key;
      Android Source Explorer unchanged. Findings/score unchanged (list_source_files is only hit by
      the on-demand /files endpoint, never the analysis pipeline): iOS 14/92/B, Android 47/34/F.
      904 tests pass (NEW test_ios_source_explorer_listing.py: ipa_extract lists viewable + excludes
      binaries; an Android-shaped scan has no ipa_extract key).
    Files: backend/decompiler.py; NEW backend/tests/test_ios_source_explorer_listing.py.
    Commit-ready: Y  (superseded/refined by RUN 28 — see below; committed as part of RUN 28)

[x] RUN 28 — three live iOS UI bugs (binary view-code / Security-Explorer count / JSON) + 2 verifies  DONE
    VERIFIED EACH against the REAL endpoints (L6 discipline — sims passed while UI failed before).
    BUG 1 — binary-finding "View Code" showed a GENERIC protections card, never the matched symbol.
      Root: the finding row/drawer "View Code" fetched /file?path=Runner -> inspect_file -> generic
      describe() card, discarding the finding's own evidence (evidence_view.primary already had
      symbol=_CC_MD5, string_index=8731). FIX: /file gains an optional strings_index; when a binary
      FINDING passes it, the server returns the Mach-O's extracted-strings listing (decompiler.
      binary_strings_listing, reproduced with the SAME 5 MiB read + _extract_strings the SAST used,
      so the index matches) and the viewer scrolls to the symbol. A bare tree browse (no index)
      still returns the generic card — the two paths are NOT collapsed (VERIFY 4). Frontend:
      buildEvidence marks the binary entry with symbol+stringsIndex; openEvidence/openCode pass
      strings_index; new "View Strings" button on the drawer; fixed a p.stringIndex->p.string_index
      typo. VERIFIED: GET /file?path=Runner&strings_index=8731 -> text listing whose line 8731 is
      exactly "_CC_MD5" (surrounded by _CC_SHA1/_CCRandomGenerateBytes); no-index -> {binary:true}.
    BUG 2 — Security Explorer "secrets 4" then "No files in the secrets category". Two causes:
      (a) PATH MISMATCH: tree paths are "ipa_extract/Payload/Runner.app/…" but the overlay's
          finding/secret paths are "Runner.app/…"; normalizePath stripped only ONE prefix, leaving
          "Payload/…" on one side. FIX: normalizePath now strips prefix segments REPEATEDLY
          (ipa_extract/ + Payload/) so both sides reduce to "Runner.app/…".
      (b) COUNT vs LIST from different sources: count = securityIndex[id].length, list = tree ∩
          category. FIX: the category COUNT is now derived from the SAME tree-intersection as the
          list (filterFileCount), so count === list by construction, every category, both platforms.
      VERIFIED (real security_index + real /files, run through the ACTUAL model.js functions):
      iOS secrets 4==4, crypto 3==3, network 1==1, authorization 1==1 — count==list for all. Android
      count==list too (this also fixed a latent Android count!=list where a file in jadx+apk_extract
      was listed but under-counted). Android findings/score 47/34/F unchanged.
    BUG 3 — minified JSON (AssetManifest.json) rendered as one line. FIX: CodeBlockViewer pretty-
      prints JSON for DISPLAY only (JSON.stringify(JSON.parse(raw),null,2)); parse-fail falls back to
      raw; Copy still uses the original `content`. VERIFIED: AssetManifest.json raw 1 line (8469 chars)
      -> 368 indented lines; Copy path untouched.
    TREE REFINEMENT (enables VERIFY 4 + BUG 2 "list it"): RUN 27 listed only VIEWABLE ipa_extract
      files, so binaries weren't browsable and iOS security categories on Mach-O (crypto/secrets)
      showed 0. RUN 28 browses the WHOLE bundle — viewable->content, binary->card, binary finding->
      strings — skipping only pure media/assets (.png/.svg/.ttf/.car/…). iOS tree 80 -> 209 files;
      probed ALL 209 through the real /file: 164 content + 45 card, 0 errors, 0 media.
    VERIFY 4 (CORRECT, untouched): Runner + embedded.mobileprovision now in the tree; a bare browse
      (no finding context) returns the generic binary card. CONFIRMED via GET /file (no strings_index).
    VERIFY 5 (CORRECT, untouched): 67 Info.plist files across the bundle are ALL distinct on disk
      (distinct md5); each .framework has its own. The server serves each file's real bytes. No bug.
    DISCIPLINE: presentation/explorer only — iOS 14/92/B, Android 47/34/F unchanged. Android tree
      (/files: jadx/apktool/apk_extract, no ipa_extract) + Android Security Explorer unchanged.
      904 tests pass (RUN 27 listing test updated: binaries now listed, media excluded).
    Files: backend/main.py, backend/decompiler.py, backend/tests/test_ios_source_explorer_listing.py,
      frontend/src/pages/Results.jsx, frontend/src/components/CodeBlockViewer.jsx,
      frontend/src/components/workspace2/{SourceExplorer.jsx, source-explorer-model.js, ui.jsx, panels.jsx}.
    Commit-ready: Y  (committed 597a59a; pushed to origin/v1.3-dev)

[x] RUN 29 — three live-UI bugs, VERIFIED BY ACTUALLY RENDERING (Playwright headless Chromium)  DONE
    *** Closed the L6 gap for this run: installed Playwright + drove the REAL rebuilt UI (login ->
        /scans/:id/:section -> click), asserting the rendered DOM (scroll position, strings, drawer
        text) — not HTTP/simulation. RUN 24/28 passed sims while the UI failed; this did not. ***
    BUG 1 — view-code autoscroll broken for large content (REGRESSION surfaced by RUN 28's binary
      strings). CodeBlockViewer's 120ms + behavior:'smooth' fired before an 11k-row Mach-O strings
      table laid out and a smooth scroll to a far row under-shot. FIX: rAF-gated INSTANT scroll with
      a re-assert after late paint. ALSO fixed a RUN 28 mismatch: JSON was beautified in the VIEWER
      but the focus line was resolved against the RAW bytes -> moved beautify into openCode so the
      resolved line and the rendered rows agree; rawContent kept for Copy. VERIFIED in real UI:
      MD5 binary (11825 rows) focus 8731 inView+centered; Realm 1160, SHA-1 2758 centered; iOS plist
      32 in view; Android source (jadx .java) 56 centered.
    BUG 2 — binaries showed a dead "no source" card. The extracted STRINGS are the readable content
      of a Mach-O (no jadx equivalent exists for iOS). FIX (main.py /file): a binary with a useful
      amount of strings returns the strings listing (searchable text, X-Beetle-View header) for BOTH
      a file-tree browse AND a finding (which also scrolls to its symbol); only a truly-opaque blob
      (<20 strings) still cards. Supersedes RUN 28's "browse -> card". VERIFIED in real UI: browsing
      Runner -> 11825 rows of strings, header "Compiled binary — extracted strings (searchable)",
      search "_CC_MD5" -> 1/2 matches.
    BUG 3 — findings showed WRONG "Why Dangerous" (categorizer false-match). analyst_intel.categorize
      greedy-substring-matched a title+description+EVIDENCE blob, so a stack-canary/malloc finding on
      a Firebase framework rendered "Permissive Firebase rules expose the database", Realm-on-a-
      webview-framework rendered WebView, and a deep-link finding titled "-> WebViewActivity" rendered
      WebView. FIX: categorize on the finding's OWN identity — rule_id + category FIELD + cwe are
      authoritative; the free-text TITLE is a last resort only; unconfident -> GENERIC (neutral).
      Storage-at-rest checked before crypto (Realm/NSUserDefaults -> FILE_STORAGE, not crypto);
      generalized the FILE_STORAGE narrative to cover unencrypted local DB/prefs; removed loose tokens
      ("_des" matched "_deserialization", "ats" matched other words). Drives why_dangerous +
      attack_scenario + remediation + code_example together (all keyed on the category). Locked with
      test_analyst_categorize.py (8 cases, both directions). VERIFIED in real drawers: Realm/
      NSUserDefaults -> storage, canary/malloc/deserialization -> neutral, MD5/SHA1 -> crypto,
      cloud_firebase -> firebase, deeplink(->WebViewActivity) -> deep-links, jailbreak -> root.
    BOTH-PLATFORM SWEEP: full table built for all 14 iOS + 47 Android findings (rule_id -> category /
      view-type / scroll). 0 cross-category text leaks on either platform after the fixes.
    DISCIPLINE: iOS 14/92/B, Android 47/34/F unchanged (BUG 3 text-only; BUG 1/2 presentation).
      912 tests pass (8 new). Android Source Explorer / scroll / JSON unaffected (verified).
    Files: backend/main.py, backend/analyzers/analyst_intel.py, backend/tests/test_analyst_categorize.py,
      frontend/src/pages/Results.jsx, frontend/src/components/CodeBlockViewer.jsx.
    Commit-ready: Y  (committed 722c8a2; pushed to origin/v1.3-dev)

[x] RUN 30 — L6 DURABLE FIX: real-UI Playwright e2e smoke test committed to the repo  DONE
    The reason RUN 24/28 shipped broken UI is there was NO automated real-render check — unit tests
    and HTTP passed while the screen was wrong. RUN 29 proved a headless-browser render catches it;
    RUN 30 makes that permanent. Added frontend/e2e/smoke.spec.mjs (+ playwright.config.mjs, README),
    @playwright/test devDep, `npm run test:e2e`. The tests drive a RUNNING instance with headless
    Chromium and assert the RENDERED DOM (not HTTP):
      1. view-code scrolls the evidence line INTO the code viewport (geometry check — the exact RUN 29
         regression: a focus row that renders but sits below the scroll body).
      2. a Mach-O opens to its searchable extracted STRINGS, not a dead "no source" card.
      3. the finding drawer renders a Why-Dangerous narrative and a non-firebase finding never borrows
         the "Permissive Firebase rules" text (the RUN 29 categorizer false-match symptom).
    Robust: the suite SKIPS cleanly when no stack/scan is reachable (health check + env gating:
    E2E_BASE_URL / E2E_SCAN / E2E_IPA), so it never fails a build spuriously.
    ACTUALLY RUN (not just written): against a live iOS scan -> 3/3 PASS; against a live Android scan
    -> 2 PASS + 1 SKIP (the Mach-O test correctly N/A for Android); with the stack down -> 3 SKIP.
    L6 status: was "frontend view-code/scroll has NO regression test". NOW: a real e2e harness exists
    and is wired to `npm run test:e2e`. L6 -> substantially CLOSED for the view-code/strings/narrative
    surface; broader component coverage remains optional.
    No app code changed — presentation/test tooling only. iOS 14/92/B, Android 47/34/F unaffected.
    Files: frontend/e2e/smoke.spec.mjs, frontend/e2e/README.md, frontend/playwright.config.mjs,
      frontend/package.json, frontend/package-lock.json, frontend/.gitignore.
    Commit-ready: Y

═══════════════ TIER 3 — MobSF PARITY · FP ELIMINATION (RUN 31–36) ═══════════════

[x] RUN 31 — Kill the command-injection FP + taint label honesty (ANDROID)  DONE
    HOUSEKEEPING (a) — NO-OP, the prompt's premise was stale: there is NO 0-byte
      checkin-ios-normal.ipa. Not on disk, never in git history, and zero references in
      backend/ frontend/ scripts/ *.md *.json. The only two hits in the repo are the
      housekeeping instruction inside BEETLE_PROMPTS.md itself. Nothing deleted/repointed.
    HOUSEKEEPING (b) — baselines captured in baseline/ (JSON + PDF + BASELINE_SUMMARY.json).
      VERIFIED FIRST that the running container's BAKED code was byte-identical to repo HEAD
      (md5 on taint_analyzer / android_analyzer / main.py) — otherwise the "before" set is a lie.
        ib2_v140     23/F  55 findings  C3/H7/M13/L6/I26
        ishop_v140   34/F  47 findings  C1/H11/M8/L7/I20
        checkin_ios  92/B  14 findings  C0/H0/M4/L2/I8   <- iOS guard confirmed

    CONFIRM-GATE — THREE PROMPT FACTS WERE WRONG, verified against live source before editing:
      (a) TWO root-detection findings exist, not one — android_no_root_detection (code_rules.py:592)
          and android_runtime_exec (reclassified at finding_model.py:983, security_control=True).
          Both INFO, both at sources/com/android/insecurebankv2/PostLogin.java:26.
      (b) *** THE PROMPT'S FIX A COULD NOT WORK AS WRITTEN. *** It said to drop an Execution flow
          whose "sink call-site file:line" coincides with a defensive-control finding. THE TAINT
          FLOW HAS NO file AND NO line. reconcile_taint_flows:634 synthesizes them:
              "file": flow.get("file") or flow.get("class_name")  -> "com.android.insecurebankv2.PostLogin;"
              "line": flow.get("line") or 0                        -> 0
          A class name with a trailing semicolon at line 0 can NEVER string-match the finding's
          "sources/com/android/insecurebankv2/PostLogin.java":26. Implementing it literally yields a
          veto that NEVER FIRES — green tests, FP still in the artifact. Reported; human rejected the
          file:line join and the class-granular fallback (would drop a TP) and directed the
          constant-argument guard instead.
      (c) "PROVEN" is NOT in taint_analyzer.py. The badge is attack_chains/engine.py:65 + :501
          (field reachability_proof), rendered at pdf_generator.py:478. The "Reachable: YES (HIGH)"
          label originates at trust_engine.py:84-86.
      GROUND TRUTH (real jadx source, NOT the prompt): exec is at PostLogin.java:26 with
      "/system/xbin/which" (prompt said :132 / "/system/bin/which"); the source is at :64 (prompt
      said :47). MobSF's "92%" is overall_exploitability; overall_confidence is 85. Substance identical.

    FIX A — CONSTANT-ARGUMENT GUARD (taint_analyzer.py). Feasibility PROVEN with androguard against
      the real APK before writing a line: MethodAnalysis.get_xref_from() yields (class, caller, byte
      offset), and the instructions at that offset decide it outright —
        FP  PostLogin->doesSUexist @40: new-array + aput-object of const-string "/system/xbin/which"
            and "su" -> invoke Runtime.exec(v6)          => arg PROVABLY constant  => DROP
        TP  ViewStatement->onCreate @246: move-result-object (StringBuilder.toString) => NOT constant => KEEP
        TP  MyWebViewClient->shouldOverrideUrlLoading @0: arg is a method PARAMETER  => NOT constant => KEEP
      NOTE the exec lives in doesSUexist, NOT onCreate — the flow's method_name is the SOURCE method,
      so no class/method join was ever available. Only a call-site analysis could work.
      The guard drops an Execution flow ONLY when every reachable call site of that sink passes args
      provably from const* opcodes (directly, or an array built entirely of const* values). It is
      FAIL-OPEN by construction: a parameter, a move-result, a field read, or an unreadable call site
      all KEEP the flow. It can remove an FP; it can never drop a TP.
      Suppression is NOT silent: scan_metrics.taint_execution_flows_dropped_const_arg = 1 on IB2.

    FIX B — LABEL HONESTY. New proof class PROOF_REACHABLE = "method-reachable", ranked
      proven > method-reachable > heuristic > manifest-only. A taint flow is a CALL-GRAPH BFS with no
      def-use check: it shows the source-calling method can REACH the sink-calling method, never that
      the tainted value arrives. So:
        - engine.py reachability_proof() now returns PROOF_REACHABLE, never PROOF_PROVEN.
          PROOF_PROVEN is now UNREACHABLE ON PURPOSE — reserved for a future def-use pass (kept
          defined so the badge + ranking survive that upgrade).
        - The RUN 25 MEDIUM cap now covers method-reachable too (_UNPROVEN_DATAFLOW): an unproven
          data-flow must never present as a HIGH/CRITICAL exploit.
        - trust_engine.py:84-86 returned HIGH ("fully proven path") for ANY call_chain -> now MEDIUM,
          plus a new reachability_basis = "method-reachable (data-flow not proven)".
        - Wired every consumer: pdf badge (REACHABLE, amber — never reads "PROVEN"), analyst_intel
          _PROOF_PHRASE + fp_note, workspaces.py proof checklist (does NOT tick the data-flow box,
          DOES count as reachability support).
      DELIBERATELY NOT collapsed into "heuristic": a call-graph link is real evidence and stronger
      than bare co-occurrence. Collapsing them would understate — a different dishonesty.
    FRONTEND: NO CHANGE NEEDED. The "Reachable: YES (HIGH)" string at workspace/SectionViews.jsx:555
      is a DEAD RENDER PATH — the file is imported by Results.jsx:40 but `<SectionViews` is never
      mounted (only <Workspace/> workspace2 renders). Live UI shows only "Reachable" via
      reachabilityLabel(), which makes no proof claim. (Corrects a stale note that called the file
      tree-shaken: it IS bundled, just never rendered.)

    ARTIFACT VERIFICATION (real reports, not tests). A VirusTotal HIGH first appeared in the after-scan
      — PROVEN ENVIRONMENTAL, not RUN 31: baseline ran with virustotal.api_key_set=false ("not
      configured"), and the recreated container picked up VIRUSTOTAL_API_KEY from .env. Re-ran the
      after-scan with VT disabled so both sides share the same env. CLEAN LIKE-FOR-LIKE:
        InsecureBankv2  55 -> 53 findings, C3 -> C1, score 23 -> 35 (grade F held)
          REMOVED (both FPs, nothing else): CRITICAL "Attack Chain: Exported Component to Command
            Injection" and CRITICAL "Taint Flow: Intent.getStringExtra -> Runtime.exec"
          ADDED: NONE.  H/M/L/I counts, chain_penalty (20) and bonuses all IDENTICAL.
          SCORE FULLY ATTRIBUTED: the ONLY changed term is the critical deduction 27.5 -> 15.0
            (3 criticals -> 1). 80.23 - 67.73 = 12.50 = exactly that delta.
          TRUE POSITIVES SURVIVE: taint flows 13 -> 12 (only the exec flow dropped); WebView.loadUrl
            + all 6 crypto flows KEPT. 0 Execution flows remain (the only one was the FP).
          "Root Detection Present" INFO STILL FIRES on PostLogin.java:26 (both rule_ids).
          Surviving WebView taint finding now reads reachability_confidence MEDIUM +
            basis "method-reachable (data-flow not proven)" (was HIGH, "fully proven").
        InsecureShop    47 findings, C1/H11/M8/L7/I20, score 34/F — IDENTICAL. 0 Execution flows
          before AND after (nothing to lose), const-arg dropped = 0, all 6 chains unchanged.
        testapp.ipa     14 findings, 92/B — IDENTICAL. iOS never runs taint_analyzer (androguard-only),
          so iOS is untouched by construction as well as in fact.
    HONEST GAP: no chain in EITHER app now carries "method-reachable" in the artifact — IB2's only
      taint-backed injection chain WAS the FP (now gone) and the rest are manifest-only/heuristic. So
      the new badge/phrase is exercised by unit tests, NOT by a live artifact on this corpus. The
      trust_engine relabel IS live (the WebView finding). Re-check the badge on an app with a real
      taint-backed injection chain.
    Files changed: backend/analyzers/taint_analyzer.py, backend/analyzers/trust_engine.py,
      backend/analyzers/attack_chains/engine.py, backend/analyzers/analyst_intel.py,
      backend/analyzers/workspaces.py, backend/report/pdf_generator.py,
      NEW backend/tests/test_taint_const_arg_guard.py (12 tests, BOTH directions),
      backend/tests/test_chain_reachability.py (2 tests re-locked to the honest contract).
    Tests: 924 passed, 11 skipped (was 912).
    Commit-ready: Y  (committed 688060f on main — human confirmed; a stray `@` from a PowerShell
      here-string leaked into the first commit message and was amended out.)

[x] RUN 32 — StrandHogg 2.0 (platform-gated) with calibrated severity + grouping (ANDROID)  DONE
    HOUSEKEEPING carried from RUN 31: baseline/ + after_run31/ added to .gitignore (scan artifacts,
      regenerable, large). Did not commit them.
    CONFIRM-GATE — verified before edit:
      - Detector at _process_component (android_analyzer.py:1527); StrandHogg 1.0 block at :1765 fires
        only on non_default_affinity or risky_launch. On IB2, ZERO such findings in baseline — 1.0 is
        correctly silent, so a 2.0 rule is purely additive.
      - target_sdk is reachable: _parse_manifest (sets app_info.target_sdk) runs at :423, BEFORE
        _analyze_components at :424. IB2 target_sdk=22 (<29).
      - is_launcher + label are LOCALS in _process_component, NOT in comp_info — a post-loop grouped
        pass can't see them. Persisted is_launcher into comp_info (1 line).
    *** THE PROMPT CONTRADICTED ITSELF — reported, owner adjudicated before edit. ***
      Real manifest: IB2 has 5 exported activities (LoginActivity is exported-BY-DEFAULT via its
      MAIN/LAUNCHER filter; the other 4 are exported="true"). Prompt said "4 rows" — a miscount.
      Applying the FIX's OWN keyword rule {login,auth,payment,transfer,pin} OR launcher to the real
      names gives the OPPOSITE of the prompt's VERIFY table for two activities: DoTransfer=HIGH (via
      'transfer', not MEDIUM) and ChangePassword=MEDIUM ('password'/'change' are NOT in the set, not
      HIGH). Owner ruling: SCOPE = all 5 (incl. launcher — StrandHogg 2.0 applies to any exported
      activity; the launcher is a prime overlay target). SEVERITY = keep the keyword rule as written;
      do NOT edit the list to match the (erroneous) VERIFY table. Rule-derived result:
        LoginActivity HIGH(launcher) · PostLogin HIGH(login) · DoTransfer HIGH(transfer) ·
        ViewStatement MEDIUM · ChangePassword MEDIUM   -> 5 rows, 3 HIGH / 2 MEDIUM.
    FIX: new _detect_strandhogg2(results), called once after the component loop in _analyze_components.
      Gate: target_sdk parsed via _sdk_int(); fires only when known AND <29 (unknown/'?' never fires —
      absence of evidence, not vulnerability). Iterates attack_surface.activities, keeps exported,
      computes per-row severity (sensitive-name OR launcher -> HIGH), emits ONE grouped finding
      (rule_id manifest_strandhogg2) with N rows in strandhogg2_activities + the enumerated
      description. cwe CWE-926 / masvs MASVS-PLATFORM-1 / owasp M1 / cve CVE-2020-0096; remediation
      "Set targetSdkVersion >= 29". Evidence anchored via manifest_evidence_spec {targetSdkVersion:22}
      -> resolves to AndroidManifest.xml line 2 (the exact attribute the fix changes). Kept the 1.0
      rule untouched (separate, and it does not fire here anyway); the 2.0 keyword set is a NEW local
      constant, so 1.0 behaviour on other apps is unchanged.
    *** ARTIFACT VERIFICATION CAUGHT AN FP I INTRODUCED — then fixed it. *** First regenerated IB2
      showed +2 findings: the StrandHogg finding (expected) AND a bogus CRITICAL-class attack chain
      "Dynamic Code Loading / Reflection RCE". Proven deterministic (two rescans identical) and traced
      to MY finding: the chain's required_findings was my StrandHogg finding's canonical_id. ROOT CAUSE
      — attack_chains/engine.py:213-214 tags CODE_LOADING on a BARE PROSE SUBSTRING ("reflection" in
      blob), and my description said "reflection-based task hijacking". StrandHogg 2.0 is task hijacking,
      NOT code loading -> category-error chain. FIX (scoped to my new finding, zero regression risk):
      reworded the description to drop the "reflection" token ("hijack the task and overlay..."). The
      shared tagger's over-broad prose match is a REAL latent bug but out of scope here (a shared-engine
      change needs its own both-directions proof vs InsecureShop's legit RUN 25 Reflection chain) —
      LOGGED FOR RUN 35 (mislabel sweep). Added a regression test asserting the StrandHogg finding is
      NOT tagged CODE_LOADING, so the FP cannot silently return.
    ARTIFACT (final, VT off both sides — same env-confound control as RUN 31):
      InsecureBankv2  53 -> 54 findings (+1: ONLY the grouped StrandHogg HIGH). ADDED: nothing else.
        REMOVED: nothing. Chains IDENTICAL to RUN 31 (4 -> 4; the bogus chain is gone). Severity
        H7 -> H8, all other counts unchanged. Score 35 -> 34 (F held), fully attributed: high
        deduction 20.74 -> 21.74 (+1.00), chain_penalty 20 -> 20, bonuses identical. 5-row card:
        LoginActivity/PostLogin/DoTransfer HIGH, ViewStatement/ChangePassword MEDIUM; evidence on
        AndroidManifest.xml:2; remediation cites targetSdk>=29 + CVE-2020-0096.
      InsecureShop (NEGATIVE GATE)  targetSdk=29 -> StrandHogg does NOT fire. 47 findings / 34 F —
        BYTE-IDENTICAL, delta NONE. Gate proven both ways.
      testapp.ipa  targetSdk=None (iOS) -> does not fire. 14 findings / 92 B — IDENTICAL, delta NONE.
    Files changed: backend/analyzers/android_analyzer.py (persist is_launcher into comp_info; new
      _STRANDHOGG2_* constants, _sdk_int(), _detect_strandhogg2(); call after the component loop);
      NEW backend/tests/test_strandhogg2.py (11 tests: both gate directions + calibration + the
      CODE_LOADING FP guard).
    Tests: 935 passed, 11 skipped (was 924).
    Commit-ready: Y  (committed dc1bf87 on main; message written via file to avoid the here-string
      `@` pitfall from RUN 31.)

[x] RUN 33 — Trackers: class-inventory matching surface + confidence tiers (ANDROID)  DONE
    CONFIRM-GATE — the prompt's root-cause description was PARTLY WRONG; verified against live source:
      - Two callers of detect_trackers: android_analyzer.py:840 (primary results["trackers"]) and
        :2022 (SDK list). iOS uses detect_trackers_ios (untouched) — scope boundary confirmed.
      - The matched set is NOT a "pre-categorized SDK set": it is package_hints from
        _collect_package_hints (2070), which is MANIFEST/component-derived. On IB2 it has 44 entries,
        ALL from the manifest — AdMob matched ONLY because AdActivity is manifest-declared.
      - There is NO existing full class inventory and NO dx.get_classes() on the Android path (only
        taint_analyzer has its own AnalyzeAPK). The prompt's "a full class list already exists" is
        inaccurate. Proven with androguard on the real APK: IB2's DEX has 118 analytics + 193
        tagmanager classes that package_hints entirely misses (they are statically linked, never
        declared) — THAT is why Beetle found 1, MobSF 3.
      - jadx DID decompile analytics/tagmanager dirs, but the tree-walk that would harvest them never
        contributed (package_hints was manifest-only for IB2) — so the fix must read the DEX, not rely
        on the walk.
    FIX (three parts, Android path only):
      1. tracker_db.py — schema gains optional code_signature (regex on dotted class name) + domain.
         Added Google Analytics + Google Tag Manager signatures; added domains to AdMob / Firebase
         Analytics / Crashlytics / Facebook. TODO left for full 432-entry Exodus ingest.
      2. detect_trackers(package_names, class_names=None, endpoints=None): matches signature pkg
         (and code_signature) against the FULL DEX class inventory, keeping the manifest-prefix path
         as fallback. Backward compatible (both new args optional; iOS unaffected).
      3. Confidence tiering: code-class match + domain seen in results["endpoints"] => "confirmed";
         class/prefix only => "likely". matched_class + domain attached as evidence (list of {type}).
      Inventory sourced by _collect_dex_classes(apk) in android_analyzer.py — a DEX class-TABLE read
      (androguard DEX.get_classes_names on apk.get_all_dex bytes), ~2s, NOT a decompile/AnalyzeAPK
      pass. Stashed transiently as results["_dex_classes"]; the primary caller pop()s it and a
      defensive pop at finalize guarantees it never serializes (would be 6.5k class names).
      Rendering: PDF _trackers_section Linkage column falls back to the confidence tier when
      statically_linked is absent (iOS keeps statically_linked -> byte-unchanged). Frontend
      panels2.jsx tracker row shows a colored confidence badge + the matched class.
    *** DETERMINISM BUG CAUGHT IN VERIFICATION *** The first matched_class was `next(c for c in
      class_names ...)` over a SET — non-deterministic order, so matched_class drifted run-to-run
      (e.g. ...analytics.internal.zzw vs ...AnalyticsReceiver) and would break the Android byte-stable
      guard. Fixed to min() over ALL matches: deterministic AND surfaces a clean public class. Proven:
      two consecutive IB2 scans now produce BYTE-IDENTICAL tracker output. Locked with a test.
    ARTIFACT (VT off both sides):
      InsecureBankv2  detect_trackers returns 5: Google AdMob, Google Analytics, Google Tag Manager,
        Google Maps SDK, Google Sign-In. SPOT-CHECKED each in the DEX (analytics 118 / tagmanager 193 /
        ads 288 / maps 275 / auth 55 classes) — all real classes (IB2 statically links the monolithic
        play-services), so none is a false match.
        *** AXIS CORRECTION (human, post-commit) — do NOT read this as "5 trackers beats MobSF's 3". ***
        On the Exodus-comparable definition (analytics/advertising/attribution that phone home) Beetle
        finds 3 — AdMob + Analytics + Tag Manager — which MATCHES MobSF's 3, plus confidence tiering
        MobSF lacks. Google Maps SDK and Google Sign-In are BUNDLED FUNCTIONAL SDKs, not Exodus
        trackers; counting them on the same axis inflates the number. They are correct SDK detections
        (and the SDK-list caller rightly lists them), but the report must label "tracker (Exodus)" vs
        "bundled SDK" so the tracker count reads as 3, not 5. That label/rendering split is a
        shared-surface change (frontend panels2 + PDF) -> DEFERRED TO RUN 35 (mislabel sweep). See the
        RUN 35 TODO below.
        All 5 are "likely" (IB2 has 0 endpoints, so no domain corroboration is possible — the honest
        tier). findings 54->54, score 34->34 (trackers emit no findings — no regression). SDK list
        caller consistent: same 4 new real SDKs added.
      InsecureShop (NEGATIVE / no-FP direction)  trackers 0 -> 0. *** PROMPT EXPECTATION WRONG: it
        said "expect Firebase/Crashlytics". The real classes.dex has NEITHER — its com.google.* is
        Material UI (517) + Gson (128); zero firebase/gms/crashlytics/facebook. detect_trackers on the
        real inventory returns [] — CORRECT no-FP behavior, not a miss. findings/score byte-identical.
      testapp.ipa  iOS trackers BYTE-IDENTICAL (9->9), findings 14->14, score 92/B. iOS uses
        detect_trackers_ios (untouched) — unchanged by construction and in fact.
    HONEST GAP: the "confirmed" tier is not exercised by a live artifact on this corpus (IB2 has 0
      endpoints; InsecureShop has no trackers). It is unit-tested. Re-check on an app that both
      bundles a tracker SDK and emits its domain as an endpoint.
    Files changed: backend/analyzers/tracker_db.py (import re; GA/TagManager sigs + domains; rewritten
      detect_trackers with class/endpoint args + tiering + deterministic min match),
      backend/analyzers/android_analyzer.py (_collect_dex_classes; stash/pop transient; both callers),
      backend/report/pdf_generator.py (Linkage confidence fallback),
      frontend/src/components/workspace2/panels2.jsx (confidence badge + matched class),
      NEW backend/tests/test_tracker_class_matching.py (11 tests: surface fix, tiering, no-FP,
      determinism, iOS-guard).
    Tests: 946 passed, 11 skipped (was 935). Frontend build OK.
    Commit-ready: Y  (committed 69197a5 on main; axis correction committed a29347d.)

[x] RUN 34 — APKID parity + context-aware Janus severity (ANDROID)  DONE — SHIPPED PART B ONLY
    *** THE PROMPT'S PART A PREMISE WAS FALSE, AND "MATCHING MobSF" WOULD HAVE IMPORTED AN FP. ***
    CONFIRM-GATE + investigation (all verified against live source + the real DEX/jadx):
      - apkid is NOT installable here (host py3.14 has no yara-python-dex wheel; the report container
        is read-only and apkid is intentionally not a baked dep). So a real-apkid CLI path could never
        be verified on an artifact — an unverifiable liability.
      - "Beetle has no packer/anti-analysis layer" is FALSE. api_analyzer.py:225 detect_apkid_features
        is an existing regex "Mimics APKiD behaviour without requiring the tool" that already populates
        results["apkid"] (anti-VM Build.* / anti-debug / packer / compiler) on every Android scan
        (wired at android_analyzer.py:606). The data was just never rendered or turned into findings.
      - So the apparent gap was "surface the data", not "add an engine". I built that (build_apkid_
        findings + PDF section) — then the REAL ARTIFACT killed it:
      - *** MobSF's anti-VM on IB2 is a LIBRARY-CODE OVER-MATCH. *** Ground truth: IB2 references
        Build.MODEL/MANUFACTURER/DEVICE, but in ZERO app-owned files — every hit is in bundled
        play-services/AndroidX. InsecureShop the same (Build.* only in Material/Glide). NEITHER app
        has emulator-telltale strings (goldfish/ranchu/qemu/google_sdk = 0 in both). So neither app's
        OWN code does anti-VM; both just let libraries read device info. Emitting an anti-VM finding
        (even hedged INFO) would flag LIBRARY behaviour as app behaviour — a false positive by Beetle's
        own ownership discipline (RUN 8/9/25), and exactly the "copy MobSF's FP-driven output" the
        project forbids. The existing results["apkid"] on this corpus is entirely library-owned or
        noise (the "R8" label is itself an FP — no R8 marker in IB2's dex, confirmed).
      DECISION (human-ratified): SHIP PART B ONLY. Drop Part A entirely — do NOT ship the surfacing
      (would import the FP) and do NOT ship dormant app-owned-restricted plumbing (verified only by
      "it correctly emitted nothing" = the tests-not-artifact trap). Reverted apkid_engine.py,
      build_apkid_findings, the PDF _apkid_section, and all wiring. detect_apkid_features itself was
      never modified.
    PART B — CONTEXT-AWARE JANUS SEVERITY (shipped, verified on the real artifact):
      cert_analyzer.py cert_v1_signature_only: was blanket MEDIUM. Now gated via _janus_severity() on
      whether minSdk reaches the Janus-vulnerable OS range (Android 5.0–8.0 / API 21–26, fixed in
      8.1/API 27): minSdk <= 26 (or unknown) -> HIGH; minSdk >= 27 -> MEDIUM. Each carries a
      severity_reason naming the concrete range + value. IB2 minSdk=15 -> HIGH (justified). Neither
      MobSF's blanket-HIGH nor Beetle's old blanket-MEDIUM; more correct than both.
      low_min_sdk enrichment: kept MEDIUM, named the concrete pre-5.0 OS risks (unpatchable browser-
      engine RCE, no SELinux/FDE, install-time permissions, v1/Janus, weak TLS). REWORDED to drop the
      literal "WebView"/"addJavascriptInterface" tokens — my first draft of that text tripped the
      chain capability tagger (the RUN 32 keyword-contamination class) and spawned a bogus "WebView
      JavaScript Bridge RCE" chain with low_min_sdk as a required member. Reword removed it.
    ARTIFACT (VT off both sides):
      InsecureBankv2  findings 54->54, score 34/F held. ONLY delta: Janus MEDIUM->HIGH (severity
        H8->H9, M13->M12). ADDED/REMOVED findings: NONE. Chains IDENTICAL to RUN 33 (WebView chain did
        NOT appear — reword worked). No APKID findings, no APKID section (Part A dropped).
      InsecureShop  47 findings / 34 F — byte-stable. No Janus finding (v2-signed, gate doesn't fire).
        low_min_sdk reworded (no WebView token); chains IDENTICAL (no spurious chain here either).
      testapp.ipa  14 / 92 B — unchanged (cert_analyzer + low_min_sdk are Android-only).
    COMPARISON DATA POINT (for the MobSF write-up): "MobSF flags anti-VM on IB2 by matching library
      Build.* access; Beetle's ownership filter is correctly silent — MobSF FPs, Beetle is precise."
    Files changed: backend/analyzers/cert_analyzer.py (_janus_severity + gated finding),
      backend/analyzers/android_analyzer.py (low_min_sdk enriched+reworded description),
      NEW backend/tests/test_janus_context_severity.py (6 tests: range gate both directions + reason).
    Tests: 951 passed, 11 skipped.
    Commit-ready: Y

═══════════════ RUN 35 — FP/mislabel sweep (R35-A done; T1–T3 + R35-B pending) ═══════════════
[x] R35-A  Chain tagger prose over-match — FIXED (own commit).  ANDROID+shared (iOS proven no-drift).
    ROOT CAUSE (confirmed): tag_capabilities (attack_chains/engine.py) added WEBVIEW on
    `"webview" in blob` and CODE_LOADING on `"dexclassloader"/"dynamic code"/"reflection" in blob` —
    bare prose substrings of a finding's title/description. RUN 32 (StrandHogg "reflection-based" ->
    Reflection RCE) and RUN 34 (low-minSdk naming "WebView"/"addJavascriptInterface" -> WebView Bridge
    RCE) both formed bogus chains this way; both had been worked around by rewording, leaving the root
    cause live.
    BOTH-DIRECTIONS TENSION (the user flagged, confirmed real): InsecureShop's legit RUN 25 chain
    requires android_reflection ("Java Reflection Usage") — which has NO reflection taint-sink and
    category "Code Quality", so it earned CODE_LOADING ONLY via the prose "reflection" match. Deleting
    the prose match naively would have killed the true positive.
    FIX: tag by IDENTITY, not prose. CODE_LOADING now requires a taint sink in
    {reflection,dynamicloading} OR rule_id in {android_reflection, android_dex_class_loader,
    behavior_dynamic_class_and_dexloading} OR category "Dynamic Code Loading". WEBVIEW now requires
    category "webview" OR a webview rule_id prefix (android_webview/ios_webview/ios_wkwebview) OR a
    WebView taint sink. android_insecure_deserialization (adjacent in the rule table) is explicitly
    NOT swept in. The genuine reflection/webview RULES keep the capability; a prose-only mention never
    earns it.
    VERIFY (both directions, real artifacts):
      InsecureShop: chains BYTE-IDENTICAL — "Dynamic Code Loading / Reflection RCE" AND "Deep Link to
        WebView File Disclosure" both SURVIVE (android_reflection tags by rule_id; webview by category).
        47 findings / 34 F unchanged.
      InsecureBankv2: chains identical, no bogus Reflection/WebView chain, 54 findings / 34 F unchanged.
      testapp.ipa: chains identical, 92/B — no iOS drift (shared engine).
      Unit tests lock the mechanism so the FP CANNOT recur: a StrandHogg-like ("reflection-based" prose,
      manifest_strandhogg2 rule) and a low-minSdk-like ("WebView/addJavascriptInterface" prose,
      manifest_low_min_sdk rule) earn NO CODE_LOADING/WEBVIEW; the genuine rules still do.
    Files: backend/analyzers/attack_chains/engine.py (tag_capabilities + 2 identity constants),
      NEW backend/tests/test_capability_tagger_identity.py (12 tests, both directions).
    Tests: 962 passed, 11 skipped. Commit-ready: Y.

[x] T1–T3  FP/mislabel sweep (crypto + SQLi) — DONE (own commit).  ANDROID (crypto/SQLi); iOS no-drift.
    Prompt line numbers were off (said key @:25, IV @:28); used LIVE source: CryptoClass.java key
    literal @:21, all-zero IV @:22, CBC @:27.
    T1 — "User-Controlled Data in Crypto Operation" was HIGH noise. Reaching a crypto API with user
      data is the NORMAL use of crypto, not a weakness (a user IV is public; user plaintext is the
      point). taint_analyzer._calibrate_severity now returns LOW for Crypto sinks, and _flow_to_finding
      reframes the crypto flow as CONTEXT that points at the structural crypto findings. The genuine
      weaknesses are detected STRUCTURALLY and SURVIVE: Hardcoded Key (CRITICAL), CBC Padding Oracle
      (MEDIUM), Base64-as-encryption (LOW). Verified on the IB2 artifact.
    T2 — "Hardcoded Encryption Key" (CRITICAL) had the right conclusion but its greedy multiline
      pattern put evidence on the SecretKeySpec usage line (26). New code_analyzer.refine_hardcoded_
      key_evidence (post-SAST, BEFORE evidence_selection) repoints it to the key STRING LITERAL —
      IB2 now CryptoClass.java:21, snippet `String key = "This is the super secret key 123";`, masked
      value surfaced via secret_intel.mask_value. Followed the CONSUMER-FIELD RULE: updated
      file_evidence[*].lines (the field the code viewer reads), not just f.line.
    T3 — "Exported Component to SQL Injection" chain was built on a SQL step whose OWN evidence reads
      "Raw SQL Query (Parameterized) — No Injection Evidence" (self-contradiction). tag_capabilities no
      longer grants SQL_SINK to a finding proven parameterized (sql_injection_evidence startswith
      "parameterized" / severity_downgraded_reason "parameterized raw query"), so the chain can't form.
      A REAL SQLi finding (string-building / taint-reaching) is unaffected and its chain still forms.
    ARTIFACT (VT off both sides):
      InsecureBankv2  findings 54->53 (SQLi FP chain dropped); score 34->40/F (grade held) — fully
        attributed to FP removal: HIGH 9->8 (T1 crypto), MEDIUM 12->11 + chain_penalty 20->15 (T3);
        CRITICAL held (T2). Crypto taint now LOW @ DoTransfer.java:78; key evidence @ CryptoClass:21;
        no SQLi chain; genuine crypto findings all survive.
      InsecureShop  47 findings / 34 F — UNCHANGED. No crypto taint, no hardcoded key, no
        parameterized-SQL chain -> T1–T3 correctly no-op. Chains identical; nothing suppressed.
      testapp.ipa  14 / 92 B — chains identical, no iOS drift (iOS runs no taint; T2 Android-only;
        shared tag_capabilities change touches only parameterized-SQL, which iOS has none of).
    Files: backend/analyzers/taint_analyzer.py (crypto calibration + reframed description),
      backend/analyzers/code_analyzer.py (refine_hardcoded_key_evidence + _KEY_LITERAL_RE),
      backend/analyzers/android_analyzer.py (wire T2 call), backend/analyzers/attack_chains/engine.py
      (parameterized-SQL SQL_SINK guard), NEW backend/tests/test_run35_fp_sweep.py (10 tests).
    Tests: 972 passed, 11 skipped. Commit-ready: Y.

[x] R35-B  Tracker vs bundled-SDK label split — DONE (own commit).  ANDROID data + shared render;
    iOS byte-stable.
    detect_trackers now stamps each hit with kind = classify_tracker_kind(category): "tracker" for
    behavioural/analytics/ad/crash/attribution/session/social/push/tag-management categories, "sdk"
    for functional SDKs (Maps, Identity/Sign-In, Payments, App Updates, Background Work, ML/AI, Debug).
    Frontend panels2.jsx + PDF _trackers_section render the split: the "Trackers" count/section shows
    only kind=tracker; a "Bundled SDKs (detected, not trackers)" subsection lists the rest with a note.
    iOS trackers (from detect_trackers_ios, untouched) carry NO kind -> treated as trackers -> iOS
    output byte-unchanged by construction.
    ARTIFACT (VT off):
      InsecureBankv2  trackers now read 3 (Google Analytics, Tag Manager, AdMob) + 2 bundled SDKs
        (Google Sign-In, Google Maps SDK) — the count reads 3 (= MobSF's tracker axis), no longer the
        misleading 5. All 5 still detected and shown; only the labelling/count changed.
      testapp.ipa  iOS trackers BYTE-IDENTICAL (no kind field), 14 / 92 B unchanged.
      InsecureShop  0 trackers, 47 / 34 F unchanged.
    Files: backend/analyzers/tracker_db.py (classify_tracker_kind + kind on each hit),
      frontend/src/components/workspace2/panels2.jsx (split render + tracker-count metric),
      backend/report/pdf_generator.py (_trackers_section split), backend/tests/test_tracker_class_matching.py
      (+2 tests: classifier + IB2 3-vs-2 split).
    Tests: 974 passed, 11 skipped; frontend build OK. Commit-ready: Y.
    NOTE (L6): the frontend split is verified by build + the data-level 3/2 split, not by an automated
    render test — same standing frontend-test gap. The Playwright smoke suite (RUN 30) could gain a
    tracker-count assertion in a future pass.  *** DONE in RUN 36 (see below) — L6 now CLOSED. ***

[x] RUN 36 — Self-audit + discovery (verify every finding, find more, no new FPs)  DONE
    PART 1 — PER-FINDING GROUND-TRUTH AUDIT (every finding, both apps, opened at file:line vs source):
      InsecureBankv2 (53) + InsecureShop (47) = 100 findings audited. VERDICT: NO false positives in
      either app after five runs of fixes. All app-owned HIGH/CRITICAL valid; ~46 INFO findings in
      obfuscated/library code (zz*.java, gms, androidx, Firebase) are correctly demoted library-noise
      (not FPs, not inflating severity). Defects found: (a) IB2 credential logging under-rated LOW;
      (b) IB2 SMS-exfil taint linkage missed; (c) minor: behavior_get_cell_information anchored on an
      IMPORT line (wrong-line, cosmetic INFO — logged, not fixed).
    PART 2 — KNOWN GROUND TRUTH: hardcoded key ✓ (CRITICAL, CryptoClass:21 post-T2), AES/CBC ✓,
      credentials-logged ✓ (but under-rated), ContentProvider ✓ (RUN 35 T3), allowBackup/debuggable/
      exported/root-detection ✓. MISS: hardcoded ALL-ZERO IV (CryptoClass:22) — android_weak_iv
      pattern `IvParameterSpec(new byte[` doesn't match `byte[] ivBytes = {0,..}` passed by variable;
      logged as a follow-up (needs a name-based byte-array pattern to avoid FPs).
    PART 3 — RANKED MISSED TRUE-POSITIVES (with source proof) + surgical fixes:
      FIX 1 (missed TP) — IB2 SMS exfil taint flow. MyBroadCastReceiver.java:17-18 reads
        intent.getStringExtra("phonenumber"/"newpass") -> :31 SmsManager.sendTextMessage, via an
        EXPORTED receiver. SmsManager was only a taint SOURCE (getMessageBody); added
        sendTextMessage/sendMultipartTextMessage as SINKS (cat "SmsSend", HIGH), wired _SINK_META /
        _HIGH_VALUE_SINKS / finding_model _HIGH_VALUE_TAINT_SINKS + group title + explainers. Now
        emits TAINT-SMSSEND "User-Controlled Data Sent via SMS" HIGH with the full Intent→SMS linkage.
      FIX 2 (wrong-severity) — IB2 credential logging. DoLogin.java:136 `Log.d("Successful Login:",
        …username + ":" + password)`. refine_credential_logging_severity bumps android_log_debug to
        MEDIUM + retitles "Plaintext Credentials Logged" when a credential-named VALUE is logged
        (matched after '+'/',' so a mere UI-string mention does not trip it).
      FOLLOW-UPS logged (not fixed — pattern/FP risk or needs deeper analysis): hardcoded all-zero IV;
        InsecureShopProvider returning username+password via MatrixCursor (exported, weak custom
        readPermission — needs protection-level analysis); MBR:30 System.out.println password leak
        (println not matched by Log.* rules); behavior_get_cell_information import-line anchor.
    ARTIFACT (VT off both sides) — COVERAGE UP, FPs DOWN/UNCHANGED (the CLOSING guarantee):
      InsecureBankv2  53 -> 54 findings. ADDED: TAINT-SMSSEND (HIGH, real missed TP). CHANGED: the
        credential log LOW -> MEDIUM (retitled). score 40 -> 39 (more real risk surfaced). Chains
        IDENTICAL (the SMS finding creates no bogus chain).
      InsecureShop  47 / 34 F — BYTE-UNCHANGED. No SMS usage (SMS sink can't FP), LoginActivity:84
        log is username-only -> stays LOW (credential bump correctly not tripped). Chains identical.
      testapp.ipa  14 / 92 B — unchanged (taint is androguard-only; credential-log is Android).
    L6 CLOSED: added two real-render Playwright assertions to frontend/e2e/smoke.spec.mjs and RAN them
      against a live InsecureBankv2 scan (headless Chromium): (1) the Malware panel renders 3 trackers
      with Google Maps SDK + Sign-In split into a "Bundled SDKs (not trackers)" section — the tracker
      count is NOT inflated to 5; (2) attack-chain cards render their real name + a severity label.
      Full smoke suite vs live IB2: 4 passed / 1 skipped (Mach-O = iOS-only). The last data-not-pixels
      surface is now pixel-verified.
    Files: backend/analyzers/taint_analyzer.py (SMS sink + meta + explainers),
      backend/analyzers/finding_model.py (SMS group title + value gate),
      backend/analyzers/code_analyzer.py (refine_credential_logging_severity + _CREDENTIAL_LOG_RE),
      backend/analyzers/android_analyzer.py (wire credential-log refinement),
      frontend/e2e/smoke.spec.mjs (2 L6 render tests), NEW backend/tests/test_run36_audit_fixes.py (8).
    Tests: 982 backend passed, 11 skipped; e2e 4 passed / 1 skipped vs live IB2. Commit-ready: Y.

═══════════════ FUTURE RUNS (gated on new corpus / out of current scope) ═══════════════
[ ] FUT-1  APKID app-owned surfacing. RUN 34 proved detect_apkid_features already collects anti-VM/
    packer data but it's all LIBRARY-owned on the current corpus, so surfacing it = FPs. Building the
    app-owned-restricted emitter is only worth it with a corpus that has REAL app-owned anti-analysis
    (a packed/protected/anti-emulator APK), so it can be verified on a live artifact — not shipped as
    "correctly emitted nothing here" plumbing. Gate this run on acquiring such a sample.
[ ] FUT-2  Hardcoded all-zero IV (RUN 36 Part 2 miss). android_weak_iv only matches inline
    `IvParameterSpec(new byte[`; InsecureBankv2's `byte[] ivBytes = {0,0,..}` (CryptoClass:22) passed
    by variable is missed. Add a name-gated pattern (a byte-array named *iv* initialised with a
    literal, or a zero-filled array reaching IvParameterSpec) — must not FP on arbitrary `byte[] x={}`.
[ ] FUT-3  InsecureShopProvider credential exposure. contentProvider/InsecureShopProvider.java:80-91
    returns username + password via a MatrixCursor from an EXPORTED provider protected only by a weak
    custom readPermission (com.insecureshop.permission.READ, normal-level). Needs a protection-level +
    returned-data analysis to flag "exported provider exposes credentials behind a weak permission".
[ ] FUT-4  Credential leak via System.out.println (RUN 36). MyBroadCastReceiver:30 prints the password
    with System.out.println (goes to logcat) — the Log.* rules + the RUN 36 credential-log refinement
    only cover Log.d/v/i. Extend the credential-logging signal to println/print sinks.

═══════════════ SESSION LOG ═══════════════
(append one dated line per session: what ran, what's next)
- 2026-07-12  Plan created. Nothing run yet. Next: RUN 1.
- 2026-07-12  RUN 1 attempted. Verified facts against source BEFORE editing: fact 1 and
  fact 3 confirmed; fact 2 partly wrong (iOS Mach-O strings never reach string_analysis,
  and _scan_binary_strings only emits secrets — nothing binary-derived exists to bridge).
  Also: the iLogistics Check-in IPA is nowhere on disk, so no iOS report can be
  regenerated. No files edited. RUN 1 set to [!] BLOCKED pending human answers on
  BLOCKER A (bridge source) and BLOCKER B (IPA path). Next: unblock RUN 1.
- 2026-07-12  RUN 1 UNBLOCKED and COMPLETED. Human supplied ./testapp.ipa (= iLogistics
  Check-in) and approved the corrected approach. Implemented across ios_analyzer.py,
  endpoint_intel.py, network_intel.py. Found the TRUE root cause: printable_text was never
  imported into ios_analyzer, so _scan_binary_strings had been silently dead (NameError
  swallowed by a bare `except Exception: pass`) on every iOS scan ever run. Also found and
  wired the missing domain_analyzer call on iOS (domain_intel was never even initialized).
  Caught and gated a self-introduced binary-IP FP (1.3.0.1). A real pre-change iOS scan
  disproved the prompt's IP premise: 192.168.161.138 was ALREADY surfaced from a text asset;
  RUN 1's actual win is endpoints 0 -> 78. Acceptance PASS (4/4). Android byte-identical
  (endpoints 1->1, ips 0->0, findings 45->45, severity identical). Tests 780 passed /
  11 skipped. NOT COMMITTED — nothing staged. Next: RUN 2.
- 2026-07-13  RUN 22 COMMITTED (4b71473): relabeled the 2 regex_sast mislabels.
- 2026-07-13  RUN 23 DONE + committed: android_obfuscation_missing collapsed to a single app-owned
  posture location (125->1). Attribution PROVEN — 0 unexplained leaves; delta = obf collapse + one
  file_index drop + one summary counter; taint(sorted)/timing masked. iOS 14/92/B held, score 35/F,
  897 tests pass. L4 re-scoped: obf carrier RETIRED, broader L4 STILL OPEN (log_debug/reflection
  AndroidX drift, out of scope, RUN 19 breadth fixes needed). New latent L5: taint_flows order swap.
  NOT PUSHED — awaiting human confirm of the attribution proof + L4 re-scope wording. Next: push on
  confirm, then triage remaining RUN 19 breadth proposals (1,2) / L1 / OSV.
- 2026-07-13  RUN 23 confirmed + pushed (1e9cabd). RUN 24 DONE + committed: generalized the iOS
  decodable-plist line-remap so file_evidence entries (not just f.line) get the decoded-XML line —
  cloud_firebase now scrolls to line 32 (the bucket) instead of line 3 (the <plist> header); added a
  frontend range-guard so a stale/out-of-range declared line never targets a nonexistent row. 2 plist
  findings both correct; 40 Mach-O still card; PDF shows decoded value, no bplist leak. iOS 14/92/B,
  Android finding-level byte-stable. 897 tests pass. NOT PUSHED — awaiting human confirm of the
  plist-finding table + broad proof. Next: push on confirm, then RUN 19 breadth (1,2) / L1 / OSV.
- 2026-07-13  RUN 24 confirmed + pushed (12facac). RUN 25 DONE + committed: restricted
  android_reflection + android_log_debug to app-owned code (audit 1&2). The inverted guard caught a
  cascade — un-demotion info->low (correct) surfaced a NEW "Reflection RCE" chain. Investigation:
  chain is HEURISTIC co-occurrence (CODE_LOADING can never be taint-proven), not earned as HIGH.
  Human ratified: cap heuristic chains at MEDIUM (general rule, keyed on proof type) — fixed an
  engine inversion that FORCED heuristic->HIGH; proven stay HIGH, manifest-only untouched; added
  severity_reason + a both-directions test. Delta fully attributed: reflection/log_debug info->low +
  1 MEDIUM chain, nothing else; score 35->34/F (grade held), every deduction a real finding. L4
  reduced (2 carriers retired, 17 residual, still open). iOS 14/92/B. 898 tests pass. NOT PUSHED —
  awaiting human confirm of the cascade handling + final score. Next: push on confirm; L1 / OSV / L5.
- 2026-07-13  RUN 25 confirmed + pushed (8c48657). RUN 26 DONE + committed: L1 (Android binary
  string-index-as-source-line). Heeded the consumer-field rule — did NOT touch the file-server
  (already correct). Real bug: build_evidence_view carded binary primaries iOS-only; extended to
  Android (.dex/.so/.arsc) so no phantom file:line reaches PDF/panel/SARIF. view.py only + a 4-case
  test (902 pass). Shared-file: regenerated both — Android byte-clean (carding DORMANT, no
  binary-primary finding on InsecureShop; 0 delta after L4/L5 tolerances), iOS 14/92/B, carded 11->11.
  LIMITATION: L1 only fires on a no-source/packed APK we don't have -> fix is code+test+zero-regression
  verified, live repro DEFERRED (same blocker class as L2). NOT PUSHED — awaiting human confirm of the
  verified-not-live-reproduced caveat. Next: push on confirm; then OSV / L5 / (L1 live repro if APK).
- 2026-07-14  RUN 31 DONE (not committed). Housekeeping: the checkin-ios-normal.ipa stub does NOT
  exist (never did) — no-op; baselines captured in baseline/ after proving the container's baked code
  == repo HEAD. CONFIRM-GATE caught that the prompt's FIX A was UNIMPLEMENTABLE: a taint flow carries
  no file/line (reconcile synthesizes class-name + line 0), so the specified file:line join could
  never match and would have shipped a veto that never fires. Human rejected the class-granular
  fallback; implemented the CONSTANT-ARGUMENT GUARD instead, after proving androguard feasibility on
  the real APK (exec arg = filled const-string array => dropped; loadUrl/crypto args = move-result /
  parameter => kept). FIX B: new "method-reachable" proof class — taint = call-graph reachability, NOT
  data-flow; PROOF_PROVEN is now deliberately unreachable, the MEDIUM cap covers method-reachable, and
  trust_engine no longer calls a call_chain "fully proven". ARTIFACT: IB2 55->53 findings, both
  CRITICAL FPs gone, NOTHING added, TPs (WebView + 6 crypto) survive, Root Detection INFO still on
  PostLogin.java:26, score 23->35 fully attributed to the critical deduction alone. InsecureShop and
  testapp.ipa (92/B) byte-stable. Caught + neutralized a VirusTotal env confound (baseline had no VT
  key; recreated container did) by re-scanning with VT off. 924 tests pass. Next: human confirms the
  diff -> commit -> RUN 32 (StrandHogg 2.0).
- 2026-07-14  RUN 31 committed (688060f, main; message amended to drop a stray here-string '@').
  baseline/ + after_run31/ gitignored. RUN 32 DONE (not committed): StrandHogg 2.0 (CVE-2020-0096)
  platform-gated detector. CONFIRM-GATE found the prompt self-contradicted (4 vs 5 exported activities;
  the FIX keyword rule inverts the VERIFY table for DoTransfer + ChangePassword) — reported, owner ruled
  all-5 scope + keep-the-rule severity (3 HIGH / 2 MEDIUM). ARTIFACT VERIFICATION caught a self-inflicted
  FP: my "reflection-based" wording tripped the chain tagger's bare "reflection" substring match and
  assembled a bogus "Dynamic Code Loading / Reflection RCE" chain with my finding as its required member;
  reworded to drop the token (scoped, zero-regression), added a CODE_LOADING guard test, logged the shared
  tagger over-match for RUN 35. Final artifact clean: IB2 53->54 (only the grouped StrandHogg HIGH),
  chains identical, score 35->34/F fully attributed; InsecureShop negative gate silent (targetSdk 29),
  byte-identical; iOS 92/B untouched. 935 tests pass. Next: human confirm -> commit -> RUN 33 (trackers).
- 2026-07-14  RUN 32 committed (dc1bf87, main). RUN 33 DONE (not committed): tracker class-inventory
  matching + confidence tiers. CONFIRM-GATE found the prompt's root cause partly wrong — package_hints
  is manifest-derived (not a pre-categorized SDK set) and there is NO existing full class list; proved
  with androguard that IB2's DEX carries 118 analytics + 193 tagmanager classes the manifest misses.
  Added GA + Tag Manager signatures + domains, a code_signature/domain schema, and rewrote
  detect_trackers to match the FULL DEX class inventory (cheap DEX class-table read, not a decompile)
  with confirmed/likely tiering. Caught a determinism bug in verification (matched_class picked from a
  set via next() -> drifts run-to-run) and fixed to min() -> two IB2 scans now byte-identical.
  ARTIFACT: IB2 detect_trackers 1->5 (AdMob/Analytics/TagManager/Maps/Sign-In, all spot-checked real
  in DEX). AXIS NOTE (human correction): on the Exodus definition that's 3 real trackers = MATCHES
  MobSF (Maps + Sign-In are bundled SDKs, not trackers); tracker-vs-SDK label split deferred to RUN 35.
  findings/score unchanged. InsecureShop 0->0 (prompt expected Firebase/Crashlytics
  but the real classes.dex has none — Material UI + Gson only; correct no-FP result). iOS trackers
  BYTE-IDENTICAL (9, 92/B). 946 tests pass, frontend builds. Next: human confirm -> commit -> RUN 34
  (APKID anti-VM/packer/compiler).
- 2026-07-14  RUN 33 committed (69197a5) + axis correction (a29347d). RUN 34 DONE — SHIPPED PART B
  ONLY. Investigation flipped the run: the prompt's "Beetle has no packer layer" was false
  (detect_apkid_features already collects anti-VM/packer data, just unrendered), and — decisively —
  MobSF's anti-VM on IB2 is a LIBRARY-CODE over-match: Build.* appears in ZERO app-owned files in
  either test app, and neither has emulator-telltale strings, so surfacing it would import MobSF's FP
  (violates Beetle's ownership discipline). Human ratified: drop Part A entirely (reverted apkid_engine
  + build_apkid_findings + PDF section + wiring), ship only Part B. Part B = context-aware Janus
  severity (v1-only signing gated on minSdk reaching the Janus API 21-26 range; IB2 minSdk 15 ->
  MEDIUM->HIGH with justification) + low_min_sdk concrete-OS-risk enrichment (reworded to avoid the
  RUN 32 keyword-contamination class after a first draft spawned a bogus WebView chain). ARTIFACT: IB2
  only delta = Janus MEDIUM->HIGH, no new findings/chains, 34/F held; InsecureShop + iOS byte-stable.
  951 tests pass. Logged: MobSF-anti-VM-FP comparison data point; FUT-1 (APKID app-owned surfacing,
  gated on a packed-APK corpus). Next: human confirm -> commit -> RUN 35 (FP/mislabel sweep, incl.
  R35-A/R35-B).
- 2026-07-14  RUN 35 executed in 3 commits (sequenced per human): R35-A (d590d42) capability tagger
  keys on identity not prose — killed the RUN 32/34 prose-coincidence chains at the root while
  PRESERVING InsecureShop's legit RUN 25 Reflection chain (both directions proven on real artifacts).
  T1-T3 (3241067) crypto/SQLi FP sweep: crypto taint HIGH->LOW context, hardcoded-key evidence
  repointed to the key literal (CryptoClass:21, masked), SQLi chain no longer built on a proven-
  parameterized step; IB2 54->53 / 34->40 F fully FP-attributed, InsecureShop + iOS untouched. R35-B
  (this commit) tracker vs bundled-SDK kind split: IB2 reads 3 trackers + 2 SDKs (= MobSF axis), iOS
  byte-stable. 974 tests pass. Next: human confirm -> RUN 36 (self-audit + discovery).
- 2026-07-14  RUN 36 DONE (self-audit + discovery). Part 1: audited all 100 findings (IB2 53 +
  InsecureShop 47) against decompiled source — NO false positives in either app after five runs of
  fixes; library-INFO correctly demoted. Two confirmed defects fixed surgically: (1) missed IB2
  SMS-exfil taint flow — added SmsManager.sendTextMessage as a taint sink (cat SmsSend, HIGH), now
  emits TAINT-SMSSEND with the Intent-extra→SMS linkage via the exported MyBroadCastReceiver; (2) IB2
  credential logging LOW→MEDIUM (DoLogin:136 logs username:password) via a credential-value refinement
  that leaves username-only logs LOW. Coverage up, FPs unchanged: IB2 53→54 (only the real SMS TP
  added), chains identical; InsecureShop + iOS byte-unchanged. L6 CLOSED — added 2 real-render
  Playwright assertions (tracker count 3-not-5 with bundled-SDK split; chain-card name+severity) and
  RAN them green against a live IB2 scan (full smoke 4 pass / 1 iOS-skip). Logged FUT-2/3/4
  (hardcoded-IV pattern, InsecureShopProvider credential exposure, println credential leak). 982
  backend tests pass. Next: human confirm → commit. This completes the RUN 31–36 production-readiness
  arc.
