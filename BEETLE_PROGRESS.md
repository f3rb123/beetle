# BEETLE_PROGRESS.md — Live Execution Tracker
Claude Code: read this FIRST every session (see CLAUDE.md). Work the first non-[x] run. Update after each run and before stopping.

Status key:  [ ] TODO   [~] IN-PROGRESS   [x] DONE   [!] BLOCKED (needs human)

Baseline before start: iOS grade A 97/100 (0/0/0); MobSF 50/100 grade B. Target: correct + beats MobSF, Android unchanged.

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

[ ] RUN 6 — Info.plist section label + render (iOS-only)
    Files changed:
    Acceptance (3 permissions + ATS render, Android still "AndroidManifest"): 
    Commit-ready:
    Resume notes:

[ ] RUN 7 — SDK categories, no more 39×unknown (iOS-only)
    Files changed:
    Acceptance: 
    Commit-ready:
    Resume notes:

═══════════════ TIER 2 — PARITY + DIFFERENTIATORS ═══════════════

[ ] RUN 8 — Binary insecure-API + logging + malloc scan (iOS-only)
    Files changed:
    Acceptance (findings shown, MASVS-CODE off 0/100): 
    Commit-ready:
    Resume notes:

[ ] RUN 9 — Per-binary protection table (iOS-only) — FP GUARD on App.framework/App
    Files changed:
    Acceptance (full table; NO HIGH FP on App.framework/App): 
    Commit-ready:
    Resume notes:

[ ] RUN 10 — Dedicated ATS section (iOS-only)
    Files changed:
    Acceptance: 
    Commit-ready:
    Resume notes:

[ ] RUN 11 — iOS tracker detection wire-up (iOS-only)
    Files changed:
    Acceptance (AdMob + Crashlytics shown): 
    Commit-ready:
    Resume notes:

[ ] RUN 12 — Property Lists section (iOS-only)
    Files changed:
    Acceptance: 
    Commit-ready:
    Resume notes:

[ ] RUN 13 — Strings section + email FP filter (SHARED: both platforms)
    Files changed:
    Android diff: 
    Acceptance (no Dart-symbol email FPs): 
    Commit-ready:
    Resume notes:

[ ] RUN 14 — Vulnerable components verify + optional App Store metadata
    Files changed:
    Acceptance (OSV coverage real): 
    Commit-ready:
    Resume notes:

═══════════════ TIER 3 — SCORE CALIBRATION ═══════════════

[ ] RUN 15 — Score model realism (SHARED: scoring) — FP GUARD
    Files changed:
    Both reports regenerated: 
    Acceptance (every deduction = real finding; no AOT FP inflates): 
    Commit-ready:
    Resume notes:

═══════════════ TIER 4 — PENDING ANDROID + WEB/PDF ═══════════════

[ ] RUN 16 — Android 5.1a verbose summary gate (SHARED: report_summaries.py)
    Files changed:
    Android diff (only intended gating): 
    Acceptance: 
    Commit-ready:
    Resume notes:

[ ] RUN 17 — Android 5.1b promote privacy taint finding (Android)
    Files changed:
    Acceptance: 
    Commit-ready:
    Resume notes:

[ ] RUN 18 — Web/PDF parity (P1 panels2.jsx, P2 panels.jsx)
    Files changed:
    Acceptance: 
    Commit-ready:
    Resume notes:

[ ] RUN 19 — Hygiene: regex_sast base audit (MEASURE ONLY)
    Files changed (should be none — report only):
    Acceptance: 
    Commit-ready:
    Resume notes:

═══════════════ LATENT / CROSS-PLATFORM (raised mid-run, not yet actioned) ═══════════════

[ ] L1 — RUN 4's Android twin: does Android render a string-index as a source line?
    RUN 4 fixed this for iOS ONLY (gated on platform == "ios") because widening it would have
    broken the Android byte-diff that RUN 4 is required to preserve. But the same root cause
    plausibly exists on Android: classes.dex, resources.arsc and lib/**/*.so are binary too,
    and if any analyzer scans them as an extracted-strings listing, its "line" is a string
    index, not a source line — exactly the iOS bug.
    OWNER: check during RUN 16/17 (Android correctness), where an Android output delta is in
    scope and expected. Concretely: look for findings whose primary file is .dex/.arsc/.so and
    that carry a non-zero line, and see whether _collect_android_files string-dumps them the way
    _collect_ios_files does (code_analyzer.py:552-557). If so, reuse _is_binary_evidence /
    _as_binary_evidence (already written, platform-gated) and pass the Android binary set.
    NOT a regression introduced by RUN 4 — pre-existing, merely unmasked by it.

[ ] L2 — RUN 4 acceptance clause "file-resolved finding highlights the correct line" is
    DEFERRED-UNTESTABLE, *not* passed. A Flutter release IPA ships no text source, so no
    positive case exists in this corpus: the only file-resolved finding WAS the binary plist
    (now correctly binary evidence). No line-remapping bug was found or fixed. RE-TEST this
    clause when a Swift/ObjC-source app enters the corpus. Do not mark it passed on the
    strength of the iOS report alone.

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
