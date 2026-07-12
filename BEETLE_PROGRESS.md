# BEETLE_PROGRESS.md — Live Execution Tracker
Claude Code: read this FIRST every session (see CLAUDE.md). Work the first non-[x] run. Update after each run and before stopping.

Status key:  [ ] TODO   [~] IN-PROGRESS   [x] DONE   [!] BLOCKED (needs human)

Baseline before start: iOS grade A 97/100 (0/0/0); MobSF 50/100 grade B. Target: correct + beats MobSF, Android unchanged.

═══════════════ METHODOLOGY — READ BEFORE ANY SHARED-FILE RUN ═══════════════
(applies to RUN 13, 15, 16, 17 and every future shared-file change)

THE ANDROID GUARD IS ORDER-INSENSITIVE ON SET-DERIVED FIELDS.
Byte-equality is the right test ONLY for fields that are already deterministically ordered:
    endpoints, ips, findings, severity_summary, secrets   -> compare byte-for-byte.
Fields backed by a Python set are NOT stably ordered across processes — their order changes
on every backend restart even with byte-identical code (see L3: androguard's
apk.get_permissions() at android_analyzer.py:1353). Compare these as SETS / multisets:
    permissions (all / classified / dangerous), and any other set-derived collection.
Concretely:  sorted(json.dumps(x, sort_keys=True) for x in lst)  on both sides, then compare.

ALSO MASK VOLATILE FIELDS before any byte-compare: timestamp / scan_time / generated_at /
created_at / updated_at. evidence_bundle carries a scan-time timestamp, so two scans of the
SAME apk on the SAME build are never byte-equal.
AND: Android findings still contain residual run-to-run nondeterminism even after masking
(see L4) - a rejected evidence candidate's line number moves between runs. Prove any findings
delta with a SAME-BUILD DOUBLE SCAN before attributing it to your change.

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

[ ] L4 - Android FINDINGS are nondeterministic run-to-run (PRE-EXISTING, deeper than L3).
    FOUND during RUN 8's Android guard. Two scans of the SAME InsecureShop.apk on the SAME
    build, code byte-identical, produce different findings JSON:
        evidence_selection.rejected[...] for "Exported Intent to JS-Enabled WebView"
        -> androidx/viewpager2/widget/ViewPager2.java  line 428  (run X)
        -> androidx/viewpager2/widget/ViewPager2.java  line 429  (run Y)
    A REJECTED candidate (file_score -89), not the primary - so no user-visible severity or
    primary-evidence change. Content that matters (severity_summary, endpoints, ips, secrets,
    permissions, finding identities) is identical.
    Separately, evidence_bundle.timestamp differs every scan by construction (scan time).
    WHY IT MATTERS: same reason as L3, one level deeper - literal "byte-identical Android
    output" is NOT achievable, so a naive byte-diff always fails and can be misread as a
    regression. The guard must mask timestamps AND tolerate this rejected-candidate jitter.
    LIKELY CAUSE: candidate collection walks a dict/set or races the parallel scan pool, so two
    equal-scoring match lines in the same file swap order. NOT yet root-caused.
    OWNER: RUN 16/17. Fix = sort candidates by (file_path, line) before selection.

[ ] L3 — Android permission ORDER is nondeterministic across processes (PRE-EXISTING).
    FOUND during RUN 6's Android diff. results["permissions"]["all"/"classified"/"dangerous"]
    come back in a DIFFERENT ORDER on every backend restart, with byte-identical code and the
    same APK. PROVEN, not assumed: restarted the container 3x with no rebuild and got 3
    different orders (INTERNET-first, WAKE_LOCK-first, INTERNET-first-but-different-tail).
    Two scans inside ONE process always agree — classic PYTHONHASHSEED-dependent set iteration.
    ROOT CAUSE: android_analyzer.py:1353 `perms = apk.get_permissions()` — androguard returns
    set-derived, unsorted output, and it is stored as-is.
    WHY IT MATTERS: (a) it makes any report diff / scan-compare feature show phantom changes;
    (b) it partially undermines the "byte-identical Android output" methodology this whole plan
    relies on — content is stable, ORDER is not. Every Android diff so far compared endpoints /
    ips / findings / severity / secrets, which ARE stable; permissions were first compared in
    RUN 6 and is where this surfaced.
    FIX (one line, but it CHANGES Android output ordering, so it is out of RUN 6's no-delta
    scope): sort deterministically at android_analyzer.py:1354, e.g.
        results["permissions"]["all"] = sorted(perms)
    and keep `classified` derived in that same sorted order.
    OWNER: RUN 16/17 (Android correctness), where an intentional Android delta is in scope.

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
