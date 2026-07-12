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

[ ] RUN 8.1 - MASVS control DETECTION (iOS-only) - MUST LAND BEFORE RUN 15
    WHY: RUN 8 proved MASVS-CODE cannot move off 0 by adding findings - score =
      (controls_present/expected)*60 + (40 - penalty), so findings only ever subtract. The score
      is floored until Beetle can DETECT CONTROLS the app actually implements.
    Do: implement control detection in masvs_intel._detect_controls for iOS, driven by REAL
      evidence already in the report (RUN 7 categorised the frameworks, so the signal exists):
        IOSSecuritySuite / flutter_jailbreak_detection_plus  -> anti-tampering / RESILIENCE
        flutter_secure_storage (Keychain-backed)             -> secure storage / STORAGE
        (only controls with genuine evidence - see guard)
    GUARD (same discipline as RUN 7's "unknown stays reachable"): a control is marked PRESENT
      ONLY with real evidence that it is implemented. NEVER assume a control present to lift the
      score. Add a test that a control with no evidence stays ABSENT.
    Android: unchanged (iOS-scoped). Regenerate both; Android content-identical.

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
