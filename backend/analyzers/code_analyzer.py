"""
Cortex SAST Engine — per-file, per-line attribution.
Each finding carries:
  files: [{path, lines: [int, ...], snippet: str}]
  file_path: str   (first match, for quick reference)
  line: int        (first match line)
  snippet: str     (first match line text)
"""
import re
import os
from .code_rules import CODE_RULES, IOS_CODE_RULES
from .path_utils import normalize_relative_path
from .evidence_scanner import is_namespace_url, classify_ip
from .source_corpus import SourceCorpus
from . import regex_prefilter

# ── Phase 4 (P2): per-match validators for noise-prone SAST rules ─────────────
# A rule's regex can shape-match non-findings (XML namespace URLs, vector
# drawable coordinates, version numbers). These validators run per match and
# drop the bad ones BEFORE a finding is built, so the validators that already
# clean the IPs/endpoints arrays now also govern SAST results.
_STRICT_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _validate_http_match(matched_text: str, line_text: str) -> bool:
    """Drop http:// hits that are XML namespace / schema URIs (schemas.android.com,
    xmlns, w3.org, …) — they are identifiers, not plaintext network endpoints."""
    return not is_namespace_url(line_text)


def _validate_ip_match(matched_text: str, line_text: str) -> bool:
    """Accept only lines containing a real, routable 4-octet IPv4 literal.

    The android_hardcoded_ip regex matches partials like "10.0" (from
    android:rotation="10.0") and version/coordinate values; classify_ip rejects
    anything that isn't a valid, non-reserved IPv4 address."""
    for cand in _STRICT_IPV4.findall(line_text or ""):
        if classify_ip(cand) is not None:
            return True
    return False


_SAST_MATCH_VALIDATORS = {
    "android_http_connection": _validate_http_match,
    "android_hardcoded_ip":    _validate_ip_match,
}


# ── Resource-ID constant class detection (decompiled R.java) ──────────────────
# A decompiled `R` class (often obfuscated to e.g. N0/a.java) is nothing but
# `public static final int NAME = 0x7f######;` — Android resource IDs in the
# 0x7f000000–0x7fffffff range (R.drawable/string/id/layout) — plus int[] styleable
# arrays. Those integers are never secrets and the class is never app logic, yet a
# long value like 2130837504 can look like a secret candidate and the class can be
# picked as chain/secret evidence. This flags such classes so they can be excluded.
_RES_ID_MIN = 0x7F000000
_RES_ID_MAX = 0x7FFFFFFF
_RES_ID_MIN_COUNT = 3            # need a meaningful number of resource-ID constants
_RES_LOGIC_TOLERANCE = 1         # a stray private ctor is fine; real logic is not

_INT_SCALAR_RE = re.compile(r"\bint\s+\w+\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;")
_INT_ARRAY_RE = re.compile(r"\bint\s*\[\s*\]\s+\w+\s*=\s*\{([^}]*)\}\s*;")
_NUM_RE = re.compile(r"0x[0-9a-fA-F]+|\d+")
# A generated R class contains NO string literals. Any substantial quoted string
# means the class holds real data (e.g. a secret) — never treat it as an R class.
_STR_LITERAL_RE = re.compile(r'"[^"\n]{8,}"')
# Tokens that indicate real executable logic — absent from a pure constant class.
_LOGIC_RE = re.compile(
    r"\b(?:if|for|while|switch|synchronized|throw|catch)\b"
    r"|\breturn\s+\S"
    r"|\bnew\s+\w"
    r"|\.\w+\s*\("
)


def _in_res_range(token: str) -> bool:
    try:
        n = int(token, 16) if token.lower().startswith("0x") else int(token)
    except ValueError:
        return False
    return _RES_ID_MIN <= n <= _RES_ID_MAX


def is_resource_id_class(source_text: str) -> bool:
    """True when a class body is dominated by Android resource-ID int constants
    (values in the 0x7f resource range) and carries essentially no logic — i.e. a
    decompiled ``R`` class (R.drawable/string/id/layout), even when obfuscated.

    Such a class is never a secret and never app logic, so it must not be a secret
    candidate or a chain/evidence location."""
    if not source_text or _STR_LITERAL_RE.search(source_text):
        return False

    scalars = _INT_SCALAR_RE.findall(source_text)
    res_scalars = sum(1 for v in scalars if _in_res_range(v))

    res_arrays = 0
    for body in _INT_ARRAY_RE.findall(source_text):
        vals = _NUM_RE.findall(body)
        if vals and all(_in_res_range(v) for v in vals):
            res_arrays += 1

    res_ids = res_scalars + res_arrays
    if res_ids < _RES_ID_MIN_COUNT:
        return False
    # Nearly every scalar int constant must be a resource ID (a real class with
    # numeric config would have non-0x7f ints and drop this ratio).
    if scalars and res_scalars / len(scalars) < 0.8:
        return False
    # And the class must carry no meaningful executable logic.
    return len(_LOGIC_RE.findall(source_text)) <= _RES_LOGIC_TOLERANCE


# A decompiled R-constants class by PATH: R.java / R2.java / R$layout.java, plus the
# smali/kt equivalents. Obfuscated R classes (N0/a.java) have no path signal — those
# are matched against the ``r_classes`` set recorded during the secret walk instead.
_R_CLASS_PATH_RE = re.compile(r'(?:^|/)R\d?(?:\$[A-Za-z0-9_]+)?\.(?:java|kt|smali)$', re.I)
# A snippet that is an Android resource-ID constant assignment (``… = 0x7f0a00b3``).
_RES_ID_SNIPPET_RE = re.compile(r'0x7[fF][0-9a-fA-F]{6}\b')


def is_resource_id_target(path: str, snippet: str = "", r_classes=None) -> bool:
    """True when a (path, snippet) points at an auto-generated resource-ID constant
    class — an R.java / R$* / R2 by path, an obfuscated R class recorded in
    ``r_classes`` (the secret walk's ``resource_id_classes``), or a snippet that is a
    0x7f resource-ID assignment. Such a location can NEVER hold a secret or be a valid
    code-viewer / chain-evidence target, so callers must refuse it and fall back to
    the real evidence file."""
    p = (path or "").replace("\\", "/").strip()
    if not p:
        return False
    if r_classes:
        pl = p.lower()
        for rc in r_classes:
            rcl = str(rc or "").replace("\\", "/").lower()
            if rcl and (pl == rcl or pl.endswith("/" + rcl) or rcl.endswith("/" + pl)):
                return True
    if _R_CLASS_PATH_RE.search(p):
        return True
    if snippet and _RES_ID_SNIPPET_RE.search(snippet):
        return True
    return False


# ── Raw-SQL severity resolution (android_sqlite_raw_query) ────────────────────
# rawQuery/execSQL/compileStatement fire on EVERY raw query, including safe
# parameterized calls like rawQuery("… WHERE id = ?", args). HIGH must require
# actual string building in the SQL argument (the same signal the codebase already
# keys off in android_insecure_content_resolver_query, which requires '+'), or a
# taint flow reaching the sink. Otherwise the query is parameterized → INFO.
_SQL_SINK_CALL_RE = re.compile(r"(?:rawQuery|execSQL|compileStatement)\s*\(", re.IGNORECASE)
# '+' concatenation touching a string/identifier, String.format, or Kotlin string
# interpolation ($var / ${…}) inside a string literal.
_SQL_CONCAT_RE = re.compile(r'"\s*\+|\+\s*"|\+\s*[A-Za-z_(]|\)\s*\+')
_SQL_FORMAT_RE = re.compile(r"String\.format\s*\(", re.IGNORECASE)
_KOTLIN_INTERP_RE = re.compile(r'"[^"]*\$\{?[A-Za-z_]')


def _sql_arg_region(text: str) -> str:
    """Text of the SQL sink argument: from the sink call's '(' forward, capped so
    the scan can't bleed past the statement into unrelated context lines."""
    m = _SQL_SINK_CALL_RE.search(text or "")
    if not m:
        return ""
    return text[m.end(): m.end() + 400]


def _has_sql_string_building(text: str) -> bool:
    """True when the SQL argument is built from concatenation / format / Kotlin
    interpolation — i.e. NOT a pure parameterized ('?' + selectionArgs) query."""
    region = _sql_arg_region(text)
    if not region:
        return False
    return bool(_SQL_CONCAT_RE.search(region)
                or _SQL_FORMAT_RE.search(region)
                or _KOTLIN_INTERP_RE.search(region))


def _to_dotted_class(path: str) -> str:
    """'sources/com/app/Dao.java' → 'sources.com.app.Dao' for suffix comparison
    against a taint engine dotted class name."""
    p = re.sub(r"\.(java|kt|smali)$", "", str(path or "").replace("\\", "/"))
    return p.replace("/", ".")


def _same_class(sast_path: str, taint_class: str) -> bool:
    """Whether a SAST relative path and a taint dotted class name denote the same
    class. Matched by dotted-suffix so 'sources.com.app.Dao' aligns with
    'com.app.Dao' without colliding on bare simple names."""
    tc = str(taint_class or "").split("$", 1)[0].strip()
    if not tc:
        return False
    dotted = _to_dotted_class(sast_path)
    return dotted.endswith(tc) or tc.endswith(dotted)


def _taint_sqlite_classes(results: dict) -> tuple[set, set]:
    """(classes with a SQLite taint FINDING, classes with a SQLite taint FLOW).

    A finding guarantees the sink is already represented in results['findings'];
    a flow only confirms reachability. Both are read from the taint engine's own
    output — never from this rule."""
    finding_classes: set = set()
    flow_classes: set = set()

    def _is_sqlite(sink: str) -> bool:
        return str(sink or "").replace(" ", "").lower() in ("sqlite", "sql")

    for tf in results.get("taint_flows") or []:
        if isinstance(tf, dict) and _is_sqlite(tf.get("sink_cat")):
            c = str(tf.get("class_name") or tf.get("class") or "").split("$", 1)[0]
            if c:
                flow_classes.add(c)
    for f in results.get("findings") or []:
        if not isinstance(f, dict):
            continue
        rid = str(f.get("rule_id", "")).upper()
        tflow = f.get("taint_flow") or {}
        if rid.startswith("TAINT-") and _is_sqlite(tflow.get("sink_cat")):
            c = str(f.get("file_path") or tflow.get("class_name") or "").split("$", 1)[0]
            if c:
                finding_classes.add(c)
                flow_classes.add(c)
    return finding_classes, flow_classes


def resolve_sql_raw_query_severity(results: dict) -> dict:
    """Reconcile android_sqlite_raw_query severity with the actual evidence.

    For each such finding, in priority order:
      1. A SQLite taint FINDING already covers this class → drop the SAST finding
         (the taint finding, with its data-flow proof, represents the sink once).
      2. A SQLite taint FLOW reaches this class → HIGH (tainted source → sink).
      3. String building in the SQL argument (concatenation / String.format /
         Kotlin interpolation) → HIGH.
      4. Otherwise (only '?' placeholders / selectionArgs) → downgrade to INFO.

    Runs after the taint stage so branches 1-2 have data; deterministic and
    idempotent. Returns a small stats dict."""
    findings = results.get("findings") or []
    finding_classes, flow_classes = _taint_sqlite_classes(results)
    stats = {"deduped_taint": 0, "taint_high": 0, "concat_high": 0, "downgraded_info": 0}
    kept: list = []
    changed = False

    for f in findings:
        if not isinstance(f, dict) or f.get("rule_id") != "android_sqlite_raw_query":
            kept.append(f)
            continue
        fpath = f.get("file_path") or ""

        if any(_same_class(fpath, tc) for tc in finding_classes):
            stats["deduped_taint"] += 1
            changed = True
            continue  # dropped — covered by the taint finding

        if any(_same_class(fpath, tc) for tc in flow_classes):
            f["severity"] = "high"
            f["sql_injection_evidence"] = "taint flow reaches SQLite sink"
            stats["taint_high"] += 1
            changed = True
            kept.append(f)
            continue

        texts = [f.get("snippet", ""), f.get("code_context", "")]
        texts += [fe.get("snippet", "") for fe in (f.get("file_evidence") or []) if isinstance(fe, dict)]
        if any(_has_sql_string_building(t) for t in texts):
            if f.get("severity") != "high":
                changed = True
            f["severity"] = "high"
            f["sql_injection_evidence"] = "string-building in SQL argument (concatenation/format/interpolation)"
            stats["concat_high"] += 1
        else:
            f["severity"] = "info"
            f["title"] = "Raw SQL Query (Parameterized) — No Injection Evidence"
            f["description"] = (
                "Raw SQLite API used, but the query argument shows no string "
                "concatenation, String.format or interpolation — only '?' placeholders "
                "with selectionArgs. No evidence of SQL injection."
            )
            f["recommendation"] = (
                "No action required for the injection risk. Keep binding all "
                "user-controlled values through '?' placeholders / selectionArgs."
            )
            f["sql_injection_evidence"] = "parameterized (no string-building detected)"
            f["severity_downgraded_reason"] = "parameterized raw query"
            stats["downgraded_info"] += 1
            changed = True
        kept.append(f)

    if changed:
        results["findings"] = kept
    results["sql_raw_query_resolution"] = stats
    return stats


# ── RUN 35 T2: point the hardcoded-key finding at the key LITERAL, not the usage line ──
# The android_encryption_key_hardcoded pattern is a greedy multiline regex that starts at a
# SecretKeySpec/Cipher call, so its evidence line lands on the USAGE, not the actual key literal
# (e.g. `String key = "This is the super secret key 123";`). The conclusion is right; only the
# location was wrong. This repoints it. Runs post-SAST, BEFORE evidence_selection, so the corrected
# location flows to every consumer (panel / PDF / SARIF).
_HARDCODED_KEY_RULES = {"android_encryption_key_hardcoded"}
_KEY_LITERAL_RE = re.compile(
    r'\b(?:final\s+)?(?:String|char\[\]|byte\[\])\s+\w*(?:key|secret|passwd|password|pwd)\w*\s*'
    r'=\s*"([^"]{4,})"', re.IGNORECASE)


def refine_hardcoded_key_evidence(results: dict) -> dict:
    """Repoint each hardcoded-encryption-key finding at the key string literal in its own file."""
    from . import scan_storage
    stats = {"repointed": 0}
    scan_id = results.get("scan_id")
    if not scan_id:
        return stats
    file_cache: dict = {}
    for f in results.get("findings") or []:
        if not isinstance(f, dict) or f.get("rule_id") not in _HARDCODED_KEY_RULES:
            continue
        rel = f.get("file_path") or ""
        if not rel:
            continue
        content = file_cache.get(rel)
        if content is None:
            p = scan_storage.resolve_source_file(scan_id, rel)
            content = p.read_text(errors="replace") if (p and p.is_file()) else ""
            file_cache[rel] = content
        if not content:
            continue
        m = _KEY_LITERAL_RE.search(content)
        if not m:
            continue  # no literal key assignment found — leave evidence as-is
        key_line = content[:m.start()].count("\n") + 1
        src_lines = content.splitlines()
        snippet = src_lines[key_line - 1].strip() if key_line - 1 < len(src_lines) else m.group(0)
        try:
            from .secret_intel import mask_value
            masked = mask_value(m.group(1))
        except Exception:
            masked = "***"
        f["line"] = key_line
        f["snippet"] = snippet
        f["code_context"] = _get_context(content, key_line)
        f["masked_key_value"] = masked
        f["evidence_repointed_reason"] = "moved from crypto-usage line to the key string literal"
        # CONSUMER-FIELD RULE (RUN 20/24): update the file_evidence entry the code viewer reads,
        # not just the top-level line.
        for fe in (f.get("file_evidence") or []):
            if isinstance(fe, dict) and normalize_relative_path(fe.get("path", "")) == normalize_relative_path(rel):
                fe["lines"] = [key_line]
                fe["snippet"] = snippet
        stats["repointed"] += 1
    results["hardcoded_key_evidence_repoint"] = stats
    return stats


# ── RUN 36: plaintext-credential logging is worse than the generic Log.d LOW ──
# android_log_debug is a generic "sensitive data may be logged" LOW. When the logged VALUE is a
# credential-named variable (e.g. InsecureBankv2 DoLogin.java:136 logs username + ":" + password),
# that is plaintext credentials to logcat and warrants MEDIUM. Matched on a credential identifier
# used as a logged value (after '+' or ',') so a mere string-literal mention ("enter password") does
# NOT trip it — verified: InsecureShop's Log.d("userName", valueOf) stays LOW.
_CREDENTIAL_LOG_RE = re.compile(
    r'[+,]\s*[\w.]*(?:password|passwd|pwd|credential|secret|token|apikey|api_key)[\w.]*',
    re.IGNORECASE)


def refine_credential_logging_severity(results: dict) -> dict:
    """Upgrade android_log_debug to MEDIUM when a credential-named value is written to the log."""
    stats = {"bumped": 0}
    for f in results.get("findings") or []:
        if not isinstance(f, dict) or f.get("rule_id") != "android_log_debug":
            continue
        texts = [f.get("snippet", ""), f.get("code_context", "")]
        texts += [fe.get("snippet", "") for fe in (f.get("file_evidence") or []) if isinstance(fe, dict)]
        if any(_CREDENTIAL_LOG_RE.search(t or "") for t in texts):
            if f.get("severity") != "medium":
                f["severity_original"] = f.get("severity_original") or f.get("severity")
                f["severity"] = "medium"
            f["title"] = "Plaintext Credentials Logged (Log.d/v/i)"
            f["credential_logging"] = True
            f["severity_upgraded_reason"] = "a credential-named value is written to logcat"
            f["description"] = (
                "A credential-named value (password / token / secret) is concatenated into a logcat "
                "call. On a rooted or pre-API-26 device any app with READ_LOGS can read it, so this "
                "leaks plaintext credentials — more than the generic 'sensitive data may be logged'."
            )
            stats["bumped"] += 1
    results["credential_logging_resolution"] = stats
    return stats

try:
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from custom_rules import get_rules_for_scanner as _get_custom_rules
except Exception:
    def _get_custom_rules(platform): return []


def run_android_sast(scan_dirs, results: dict, *, corpus: SourceCorpus | None = None):
    file_map = _collect_android_files(scan_dirs, corpus=corpus or SourceCorpus())
    custom = _get_custom_rules("android")
    _run_rules_per_file(file_map, CODE_RULES + custom, results)


def run_ios_sast(tmpdir: str, results: dict, *, corpus: SourceCorpus | None = None):
    file_map = _collect_ios_files(tmpdir, corpus=corpus or SourceCorpus())
    custom = _get_custom_rules("ios")
    _run_rules_per_file(file_map, IOS_CODE_RULES + custom, results)


def _run_rules_per_file(file_map: dict, rules: list, results: dict):
    """
    For each rule, scan every file and collect:
      - which files matched
      - which line numbers matched in each file
      - snippet from first match per file
    Produces one finding per rule with full attribution.
    """
    rule_matches = {}  # rule_id -> {rule, files: [{path, lines, snippet}]}

    compiled_rules = []
    for rule in rules:
        try:
            pattern = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE | re.DOTALL)
        except re.error:
            continue
        compiled_rules.append((rule, pattern, _SAST_MATCH_VALIDATORS.get(rule["id"])))

    # Files OUTER so the casefolded prefilter key and the splitlines() result
    # are computed once per file instead of once per (rule, file) — profiling
    # showed 825k splitlines calls (rules x files) dominating this stage.
    for rel_path, content in file_map.items():
        folded = regex_prefilter.fold(content)
        lines_content = None
        for rule, pattern, validator in compiled_rules:
            if not regex_prefilter.may_match(rule["pattern"], folded):
                continue
            rule_id = rule["id"]
            try:
                matched_lines = []
                first_snippet = ""

                for match in pattern.finditer(content):
                    if lines_content is None:
                        lines_content = content.splitlines()
                    line_no = content[:match.start()].count("\n") + 1
                    if validator:
                        line_text = lines_content[line_no - 1] if line_no - 1 < len(lines_content) else match.group(0)
                        if not validator(match.group(0), line_text):
                            continue
                    if line_no not in matched_lines:
                        matched_lines.append(line_no)
                        if not first_snippet and line_no <= len(lines_content):
                            first_snippet = lines_content[line_no - 1].strip()

                if matched_lines:
                    if rule_id not in rule_matches:
                        rule_matches[rule_id] = {"rule": rule, "files": []}
                    rule_matches[rule_id]["files"].append({
                        "path":    rel_path,
                        "lines":   matched_lines,
                        "snippet": first_snippet,
                    })
            except Exception:
                continue

    # Emit findings in RULE order (not file-discovery order) so the findings
    # list is identical to the historical rule-outer iteration.
    emitted = set()
    ordered = []
    for rule, _pattern, _validator in compiled_rules:
        rid = rule["id"]
        if rid in rule_matches and rid not in emitted:
            emitted.add(rid)
            ordered.append((rid, rule_matches[rid]))

    # RUN 25: some rules (android_reflection, android_log_debug) are only meaningful in the app's
    # own code — a Log/reflection call inside a bundled library is not the app's finding. Gate them
    # on the EXISTING per-file APPLICATION ownership signal (classify_file.is_application — the same
    # signal RUN 8/9/15 use), not a new heuristic. Build the context once, lazily, only if needed.
    _app_owned_cache: dict[str, bool] = {}
    _own_ctx = None
    if any(data["rule"].get("app_owned_only") for _rid, data in ordered):
        from .evidence_selection.library import classify_file as _classify_file
        from .ownership.engine import context_from_results as _ctx_from_results
        _own_ctx = _ctx_from_results(results)

        def _is_app_owned(path: str) -> bool:
            v = _app_owned_cache.get(path)
            if v is None:
                v = bool(_classify_file(path, _own_ctx).is_application)
                _app_owned_cache[path] = v
            return v

    for rule_id, data in ordered:
        rule    = data["rule"]
        fentries = sorted(data["files"], key=lambda x: x["path"])

        # RUN 25: app-owned-only rules keep only application-owned evidence; if none remains the
        # finding does not fire (a purely-library match is not the app's issue). Everything
        # downstream (fusion merged_locations, ownership, evidence_selection) then sees only
        # app-owned files, so no library candidate can carry the L4 jadx line-drift.
        if rule.get("app_owned_only"):
            fentries = [e for e in fentries if _is_app_owned(e["path"])]
            if not fentries:
                continue

        # Primary evidence = first file, first line
        primary   = fentries[0]
        file_path = primary["path"]
        line      = primary["lines"][0] if primary["lines"] else 0
        snippet   = primary["snippet"]

        # Build code context (±2 lines around first match)
        code_context = _get_context(file_map.get(file_path, ""), line)

        finding = {
            "title":          rule["title"],
            "severity":       rule["severity"],
            "category":       rule["category"],
            "description":    rule["description"],
            "impact":         rule.get("impact", ""),
            "recommendation": rule["recommendation"],
            "cwe":            rule.get("cwe", ""),
            "masvs":          rule.get("masvs", ""),
            "owasp":          rule.get("owasp", ""),
            "rule_id":        rule_id,
            "source":         "SAST",
            "confidence":     rule.get("confidence", 75),
            "exploitability": rule.get("exploitability", 50),
            "validation_status": "detected",
            # Primary evidence fields
            "file_path":      file_path,
            "line":           line,
            "snippet":        snippet,
            "code_context":   code_context,
            # Full multi-file attribution — MobSF style
            "files":          [f["path"] for f in fentries],
            "file_evidence":  fentries,  # [{path, lines, snippet}] for code viewer
            "file_count":     len(fentries),
        }
        if rule.get("poc"):
            finding["poc"] = rule["poc"]
        # RUN 23: mark whole-app posture rules so evidence_selection collapses their many
        # duplicate locations to one representative. Set only when true — never stamp the key
        # on ordinary findings (that would be a no-op field change across the whole report).
        if rule.get("posture"):
            finding["posture"] = True

        results["findings"].append(finding)


def _get_context(content: str, line_no: int, radius: int = 2) -> str:
    if not content or not line_no:
        return ""
    lines = content.splitlines()
    start = max(0, line_no - radius - 1)
    end   = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


_SAST_MAX_FILES       = int(os.environ.get("CORTEX_SAST_MAX_FILES", "15000"))
_SAST_MAX_FILE_BYTES  = int(os.environ.get("CORTEX_SAST_MAX_FILE_BYTES", str(2 * 1024 * 1024)))
# Only skip the highest-volume pure-noise trees (stdlibs). Keep GMS/firebase/
# material IN — they occasionally embed real config secrets.
_SAST_SKIP_PREFIXES = (
    # Support-library stdlib shells only. Do NOT skip `androidx/*` broadly —
    # apps ship real code under androidx/work, androidx/security, etc.
    "smali/android/support/v4/",
    "smali/android/support/v7/",
    "smali/kotlin/",
    "smali/kotlinx/",
    "smali_classes2/kotlin/",
    "smali_classes2/kotlinx/",
    "smali_classes3/kotlin/",
    "smali_classes3/kotlinx/",
    "original/",
    "unknown/",
)


def _collect_android_files(scan_dirs, *, corpus: SourceCorpus | None = None) -> dict:
    corpus = corpus or SourceCorpus()
    if isinstance(scan_dirs, str):
        scan_dirs = [scan_dirs]
    scan_dirs = [d for d in (scan_dirs or []) if d and os.path.exists(d)]

    # Prioritise jadx (Java source) → apk_extract → apktool (smali last) so
    # high-value decompiled Java is collected first, before any file cap.
    def _dir_priority(p: str) -> int:
        pl = p.lower().replace("\\", "/")
        if "/jadx" in pl:        return 0
        if "/apk_extract" in pl: return 1
        if "/apktool" in pl:     return 2
        return 3
    scan_dirs = sorted(scan_dirs, key=_dir_priority)

    result = {}
    skipped_noise = 0
    skipped_size  = 0
    target_exts = {
        ".smali", ".java", ".kt", ".xml", ".json",
        ".properties", ".gradle", ".txt", ".js", ".bundle",
    }
    fallback_only = len(scan_dirs) <= 1

    for scan_dir in scan_dirs:
        if len(result) >= _SAST_MAX_FILES:
            break
        include_binary_fallback = fallback_only and os.path.basename(scan_dir).lower() not in {"jadx", "apktool"}
        for root, dirs, files in corpus.walk(scan_dir):
            # Prune noise dirs in-place so os.walk doesn't descend into them.
            rel_root = normalize_relative_path(os.path.relpath(root, scan_dir)).rstrip("/") + "/"
            if any(rel_root.startswith(p) or ("/" + p) in ("/" + rel_root) for p in _SAST_SKIP_PREFIXES):
                skipped_noise += len(files)
                dirs[:] = []
                continue

            for fname in files:
                if len(result) >= _SAST_MAX_FILES:
                    break
                ext  = os.path.splitext(fname)[1].lower()
                fpath = os.path.join(root, fname)
                rel   = normalize_relative_path(os.path.relpath(fpath, scan_dir))
                if rel in result:
                    continue
                if any(rel.startswith(p) for p in _SAST_SKIP_PREFIXES):
                    skipped_noise += 1
                    continue
                try:
                    fsize = os.path.getsize(fpath)
                except OSError:
                    continue
                if ext in target_exts:
                    if fsize > _SAST_MAX_FILE_BYTES:
                        skipped_size += 1
                        continue
                    content = corpus.read_text(fpath)
                    if content is None:
                        continue
                    result[rel] = content
                elif include_binary_fallback and ext == ".dex":
                    raw = corpus.read_bytes(fpath, max_bytes=8 * 1024 * 1024)
                    if raw is None:
                        continue
                    result[rel] = _extract_strings(raw)
                elif include_binary_fallback and ext == ".so":
                    raw = corpus.read_bytes(fpath, max_bytes=4 * 1024 * 1024)
                    if raw is None:
                        continue
                    result[rel] = _extract_strings(raw)

    try:
        import logging as _lg
        _lg.getLogger("cortex.sast").info(
            f"_collect_android_files: kept={len(result)} "
            f"skipped_noise={skipped_noise} skipped_size={skipped_size} "
            f"cap={_SAST_MAX_FILES}"
        )
    except Exception:
        pass
    return result


def _collect_ios_files(tmpdir: str, *, corpus: SourceCorpus | None = None) -> dict:
    corpus = corpus or SourceCorpus()
    result = {}
    target_exts = {".swift",".m",".h",".js",".json",".plist",".xml",".strings",".txt"}
    for root, _, files in corpus.walk(tmpdir):
        for fname in files:
            ext   = os.path.splitext(fname)[1].lower()
            fpath = os.path.join(root, fname)
            rel   = normalize_relative_path(os.path.relpath(fpath, tmpdir))
            if ext in target_exts:
                content = corpus.read_text(fpath)
                if content is None:
                    continue
                result[rel] = content
            else:
                raw = corpus.read_bytes(fpath, max_bytes=5 * 1024 * 1024)
                if raw is None:
                    continue
                if len(raw) > 100:
                    result[rel] = _extract_strings(raw)
    return result


_NONPRINTABLE_TO_NUL = bytes(i if 32 <= i < 127 else 0 for i in range(256))


def _extract_strings(data: bytes, min_len: int = 5) -> str:
    """Printable-ASCII runs of at least ``min_len``, newline-joined — identical
    output to the historical per-byte loop, at C speed (translate + split)."""
    printable = data.translate(_NONPRINTABLE_TO_NUL).decode("latin-1")
    return "\n".join(run for run in printable.split("\x00") if len(run) >= min_len)
