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

    for rule_id, data in ordered:
        rule    = data["rule"]
        fentries = sorted(data["files"], key=lambda x: x["path"])

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
