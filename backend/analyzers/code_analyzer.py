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

try:
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from custom_rules import get_rules_for_scanner as _get_custom_rules
except Exception:
    def _get_custom_rules(platform): return []


def run_android_sast(scan_dirs, results: dict):
    file_map = _collect_android_files(scan_dirs)
    custom = _get_custom_rules("android")
    _run_rules_per_file(file_map, CODE_RULES + custom, results)


def run_ios_sast(tmpdir: str, results: dict):
    file_map = _collect_ios_files(tmpdir)
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

    for rule in rules:
        rule_id = rule["id"]
        try:
            pattern = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE | re.DOTALL)
        except re.error:
            continue

        for rel_path, content in file_map.items():
            try:
                lines_content = content.splitlines()
                matched_lines = []
                first_snippet = ""

                for match in pattern.finditer(content):
                    line_no = content[:match.start()].count("\n") + 1
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

    for rule_id, data in rule_matches.items():
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


def _collect_android_files(scan_dirs) -> dict:
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
        for root, dirs, files in os.walk(scan_dir):
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
                    try:
                        with open(fpath, "r", errors="replace") as f:
                            result[rel] = f.read()
                    except Exception:
                        continue
                elif include_binary_fallback and ext == ".dex":
                    try:
                        with open(fpath, "rb") as f:
                            raw = f.read(8 * 1024 * 1024)
                        result[rel] = _extract_strings(raw)
                    except Exception:
                        continue
                elif include_binary_fallback and ext == ".so":
                    try:
                        with open(fpath, "rb") as f:
                            raw = f.read(4 * 1024 * 1024)
                        result[rel] = _extract_strings(raw)
                    except Exception:
                        continue

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


def _collect_ios_files(tmpdir: str) -> dict:
    result = {}
    target_exts = {".swift",".m",".h",".js",".json",".plist",".xml",".strings",".txt"}
    for root, _, files in os.walk(tmpdir):
        for fname in files:
            ext   = os.path.splitext(fname)[1].lower()
            fpath = os.path.join(root, fname)
            rel   = normalize_relative_path(os.path.relpath(fpath, tmpdir))
            if ext in target_exts:
                try:
                    with open(fpath, "r", errors="replace") as f:
                        result[rel] = f.read()
                except Exception:
                    continue
            else:
                try:
                    with open(fpath, "rb") as f:
                        raw = f.read(5 * 1024 * 1024)
                    if len(raw) > 100:
                        result[rel] = _extract_strings(raw)
                except Exception:
                    continue
    return result


def _extract_strings(data: bytes, min_len: int = 5) -> str:
    result, current = [], []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return "\n".join(result)
