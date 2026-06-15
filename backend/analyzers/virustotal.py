"""
VirusTotal v3 integration — hash-based malware lookup.

Looks up the APK/IPA SHA-256 and any embedded DEX files against the
VirusTotal API.  Gracefully skips when VIRUSTOTAL_API_KEY is not set.

Results are stored in results['virustotal']:
  {
    "available": bool,
    "api_key_set": bool,
    "main": <file_report | None>,
    "dex_files": [<file_report>, ...],
    "error": str | None,
  }

file_report schema:
  {
    "hash": str,
    "filename": str,
    "detection_ratio": str,   # "3 / 72"
    "malicious": int,
    "suspicious": int,
    "undetected": int,
    "harmless": int,
    "timeout": int,
    "verdict": str,           # "clean" | "suspicious" | "malicious" | "unknown"
    "threat_label": str,      # suggested_threat_label or ""
    "family": str,            # popular_threat_classification.popular_threat_name or ""
    "engines": [              # top detections only (malicious/suspicious first)
      {"engine": str, "result": str, "category": str},
      ...
    ],
    "last_analysis_date": str,
    "permalink": str,
  }
"""

import hashlib
import os
import time
import zipfile
from pathlib import Path

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
VT_BASE = "https://www.virustotal.com/api/v3/files"
_REQUEST_TIMEOUT = 8
_MAX_DEX_FILES = 5          # cap to avoid quota burn
_RATE_DELAY = 0.25          # seconds between requests (free tier = 4 req/min)


def _verdict(malicious: int, suspicious: int) -> str:
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"


def _parse_report(data: dict, filename: str = "") -> dict:
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless   = stats.get("harmless", 0)
    timeout    = stats.get("timeout", 0)
    total      = malicious + suspicious + undetected + harmless + timeout

    # Engine-level results — keep only detections + first 5 clean ones for context
    all_results = attrs.get("last_analysis_results", {})
    engines = []
    for engine_name, info in all_results.items():
        cat = info.get("category", "")
        result = info.get("result") or ""
        if cat in ("malicious", "suspicious"):
            engines.append({"engine": engine_name, "result": result, "category": cat})
    # sort detections first
    engines.sort(key=lambda e: 0 if e["category"] == "malicious" else 1)

    # Threat label
    threat_class = attrs.get("popular_threat_classification") or {}
    threat_label = threat_class.get("suggested_threat_label", "")
    family = ""
    names = threat_class.get("popular_threat_name", [])
    if names:
        family = names[0].get("value", "") if isinstance(names[0], dict) else str(names[0])

    last_date = attrs.get("last_analysis_date", "")
    if last_date:
        import datetime
        try:
            last_date = datetime.datetime.utcfromtimestamp(int(last_date)).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            pass

    sha256 = attrs.get("sha256", data.get("id", ""))

    return {
        "hash":             sha256,
        "filename":         filename,
        "detection_ratio":  f"{malicious} / {total}" if total else "? / ?",
        "malicious":        malicious,
        "suspicious":       suspicious,
        "undetected":       undetected,
        "harmless":         harmless,
        "timeout":          timeout,
        "verdict":          _verdict(malicious, suspicious),
        "threat_label":     threat_label,
        "family":           family,
        "engines":          engines[:30],    # cap for storage
        "last_analysis_date": str(last_date),
        "permalink":        f"https://www.virustotal.com/gui/file/{sha256}",
    }


def _lookup(sha256: str, filename: str = "") -> dict | None:
    """Return a parsed report or None on 404 / error."""
    if not _HTTPX or not VT_API_KEY:
        return None
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.get(
                f"{VT_BASE}/{sha256}",
                headers={"x-apikey": VT_API_KEY},
            )
        if resp.status_code == 404:
            return {"hash": sha256, "filename": filename, "verdict": "unknown",
                    "detection_ratio": "not found", "malicious": 0, "suspicious": 0,
                    "undetected": 0, "harmless": 0, "timeout": 0, "threat_label": "",
                    "family": "", "engines": [], "last_analysis_date": "",
                    "permalink": f"https://www.virustotal.com/gui/file/{sha256}"}
        resp.raise_for_status()
        return _parse_report(resp.json().get("data", {}), filename)
    except Exception as exc:
        return {"hash": sha256, "filename": filename, "verdict": "error",
                "detection_ratio": "error", "malicious": 0, "suspicious": 0,
                "undetected": 0, "harmless": 0, "timeout": 0,
                "threat_label": "", "family": "", "engines": [],
                "last_analysis_date": "", "permalink": "",
                "error": str(exc)}


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_dex_hashes(apk_path: str) -> list[tuple[str, str]]:
    """Return [(sha256, dex_name), ...] for DEX files inside the APK/IPA zip."""
    out = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = sorted(
                n for n in zf.namelist()
                if n.endswith(".dex") or (n.endswith(".class") and "classes" in n)
            )[:_MAX_DEX_FILES]
            for name in dex_names:
                data = zf.read(name)
                sha = hashlib.sha256(data).hexdigest()
                out.append((sha, name))
    except Exception:
        pass
    return out


def run_virustotal(file_path: str, results: dict) -> dict:
    """
    Main entry point called from android_analyzer / ios_analyzer.

    Writes results['virustotal'] and returns a metrics dict.
    """
    vt_result = {
        "available": bool(VT_API_KEY and _HTTPX),
        "api_key_set": bool(VT_API_KEY),
        "main": None,
        "dex_files": [],
        "error": None,
    }
    results["virustotal"] = vt_result
    metrics = {"ran": False, "main_verdict": "unknown", "error": None}

    if not VT_API_KEY:
        vt_result["error"] = "VIRUSTOTAL_API_KEY not configured"
        metrics["error"] = "no_api_key"
        return metrics

    if not _HTTPX:
        vt_result["error"] = "httpx not installed"
        metrics["error"] = "no_httpx"
        return metrics

    try:
        main_sha256 = _sha256_file(file_path)
        filename = Path(file_path).name

        main_report = _lookup(main_sha256, filename)
        vt_result["main"] = main_report
        metrics["ran"] = True
        if main_report:
            metrics["main_verdict"] = main_report.get("verdict", "unknown")

        # DEX files (Android only)
        dex_entries = _extract_dex_hashes(file_path)
        for idx, (dex_sha, dex_name) in enumerate(dex_entries):
            time.sleep(_RATE_DELAY)
            report = _lookup(dex_sha, dex_name)
            if report:
                vt_result["dex_files"].append(report)

        # Inject a finding if main file is flagged
        if main_report and main_report.get("malicious", 0) > 0:
            results.setdefault("findings", []).append({
                "title":          f"VirusTotal: {main_report['malicious']} engines flagged this file as malicious",
                "severity":       "critical",
                "category":       "Malware",
                "description":    (
                    f"VirusTotal detection ratio: {main_report['detection_ratio']}. "
                    + (f"Threat label: {main_report['threat_label']}. " if main_report.get("threat_label") else "")
                    + "The application binary itself is identified as malicious by multiple AV engines."
                ),
                "recommendation": "Do not install or distribute this application. Perform a full malware analysis before any further use.",
                "confidence":     min(95, 50 + main_report["malicious"] * 2),
                "exploitability": 90,
                "source":         "VIRUSTOTAL",
                "cwe":            "CWE-506",
                "masvs":          "MASVS-CODE-4",
                "owasp":          "M9",
                "validation_status": "validated",
            })

    except Exception as exc:
        vt_result["error"] = str(exc)
        metrics["error"] = str(exc)

    return metrics
