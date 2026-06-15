import os
import re
import zipfile
import urllib.request
import urllib.error
import json
from pathlib import Path


def check_firebase_db(results: dict):
    """Test Firebase Realtime Database for unauthenticated access."""
    # Find Firebase URLs from endpoints and secrets
    firebase_urls = set()

    for endpoint in results.get("endpoints", []):
        if "firebaseio.com" in endpoint:
            # Normalize to base URL
            match = re.search(r'https?://[a-z0-9\-]+\.firebaseio\.com', endpoint)
            if match:
                firebase_urls.add(match.group(0))

    for secret in results.get("secrets", []):
        if secret.get("category") == "Firebase":
            desc = secret.get("description", "")
            match = re.search(r'https?://[a-z0-9\-]+\.firebaseio\.com', desc)
            if match:
                firebase_urls.add(match.group(0))

    for url in list(firebase_urls)[:3]:  # check up to 3
        try:
            test_url = url.rstrip("/") + "/.json"
            req = urllib.request.Request(test_url, headers={"User-Agent": "Cortex-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(1000).decode("utf-8", errors="replace")
                status = resp.status

                if status == 200 and body != "null":
                    results["findings"].append({
                        "title":          "Firebase Database — Unauthenticated Read Access CONFIRMED",
                        "severity":       "critical",
                        "category":       "Cloud Configuration",
                        "description":    f"Firebase Realtime Database at `{url}` returned data without authentication (HTTP 200). Data is publicly readable.",
                        "impact":         "All data in this Firebase database is exposed to any unauthenticated user on the internet.",
                        "poc":            f"curl {test_url}",
                        "recommendation": "Immediately set Firebase security rules to require authentication:\n{{\"rules\": {{\"rules\": {{\".read\": \"auth != null\", \".write\": \"auth != null\"}}}}}}",
                        "masvs":          "MASVS-NETWORK-1",
                        "owasp":          "M8",
                    })
                elif status == 200:
                    results["findings"].append({
                        "title":          "Firebase Database — Accessible (Empty Response)",
                        "severity":       "medium",
                        "category":       "Cloud Configuration",
                        "description":    f"Firebase DB at `{url}` returned HTTP 200 with null data. Rules may allow read but database is empty.",
                        "poc":            f"curl {test_url}",
                        "recommendation": "Verify Firebase security rules require authentication.",
                        "masvs":          "MASVS-NETWORK-1",
                        "owasp":          "M8",
                    })
                else:
                    results["findings"].append({
                        "title":          "Firebase Database — Access Restricted",
                        "severity":       "info",
                        "category":       "Cloud Configuration",
                        "description":    f"Firebase DB at `{url}` returned HTTP {status}. Access appears restricted.",
                    })
        except urllib.error.HTTPError as e:
            if e.code == 401:
                results["findings"].append({
                    "title":       "Firebase Database — Authentication Required",
                    "severity":    "info",
                    "category":    "Cloud Configuration",
                    "description": f"Firebase DB at `{url}` requires authentication (HTTP 401). Rules are configured correctly.",
                })
        except Exception:
            pass  # Network unavailable or timeout — skip silently


def check_assetlinks(results: dict):
    """Fetch and validate Android assetlinks.json for deeplinks."""
    attack_surface = results.get("attack_surface", {})
    activities = attack_surface.get("activities", [])

    # Collect all HTTPS hosts from browsable intent filters
    hosts_to_check = set()
    for act in activities:
        if act.get("browsable"):
            for scheme in act.get("schemes", []):
                if scheme in ("https", "http"):
                    for host in act.get("hosts", []):
                        if host and "." in host:
                            hosts_to_check.add(host)

    pkg = results.get("app_info", {}).get("package", "")

    for host in list(hosts_to_check)[:3]:  # check up to 3 hosts
        url = f"https://{host}/.well-known/assetlinks.json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Cortex-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(10000).decode("utf-8", errors="replace")
                data = json.loads(body)

                # Check if package is in assetlinks
                pkg_found = False
                if isinstance(data, list):
                    for entry in data:
                        target = entry.get("target", {})
                        if target.get("package_name") == pkg:
                            pkg_found = True
                            break

                if pkg_found:
                    results["findings"].append({
                        "title":       f"assetlinks.json Valid — {host}",
                        "severity":    "info",
                        "category":    "Deeplinks",
                        "description": f"assetlinks.json at {host} correctly references this app. App Links are properly configured.",
                    })
                else:
                    results["findings"].append({
                        "title":          f"assetlinks.json Missing App Package — {host}",
                        "severity":       "medium",
                        "category":       "Deeplinks",
                        "description":    f"assetlinks.json exists at {host} but does not include package `{pkg}`. "
                                           "Android will not verify this as an App Link, making it vulnerable to custom scheme hijacking.",
                        "poc":            f"curl {url}",
                        "recommendation": "Add this app's package name and SHA-256 fingerprint to assetlinks.json.",
                        "masvs":          "MASVS-PLATFORM-1",
                        "owasp":          "M1",
                    })

        except urllib.error.HTTPError:
            results["findings"].append({
                "title":          f"assetlinks.json Not Found — {host}",
                "severity":       "high",
                "category":       "Deeplinks",
                "description":    f"No assetlinks.json found at `{host}`. App uses https:// deeplinks without App Link verification. "
                                   "Any app can register the same URL scheme.",
                "poc":            f"curl {url}",
                "recommendation": "Host assetlinks.json at https://{host}/.well-known/assetlinks.json with your app's package and fingerprint.",
                "masvs":          "MASVS-PLATFORM-1",
                "owasp":          "M1",
            })
        except Exception:
            pass


def analyze_file_inventory(apk_path: str, results: dict):
    """Analyze all files in APK for suspicious entries."""
    suspicious = []
    all_files  = []

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for info in z.infolist():
                name = info.filename
                size = info.file_size
                all_files.append({
                    "name": name,
                    "size": size,
                    "compressed": info.compress_size,
                })

                # Flag suspicious files
                fname_lower = name.lower()

                # Embedded APKs
                if fname_lower.endswith(".apk") and name != "":
                    suspicious.append({"file": name, "reason": "Embedded APK", "severity": "high"})

                # Embedded DEX outside expected locations
                elif fname_lower.endswith(".dex") and not fname_lower.startswith("classes"):
                    suspicious.append({"file": name, "reason": "Non-standard DEX file", "severity": "high"})

                # Executable binaries outside lib/
                elif fname_lower.endswith((".exe", ".elf", ".bin")) and "lib/" not in fname_lower:
                    suspicious.append({"file": name, "reason": "Embedded executable binary", "severity": "high"})

                # Shell scripts
                elif fname_lower.endswith((".sh", ".bat", ".ps1")):
                    suspicious.append({"file": name, "reason": "Shell/batch script in APK", "severity": "medium"})

                # JAR files (possible classpath manipulation)
                elif fname_lower.endswith(".jar") and "lib" not in fname_lower:
                    suspicious.append({"file": name, "reason": "Embedded JAR file", "severity": "medium"})

                # Crypto key files
                elif fname_lower.endswith((".pem", ".p12", ".pfx", ".key", ".jks", ".bks")):
                    suspicious.append({"file": name, "reason": "Cryptographic key/cert file embedded", "severity": "critical"})

                # DB files
                elif fname_lower.endswith((".db", ".sqlite", ".sqlite3")):
                    suspicious.append({"file": name, "reason": "Database file bundled in APK", "severity": "medium"})

    except Exception:
        pass

    results["file_inventory"] = {
        "total_files": len(all_files),
        "suspicious":  suspicious,
    }

    for item in suspicious:
        results["findings"].append({
            "title":          f"Suspicious File in APK — {Path(item['file']).name}",
            "severity":       item["severity"],
            "category":       "File Analysis",
            "description":    f"Suspicious file detected: `{item['file']}` — {item['reason']}.",
            "recommendation": "Investigate why this file is bundled. Remove if not required.",
            "masvs":          "MASVS-CODE-4" if item["severity"] != "critical" else "MASVS-CRYPTO-2",
            "owasp":          "M7",
        })


def detect_obfuscation(tmpdir: str, results: dict):
    """Heuristic obfuscation detection based on class name patterns."""
    short_classes = 0
    total_classes  = 0
    sample_short   = []

    for root, _, files in os.walk(tmpdir):
        for fname in files:
            if fname.endswith(".smali") or (fname.endswith(".java") and len(fname) < 6):
                total_classes += 1
                base = os.path.splitext(fname)[0]
                if len(base) <= 2:
                    short_classes += 1
                    if len(sample_short) < 10:
                        sample_short.append(base)

    if total_classes > 50:
        ratio = short_classes / total_classes
        if ratio > 0.4:
            results["findings"].append({
                "title":       "Code Obfuscation Detected (ProGuard/R8)",
                "severity":    "info",
                "category":    "Resilience",
                "description": f"~{int(ratio*100)}% of class names are 1-2 characters, indicating active obfuscation. "
                               "This is expected for release builds and makes static analysis harder.",
                "masvs":       "MASVS-RESILIENCE-3",
                "owasp":       "M7",
            })
        elif ratio < 0.05 and total_classes > 100:
            results["findings"].append({
                "title":       "Code Obfuscation Not Detected",
                "severity":    "low",
                "category":    "Resilience",
                "description": "Class names appear unobfuscated. ProGuard/R8 minification does not appear to be enabled. "
                               "This makes reverse engineering significantly easier.",
                "recommendation": "Enable minifyEnabled = true and obfuscation in release build config.",
                "masvs":          "MASVS-RESILIENCE-3",
                "owasp":          "M7",
            })


# ─── S3 bucket open-read probe ────────────────────────────────────────────────
_S3_RE = re.compile(
    r"https?://(?P<bucket>[a-z0-9.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com",
    re.IGNORECASE,
)


def check_s3_buckets(results: dict, max_buckets: int = 5):
    """Probe any S3 URLs referenced by the app for unauthenticated list/read."""
    if os.environ.get("CORTEX_DISABLE_LIVE_CHECKS", "").lower() in ("1", "true", "yes"):
        return
    buckets = {}
    # gather from endpoints + secrets + strings
    sources = []
    sources.extend(results.get("endpoints", []) or [])
    for s in results.get("secrets", []) or []:
        for v in (s.get("match"), s.get("description")):
            if v:
                sources.append(v)
    for src in sources:
        m = _S3_RE.search(str(src))
        if not m:
            continue
        bucket = m.group("bucket").split(".")[0]
        if bucket and bucket not in buckets:
            buckets[bucket] = m.group(0)
        if len(buckets) >= max_buckets:
            break

    for bucket, base in list(buckets.items())[:max_buckets]:
        list_url = f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=1"
        try:
            req = urllib.request.Request(list_url, headers={"User-Agent": "Cortex-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                if resp.status == 200 and "<ListBucketResult" in body:
                    results["findings"].append({
                        "title":          f"S3 Bucket Publicly Listable — {bucket}",
                        "severity":       "critical",
                        "category":       "Cloud Configuration",
                        "rule_id":        "cloud_s3_public_list",
                        "description":    f"S3 bucket `{bucket}` responds to unauthenticated ListObjectsV2 calls. Object keys (and possibly content) are enumerable by anyone.",
                        "impact":         "Attackers can enumerate and download objects. Often exposes user uploads, backups, and credentials.",
                        "poc":            f"curl '{list_url}'",
                        "recommendation": "Block public ACLs, enable S3 Block Public Access at account level, and switch to presigned URLs.",
                        "masvs":          "MASVS-NETWORK-1",
                        "owasp":          "M8",
                        "confidence":     "high",
                    })
        except urllib.error.HTTPError as e:
            if e.code in (403,):
                results["findings"].append({
                    "title":       f"S3 Bucket Exists, Listing Denied — {bucket}",
                    "severity":    "info",
                    "category":    "Cloud Configuration",
                    "description": f"Bucket `{bucket}` exists but denies anonymous listing (HTTP 403).",
                })
        except Exception:
            pass
