import json
import re
import socket
import urllib.error
import urllib.request


SUSPICIOUS_KEYWORDS = {
    "dev": 20,
    "stage": 20,
    "staging": 20,
    "qa": 15,
    "uat": 15,
    "test": 15,
    "debug": 20,
    "internal": 10,
}

SUSPICIOUS_TLDS = {
    ".ru": 25,
    ".su": 20,
    ".click": 15,
    ".top": 10,
    ".xyz": 8,
}

DYNAMIC_DNS_HINTS = (
    "duckdns.org", "no-ip.", "dynu.", "ddns.", "hopto.org", "myftp.org",
)

OFAC_COUNTRIES = {
    "Cuba", "Iran", "North Korea", "Russia", "Syria",
    "Venezuela", "Belarus", "Myanmar", "Libya", "Somalia",
    "Sudan", "Yemen", "Zimbabwe",
}


def check_domains(endpoints: list, results: dict):
    """
    For each unique domain extracted from endpoints:
    - Resolve IP
    - Do basic geo lookup via ip-api.com (free, no key needed)
    - Add heuristic reputation scoring
    - Flag sanctioned-country and suspicious infrastructure patterns
    """
    domains = _extract_unique_domains(endpoints)
    domain_intel = []

    for domain in list(domains)[:30]:
        intel = {
            "domain": domain,
            "ip": None,
            "country": None,
            "city": None,
            "region": None,
            "lat": None,
            "lon": None,
            "status": "unknown",
            "risk_flags": [],
            "risk_score": 0,
            "reputation": "unknown",
        }
        try:
            ip = socket.gethostbyname(domain)
            intel["ip"] = ip

            if _is_private_ip(ip):
                intel["status"] = "private"
                intel["risk_flags"].append("private_ip")
                intel["risk_score"] += 5
                _finalize_intel(intel)
                domain_intel.append(intel)
                continue

            geo_url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon"
            req = urllib.request.Request(geo_url, headers={"User-Agent": "Cortex/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                geo = json.loads(resp.read().decode())
                if geo.get("status") == "success":
                    intel["country"] = geo.get("country")
                    intel["city"] = geo.get("city")
                    intel["region"] = geo.get("regionName")
                    intel["lat"] = geo.get("lat")
                    intel["lon"] = geo.get("lon")
                    intel["status"] = "ok"

                    if _is_ofac_country(geo.get("country", "")):
                        intel["ofac"] = True
                        intel["risk_flags"].append("ofac_country")
                        intel["risk_score"] += 35
        except socket.gaierror:
            intel["status"] = "dns_failed"
            intel["risk_flags"].append("dns_resolution_failed")
            intel["risk_score"] += 10
        except Exception:
            intel["status"] = "error"
            intel["risk_flags"].append("intel_lookup_failed")

        _apply_domain_heuristics(intel)
        _finalize_intel(intel)
        domain_intel.append(intel)

        if "ofac_country" in intel["risk_flags"]:
            results["findings"].append({
                "title": f"Domain Communicates With OFAC Sanctioned Country — {domain}",
                "severity": "medium",
                "category": "Network Intelligence",
                "description": f"Domain `{domain}` ({intel.get('ip') or 'unresolved'}) resolves to {intel.get('country')}. This country appears on the OFAC sanctioned list.",
                "recommendation": "Verify this connection is legitimate and required. Review legal and data-transfer obligations.",
                "cwe": "CWE-359",
                "masvs": "MASVS-NETWORK-1",
                "owasp": "M5",
            })

        if intel["risk_score"] >= 35 and "ofac_country" not in intel["risk_flags"]:
            results["findings"].append({
                "title": f"Suspicious External Domain Infrastructure — {domain}",
                "severity": "medium",
                "category": "Network Intelligence",
                "description": f"Domain `{domain}` was enriched with suspicious indicators: {', '.join(intel['risk_flags'])}.",
                "impact": "Test, staging, dynamic-DNS, or suspicious-TLD infrastructure in production apps can expose internal services and weaken trust boundaries.",
                "recommendation": "Review whether this endpoint belongs in production. Remove test or transient infrastructure from release builds.",
                "cwe": "CWE-200",
                "masvs": "MASVS-NETWORK-1",
                "owasp": "M5",
            })

    results["domain_intel"] = domain_intel


def _extract_unique_domains(endpoints: list) -> set:
    domains = set()
    url_pattern = re.compile(r"https?://([a-zA-Z0-9\-._]+)")
    for url in endpoints:
        m = url_pattern.match(url)
        if m:
            domain = m.group(1).lower()
            if "." in domain and len(domain) > 4:
                if not any(skip in domain for skip in [
                    "schemas.android", "www.w3.org", "xmlns",
                    "example.com", "localhost", "dummy.com",
                ]):
                    domains.add(domain)
    return domains


def _apply_domain_heuristics(intel: dict):
    domain = intel.get("domain", "").lower()
    if not domain:
        return

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", domain):
        intel["risk_flags"].append("literal_ip_domain")
        intel["risk_score"] += 20

    for keyword, weight in SUSPICIOUS_KEYWORDS.items():
        if re.search(rf"(^|[.\-]){re.escape(keyword)}([.\-]|$)", domain):
            intel["risk_flags"].append(f"{keyword}_host")
            intel["risk_score"] += weight

    for tld, weight in SUSPICIOUS_TLDS.items():
        if domain.endswith(tld):
            intel["risk_flags"].append(f"suspicious_tld:{tld}")
            intel["risk_score"] += weight

    if any(hint in domain for hint in DYNAMIC_DNS_HINTS):
        intel["risk_flags"].append("dynamic_dns")
        intel["risk_score"] += 25


def _finalize_intel(intel: dict):
    score = intel.get("risk_score", 0)
    if score >= 45:
        intel["reputation"] = "high-risk"
    elif score >= 20:
        intel["reputation"] = "review"
    elif intel.get("status") == "ok":
        intel["reputation"] = "observed"
    else:
        intel["reputation"] = "unknown"


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
        return (
            first == 10
            or first == 127
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
        )
    except Exception:
        return False


def _is_ofac_country(country: str) -> bool:
    return country in OFAC_COUNTRIES
