"""
SAST / Semgrep rule-pack configuration (Beetle 2.0, Phase 2.4).

THE central, data-driven place rule packs live, so enabling a new pack requires NO
code change — only data (this table) or environment / a JSON config file. Beetle never
vendors or modifies Semgrep rules; a "pack" is just *where Semgrep gets rules from* (a
``--config`` value: a registry shorthand like ``p/android``, a URL, or a path) plus the
languages it applies to and a tier.

Project detection picks only the languages a scan actually contains (Android → java/
kotlin/xml, iOS → swift/objc, Flutter → dart/yaml, React Native → js/ts), so we never
run a Java ruleset against an iOS app — "only relevant packs, no unnecessary scans."

Tiers (priority order — earlier = higher precedence; the ``priority`` seam is reserved
for future pack-priority resolution): official → enterprise → organization → community
→ experimental.

Configuration surfaces (no code change needed to add a pack):
  CORTEX_SEMGREP_PACKS         comma list of pack ids to allow (whitelist; empty = all enabled)
  CORTEX_SEMGREP_DISABLE_PACKS comma list of pack ids to disable
  CORTEX_SEMGREP_EXTRA_CONFIG  comma list of extra --config values (org/enterprise rules, paths, URLs)
  CORTEX_SEMGREP_CONFIG_FILE   path to a JSON file of additional/override pack dicts

Future-reserved pack fields (documented, NOT acted on this phase): ``priority``,
``offline_path`` (offline rule bundle), ``version`` (rule version pin), ``repo``
(organization rule repository).
"""
from __future__ import annotations

import json
import logging
import os

log = logging.getLogger("cortex.sast.config")

# ── Tiers ─────────────────────────────────────────────────────────────────────
TIER_OFFICIAL = "official"
TIER_ENTERPRISE = "enterprise"
TIER_ORGANIZATION = "organization"
TIER_COMMUNITY = "community"
TIER_EXPERIMENTAL = "experimental"
TIER_ORDER = (TIER_OFFICIAL, TIER_ENTERPRISE, TIER_ORGANIZATION, TIER_COMMUNITY, TIER_EXPERIMENTAL)

# ── Canonical language tokens ─────────────────────────────────────────────────
LANGS = ("java", "kotlin", "swift", "objc", "dart", "javascript", "typescript",
         "yaml", "xml", "json")

# ── Default rule packs (DATA — add a pack here or via env/JSON; no code change) ─
# Each: id, tier, config (Semgrep --config value), languages[], enabled.
DEFAULT_PACKS: list[dict] = [
    # Selection signal is java/kotlin (Android), NOT xml — xml is too coarse and would
    # pull the Android pack into an iOS scan. Semgrep still applies the pack's XML
    # manifest rules to XML files; this list only decides WHEN to run the pack.
    {"id": "semgrep-android", "tier": TIER_OFFICIAL, "config": "p/android",
     "languages": ["java", "kotlin"], "enabled": True},
    {"id": "semgrep-java", "tier": TIER_OFFICIAL, "config": "p/java",
     "languages": ["java"], "enabled": True},
    {"id": "semgrep-kotlin", "tier": TIER_OFFICIAL, "config": "p/kotlin",
     "languages": ["kotlin"], "enabled": True},
    {"id": "semgrep-javascript", "tier": TIER_OFFICIAL, "config": "p/javascript",
     "languages": ["javascript"], "enabled": True},
    {"id": "semgrep-typescript", "tier": TIER_OFFICIAL, "config": "p/typescript",
     "languages": ["typescript"], "enabled": True},
    {"id": "semgrep-swift", "tier": TIER_COMMUNITY, "config": "p/swift",
     "languages": ["swift"], "enabled": True},
    # Secrets are owned by Beetle's Secret Intelligence Engine — off by default to
    # avoid double-sourcing; an operator can enable it via CORTEX_SEMGREP_PACKS.
    {"id": "semgrep-secrets", "tier": TIER_OFFICIAL, "config": "p/secrets",
     "languages": list(LANGS), "enabled": False},
]

# ── Project detection: platform / framework → languages present ────────────────
PLATFORM_LANGUAGES = {
    "android": ["java", "kotlin", "xml", "json", "yaml"],
    "ios": ["swift", "objc", "xml", "json", "yaml"],   # Info.plist ≈ xml
}
FRAMEWORK_LANGUAGES = {
    "flutter": ["dart", "yaml", "json"],
    "react_native": ["javascript", "typescript", "json"],
}


def _csv_env(name: str) -> list[str]:
    return [x.strip() for x in (os.environ.get(name, "") or "").split(",") if x.strip()]


def load_packs() -> list[dict]:
    """All configured packs = DEFAULT_PACKS + JSON-file packs, with env enable/disable
    applied. Pure (re-reads env each call so tests/config changes take effect)."""
    packs = [dict(p) for p in DEFAULT_PACKS]

    # JSON config file (additional / override by id).
    cfg_file = os.environ.get("CORTEX_SEMGREP_CONFIG_FILE")
    if cfg_file and os.path.isfile(cfg_file):
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                extra = json.load(f)
            entries = extra.get("packs", extra) if isinstance(extra, dict) else extra
            by_id = {p["id"]: p for p in packs}
            for e in entries or []:
                if isinstance(e, dict) and e.get("id"):
                    by_id[e["id"]] = {**by_id.get(e["id"], {}), **e}
            packs = list(by_id.values())
        except Exception:
            log.exception("[sast.config] failed to load CORTEX_SEMGREP_CONFIG_FILE")

    whitelist = set(_csv_env("CORTEX_SEMGREP_PACKS"))
    disabled = set(_csv_env("CORTEX_SEMGREP_DISABLE_PACKS"))
    for p in packs:
        p.setdefault("enabled", True)
        if whitelist:
            p["enabled"] = p["id"] in whitelist
        if p["id"] in disabled:
            p["enabled"] = False
    return packs


def languages_for(platform: str | None, framework: str | None = None) -> list[str]:
    """The languages a scan of this platform/framework actually contains."""
    langs: list[str] = []
    for lng in PLATFORM_LANGUAGES.get((platform or "").lower(), []):
        if lng not in langs:
            langs.append(lng)
    for lng in FRAMEWORK_LANGUAGES.get((framework or "").lower(), []):
        if lng not in langs:
            langs.append(lng)
    return langs or list(LANGS)


def configs_for(languages: list[str]) -> list[str]:
    """The Semgrep ``--config`` values to run for the given languages: enabled packs
    whose languages intersect, in tier order, plus any CORTEX_SEMGREP_EXTRA_CONFIG.
    De-duplicated, order-stable — this is what the adapter passes to Semgrep."""
    want = set(languages or [])
    out: list[str] = []
    for tier in TIER_ORDER:
        for p in load_packs():
            if not p.get("enabled") or p.get("tier") != tier:
                continue
            if want & set(p.get("languages", [])):
                cfg = p.get("config")
                if cfg and cfg not in out:
                    out.append(cfg)
    for extra in _csv_env("CORTEX_SEMGREP_EXTRA_CONFIG"):
        if extra not in out:
            out.append(extra)
    return out


def configs_for_project(platform: str | None, framework: str | None = None) -> list[str]:
    """Convenience: project detection → relevant ``--config`` values."""
    return configs_for(languages_for(platform, framework))


def summary() -> dict:
    packs = load_packs()
    return {
        "packs": [{"id": p["id"], "tier": p.get("tier"), "config": p.get("config"),
                   "enabled": p.get("enabled", True)} for p in packs],
        "enabled": [p["id"] for p in packs if p.get("enabled")],
        "extra_config": _csv_env("CORTEX_SEMGREP_EXTRA_CONFIG"),
    }
