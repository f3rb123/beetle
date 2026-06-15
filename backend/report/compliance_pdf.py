"""
Cortex Compliance Report Generator
====================================
Produces a structured compliance PDF mapped to a chosen framework.

Supported frameworks:
  - masvs   : OWASP MASVS v2 (MAS-TESTING-GUIDE 2.x control IDs)
  - pci_dss : PCI-DSS v4.0 mobile-relevant requirements (req 6, 8, 10, 12)
  - owasp_mobile: OWASP Mobile Top 10 (M1–M10)

Each framework defines a list of controls. For every control:
  - Map findings → control via tags (masvs / owasp / cwe fields)
  - Status: PASS if no findings mapped; FAIL if any finding mapped
  - Severity of mapped findings shown inline

Output structure:
  Cover → Executive Summary → Compliance Scorecard → Per-Control Detail
"""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph,
    SimpleDocTemplate, Spacer, Table, TableStyle,
)

# ── Reuse theme + style machinery from the main generator ────────────────────
from .pdf_generator import THEMES, SEVERITY_COLORS, _build_styles, _table_style

PAGE_W, PAGE_H = A4

# ── Control framework definitions ─────────────────────────────────────────────

# MASVS v2 controls — key fields used for mapping:
#   masvs_prefix: prefix of the MASVS field in findings (e.g. "MASVS-STORAGE")
MASVS_CONTROLS = [
    # MASVS-STORAGE
    {
        "id": "MASVS-STORAGE-1",
        "title": "Sensitive data is not stored on the device unnecessarily",
        "category": "Storage",
        "masvs_prefix": "MASVS-STORAGE-1",
        "owasp_tags": ["M2"],
        "cwe_tags": ["CWE-312", "CWE-313", "CWE-922"],
        "description": "Verify that sensitive data is not written to persistent storage in clear text.",
    },
    {
        "id": "MASVS-STORAGE-2",
        "title": "Sensitive data is not shared to third parties",
        "category": "Storage",
        "masvs_prefix": "MASVS-STORAGE-2",
        "owasp_tags": ["M2"],
        "cwe_tags": ["CWE-532", "CWE-200"],
        "description": "Verify that no sensitive data is exposed through logs or backups.",
    },
    # MASVS-CRYPTO
    {
        "id": "MASVS-CRYPTO-1",
        "title": "Strong cryptography is used following current best practices",
        "category": "Cryptography",
        "masvs_prefix": "MASVS-CRYPTO-1",
        "owasp_tags": ["M5"],
        "cwe_tags": ["CWE-327", "CWE-326", "CWE-330"],
        "description": "Verify that proven cryptographic primitives with secure parameters are used.",
    },
    {
        "id": "MASVS-CRYPTO-2",
        "title": "Key management follows security best practices",
        "category": "Cryptography",
        "masvs_prefix": "MASVS-CRYPTO-2",
        "owasp_tags": ["M5"],
        "cwe_tags": ["CWE-321", "CWE-798"],
        "description": "Keys must not be hardcoded and must be stored in the Android Keystore/iOS Secure Enclave.",
    },
    # MASVS-AUTH
    {
        "id": "MASVS-AUTH-1",
        "title": "Authentication is based on platform mechanisms",
        "category": "Authentication",
        "masvs_prefix": "MASVS-AUTH",
        "owasp_tags": ["M4"],
        "cwe_tags": ["CWE-287", "CWE-306"],
        "description": "All authentication uses platform-provided mechanisms; no custom schemes.",
    },
    # MASVS-NETWORK
    {
        "id": "MASVS-NETWORK-1",
        "title": "Data is encrypted in transit",
        "category": "Network",
        "masvs_prefix": "MASVS-NETWORK-1",
        "owasp_tags": ["M3"],
        "cwe_tags": ["CWE-319", "CWE-295"],
        "description": "Verify all network communication uses TLS with valid certificates.",
    },
    {
        "id": "MASVS-NETWORK-2",
        "title": "Certificate pinning is implemented where required",
        "category": "Network",
        "masvs_prefix": "MASVS-NETWORK-2",
        "owasp_tags": ["M3"],
        "cwe_tags": ["CWE-297"],
        "description": "High-value apps must pin certificate or public key; no wildcard pins.",
    },
    # MASVS-PLATFORM
    {
        "id": "MASVS-PLATFORM-1",
        "title": "Component usage follows least privilege principle",
        "category": "Platform",
        "masvs_prefix": "MASVS-PLATFORM-1",
        "owasp_tags": ["M1"],
        "cwe_tags": ["CWE-926", "CWE-927"],
        "description": "Exported components restricted; Intents validated; IPC interfaces minimal.",
    },
    {
        "id": "MASVS-PLATFORM-2",
        "title": "WebViews are configured securely",
        "category": "Platform",
        "masvs_prefix": "MASVS-PLATFORM-2",
        "owasp_tags": ["M1"],
        "cwe_tags": ["CWE-749", "CWE-79"],
        "description": "WebViews disable JavaScript where not required; file access restricted.",
    },
    # MASVS-CODE
    {
        "id": "MASVS-CODE-1",
        "title": "Input validation and output encoding prevent injection",
        "category": "Code Quality",
        "masvs_prefix": "MASVS-CODE",
        "owasp_tags": ["M7"],
        "cwe_tags": ["CWE-89", "CWE-78", "CWE-134"],
        "description": "All untrusted input validated; SQL, command, and format-string injection prevented.",
    },
    {
        "id": "MASVS-CODE-4",
        "title": "The app does not contain debug/insecure configuration",
        "category": "Code Quality",
        "masvs_prefix": "MASVS-CODE-4",
        "owasp_tags": ["M8"],
        "cwe_tags": ["CWE-215", "CWE-489"],
        "description": "Debug flags, test accounts, and unsafe defaults removed from release builds.",
    },
    # MASVS-RESILIENCE
    {
        "id": "MASVS-RESILIENCE-1",
        "title": "Code obfuscation applied",
        "category": "Resilience",
        "masvs_prefix": "MASVS-RESILIENCE",
        "owasp_tags": ["M9"],
        "cwe_tags": [],
        "description": "App binary is obfuscated; reverse-engineering effort is high.",
    },
    # MASVS-PRIVACY
    {
        "id": "MASVS-PRIVACY-1",
        "title": "App minimises data collection and enforces data minimisation",
        "category": "Privacy",
        "masvs_prefix": "MASVS-PRIVACY",
        "owasp_tags": ["M2"],
        "cwe_tags": ["CWE-359"],
        "description": "Only data necessary for documented functionality is collected and retained.",
    },
]

# PCI-DSS v4.0 mobile-relevant requirements
PCI_CONTROLS = [
    {
        "id": "REQ-6.2",
        "title": "Bespoke software protects against common vulnerabilities",
        "category": "Secure Software",
        "masvs_prefix": "MASVS-CODE",
        "owasp_tags": ["M7"],
        "cwe_tags": ["CWE-89", "CWE-78", "CWE-79"],
        "description": "Software protects against OWASP Mobile Top 10 and injection vulnerabilities.",
    },
    {
        "id": "REQ-6.3",
        "title": "Security vulnerabilities are identified and managed",
        "category": "Secure Software",
        "masvs_prefix": "MASVS-CODE",
        "owasp_tags": ["M8", "M9"],
        "cwe_tags": ["CWE-1026", "CWE-1035"],
        "description": "Vulnerability scanning is performed and findings remediated within SLA.",
    },
    {
        "id": "REQ-6.4",
        "title": "Public-facing web applications are protected against attack",
        "category": "Secure Software",
        "masvs_prefix": "MASVS-PLATFORM-2",
        "owasp_tags": ["M1"],
        "cwe_tags": ["CWE-79", "CWE-749"],
        "description": "WebViews and API integrations protected against injection and XSS.",
    },
    {
        "id": "REQ-8.2",
        "title": "User and system accounts are strictly managed",
        "category": "Identity Management",
        "masvs_prefix": "MASVS-AUTH",
        "owasp_tags": ["M4"],
        "cwe_tags": ["CWE-287", "CWE-521"],
        "description": "Strong authentication required; credentials never hardcoded.",
    },
    {
        "id": "REQ-8.3",
        "title": "User authentication factors are secured",
        "category": "Identity Management",
        "masvs_prefix": "MASVS-CRYPTO",
        "owasp_tags": ["M5"],
        "cwe_tags": ["CWE-798", "CWE-321"],
        "description": "Passwords and keys encrypted; hardcoded secrets prohibited.",
    },
    {
        "id": "REQ-10.2",
        "title": "Audit logs capture events related to cardholder data",
        "category": "Logging",
        "masvs_prefix": "MASVS-STORAGE-2",
        "owasp_tags": ["M2"],
        "cwe_tags": ["CWE-532"],
        "description": "Sensitive data must not appear in application logs.",
    },
    {
        "id": "REQ-12.3",
        "title": "Technical policies protect cryptographic keys",
        "category": "Cryptography",
        "masvs_prefix": "MASVS-CRYPTO-2",
        "owasp_tags": ["M5"],
        "cwe_tags": ["CWE-321", "CWE-326"],
        "description": "Key lifecycle managed; no hardcoded or weak keys in app binary.",
    },
    {
        "id": "REQ-12.6",
        "title": "Security awareness training includes mobile threats",
        "category": "Policy",
        "masvs_prefix": "",
        "owasp_tags": [],
        "cwe_tags": [],
        "description": "Security practices cover mobile-specific risks and OWASP Mobile Top 10.",
    },
]

# OWASP Mobile Top 10 (2024)
OWASP_MOBILE_CONTROLS = [
    {"id": "M1",  "title": "Improper Credential Usage",           "owasp_tags": ["M1"],  "cwe_tags": ["CWE-312","CWE-522"], "description": "Hardcoded credentials, insecure storage, improper auth flows."},
    {"id": "M2",  "title": "Inadequate Supply Chain Security",    "owasp_tags": ["M2"],  "cwe_tags": [],                    "description": "Third-party components with known vulnerabilities."},
    {"id": "M3",  "title": "Insecure Authentication/Authorization","owasp_tags": ["M3"], "cwe_tags": ["CWE-287"],           "description": "Weak authentication, missing auth on sensitive endpoints."},
    {"id": "M4",  "title": "Insufficient Input/Output Validation", "owasp_tags": ["M4"], "cwe_tags": ["CWE-89","CWE-78"],  "description": "SQL injection, command injection, cross-site scripting via WebView."},
    {"id": "M5",  "title": "Insecure Communication",              "owasp_tags": ["M5"],  "cwe_tags": ["CWE-319","CWE-295"],"description": "Cleartext traffic, weak TLS, missing certificate validation."},
    {"id": "M6",  "title": "Inadequate Privacy Controls",         "owasp_tags": ["M6"],  "cwe_tags": ["CWE-359"],          "description": "PII collection without consent, sensitive data in logs or cache."},
    {"id": "M7",  "title": "Insufficient Binary Protections",     "owasp_tags": ["M7"],  "cwe_tags": [],                   "description": "Missing obfuscation, debug builds, insecure build settings."},
    {"id": "M8",  "title": "Security Misconfiguration",           "owasp_tags": ["M8"],  "cwe_tags": ["CWE-16","CWE-215"], "description": "Exported components, cleartext traffic config, backup enabled."},
    {"id": "M9",  "title": "Insecure Data Storage",               "owasp_tags": ["M9"],  "cwe_tags": ["CWE-312","CWE-921"],"description": "Sensitive data in SharedPreferences, SQLite, or temp files unencrypted."},
    {"id": "M10", "title": "Insufficient Cryptography",           "owasp_tags": ["M10"], "cwe_tags": ["CWE-327","CWE-326"],"description": "Weak algorithms, hardcoded keys, insecure RNG."},
]

FRAMEWORKS = {
    "masvs":         {"name": "OWASP MASVS v2",       "controls": MASVS_CONTROLS},
    "pci_dss":       {"name": "PCI-DSS v4.0 (Mobile)", "controls": PCI_CONTROLS},
    "owasp_mobile":  {"name": "OWASP Mobile Top 10",   "controls": OWASP_MOBILE_CONTROLS},
}


# ── Public entry point ────────────────────────────────────────────────────────

def generate_compliance_pdf(
    results: dict,
    output_path: str,
    framework: str = "masvs",
    theme: str = "light",
    prepared_by: str = "",
):
    """
    Generate a compliance-mapped PDF report.
    framework: 'masvs' | 'pci_dss' | 'owasp_mobile'
    """
    fw = FRAMEWORKS.get(framework, FRAMEWORKS["masvs"])
    T  = THEMES.get(theme, THEMES["light"])
    author = prepared_by.strip() or "Security Analyst"

    app_name = results.get("app_name", "Unknown App")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"Beetle {fw['name']} Compliance Report — {app_name}",
        author=author,
    )

    styles = _build_styles(T)
    story  = []

    # Map findings to controls
    mapped = _map_findings(results, fw["controls"])

    _compliance_cover(story, results, T, styles, fw, author)
    story.append(PageBreak())
    _compliance_exec_summary(story, results, T, styles, fw, mapped)
    story.append(PageBreak())
    _compliance_scorecard(story, T, styles, fw, mapped)
    story.append(PageBreak())
    _compliance_control_detail(story, T, styles, fw, mapped, results)

    def on_page(canv, doc, theme_ref=T):
        _draw_footer(canv, doc, results, theme_ref, fw["name"])

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


# ── Finding → control mapping ─────────────────────────────────────────────────

def _map_findings(results: dict, controls: list[dict]) -> dict[str, dict]:
    """
    Returns { control_id: { "control": ..., "findings": [...], "status": "PASS"|"FAIL"|"WARN" } }
    """
    all_findings = results.get("findings", []) + [
        {**s, "title": f"Secret: {s.get('name','?')}", "severity": s.get("severity","medium"),
         "masvs": "MASVS-CRYPTO-2", "owasp": "M1"}
        for s in results.get("secrets", [])
    ]

    control_map: dict[str, dict] = {}
    for ctrl in controls:
        control_map[ctrl["id"]] = {"control": ctrl, "findings": [], "status": "PASS"}

    for finding in all_findings:
        sev   = finding.get("severity", "info")
        masvs = finding.get("masvs", "") or ""
        owasp = finding.get("owasp", "") or ""
        cwe   = finding.get("cwe",   "") or ""

        for ctrl in controls:
            matched = False

            # Match on MASVS prefix
            if ctrl.get("masvs_prefix") and masvs.startswith(ctrl["masvs_prefix"]):
                matched = True

            # Match on OWASP tag
            if not matched and ctrl.get("owasp_tags"):
                for tag in ctrl["owasp_tags"]:
                    if tag in owasp:
                        matched = True
                        break

            # Match on CWE
            if not matched and ctrl.get("cwe_tags"):
                for c in ctrl["cwe_tags"]:
                    if c in cwe:
                        matched = True
                        break

            if matched:
                control_map[ctrl["id"]]["findings"].append(finding)

    # Set status
    sev_order = ["critical", "high", "medium", "low", "info"]
    for cid, entry in control_map.items():
        if not entry["findings"]:
            entry["status"] = "PASS"
        else:
            worst = min(
                (sev_order.index(f.get("severity", "info")) for f in entry["findings"]),
                default=4
            )
            entry["status"] = "FAIL" if worst <= 1 else "WARN"

    return control_map


# ── Cover page ────────────────────────────────────────────────────────────────

def _compliance_cover(story, results, T, styles, fw, author):
    story.append(Spacer(1, 30 * mm))
    story.append(Paragraph("CORTEX", styles["cover_title"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("Mobile Security Platform", styles["cover_sub"]))
    story.append(Spacer(1, 15 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 10 * mm))

    story.append(Paragraph("COMPLIANCE ASSESSMENT REPORT", styles["cover_label"]))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(results.get("app_name", "Unknown App"), styles["cover_app"]))
    story.append(Spacer(1, 2 * mm))

    pkg = results.get("app_info", {}).get("package") or results.get("app_info", {}).get("bundle_id", "")
    if pkg:
        story.append(Paragraph(pkg, styles["cover_pkg"]))

    story.append(Spacer(1, 8 * mm))

    fw_color = T["accent"].hexval()
    story.append(Paragraph(
        f'Framework: <font color="{fw_color}"><b>{fw["name"]}</b></font>',
        styles["cover_sub"],
    ))
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=0.3, color=T["border"]))
    story.append(Spacer(1, 6 * mm))

    date_str = datetime.utcnow().strftime("%B %d, %Y")
    story.append(Paragraph(f"Prepared by: {escape(author)}", styles["cover_author"]))
    story.append(Paragraph(f"Report date: {date_str} UTC", styles["cover_email"]))


# ── Executive summary ─────────────────────────────────────────────────────────

def _compliance_exec_summary(story, results, T, styles, fw, mapped):
    total   = len(mapped)
    passing = sum(1 for e in mapped.values() if e["status"] == "PASS")
    warn    = sum(1 for e in mapped.values() if e["status"] == "WARN")
    failing = sum(1 for e in mapped.values() if e["status"] == "FAIL")

    pct = int(100 * passing / total) if total else 0

    story.append(Paragraph("Executive Summary", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 6 * mm))

    # Scorecard summary row
    GREEN  = HexColor("#16a34a")
    AMBER  = HexColor("#d97706")
    RED    = HexColor("#dc2626")

    col_w = [42 * mm] * 4
    summary_rows = [[
        Paragraph(f'<font size="22" color="{GREEN.hexval()}"><b>{pct}%</b></font><br/><font size="9" color="#64748B">Controls Passing</font>', _center_style(T)),
        Paragraph(f'<font size="22" color="{GREEN.hexval()}"><b>{passing}</b></font><br/><font size="9" color="#64748B">Pass</font>', _center_style(T)),
        Paragraph(f'<font size="22" color="{AMBER.hexval()}"><b>{warn}</b></font><br/><font size="9" color="#64748B">Warn</font>', _center_style(T)),
        Paragraph(f'<font size="22" color="{RED.hexval()}"><b>{failing}</b></font><br/><font size="9" color="#64748B">Fail</font>', _center_style(T)),
    ]]
    t = Table(summary_rows, colWidths=col_w)
    t.setStyle(TableStyle([
        ("BOX",            (0, 0), (-1, -1), 0.5, T["border"]),
        ("INNERGRID",      (0, 0), (-1, -1), 0.3, T["border"]),
        ("BACKGROUND",     (0, 0), (-1, -1), T["card"]),
        ("TOPPADDING",     (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 6 * mm))

    # Narrative
    sev_ss = results.get("severity_summary", {})
    crit = sev_ss.get("critical", 0)
    high = sev_ss.get("high", 0)
    med  = sev_ss.get("medium", 0)

    narrative = (
        f"This {fw['name']} compliance report was generated by automated static analysis of "
        f"<b>{escape(results.get('app_name', '?'))}</b> "
        f"(package: {escape(results.get('app_info', {}).get('package', '?'))}).<br/><br/>"
        f"Of the {total} controls assessed, <b>{passing} passed</b>, "
        f"<b>{warn} require review</b>, and <b>{failing} have active failures</b>. "
        f"The scan identified <b>{crit} critical</b>, <b>{high} high</b>, and "
        f"<b>{med} medium</b>-severity findings that map to these controls.<br/><br/>"
        "Controls marked <b>PASS</b> indicate no automated findings were detected for that "
        "control area. This does not guarantee compliance — manual testing is required to "
        "confirm controls are correctly implemented."
    )
    story.append(Paragraph(narrative, styles["body"]))
    story.append(Spacer(1, 6 * mm))

    # Failing controls table
    failing_entries = [(cid, e) for cid, e in mapped.items() if e["status"] != "PASS"]
    if failing_entries:
        story.append(Paragraph("Controls Requiring Attention", styles["subsection_title"]))
        story.append(Spacer(1, 2 * mm))
        rows = [["Control", "Title", "Status", "Findings"]]
        for cid, entry in sorted(failing_entries, key=lambda x: (0 if x[1]["status"] == "FAIL" else 1, x[0])):
            status_color = RED if entry["status"] == "FAIL" else AMBER
            rows.append([
                Paragraph(f"<b>{cid}</b>", styles["table_cell"]),
                Paragraph(escape(entry["control"]["title"]), styles["table_cell"]),
                Paragraph(f'<font color="{status_color.hexval()}"><b>{entry["status"]}</b></font>', styles["table_cell"]),
                Paragraph(str(len(entry["findings"])), styles["table_cell"]),
            ])
        col_w = [22 * mm, 80 * mm, 18 * mm, 18 * mm]
        t2 = Table(rows, colWidths=col_w)
        t2.setStyle(_table_style(T))
        story.append(t2)


# ── Full scorecard ────────────────────────────────────────────────────────────

def _compliance_scorecard(story, T, styles, fw, mapped):
    story.append(Paragraph(f"{fw['name']} — Control Scorecard", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    GREEN  = HexColor("#16a34a")
    AMBER  = HexColor("#d97706")
    RED    = HexColor("#dc2626")
    GRAY   = HexColor("#64748b")

    rows = [["ID", "Control Title", "Category", "Status", "Findings"]]
    for ctrl in fw["controls"]:
        cid   = ctrl["id"]
        entry = mapped.get(cid, {"status": "PASS", "findings": []})
        status = entry["status"]
        color  = GREEN if status == "PASS" else (RED if status == "FAIL" else AMBER)
        cat    = ctrl.get("category", "")
        rows.append([
            Paragraph(f"<b>{cid}</b>", styles["table_cell"]),
            Paragraph(escape(ctrl["title"]), styles["table_cell"]),
            Paragraph(escape(cat), styles["table_cell"]),
            Paragraph(f'<font color="{color.hexval()}"><b>{status}</b></font>', styles["table_cell"]),
            Paragraph(str(len(entry["findings"])) if entry["findings"] else "—", styles["table_cell"]),
        ])

    col_w = [22 * mm, 80 * mm, 25 * mm, 15 * mm, 16 * mm]
    t = Table(rows, colWidths=col_w)
    t.setStyle(_table_style(T))
    story.append(t)


# ── Per-control detail ────────────────────────────────────────────────────────

def _compliance_control_detail(story, T, styles, fw, mapped, results):
    story.append(Paragraph("Control Detail", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    GREEN = HexColor("#16a34a")
    AMBER = HexColor("#d97706")
    RED   = HexColor("#dc2626")

    sev_order = ["critical", "high", "medium", "low", "info"]

    for ctrl in fw["controls"]:
        cid   = ctrl["id"]
        entry = mapped.get(cid, {"status": "PASS", "findings": []})
        status = entry["status"]
        color  = GREEN if status == "PASS" else (RED if status == "FAIL" else AMBER)
        findings = sorted(
            entry["findings"],
            key=lambda f: sev_order.index(f.get("severity", "info")) if f.get("severity") in sev_order else 4
        )

        # Control header block
        header_data = [[
            Paragraph(
                f'<b>{cid}</b> — {escape(ctrl["title"])}<br/>'
                f'<font size="8" color="{T["text_sub"].hexval()}">{escape(ctrl.get("description", ""))}</font>',
                styles["body"],
            ),
            Paragraph(
                f'<font color="{color.hexval()}"><b>{status}</b></font><br/>'
                f'<font size="8" color="{T["text_sub"].hexval()}">{len(findings)} finding{"s" if len(findings) != 1 else ""}</font>',
                _right_style(T),
            ),
        ]]
        header_tbl = Table(header_data, colWidths=[130 * mm, 28 * mm])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), T["header_bg"]),
            ("BOX",        (0, 0), (-1, -1), 0.5, T["border"]),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ]))

        block = [header_tbl]

        if findings:
            for f in findings[:8]:  # cap at 8 per control to avoid page explosion
                sev   = f.get("severity", "info")
                scol  = SEVERITY_COLORS.get(sev, HexColor("#64748b"))
                title = escape(f.get("title", "Untitled"))
                rec   = escape((f.get("recommendation") or "")[:300])
                fp    = escape(f.get("file_path", "") or "")
                line  = f.get("line", 0)

                loc_str = f"{fp}:{line}" if fp and line else (fp or "")
                row_data = [[
                    Paragraph(
                        f'<font color="{scol.hexval()}"><b>{sev.upper()}</b></font> — {title}'
                        + (f'<br/><font size="8" color="{T["text_sub"].hexval()}">{loc_str}</font>' if loc_str else ""),
                        styles["table_cell"],
                    ),
                    Paragraph(
                        rec or "—",
                        styles["table_cell"],
                    ),
                ]]
                row_tbl = Table(row_data, colWidths=[78 * mm, 80 * mm])
                row_tbl.setStyle(TableStyle([
                    ("BACKGROUND",  (0, 0), (-1, -1), T["bg"]),
                    ("BOX",         (0, 0), (-1, -1), 0.3, T["border"]),
                    ("LINEABOVE",   (0, 0), (-1, 0), 0.3, T["border"]),
                    ("VALIGN",      (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING",  (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]))
                block.append(row_tbl)

            if len(entry["findings"]) > 8:
                block.append(Paragraph(
                    f'<font size="8" color="{T["text_sub"].hexval()}">'
                    f'  … and {len(entry["findings"]) - 8} more finding(s) not shown.</font>',
                    styles["caption"],
                ))
        else:
            no_data = Table(
                [[Paragraph(f'<font color="{GREEN.hexval()}">✓ No findings mapped to this control.</font>', styles["table_cell"])]],
                colWidths=[158 * mm],
            )
            no_data.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), T["bg"]),
                ("BOX",        (0, 0), (-1, -1), 0.3, T["border"]),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ]))
            block.append(no_data)

        block.append(Spacer(1, 5 * mm))
        story.append(KeepTogether(block[:3]))  # keep header + first finding together
        for item in block[3:]:
            story.append(item)


# ── Footer ────────────────────────────────────────────────────────────────────

def _draw_footer(canv, doc, results, T, fw_name):
    canv.saveState()
    canv.setFont("Helvetica", 7)
    canv.setFillColor(T["text_sub"])
    app = results.get("app_name", "")
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    canv.drawString(20 * mm, 8 * mm, f"Beetle — {fw_name} Compliance Report — {app} — {date_str}")
    canv.drawRightString(PAGE_W - 20 * mm, 8 * mm, f"Page {doc.page}")
    canv.restoreState()


# ── Shared style helpers ──────────────────────────────────────────────────────

def _center_style(T) -> ParagraphStyle:
    return ParagraphStyle("ctr", fontName="Helvetica", fontSize=10, textColor=T["text"],
                          leading=14, alignment=TA_CENTER)

def _right_style(T) -> ParagraphStyle:
    return ParagraphStyle("rgt", fontName="Helvetica", fontSize=10, textColor=T["text"],
                          leading=14, alignment=TA_RIGHT)
