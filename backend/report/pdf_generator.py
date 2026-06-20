from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import os
from datetime import datetime
from html import escape

# ─── Themes ──────────────────────────────────────────────────────────────────
THEMES = {
    "light": {
        "bg":          HexColor("#FFFFFF"),
        "bg_page":     HexColor("#F8FAFC"),
        "cover_bg":    HexColor("#0F172A"),
        "cover_text":  HexColor("#FFFFFF"),
        "cover_sub":   HexColor("#94A3B8"),
        "accent":      HexColor("#6366F1"),
        "text":        HexColor("#0F172A"),
        "text_sub":    HexColor("#64748B"),
        "border":      HexColor("#E2E8F0"),
        "card":        HexColor("#FFFFFF"),
        "row_alt":     HexColor("#F8FAFC"),
        "header_bg":   HexColor("#F1F5F9"),
    },
    "dark": {
        "bg":          HexColor("#0F172A"),
        "bg_page":     HexColor("#0F172A"),
        "cover_bg":    HexColor("#020617"),
        "cover_text":  HexColor("#FFFFFF"),
        "cover_sub":   HexColor("#64748B"),
        "accent":      HexColor("#818CF8"),
        "text":        HexColor("#E2E8F0"),
        "text_sub":    HexColor("#94A3B8"),
        "border":      HexColor("#1E293B"),
        "card":        HexColor("#1E293B"),
        "row_alt":     HexColor("#1E293B"),
        "header_bg":   HexColor("#0F172A"),
    }
}

SEVERITY_COLORS = {
    "critical": HexColor("#DC2626"),
    "high":     HexColor("#EA580C"),
    "medium":   HexColor("#D97706"),
    "low":      HexColor("#16A34A"),
    "info":     HexColor("#0284C7"),
}

SEVERITY_BG = {
    "critical": HexColor("#FEF2F2"),
    "high":     HexColor("#FFF7ED"),
    "medium":   HexColor("#FFFBEB"),
    "low":      HexColor("#F0FDF4"),
    "info":     HexColor("#F0F9FF"),
}

SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}

PAGE_W, PAGE_H = A4


def generate_pdf(results: dict, output_path: str, theme: str = "light", prepared_by: str = "",
                 findings_scope: str = "application"):
    """Render the PDF report.

    findings_scope:
      "application" (default) — only application-owned, high-confidence findings
                                (Phase 3 default; the high-signal report).
      "all"                   — every kept finding regardless of ownership/confidence.
    """
    T = THEMES.get(theme, THEMES["light"])
    report_author = prepared_by.strip() or "Security Analyst"
    results["_report_findings_scope"] = findings_scope if findings_scope in ("application", "all") else "application"

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"Beetle Report — {results.get('app_name', 'App')}",
        author=report_author,
    )

    styles = _build_styles(T)
    story  = []

    _cover_page(story, results, T, styles, report_author)
    story.append(PageBreak())
    _executive_summary(story, results, T, styles)
    story.append(PageBreak())
    _app_info_section(story, results, T, styles)
    _permissions_section_pdf(story, results, T, styles)
    _findings_section(story, results, T, styles)
    _secrets_section(story, results, T, styles)
    _endpoints_section(story, results, T, styles)
    _behavior_section(story, results, T, styles)
    _malware_permission_section(story, results, T, styles)
    _domain_intel_section(story, results, T, styles)
    _attack_surface_section(story, results, T, styles)
    _sdks_section(story, results, T, styles)
    _components_section(story, results, T, styles)
    _taint_section(story, results, T, styles)
    _score_section(story, results, T, styles)
    _certificate_section(story, results, T, styles)
    _binary_section(story, results, T, styles)
    _string_analysis_section(story, results, T, styles)
    _browsable_section_pdf(story, results, T, styles)

    def on_page(canv, doc, theme_ref=T):
        _draw_page_footer(canv, doc, results, theme_ref)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


# ─── Cover Page ───────────────────────────────────────────────────────────────
def _cover_page(story, results, T, styles, report_author):
    # Dark cover band
    story.append(Spacer(1, 30 * mm))

    # CORTEX wordmark
    story.append(Paragraph("CORTEX", styles["cover_title"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("Mobile Recon Framework", styles["cover_sub"]))
    story.append(Spacer(1, 15 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 15 * mm))

    # App details
    app_name = results.get("app_name", "Unknown App")
    platform = results.get("platform", "").upper()
    pkg = results.get("app_info", {}).get("package") or results.get("app_info", {}).get("bundle_id", "")

    story.append(Paragraph("SECURITY ASSESSMENT REPORT", styles["cover_label"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(escape(str(app_name)), styles["cover_app"]))
    if pkg:
        story.append(Paragraph(escape(str(pkg)), styles["cover_pkg"]))

    story.append(Spacer(1, 10 * mm))

    meta_data = [
        ["Platform",  platform or results.get("platform", "Android").title()],
        ["Scan Date", datetime.utcnow().strftime("%d %B %Y")],
        ["Filename",  results.get("filename", "")[:50]],
        ["Scan ID",   results.get("scan_id", "")[:16] + "..."],
    ]

    meta_table = Table(meta_data, colWidths=[45 * mm, 110 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",   (0, 0), (0, -1), T["text_sub"]),
        ("TEXTCOLOR",   (1, 0), (1, -1), T["text"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [T["bg"], T["row_alt"]]),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 20 * mm))
    story.append(HRFlowable(width="100%", thickness=0.3, color=T["border"]))
    story.append(Spacer(1, 8 * mm))

    # Severity summary
    ss = results.get("severity_summary", {})
    sev_data = [
        [
            _sev_cell("CRITICAL", ss.get("critical", 0), "critical"),
            _sev_cell("HIGH",     ss.get("high",     0), "high"),
            _sev_cell("MEDIUM",   ss.get("medium",   0), "medium"),
            _sev_cell("LOW",      ss.get("low",      0), "low"),
            _sev_cell("INFO",     ss.get("info",     0), "info"),
        ]
    ]
    sev_table = Table(sev_data, colWidths=[30 * mm] * 5)
    sev_table.setStyle(TableStyle([
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",(0, 0), (-1, -1), 4),
    ]))
    story.append(sev_table)

    story.append(Spacer(1, 30 * mm))
    story.append(HRFlowable(width="100%", thickness=0.3, color=T["border"]))
    story.append(Spacer(1, 5 * mm))

    # Author
    story.append(Paragraph("Prepared by", styles["cover_label"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(escape(report_author), styles["cover_author"]))
    story.append(Paragraph("Static analysis operator", styles["cover_email"]))


def _sev_cell(label, count, severity):
    color = SEVERITY_COLORS.get(severity, HexColor("#64748B"))
    return Paragraph(
        f'<font color="{color.hexval()}" size="18"><b>{count}</b></font><br/>'
        f'<font color="#64748B" size="7">{label}</font>',
        ParagraphStyle("sev", alignment=TA_CENTER, leading=20)
    )


# ─── Executive Summary ────────────────────────────────────────────────────────
def _executive_summary(story, results, T, styles):
    story.append(Paragraph("Executive Summary", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 6 * mm))

    ss       = results.get("severity_summary", {})
    findings = results.get("findings", [])
    secrets  = results.get("secrets", [])
    platform = results.get("platform", "android").title()

    total_issues = sum(ss.values())
    critical     = ss.get("critical", 0)
    high         = ss.get("high",     0)

    if critical > 0:
        risk_label = "CRITICAL RISK"
        risk_color = SEVERITY_COLORS["critical"]
    elif high > 0:
        risk_label = "HIGH RISK"
        risk_color = SEVERITY_COLORS["high"]
    elif ss.get("medium", 0) > 0:
        risk_label = "MEDIUM RISK"
        risk_color = SEVERITY_COLORS["medium"]
    else:
        risk_label = "LOW RISK"
        risk_color = SEVERITY_COLORS["low"]

    story.append(Paragraph(
        f'Overall Risk Assessment: <font color="{risk_color.hexval()}"><b>{risk_label}</b></font>',
        styles["body"]
    ))
    story.append(Spacer(1, 4 * mm))

    summary_text = (
        f"This report presents the findings from a static security analysis of the {platform} application "
        f"<b>{results.get('app_name', 'the target app')}</b> using Beetle Mobile Recon Framework. "
        f"The analysis identified <b>{total_issues} total issues</b> across {len(findings)} findings, "
        f"including <b>{critical} critical</b> and <b>{high} high severity</b> items requiring immediate attention. "
        f"Additionally, <b>{len(secrets)} potential hardcoded secrets</b> were detected in the app bundle."
    )
    story.append(Paragraph(summary_text, styles["body"]))
    story.append(Spacer(1, 6 * mm))

    # Severity breakdown table
    rows = [["Severity", "Count", "Description"]]
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = ss.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS[sev]
            rows.append([
                Paragraph(f'<font color="{color.hexval()}"><b>{sev.upper()}</b></font>', styles["table_cell"]),
                Paragraph(f'<b>{count}</b>', styles["table_cell"]),
                Paragraph(_sev_desc(sev), styles["table_cell"]),
            ])

    if len(rows) > 1:
        t = Table(rows, colWidths=[30 * mm, 20 * mm, 105 * mm])
        t.setStyle(_table_style(T))
        story.append(t)

    # ── Posture scores (Phase C / H) ──────────────────────────────────────────
    expl = results.get("exploitability_score") or {}
    surf = results.get("attack_surface_score") or {}
    if expl or surf:
        story.append(Spacer(1, 5 * mm))
        if expl:
            story.append(Paragraph(
                f"Exploitability Score: <b>{int(expl.get('score', 0))}/100</b> "
                f"({escape(str(expl.get('rating', '')))}) — {escape(str(expl.get('reason', '')))}",
                styles["body"]))
        if surf:
            story.append(Paragraph(
                f"Attack Surface Score: <b>{int(surf.get('score', 0))}/100</b> "
                f"({escape(str(surf.get('rating', '')))})",
                styles["body"]))

    # ── Signal-quality funnel (Phase K) ───────────────────────────────────────
    es = results.get("executive_summary") or {}
    if es:
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Signal Quality", styles["body"]))
        funnel = [
            ("Raw detections",                  es.get("raw_detections", 0)),
            ("Duplicates grouped",              es.get("duplicates_grouped", 0)),
            ("Library findings hidden",         es.get("library_findings_hidden", 0)),
            ("False positives removed",         es.get("false_positives_suppressed", 0)),
            ("Low-value data flows pruned",     es.get("low_value_flows_pruned", 0)),
            ("High-signal findings presented",  es.get("high_signal_findings", 0)),
        ]
        srows = [["Stage", "Count"]] + [
            [Paragraph(escape(k), styles["table_cell"]),
             Paragraph(f"<b>{int(v)}</b>", styles["table_cell"])]
            for k, v in funnel
        ]
        st = Table(srows, colWidths=[120 * mm, 35 * mm])
        st.setStyle(_table_style(T))
        story.append(st)


def _sev_desc(sev):
    return {
        "critical": "Immediate exploitation risk. Requires urgent remediation.",
        "high":     "Significant security risk. Should be addressed promptly.",
        "medium":   "Moderate risk. Address in next release cycle.",
        "low":      "Minor issue. Address as part of normal maintenance.",
        "info":     "Informational finding. No direct security impact.",
    }.get(sev, "")


# ─── App Info ─────────────────────────────────────────────────────────────────
def _app_info_section(story, results, T, styles):
    story.append(Paragraph("Application Information", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    info = results.get("app_info", {})
    platform = results.get("platform", "android")

    if platform == "android":
        rows = [
            ["Package Name",     info.get("package", "—")],
            ["App Name",         info.get("app_name", "—")],
            ["Version",          f"{info.get('version_name', '—')} (build {info.get('version_code', '—')})"],
            ["Min SDK",          str(info.get("min_sdk", "—"))],
            ["Target SDK",       str(info.get("target_sdk", "—"))],
            ["Main Activity",    info.get("main_activity", "—")],
            ["File Size",        f"{info.get('size_mb', '—')} MB"],
            ["SHA-256",          info.get("sha256", "—")[:32] + "..."],
            ["Framework",        results.get("framework", {}).get("type", "native").replace("_", " ").title()],
        ]
    else:
        rows = [
            ["Bundle ID",        info.get("bundle_id", "—")],
            ["App Name",         info.get("app_name", "—")],
            ["Version",          f"{info.get('version', '—')} (build {info.get('build', '—')})"],
            ["Min iOS",          str(info.get("min_ios", "—"))],
            ["File Size",        f"{info.get('size_mb', '—')} MB"],
            ["SHA-256",          info.get("sha256", "—")[:32] + "..."],
            ["Framework",        results.get("framework", {}).get("type", "native").replace("_", " ").title()],
        ]

    t = Table(rows, colWidths=[45 * mm, 110 * mm])
    t.setStyle(_kv_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6 * mm))


# ─── Permissions ─────────────────────────────────────────────────────────────
def _permissions_section(story, results, T, styles):
    dangerous = results.get("permissions", {}).get("dangerous", [])
    if not dangerous:
        return

    story.append(Paragraph("Sensitive Permissions", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    rows = [["Permission", "Risk", "Description"]]
    for p in sorted(dangerous, key=lambda x: ["high", "medium", "low"].index(x.get("severity", "low")) if x.get("severity") in ["high", "medium", "low"] else 3):
        color = SEVERITY_COLORS.get(p.get("severity", "info"), HexColor("#64748B"))
        rows.append([
            Paragraph(p.get("short_name", p.get("permission", "")[:40]), styles["table_cell_mono"]),
            Paragraph(f'<font color="{color.hexval()}"><b>{p.get("severity", "").upper()}</b></font>', styles["table_cell"]),
            Paragraph(p.get("description", ""), styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[55 * mm, 20 * mm, 80 * mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6 * mm))


# ─── Findings ─────────────────────────────────────────────────────────────────
def _visible_findings(results):
    """Apply the Phase 3 default presentation filter for the report.

    Default ("application") shows only application-owned, high-confidence
    (>=70) findings. "all" shows every kept finding. Findings predating Phase 3
    (no ownership_label/confidence_score) are always shown so old scans don't
    silently lose their report body.
    """
    findings = results.get("findings", []) or []
    scope = results.get("_report_findings_scope", "application")
    if scope == "all":
        return findings

    visible = []
    for f in findings:
        label = f.get("ownership_label")
        conf = f.get("confidence_score")
        if label is None and conf is None:
            visible.append(f)  # pre-Phase-3 finding; don't hide it
            continue
        if not f.get("is_app_code", label == "APPLICATION"):
            continue
        if conf is not None and conf < 70:
            continue
        visible.append(f)
    return visible


def _findings_section(story, results, T, styles):
    findings = _visible_findings(results)
    real_findings = [f for f in findings if f.get("severity") != "info"]
    info_findings = [f for f in findings if f.get("severity") == "info"]

    if not findings:
        return

    story.append(PageBreak())
    story.append(Paragraph("Security Findings", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))

    scope = results.get("_report_findings_scope", "application")
    stats = results.get("finding_quality_stats") or {}
    if scope == "application" and stats:
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            f"Showing {len(findings)} high-signal, application-owned finding(s). "
            f"{stats.get('suppressed_count', 0)} false positive(s) suppressed, "
            f"{stats.get('collapsed_duplicates', 0)} duplicate(s) grouped, "
            f"{stats.get('reclassified_controls', 0)} security control(s) reclassified. "
            f"Library / framework / low-confidence findings are available in the full export.",
            styles["caption"],
        ))
    story.append(Spacer(1, 6 * mm))

    for i, finding in enumerate(real_findings + info_findings):
        sev   = finding.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, HexColor("#64748B"))

        header = [
            [
                Paragraph(
                    f'<font color="white"><b>{SEVERITY_LABELS.get(sev, sev.upper())}</b></font>',
                    ParagraphStyle("sh", fontSize=8, alignment=TA_CENTER)
                ),
                Paragraph(f'<b>{_safe(finding.get("title", "Finding"))}</b>', styles["finding_title"]),
                Paragraph(_safe(finding.get("category", "")), styles["finding_cat"]),
            ]
        ]
        header_table = Table(header, colWidths=[20 * mm, 120 * mm, 15 * mm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (0, 0), color),
            ("BACKGROUND",  (1, 0), (2, 0), T["card"]),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",  (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("BOX",         (0, 0), (-1, -1), 0.5, T["border"]),
        ]))

        content_rows = []
        signal_bits = _format_signal_quality(finding)
        if signal_bits:
            content_rows.append(["Signal", signal_bits])
        if finding.get("description"):
            content_rows.append(["Description", finding["description"]])
        evidence_text = _format_finding_evidence(finding)
        if evidence_text:
            content_rows.append(["Proof", evidence_text])
        standards = _format_standards(finding)
        if standards:
            content_rows.append(["Standards", standards])
        if finding.get("impact"):
            content_rows.append(["Impact", finding["impact"]])
        if finding.get("poc"):
            content_rows.append(["PoC / Commands", finding["poc"]])
        if finding.get("recommendation"):
            content_rows.append(["Recommendation", finding["recommendation"]])

        # "Proof" and "Standards" are pre-built, already-escaped markup (they
        # contain intentional <br/> / <font> tags); every other row is raw text
        # and must be HTML-escaped before reportlab parses it as XML.
        _PREFORMATTED = {"Proof", "Standards"}
        content_data = [
            [
                Paragraph(_safe(label), styles["finding_label"]),
                Paragraph(
                    value if label in _PREFORMATTED else _safe(value),
                    styles["finding_value"] if label != "PoC / Commands" else styles["mono"],
                ),
            ]
            for label, value in content_rows
        ]

        if content_data:
            content_table = Table(content_data, colWidths=[35 * mm, 120 * mm])
            content_table.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (0, -1), T["row_alt"]),
                ("BACKGROUND",  (1, 0), (1, -1), T["bg"]),
                ("ROWBACKGROUNDS", (1, 0), (1, -1), [T["bg"], T["card"]]),
                ("VALIGN",      (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",  (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("BOX",         (0, 0), (-1, -1), 0.5, T["border"]),
                ("LINEABOVE",   (0, 0), (-1, 0), 0, T["border"]),
            ]))

            story.append(KeepTogether([header_table, content_table, Spacer(1, 5 * mm)]))
        else:
            story.append(KeepTogether([header_table, Spacer(1, 5 * mm)]))


def _safe(text) -> str:
    """HTML-escape dynamic text for reportlab Paragraph, preserving newlines as
    <br/>. reportlab parses Paragraph content as XML, so any raw <, >, & in
    findings (code snippets, generics like List<String>, XML) would otherwise
    raise and abort PDF generation."""
    return escape(str(text)).replace("\n", "<br/>")


def _format_finding_evidence(finding: dict) -> str:
    snippets = []
    evidence_entries = finding.get("file_evidence") or []

    if evidence_entries:
        for entry in evidence_entries[:2]:
            path = entry.get("path") or finding.get("file_path") or "Unknown file"
            lines = entry.get("lines") or ([finding.get("line")] if finding.get("line") else [])
            line_str = f":{lines[0]}" if lines else ""
            snippet = entry.get("snippet") or ""
            block = f"File: {escape(str(path))}{escape(str(line_str))}"
            if snippet:
                block += f"<br/><font face='Courier'>{escape(snippet[:280])}</font>"
            snippets.append(block)
    elif finding.get("file_path") or finding.get("snippet"):
        path = finding.get("file_path") or "Unknown file"
        line = f":{finding.get('line')}" if finding.get("line") else ""
        block = f"File: {escape(str(path))}{escape(str(line))}"
        if finding.get("snippet"):
            block += f"<br/><font face='Courier'>{escape(str(finding.get('snippet'))[:280])}</font>"
        snippets.append(block)

    code_context = finding.get("code_context")
    if code_context and not snippets:
        snippets.append(f"<font face='Courier'>{escape(str(code_context)[:320])}</font>")

    return "<br/><br/>".join(snippets)


_OWNERSHIP_BADGE_LABELS = {
    "APPLICATION": "Application", "THIRD_PARTY_LIBRARY": "Third-Party Library",
    "ANDROID_FRAMEWORK": "Framework", "GOOGLE_SDK": "Google SDK",
    "FIREBASE": "Firebase", "JETPACK": "Jetpack", "UNKNOWN": "Unknown",
}


def _format_signal_quality(finding: dict) -> str:
    """Render the Phase 3 ownership / confidence / evidence line for a finding."""
    label = finding.get("ownership_label")
    if label is None and finding.get("confidence_score") is None:
        return ""  # pre-Phase-3 finding
    parts = []
    own = _OWNERSHIP_BADGE_LABELS.get(label, label)
    if own:
        parts.append(f"Ownership: {own}")
    conf = finding.get("confidence_score")
    if conf is not None:
        parts.append(f"Confidence: {conf}% ({finding.get('confidence_band', '')})")
    ev = finding.get("evidence_count")
    if ev:
        parts.append(f"Evidence: {ev} location(s)")
    sq = finding.get("signal_quality")
    if sq:
        parts.append(f"Signal Quality: {sq}")
    return "  •  ".join(p for p in parts if p)


def _format_standards(finding: dict) -> str:
    parts = []
    if finding.get("cwe"):
        parts.append(f"CWE: {finding['cwe']}")
    if finding.get("owasp"):
        parts.append(f"OWASP Mobile: {finding['owasp']}")
    if finding.get("masvs"):
        parts.append(f"MASVS/MASTG: {finding['masvs']}")
    return "<br/>".join(parts)


# ─── Secrets ─────────────────────────────────────────────────────────────────
def _secrets_section(story, results, T, styles):
    secrets = results.get("secrets", [])
    if not secrets:
        return

    story.append(PageBreak())
    story.append(Paragraph(f"Hardcoded Secrets ({len(secrets)} found)", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    rows = [["Secret Type", "Severity", "Value (masked)", "Source"]]
    for s in sorted(secrets, key=lambda x: ["critical","high","medium","low","info"].index(x.get("severity","info")) if x.get("severity") in ["critical","high","medium","low","info"] else 5):
        color = SEVERITY_COLORS.get(s.get("severity", "medium"), HexColor("#D97706"))
        rows.append([
            Paragraph(escape(str(s.get("name", ""))), styles["table_cell"]),
            Paragraph(f'<font color="{color.hexval()}"><b>{s.get("severity","").upper()}</b></font>', styles["table_cell"]),
            Paragraph(f'<font face="Courier">{escape(str(s.get("value", "")))}</font>', styles["table_cell"]),
            Paragraph(escape(str(s.get("source", ""))), styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[55 * mm, 20 * mm, 50 * mm, 30 * mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6 * mm))


# ─── Endpoints ────────────────────────────────────────────────────────────────
def _endpoints_section(story, results, T, styles):
    endpoints = results.get("endpoints", [])
    if not endpoints:
        return

    story.append(Paragraph(f"Discovered Endpoints ({len(endpoints)})", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    rows = [["URL"]]
    for url in endpoints[:100]:
        rows.append([Paragraph(f'<font face="Courier" size="8">{escape(str(url))}</font>', styles["table_cell"])])

    t = Table(rows, colWidths=[155 * mm])
    t.setStyle(_table_style(T))
    story.append(t)
    if len(endpoints) > 100:
        story.append(Paragraph(f"... and {len(endpoints) - 100} more endpoints.", styles["caption"]))
    story.append(Spacer(1, 6 * mm))


def _behavior_section(story, results, T, styles):
    behavior = results.get("behavior_analysis", [])
    if not behavior:
        return

    story.append(Paragraph(f"Behavior Analysis ({len(behavior)} rules hit)", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    rows = [["Behavior", "Severity", "Files", "Standards"]]
    for item in behavior[:25]:
        color = SEVERITY_COLORS.get(item.get("severity", "info"), HexColor("#64748B"))
        standards = ", ".join(filter(None, [item.get("cwe"), item.get("owasp"), item.get("masvs")]))
        rows.append([
            Paragraph(item.get("title", ""), styles["table_cell"]),
            Paragraph(f'<font color="{color.hexval()}"><b>{item.get("severity","").upper()}</b></font>', styles["table_cell"]),
            Paragraph(str(item.get("file_count", 0)), styles["table_cell"]),
            Paragraph(standards, styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[70 * mm, 20 * mm, 15 * mm, 50 * mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6 * mm))


def _malware_permission_section(story, results, T, styles):
    stats = results.get("malware_perms", {})
    malware = stats.get("malware_permissions", {})
    common = stats.get("common_malware_permissions", {})
    if not malware and not common:
        return

    story.append(Paragraph("Malware Permission Overlap", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    rows = [
        ["Dataset", "Matched", "Total", "Sample Permissions"],
        [
            Paragraph("Top malware set", styles["table_cell"]),
            Paragraph(str(malware.get("count", 0)), styles["table_cell"]),
            Paragraph(str(malware.get("total", 0)), styles["table_cell"]),
            Paragraph(", ".join(malware.get("matched", [])[:5]), styles["table_cell"]),
        ],
        [
            Paragraph("Common abuse set", styles["table_cell"]),
            Paragraph(str(common.get("count", 0)), styles["table_cell"]),
            Paragraph(str(common.get("total", 0)), styles["table_cell"]),
            Paragraph(", ".join(common.get("matched", [])[:5]), styles["table_cell"]),
        ],
    ]

    t = Table(rows, colWidths=[40 * mm, 20 * mm, 20 * mm, 75 * mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6 * mm))


def _domain_intel_section(story, results, T, styles):
    intel = results.get("domain_intel", [])
    if not intel:
        return

    story.append(Paragraph("Domain Intelligence", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    rows = [["Domain", "IP", "Country", "Reputation", "Risk Flags"]]
    for item in intel[:30]:
        rows.append([
            Paragraph(item.get("domain", ""), styles["table_cell_mono"]),
            Paragraph(item.get("ip", "") or "â€”", styles["table_cell"]),
            Paragraph(item.get("country", "") or "â€”", styles["table_cell"]),
            Paragraph(item.get("reputation", "") or item.get("status", ""), styles["table_cell"]),
            Paragraph(", ".join(item.get("risk_flags", [])[:4]) or "â€”", styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[45 * mm, 25 * mm, 25 * mm, 25 * mm, 40 * mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6 * mm))


# ─── Attack Surface ───────────────────────────────────────────────────────────
def _attack_surface_section(story, results, T, styles):
    platform = results.get("platform", "android")
    attack   = results.get("attack_surface", {})

    story.append(Paragraph("Attack Surface Map", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    if platform == "android":
        for comp_type in ["activities", "services", "receivers", "providers"]:
            components = attack.get(comp_type, [])
            exported   = [c for c in components if c.get("exported")]
            if not exported:
                continue

            story.append(Paragraph(comp_type.title(), styles["subsection_title"]))
            rows = [["Component", "Permission", "Deeplinks / Actions"]]
            for comp in exported:
                dls   = ", ".join(comp.get("deeplinks", []))[:60] or ", ".join(comp.get("actions", []))[:60] or "—"
                perm  = comp.get("permission") or "None"
                rows.append([
                    Paragraph(escape(str(comp.get("short_name", ""))), styles["table_cell_mono"]),
                    Paragraph(f'<font color="{SEVERITY_COLORS["high"].hexval() if perm == "None" else SEVERITY_COLORS["info"].hexval()}">{escape(str(perm))}</font>', styles["table_cell"]),
                    Paragraph(escape(str(dls)), styles["table_cell"]),
                ])

            t = Table(rows, colWidths=[55 * mm, 40 * mm, 60 * mm])
            t.setStyle(_table_style(T))
            story.append(t)
            story.append(Spacer(1, 4 * mm))
    else:
        schemes = attack.get("url_schemes", [])
        if schemes:
            story.append(Paragraph("Custom URL Schemes", styles["subsection_title"]))
            rows = [["Scheme"]] + [[Paragraph(f"{escape(str(s))}://", styles["table_cell_mono"])] for s in schemes]
            t = Table(rows, colWidths=[155 * mm])
            t.setStyle(_table_style(T))
            story.append(t)
            story.append(Spacer(1, 4 * mm))


# ─── SDKs ─────────────────────────────────────────────────────────────────────
def _sdks_section(story, results, T, styles):
    sdks = results.get("sdks", [])
    if not sdks:
        return

    story.append(Paragraph(f"Third-Party SDKs ({len(sdks)} detected)", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    rows = [["SDK Name", "Category", "Package Prefix"]]
    for sdk in sorted(sdks, key=lambda s: s.get("name", "")):
        rows.append([
            Paragraph(sdk.get("name", ""), styles["table_cell"]),
            Paragraph(sdk.get("category", ""), styles["table_cell"]),
            Paragraph(sdk.get("package", ""), styles["table_cell_mono"]),
        ])

    t = Table(rows, colWidths=[55 * mm, 35 * mm, 65 * mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6 * mm))


# ─── Vulnerable Components (CVE mapping) ─────────────────────────────────────
def _components_section(story, results, T, styles):
    components = results.get("components") or []
    cve_findings = [f for f in (results.get("findings") or []) if f.get("source") == "CVE-MAP"]
    if not components and not cve_findings:
        return

    stats = results.get("cve_stats") or {}
    kev_total = sum(1 for f in cve_findings if f.get("kev"))
    title_bits = [f"{len(components)} detected", f"{len(cve_findings)} CVEs"]
    if kev_total:
        title_bits.append(f"{kev_total} KEV")

    story.append(Paragraph(
        f"Vulnerable Components ({' · '.join(title_bits)})",
        styles["section_title"],
    ))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    # Group CVEs by (product, version)
    by_comp = {}
    for f in cve_findings:
        comp = f.get("component") or {}
        k = (comp.get("product") or f.get("rule_id", ""),
             comp.get("version") or "")
        by_comp.setdefault(k, []).append(f)

    rows = [["Component", "Version", "Ecosystem", "CVEs", "KEV", "Worst"]]
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    comp_rows = []
    for c in components:
        k = (c.get("product", ""), c.get("version", ""))
        cves = by_comp.get(k, [])
        worst = "-"
        if cves:
            worst = max(cves, key=lambda f: sev_rank.get(f.get("severity"), 0)).get("severity", "-")
        comp_rows.append((c, cves, worst))

    comp_rows.sort(key=lambda r: (-sev_rank.get(r[2], -1), -len(r[1]), r[0].get("product", "")))

    for c, cves, worst in comp_rows:
        rows.append([
            Paragraph(str(c.get("product", ""))[:60], styles["table_cell"]),
            Paragraph(str(c.get("version", "")), styles["table_cell_mono"]),
            Paragraph(str(c.get("ecosystem") or "native"), styles["table_cell"]),
            Paragraph(str(len(cves)), styles["table_cell"]),
            Paragraph(str(sum(1 for f in cves if f.get("kev"))) or "-", styles["table_cell"]),
            Paragraph(str(worst).upper(), styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[60 * mm, 25 * mm, 25 * mm, 16 * mm, 14 * mm, 20 * mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 4 * mm))

    # Detail block per CVE (cap to keep PDFs reasonable)
    MAX_DETAIL = 40
    shown = 0
    for c, cves, _ in comp_rows:
        if shown >= MAX_DETAIL or not cves:
            continue
        story.append(Paragraph(
            f"<b>{c.get('product','')} {c.get('version','')}</b> — {len(cves)} CVE(s)",
            styles["subsection_title"],
        ))
        cve_rows = [["CVE", "Severity", "CVSS", "Fix", "Summary"]]
        for f in cves[:10]:
            tag = f.get("cve") or f.get("rule_id", "")
            if f.get("kev"):
                tag += " [KEV]"
            summary = (f.get("description") or "").split("\n\n", 2)
            summary = summary[1] if len(summary) > 1 else (f.get("description") or "")
            cve_rows.append([
                Paragraph(tag, styles["table_cell_mono"]),
                Paragraph(str(f.get("severity", "")).upper(), styles["table_cell"]),
                Paragraph(str(f.get("cvss") or "-"), styles["table_cell"]),
                Paragraph(str(f.get("fix_version") or "-"), styles["table_cell_mono"]),
                Paragraph(summary[:260], styles["table_cell"]),
            ])
        ct = Table(cve_rows, colWidths=[30 * mm, 20 * mm, 14 * mm, 20 * mm, 76 * mm])
        ct.setStyle(_table_style(T))
        story.append(ct)
        story.append(Spacer(1, 3 * mm))
        shown += 1

    if stats.get("source") or stats.get("binaries_scanned") or stats.get("packages_scanned"):
        footnote = "Source: OSV.dev (cached 24h) + CISA KEV feed."
        story.append(Paragraph(footnote, styles["caption"]))
    story.append(Spacer(1, 4 * mm))


# ─── Taint Flows ─────────────────────────────────────────────────────────────
def _taint_section(story, results, T, styles):
    flows = results.get("taint_flows") or []
    if not flows:
        # Fall back to TAINT-source findings for older scans.
        flows = [f for f in (results.get("findings") or []) if f.get("source") == "TAINT"]
        if not flows:
            return

    story.append(Paragraph(
        f"Taint Flows ({len(flows)} source→sink path{'s' if len(flows) != 1 else ''})",
        styles["section_title"],
    ))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4 * mm))

    # Group by sink category
    by_cat = {}
    for flow in flows:
        tf = flow.get("taint_flow") or {}
        cat = tf.get("sink_cat") or flow.get("sink_cat") or flow.get("category") or "Unknown"
        by_cat.setdefault(cat, []).append(flow)

    summary_rows = [["Sink Category", "Paths"]]
    for cat in sorted(by_cat.keys()):
        summary_rows.append([
            Paragraph(cat, styles["table_cell"]),
            Paragraph(str(len(by_cat[cat])), styles["table_cell"]),
        ])
    st = Table(summary_rows, colWidths=[100 * mm, 60 * mm])
    st.setStyle(_table_style(T))
    story.append(st)
    story.append(Spacer(1, 4 * mm))

    # Detail: show up to 30 individual flows
    MAX_FLOWS = 30
    detail_rows = [["Severity", "Source → Sink", "Call chain"]]
    for flow in flows[:MAX_FLOWS]:
        tf = flow.get("taint_flow") or {}
        src = tf.get("source") or flow.get("source") or "?"
        snk = tf.get("sink") or flow.get("sink") or "?"
        chain = tf.get("chain") or flow.get("call_chain") or []
        chain_str = " → ".join(chain) if chain else "N/A"
        sev = flow.get("severity") or flow.get("sink_sev") or "medium"
        detail_rows.append([
            Paragraph(sev.upper(), styles["table_cell"]),
            Paragraph(f"{src} → {snk}", styles["table_cell_mono"]),
            Paragraph(chain_str[:400], styles["table_cell_mono"]),
        ])

    dt = Table(detail_rows, colWidths=[18 * mm, 55 * mm, 87 * mm])
    dt.setStyle(_table_style(T))
    story.append(dt)

    if len(flows) > MAX_FLOWS:
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            f"{len(flows) - MAX_FLOWS} additional flows omitted for brevity — see the web report.",
            styles["caption"],
        ))
    story.append(Spacer(1, 6 * mm))


# ─── Page Footer ─────────────────────────────────────────────────────────────
def _draw_page_footer(canv, doc, results, T):
    canv.saveState()
    canv.setFont("Helvetica", 7)
    canv.setFillColor(T["text_sub"])

    footer_y = 10 * mm
    canv.drawString(20 * mm, footer_y, f"Beetle — Mobile Recon Framework | {results.get('app_name', '')} | Confidential")
    canv.drawRightString(PAGE_W - 20 * mm, footer_y, f"Page {doc.page}")
    canv.setStrokeColor(T["border"])
    canv.line(20 * mm, footer_y + 4 * mm, PAGE_W - 20 * mm, footer_y + 4 * mm)
    canv.restoreState()


# ─── Style builders ───────────────────────────────────────────────────────────
def _build_styles(T):
    def p(name, **kwargs):
        base = dict(fontName="Helvetica", fontSize=10, textColor=T["text"], leading=14)
        base.update(kwargs)
        return ParagraphStyle(name, **base)

    return {
        "cover_title":    p("ct", fontName="Helvetica-Bold", fontSize=42, textColor=T["text"], leading=48),
        "cover_sub":      p("cs", fontSize=13, textColor=T["text_sub"], leading=16),
        "cover_label":    p("cl", fontSize=8,  textColor=T["text_sub"], leading=12, fontName="Helvetica"),
        "cover_app":      p("ca", fontName="Helvetica-Bold", fontSize=22, textColor=T["text"], leading=28),
        "cover_pkg":      p("cpk",fontSize=10, textColor=T["text_sub"], leading=14),
        "cover_author":   p("cau",fontName="Helvetica-Bold", fontSize=12, textColor=T["text"], leading=16),
        "cover_email":    p("cem",fontSize=9,  textColor=T["text_sub"], leading=13),
        "section_title":  p("st", fontName="Helvetica-Bold", fontSize=14, textColor=T["text"], leading=18, spaceAfter=3),
        "subsection_title": p("sst", fontName="Helvetica-Bold", fontSize=11, textColor=T["text_sub"], leading=14, spaceAfter=2),
        "body":           p("b",  fontSize=10, leading=15),
        "table_cell":     p("tc", fontSize=9,  leading=13),
        "table_cell_mono":p("tcm",fontName="Courier", fontSize=8, leading=12),
        "mono":           p("m",  fontName="Courier", fontSize=8, textColor=T["text_sub"], leading=12, backColor=T["row_alt"]),
        "caption":        p("cap",fontSize=8,  textColor=T["text_sub"], leading=11),
        "finding_title":  p("ft", fontName="Helvetica-Bold", fontSize=10, textColor=T["text"], leading=14),
        "finding_cat":    p("fc", fontSize=7,  textColor=T["text_sub"], leading=11, alignment=TA_RIGHT),
        "finding_label":  p("fl", fontName="Helvetica-Bold", fontSize=8, textColor=T["text_sub"], leading=12),
        "finding_value":  p("fv", fontSize=9,  leading=14),
    }


def _table_style(T):
    return TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), T["header_bg"]),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 9),
        ("TEXTCOLOR",    (0, 0), (-1, 0), T["text"]),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [T["bg"], T["row_alt"]]),
        ("GRID",         (0, 0), (-1, -1), 0.3, T["border"]),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ])


def _kv_table_style(T):
    return TableStyle([
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",    (0, 0), (0, -1), T["text_sub"]),
        ("TEXTCOLOR",    (1, 0), (1, -1), T["text"]),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [T["bg"], T["row_alt"]]),
        ("GRID",         (0, 0), (-1, -1), 0.3, T["border"]),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
    ])


# ─── Security Score Section ───────────────────────────────────────────────────
def _score_section(story, results, T, styles):
    score = results.get("score", {})
    if not score:
        return

    story.append(PageBreak())
    story.append(Paragraph("Security Score", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 6 * mm))

    grade        = score.get("grade", "?")
    score_val    = score.get("score", 0)
    grade_label  = score.get("grade_label", "")
    grade_desc   = score.get("grade_desc", "")
    risk         = score.get("risk", "")
    bonuses      = score.get("bonuses", [])
    deductions   = score.get("deductions", {})

    GRADE_COLORS = {
        "A": HexColor("#16a34a"), "B": HexColor("#2563eb"),
        "C": HexColor("#d97706"), "D": HexColor("#ea580c"), "F": HexColor("#dc2626"),
    }
    gcolor = GRADE_COLORS.get(grade, HexColor("#dc2626"))

    summary = [
        [
            Paragraph(f'<font size="48" color="{gcolor.hexval()}"><b>{grade}</b></font>', ParagraphStyle("g", alignment=TA_CENTER)),
            Paragraph(f'<b>{score_val}/100</b><br/>{grade_label}<br/><font size="9" color="#64748B">{risk} Risk</font>', ParagraphStyle("s", fontSize=14, leading=20)),
            Paragraph(grade_desc, styles["body"]),
        ]
    ]
    t = Table(summary, colWidths=[25*mm, 40*mm, 90*mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0,0),(-1,-1),"MIDDLE"),
        ("BACKGROUND",(0,0),(-1,-1), T["card"]),
        ("BOX",(0,0),(-1,-1), 0.5, T["border"]),
        ("LEFTPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),10),
        ("BOTTOMPADDING",(0,0),(-1,-1),10),
    ]))
    story.append(t)
    story.append(Spacer(1, 4*mm))

    if deductions:
        rows = [["Severity", "Findings", "Points/item", "Total Deducted"]]
        for sev, info in deductions.items():
            color = SEVERITY_COLORS.get(sev, HexColor("#64748B"))
            rows.append([
                Paragraph(f'<font color="{color.hexval()}"><b>{sev.upper()}</b></font>', styles["table_cell"]),
                Paragraph(str(info["count"]),      styles["table_cell"]),
                Paragraph(str(info["per_item"]),   styles["table_cell"]),
                Paragraph(f'<b>-{info["total"]}</b>', styles["table_cell"]),
            ])
        t2 = Table(rows, colWidths=[40*mm, 30*mm, 35*mm, 50*mm])
        t2.setStyle(_table_style(T))
        story.append(t2)

    if bonuses:
        story.append(Spacer(1, 3*mm))
        bonus_text = "Good practices detected: " + ", ".join(f'{b[0]} (+{b[1]})' for b in bonuses)
        story.append(Paragraph(bonus_text, styles["caption"]))

    story.append(Spacer(1, 6*mm))


# ─── Certificate Section ──────────────────────────────────────────────────────
def _certificate_section(story, results, T, styles):
    cert = results.get("certificate", {})
    if not cert or not cert.get("available"):
        return

    story.append(Paragraph("Certificate Analysis", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4*mm))

    subject = cert.get("subject", {})
    issuer  = cert.get("issuer",  {})

    rows = [
        ["Subject CN",    subject.get("CN",  "—")],
        ["Subject O",     subject.get("O",   "—")],
        ["Issuer CN",     issuer.get("CN",   "—")],
        ["Self-Signed",   "Yes ⚠" if cert.get("self_signed") else "No"],
        ["Debug Cert",    "Yes ⚠" if cert.get("debug_cert")  else "No"],
        ["Valid From",    cert.get("valid_from",  "—")],
        ["Valid To",      cert.get("valid_to",    "—") + (" ⚠ EXPIRED" if cert.get("expired") else "")],
        ["Key Type",      cert.get("key_type",    "—")],
        ["Key Size",      f"{cert.get('key_size','—')} bits"],
        ["Sig Algorithm", cert.get("signature_algo", "—")],
        ["Scheme",        ", ".join(cert.get("scheme", [])) or "v1"],
        ["SHA-256",       cert.get("sha256_fingerprint", "—")],
    ]

    t = Table(rows, colWidths=[45*mm, 110*mm])
    t.setStyle(_kv_table_style(T))
    story.append(t)
    extra = []
    if cert.get("serial"):
        extra.append(f"Serial: {cert.get('serial')}")
    if cert.get("sha1_fingerprint"):
        extra.append(f"SHA-1: {cert.get('sha1_fingerprint')}")
    if issuer.get("O"):
        extra.append(f"Issuer O: {issuer.get('O')}")
    if extra:
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("<br/>".join(extra), styles["caption"]))
    story.append(Spacer(1, 6*mm))


# ─── Binary Analysis Section ──────────────────────────────────────────────────
def _binary_section(story, results, T, styles):
    binaries = results.get("binaries", [])
    if not binaries:
        return

    story.append(PageBreak())
    story.append(Paragraph(f"Native Binary Analysis ({len(binaries)} libraries)", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4*mm))

    rows = [["Library", "Arch", "PIE", "NX", "Canary", "RELRO", "FORTIFY", "Stripped"]]
    for b in binaries[:30]:
        def cell(val, good_val=True):
            ok = (val == good_val) if not isinstance(val, str) else (val not in ("none",""))
            color = SEVERITY_COLORS["low"] if ok else SEVERITY_COLORS["high"]
            label = str(val) if isinstance(val, str) else ("✓" if val else "✗")
            return Paragraph(f'<font color="{color.hexval()}">{label}</font>', styles["table_cell"])

        rows.append([
            Paragraph(b.get("name",""), styles["table_cell_mono"]),
            Paragraph(b.get("arch",""), styles["table_cell"]),
            cell(b.get("pie",   False)),
            cell(b.get("nx",    False)),
            cell(b.get("stack_canary", False)),
            cell(b.get("relro", "none"), "full"),
            cell(b.get("fortify", False)),
            cell(b.get("stripped", False)),
        ])

    t = Table(rows, colWidths=[40*mm, 15*mm, 15*mm, 12*mm, 18*mm, 20*mm, 18*mm, 17*mm])
    t.setStyle(_table_style(T))
    story.append(t)
    fortified = [b for b in binaries if b.get("fortify_functions")]
    if fortified:
        story.append(Spacer(1, 2*mm))
        for item in fortified[:10]:
            funcs = ", ".join(item.get("fortify_functions", [])[:8])
            story.append(Paragraph(f"{item.get('name','')}: {funcs}", styles["caption"]))
    story.append(Spacer(1, 6*mm))


# ─── String Analysis Section ──────────────────────────────────────────────────
def _string_analysis_section(story, results, T, styles):
    string_data = results.get("string_analysis", {})
    if not string_data:
        return

    story.append(Paragraph(f"String Analysis ({len(string_data)} categories)", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4*mm))

    rows = [["Category", "Severity", "Count", "Sample Values"]]
    sev_order = ["critical","high","medium","low","info"]
    for cat, info in sorted(string_data.items(), key=lambda x: sev_order.index(x[1]["severity"]) if x[1]["severity"] in sev_order else 5):
        color = SEVERITY_COLORS.get(info["severity"], HexColor("#64748B"))
        # Handle both old (string list) and new ({value, files} list) formats
        raw_matches = info.get("matches", [])
        if raw_matches and isinstance(raw_matches[0], dict):
            sample_vals = [m.get("value", "") for m in raw_matches[:3]]
        else:
            sample_vals = raw_matches[:3]
        samples = ", ".join(str(v) for v in sample_vals)
        if len(samples) > 60:
            samples = samples[:60] + "…"
        rows.append([
            Paragraph(cat, styles["table_cell"]),
            Paragraph(f'<font color="{color.hexval()}"><b>{info["severity"].upper()}</b></font>', styles["table_cell"]),
            Paragraph(str(info["count"]), styles["table_cell"]),
            Paragraph(f'<font face="Courier" size="7">{samples}</font>', styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[55*mm, 22*mm, 15*mm, 63*mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6*mm))


def _permissions_section_pdf(story, results, T, styles):
    """PDF section for full permission classification."""
    classified = results.get("permissions", {}).get("classified", [])
    dangerous  = results.get("permissions", {}).get("dangerous", [])

    if not classified and not dangerous:
        return

    items = classified if classified else dangerous

    story.append(Paragraph(f"Application Permissions ({len(items)} total)", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4*mm))

    rows = [["Permission", "Status", "Description"]]
    for p in sorted(items, key=lambda x: {"dangerous": 0, "unknown": 1, "normal": 2}.get(x.get("status", "normal"), 2)):
        status = p.get("status", "normal")
        status_colors = {"dangerous": HexColor("#DC2626"), "unknown": HexColor("#64748B"), "normal": HexColor("#16A34A")}
        color = status_colors.get(status, HexColor("#64748B"))
        rows.append([
            Paragraph(f'<font face="Courier" size="8">{p.get("permission","")}</font>', styles["table_cell"]),
            Paragraph(f'<font color="{color.hexval()}"><b>{status.upper()}</b></font>', styles["table_cell"]),
            Paragraph(p.get("description","")[:80], styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[70*mm, 22*mm, 63*mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6*mm))


def _browsable_section_pdf(story, results, T, styles):
    """PDF section for browsable activities."""
    surface = results.get("attack_surface", {})
    browsable = [c for c in surface.get("activities", []) if c.get("browsable") and c.get("deeplinks")]

    if not browsable:
        return

    story.append(Paragraph(f"Browsable Activities ({len(browsable)})", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=T["accent"]))
    story.append(Spacer(1, 4*mm))

    rows = [["Activity", "Scheme/Deeplink", "Risk"]]
    for comp in browsable:
        has_custom = any(s not in ("http", "https") for s in comp.get("schemes", []))
        risk = "HIGH — Custom scheme hijackable" if has_custom else "LOW"
        risk_color = SEVERITY_COLORS["high"] if has_custom else SEVERITY_COLORS["low"]
        deeplinks = ", ".join(comp.get("deeplinks", []))[:60]
        rows.append([
            Paragraph(comp.get("short_name", ""), styles["table_cell_mono"]),
            Paragraph(deeplinks, styles["table_cell_mono"]),
            Paragraph(f'<font color="{risk_color.hexval()}">{risk}</font>', styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[50*mm, 65*mm, 40*mm])
    t.setStyle(_table_style(T))
    story.append(t)
    story.append(Spacer(1, 6*mm))
