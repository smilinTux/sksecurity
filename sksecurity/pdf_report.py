"""
PDF audit report generation for SKSecurity.

Uses reportlab to produce a structured, branded PDF audit report from
the data collected by the `sksecurity audit` command.
"""

from io import BytesIO
from typing import Any, Dict

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# Brand colours
_DARK_BLUE = "#1a3a5c"
_MID_GREY = "#555555"
_LIGHT_GREY = "#cccccc"
_ROW_ODD = "#f7f9fc"


def generate_audit_pdf(audit_data: Dict[str, Any]) -> bytes:
    """Generate a PDF audit report from audit data collected by `sksecurity audit`.

    Args:
        audit_data: Dict with keys: timestamp, version, threat_intelligence,
                    quarantine, database, configuration.

    Returns:
        bytes: The PDF document content, ready to write to a .pdf file.

    Raises:
        ImportError: If reportlab is not installed.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF export. "
            "Install it with: pip install reportlab"
        )

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="SKSecurity Audit Report",
        author="SKSecurity Enterprise",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SKTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor(_DARK_BLUE),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "SKSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor(_MID_GREY),
        spaceAfter=16,
    )
    section_style = ParagraphStyle(
        "SKSection",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor(_DARK_BLUE),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "SKBody",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#333333"),
        spaceAfter=4,
        leading=14,
    )
    footer_style = ParagraphStyle(
        "SKFooter",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#aaaaaa"),
    )

    story = []

    # ── Header ───────────────────────────────────────────────────────────────
    story.append(Paragraph("SKSecurity Enterprise", title_style))
    story.append(Paragraph("Security Audit Report", title_style))

    ts = audit_data.get("timestamp", "unknown")
    version = audit_data.get("version", "unknown")
    story.append(
        Paragraph(f"Generated: {ts}  |  Version: {version}", subtitle_style)
    )
    story.append(
        HRFlowable(width="100%", thickness=2, color=colors.HexColor(_DARK_BLUE))
    )
    story.append(Spacer(1, 0.15 * inch))

    # ── Threat Intelligence ──────────────────────────────────────────────────
    story.append(Paragraph("Threat Intelligence Status", section_style))
    ti = audit_data.get("threat_intelligence", {})
    story.append(
        _make_table(
            [
                ["Metric", "Value"],
                ["Total Patterns", str(ti.get("total_patterns", "N/A"))],
                ["Last Update", str(ti.get("last_update", "N/A"))],
                ["Sources", str(len(ti.get("sources", [])))],
            ]
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    # ── Quarantine Status ────────────────────────────────────────────────────
    story.append(Paragraph("Quarantine Status", section_style))
    q = audit_data.get("quarantine", {})
    story.append(
        _make_table(
            [
                ["Severity", "Count"],
                ["Total Items", str(q.get("total_items", 0))],
                ["Critical", str(q.get("critical_count", 0))],
                ["High", str(q.get("high_count", 0))],
                ["Medium", str(q.get("medium_count", 0))],
                ["Low", str(q.get("low_count", 0))],
            ]
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    # ── Security Database ────────────────────────────────────────────────────
    story.append(Paragraph("Security Database", section_style))
    db = audit_data.get("database", {})
    story.append(
        _make_table(
            [
                ["Metric", "Value"],
                ["Total Events", str(db.get("total_events", 0))],
                ["Recent Alerts", str(db.get("recent_alerts", 0))],
            ]
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    # ── Configuration ────────────────────────────────────────────────────────
    story.append(Paragraph("Configuration Summary", section_style))
    cfg = audit_data.get("configuration", {})
    story.append(
        _make_table(
            [
                ["Setting", "Value"],
                ["Auto-quarantine", str(cfg.get("auto_quarantine", "N/A"))],
                ["Risk Threshold", str(cfg.get("risk_threshold", "N/A"))],
                ["Dashboard Port", str(cfg.get("dashboard_port", "N/A"))],
            ]
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    # ── Status footer ────────────────────────────────────────────────────────
    story.append(
        HRFlowable(width="100%", thickness=1, color=colors.HexColor(_LIGHT_GREY))
    )
    story.append(Spacer(1, 0.08 * inch))
    story.append(
        Paragraph(
            "Overall Status: <font color='green'><b>OPERATIONAL</b></font>",
            body_style,
        )
    )
    story.append(
        Paragraph(
            "Generated by SKSecurity Enterprise — sksecurity.io",
            footer_style,
        )
    )

    doc.build(story)
    return buffer.getvalue()


def _make_table(data: list) -> Table:
    """Build a styled two-column reportlab Table."""
    t = Table(data, colWidths=["40%", "60%"])
    t.setStyle(
        TableStyle(
            [
                # Header
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_DARK_BLUE)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                # Data rows
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("TOPPADDING", (0, 1), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.HexColor(_ROW_ODD), colors.white],
                ),
                # Grid
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(_LIGHT_GREY)),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t
