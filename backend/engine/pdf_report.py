"""
engine/pdf_report.py
─────────────────────────────────────────────────────────────────────────────
Generates a professional PDF compliance report from a GRC report dict.
Uses reportlab (pip install reportlab).

Output
──────
Returns the PDF as bytes, ready to be streamed via FastAPI's
StreamingResponse or written to a file.

Sections
────────
1. Cover page     — title, score badge, risk level, generated date
2. Executive summary — KPI table across all frameworks
3. Control details   — one section per control with check breakdown
4. Evidence summary  — files loaded, types found
"""
from __future__ import annotations

import io
from datetime import datetime
from typing import Optional

try:
    from reportlab.lib.pagesizes  import A4
    from reportlab.lib.styles     import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units      import cm
    from reportlab.lib            import colors
    from reportlab.platypus       import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    _REPORTLAB = True
except ImportError:
    _REPORTLAB = False


# ── Colour palette ────────────────────────────────────────────────────────────
C_DARK   = colors.HexColor("#0d0f17")
C_BLUE   = colors.HexColor("#3b82f6")
C_GREEN  = colors.HexColor("#22c55e")
C_AMBER  = colors.HexColor("#f59e0b")
C_RED    = colors.HexColor("#ef4444")
C_LIGHT  = colors.HexColor("#f1f5f9")
C_BORDER = colors.HexColor("#e2e8f0")
C_TEXT   = colors.HexColor("#1e293b")
C_MUTED  = colors.HexColor("#64748b")

STATUS_COLORS = {
    "pass":           C_GREEN,
    "partial":        C_AMBER,
    "fail":           C_RED,
    "missing":        C_MUTED,
    "not_applicable": C_MUTED,
}


def _score_color(score: float) -> object:
    if score >= 90: return C_GREEN
    if score >= 70: return C_AMBER
    return C_RED


def generate_pdf_report(report: dict) -> bytes:
    """
    Generate a PDF compliance report and return it as bytes.

    Args:
        report: The full report dict from GRCRunner.run() / /api/report.

    Returns:
        PDF bytes.

    Raises:
        ImportError: if reportlab is not installed.
    """
    if not _REPORTLAB:
        raise ImportError(
            "reportlab is not installed. Run: pip install reportlab"
        )

    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(
        buf,
        pagesize    = A4,
        leftMargin  = 2 * cm,
        rightMargin = 2 * cm,
        topMargin   = 2 * cm,
        bottomMargin= 2 * cm,
        title       = "BABCOM GRC Compliance Report",
    )
    styles  = getSampleStyleSheet()
    story   = []
    summary = report.get("summary", {})
    controls= report.get("controls", [])
    score   = summary.get("overall_score", 0)
    risk    = summary.get("risk_level", "Unknown")

    # ── Styles ────────────────────────────────────────────────────────────────
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=22,
                        textColor=C_DARK, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14,
                        textColor=C_DARK, spaceAfter=4, spaceBefore=14)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=10,
                          textColor=C_TEXT, leading=14)
    muted = ParagraphStyle("muted", parent=styles["Normal"], fontSize=9,
                           textColor=C_MUTED, leading=12)
    bold_body = ParagraphStyle("bold_body", parent=body, fontName="Helvetica-Bold")

    def tbl_style(extra=None):
        base = [
            ("BACKGROUND", (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, 0), 9),
            ("FONTSIZE",   (0, 1), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
            ("GRID",       (0, 0), (-1, -1), 0.3, C_BORDER),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]
        if extra:
            base.extend(extra)
        return TableStyle(base)

    # ── Cover page ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.5 * cm))
    story.append(Paragraph("🛡 BABCOM GRC Platform", h1))
    story.append(Paragraph("Compliance Assessment Report", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=12))
    story.append(Spacer(1, 0.5 * cm))

    cover_data = [
        ["Overall Score", "Risk Level", "Controls Passed", "Issues Found"],
        [
            f"{score}%",
            risk,
            f"{summary.get('pass', 0)} / {summary.get('total_controls', 0)}",
            f"{summary.get('fail', 0) + summary.get('partial', 0)}",
        ],
    ]
    score_col = _score_color(score)
    risk_col  = {"Low":C_GREEN,"Medium":C_AMBER,"High":C_RED,"Critical":C_RED}.get(risk, C_MUTED)

    cover_tbl = Table(cover_data, colWidths=[4*cm, 4*cm, 4.5*cm, 4.5*cm])
    cover_tbl.setStyle(tbl_style([
        ("FONTSIZE",  (0, 1), (-1, 1), 16),
        ("FONTNAME",  (0, 1), (-1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 1), (0,  1), score_col),
        ("TEXTCOLOR", (1, 1), (1,  1), risk_col),
        ("ALIGN",     (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(cover_tbl)
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        f"Generated: {report.get('generated_at', datetime.utcnow().isoformat())}",
        muted
    ))
    story.append(PageBreak())

    # ── Framework breakdown ───────────────────────────────────────────────────
    story.append(Paragraph("Framework Breakdown", h2))
    by_fw = summary.get("by_framework", {})
    fw_data = [["Framework", "Score", "Pass", "Partial", "Fail", "Missing"]]
    for fw, d in by_fw.items():
        fw_data.append([
            fw,
            f"{d.get('score', 0):.1f}%",
            str(d.get("pass", 0)),
            str(d.get("partial", 0)),
            str(d.get("fail", 0)),
            str(d.get("missing", 0)),
        ])
    fw_tbl = Table(fw_data, colWidths=[4*cm, 2.5*cm, 2*cm, 2.5*cm, 2*cm, 2.5*cm])
    fw_tbl.setStyle(tbl_style([("ALIGN", (1,0), (-1,-1), "CENTER")]))
    story.append(fw_tbl)

    # ── Control details ───────────────────────────────────────────────────────
    story.append(Paragraph("Control Details", h2))
    ctrl_data = [["Control ID", "Name", "Framework", "Status", "Score", "Checks"]]
    for c in controls:
        ctrl_data.append([
            c["control_id"],
            c["control_name"],
            c["framework"],
            c["status"].upper(),
            f"{c['score']}%",
            f"{c['passed_checks']}/{c['total_checks']}",
        ])
    ctrl_tbl = Table(ctrl_data, colWidths=[2.5*cm, 5.5*cm, 2.5*cm, 2*cm, 1.5*cm, 1.5*cm])
    # Colour status cells
    status_extras = []
    for row_idx, c in enumerate(controls, start=1):
        col = STATUS_COLORS.get(c["status"], C_MUTED)
        status_extras.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), col))
        status_extras.append(("FONTNAME",  (3, row_idx), (3, row_idx), "Helvetica-Bold"))
    ctrl_tbl.setStyle(tbl_style(status_extras))
    story.append(ctrl_tbl)
    story.append(Spacer(1, 0.3 * cm))

    # ── Per-control checks breakdown ──────────────────────────────────────────
    story.append(Paragraph("Check-Level Findings", h2))
    for c in controls:
        if not c.get("checks"):
            continue
        story.append(Paragraph(
            f"<b>{c['control_id']} — {c['control_name']}</b>  "
            f"[{c['status'].upper()}  {c['score']}%]",
            body
        ))
        if c.get("recommendation"):
            story.append(Paragraph(f"Recommendation: {c['recommendation']}", muted))
        chk_data = [["", "Check", "Actual", "Expected"]]
        for chk in c["checks"]:
            chk_data.append([
                "✓" if chk["passed"] else "✗",
                chk["description"],
                str(chk.get("actual") or "—")[:40],
                str(chk.get("expected") or "—")[:40],
            ])
        chk_tbl = Table(
            chk_data,
            colWidths=[0.6*cm, 6.5*cm, 4*cm, 4*cm],
        )
        # Colour the pass/fail column
        chk_extras = []
        for row_idx, chk in enumerate(c["checks"], start=1):
            col = C_GREEN if chk["passed"] else C_RED
            chk_extras.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), col))
            chk_extras.append(("FONTNAME",  (0, row_idx), (0, row_idx), "Helvetica-Bold"))
        chk_tbl.setStyle(tbl_style(chk_extras))
        story.append(chk_tbl)
        story.append(Spacer(1, 0.25 * cm))

    # ── Evidence sources ──────────────────────────────────────────────────────
    sources = report.get("sources", [])
    if sources:
        story.append(PageBreak())
        story.append(Paragraph("Evidence Sources", h2))
        src_data = [["File", "Type", "Source"]]
        for s in sources:
            src = s.get("source", "local")
            src_label = "GitHub" if "github" in src else "Local"
            src_data.append([s.get("file", "?"), s.get("type", "?"), src_label])
        src_tbl = Table(src_data, colWidths=[7*cm, 3*cm, 5*cm])
        src_tbl.setStyle(tbl_style())
        story.append(src_tbl)

    # ── Build ─────────────────────────────────────────────────────────────────
    doc.build(story)
    return buf.getvalue()
