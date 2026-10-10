from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


RED = colors.HexColor("#E50914")
DARK_RED = colors.HexColor("#650000")
BLACK = colors.HexColor("#050505")
DARK = colors.HexColor("#101010")
GRAY = colors.HexColor("#666666")
LIGHT = colors.HexColor("#EEEEEE")


def severity_color(severity):
    severity = severity.upper()

    if severity == "CRITICAL":
        return colors.HexColor("#FF1E1E")
    if severity == "HIGH":
        return colors.HexColor("#D71920")
    if severity == "MEDIUM":
        return colors.HexColor("#FF8C00")
    if severity == "LOW":
        return colors.HexColor("#777777")

    return colors.HexColor("#555555")


def generate_pdf(scan):
    """
    Generate a professional VULN-X security assessment PDF.

    scan is expected to contain:
        target
        scan_type
        security_score
        status
        started_at
        completed_at
        findings
        ports
    """

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=f"VULN-X Security Report - {scan['target']}",
        author="VULN-X",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "VulnTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=28,
        leading=32,
        textColor=RED,
        alignment=TA_LEFT,
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=GRAY,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        textColor=RED,
        spaceBefore=12,
        spaceAfter=10,
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#333333"),
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=GRAY,
    )

    story = []

    # ---------------------------------------------------------
    # HEADER
    # ---------------------------------------------------------

    story.append(Paragraph("VULN-X", title_style))

    story.append(
        Paragraph(
            "INTELLIGENT VULNERABILITY SCANNER",
            subtitle_style,
        )
    )

    header_data = [
        ["SECURITY ASSESSMENT REPORT", ""],
        ["Target", str(scan["target"])],
        ["Scan Type", str(scan["scan_type"]).upper()],
        ["Status", str(scan["status"]).upper()],
        [
            "Scan Date",
            str(scan.get("completed_at") or datetime.utcnow()),
        ],
    ]

    header_table = Table(
        header_data,
        colWidths=[45 * mm, 120 * mm],
    )

    header_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), RED),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("SPAN", (0, 0), (-1, 0)),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F4F4F4")),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 1), (1, -1), "Helvetica"),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#333333")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(header_table)
    story.append(Spacer(1, 12))

    # ---------------------------------------------------------
    # SECURITY SCORE
    # ---------------------------------------------------------

    score = int(scan.get("security_score", 0))

    findings = scan.get("findings", [])
    
    assessment_failed = any(
        finding.get("title") == "Web service could not be assessed"
        for finding in findings
    )
    
    if assessment_failed:
        risk = "ASSESSMENT INCOMPLETE"
    elif score >= 90:
        risk = "SECURE"
    elif score >= 75:
        risk = "LOW RISK"
    elif score >= 50:
        risk = "MODERATE RISK"
    elif score >= 25:
        risk = "HIGH RISK"
    else:
        risk = "CRITICAL"

    story.append(Paragraph("SECURITY SCORE", heading_style))

    score_table = Table(
        [
            [
                Paragraph(
                    f"<b>{score}/100</b>",
                    ParagraphStyle(
                        "Score",
                        fontSize=30,
                        textColor=RED,
                        alignment=TA_CENTER,
                    ),
                ),
                Paragraph(
                    f"<b>{risk}</b>",
                    ParagraphStyle(
                        "Risk",
                        fontSize=16,
                        textColor=colors.HexColor("#333333"),
                        alignment=TA_CENTER,
                    ),
                ),
            ]
        ],
        colWidths=[70 * mm, 95 * mm],
        rowHeights=[25 * mm],
    )

    score_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F7F7")),
                ("BOX", (0, 0), (-1, -1), 1, RED),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story.append(score_table)

    # ---------------------------------------------------------
    # FINDING SUMMARY
    # ---------------------------------------------------------

    findings = scan.get("findings", [])

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    counts = {
        severity: sum(
            1
            for finding in findings
            if finding.get("severity", "").upper() == severity
        )
        for severity in severities
    }

    story.append(Paragraph("FINDING SUMMARY", heading_style))

    summary_data = [["Severity", "Count"]]

    for severity in severities:
        summary_data.append(
            [
                severity,
                str(counts[severity]),
            ]
        )

    summary_table = Table(
        summary_data,
        colWidths=[70 * mm, 95 * mm],
    )

    table_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]

    for row, severity in enumerate(severities, start=1):
        table_commands.append(
            (
                "TEXTCOLOR",
                (0, row),
                (0, row),
                severity_color(severity),
            )
        )
        table_commands.append(
            (
                "FONTNAME",
                (0, row),
                (0, row),
                "Helvetica-Bold",
            )
        )

    summary_table.setStyle(TableStyle(table_commands))

    story.append(summary_table)

    # ---------------------------------------------------------
    # OPEN PORTS
    # ---------------------------------------------------------

    story.append(Paragraph("PORT ANALYSIS", heading_style))

    ports = scan.get("ports", [])

    port_data = [
        ["Port", "Protocol", "State", "Service", "Risk"]
    ]

    for port in ports:
        port_data.append(
            [
                str(port.get("port", "")),
                str(port.get("protocol", "")),
                str(port.get("state", "")),
                str(port.get("service", "")),
                str(port.get("risk", "")),
            ]
        )

    if len(port_data) == 1:
        port_data.append(["-", "-", "NO DATA", "-", "-"])

    port_table = Table(
        port_data,
        colWidths=[
            20 * mm,
            25 * mm,
            30 * mm,
            45 * mm,
            30 * mm,
        ],
        repeatRows=1,
    )

    port_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.white,
                    colors.HexColor("#F7F7F7"),
                ]),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story.append(port_table)

    # ---------------------------------------------------------
    # FINDINGS
    # ---------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "VULNERABILITY FINDINGS",
            heading_style,
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No findings were recorded for this assessment.",
                body_style,
            )
        )

    for index, finding in enumerate(findings, start=1):

        severity = finding.get("severity", "INFO").upper()

        finding_header = Table(
            [
                [
                    Paragraph(
                        f"<b>{severity}</b>",
                        ParagraphStyle(
                            "Severity",
                            fontSize=9,
                            textColor=colors.white,
                        ),
                    ),
                    Paragraph(
                        f"<b>{index}. {finding.get('title', 'Finding')}</b>",
                        ParagraphStyle(
                            "FindingTitle",
                            fontSize=11,
                            textColor=colors.HexColor("#222222"),
                        ),
                    ),
                ]
            ],
            colWidths=[28 * mm, 137 * mm],
        )

        finding_header.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, 0),
                        severity_color(severity),
                    ),
                    (
                        "BACKGROUND",
                        (1, 0),
                        (1, 0),
                        colors.HexColor("#F2F2F2"),
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.HexColor("#CCCCCC"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                ]
            )
        )

        story.append(finding_header)
        story.append(Spacer(1, 5))

        details = [
            [
                Paragraph("<b>Category</b>", small_style),
                Paragraph(
                    str(finding.get("category", "N/A")),
                    body_style,
                ),
            ],
            [
                Paragraph("<b>Description</b>", small_style),
                Paragraph(
                    str(finding.get("description", "N/A")),
                    body_style,
                ),
            ],
            [
                Paragraph("<b>Evidence</b>", small_style),
                Paragraph(
                    str(finding.get("evidence", "N/A")),
                    body_style,
                ),
            ],
            [
                Paragraph("<b>Impact</b>", small_style),
                Paragraph(
                    str(finding.get("impact", "N/A")),
                    body_style,
                ),
            ],
            [
                Paragraph("<b>Recommendation</b>", small_style),
                Paragraph(
                    str(finding.get("recommendation", "N/A")),
                    body_style,
                ),
            ],
        ]

        if finding.get("reference"):
            details.append(
                [
                    Paragraph("<b>Reference</b>", small_style),
                    Paragraph(
                        str(finding["reference"]),
                        body_style,
                    ),
                ]
            )

        details_table = Table(
            details,
            colWidths=[35 * mm, 130 * mm],
        )

        details_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#DDDDDD")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F5F5F5")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )

        story.append(details_table)
        story.append(Spacer(1, 12))

    # ---------------------------------------------------------
    # DISCLAIMER
    # ---------------------------------------------------------

    story.append(Spacer(1, 10))

    disclaimer = """
    <b>Security Disclaimer:</b>
    VULN-X is intended for authorized defensive security assessment.
    Only scan systems that you own or have explicit permission to assess.
    Results are informational and should be validated by qualified security personnel.
    """

    story.append(
        Paragraph(
            disclaimer,
            ParagraphStyle(
                "Disclaimer",
                parent=body_style,
                fontSize=8,
                leading=12,
                textColor=colors.HexColor("#666666"),
                borderColor=colors.HexColor("#DDDDDD"),
                borderWidth=0.5,
                borderPadding=8,
                backColor=colors.HexColor("#F5F5F5"),
            ),
        )
    )

    # ---------------------------------------------------------
    # FOOTER
    # ---------------------------------------------------------

    def footer(canvas, doc):
        canvas.saveState()

        canvas.setStrokeColor(RED)
        canvas.setLineWidth(0.5)

        canvas.line(
            18 * mm,
            12 * mm,
            A4[0] - 18 * mm,
            12 * mm,
        )

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GRAY)

        canvas.drawString(
            18 * mm,
            7 * mm,
            "VULN-X | Intelligent Vulnerability Scanner",
        )

        canvas.drawRightString(
            A4[0] - 18 * mm,
            7 * mm,
            f"Page {doc.page}",
        )

        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=footer,
        onLaterPages=footer,
    )

    buffer.seek(0)

    return buffer