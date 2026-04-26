"""PDF exporter — SOC-style incident report a Tier-2 bank CISO would file.

Used by GET /export/pdf. Renders one or more `Incident` objects into a
single multi-page PDF using reportlab Platypus. Designed to look like a
deliverable a CISO would attach to a regulator notification, not a generic
data dump.

Layout per incident:
  1. Title band (incident id + severity badge colour)
  2. Detection metadata (timestamp, risk score, sectors)
  3. Executive summary paragraph (Incident.summary)
  4. Targeted assets (bullet list)
  5. MITRE ATT&CK techniques table (id → canonical name)
  6. Indicators of Compromise table
  7. Compliance breaches table with notification deadlines
  8. (single-incident export only) Appendix with full enriched-IOC JSON

Multiple incidents → cover sheet + one section per incident, separated by
PageBreak. reportlab handles auto-pagination inside each section.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from shared.schemas import Incident


# ──────────────────────────────────────────────────────────────────────────
# Static lookup tables (BATTLE_PLAN.md Appendix E + F)
# ──────────────────────────────────────────────────────────────────────────

_MITRE_NAMES = {
    "T1566": "Phishing",
    "T1078": "Valid Accounts",
    "T1190": "Exploit Public-Facing Application",
    "T1539": "Steal Web Session Cookie",
    "T1041": "Exfiltration over C2 Channel",
    "T1071": "Application Layer Protocol",
    "T1486": "Data Encrypted for Impact",
    "T1055": "Process Injection",
    "T1098": "Account Manipulation",
    "T1567": "Exfiltration to Cloud Storage",
    "T1021.002": "SMB / Admin Shares",
    "T1657": "Financial Theft",
}

_COMPLIANCE_DEADLINES = {
    "PCI-DSS Req.3": "Per acquirer contract — cardholder-data exposure",
    "PCI-DSS Req.10": "Audit cycle — logging / monitoring gap",
    "PCI-DSS Req.11": "Audit cycle — failure to detect intrusion",
    "SWIFT CSP CSCF 2.x": "24h to SWIFT — message anomaly / unauthorised access",
    "GDPR Art.33": "72h to regulator — personal-data breach",
    "Basel III ORR": "Per local Basel implementation — operational-risk event",
    "BCT Circular": "Per BCT circular — cyber-incident affecting bank operations",
}

_SEVERITY_COLOR = {
    "critical": colors.HexColor("#b71c1c"),
    "high": colors.HexColor("#e65100"),
    "medium": colors.HexColor("#f9a825"),
    "low": colors.HexColor("#9e9e9e"),
}


# ──────────────────────────────────────────────────────────────────────────
# Style helpers
# ──────────────────────────────────────────────────────────────────────────


def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontSize=18,
            textColor=colors.HexColor("#0d47a1"),
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#555555"),
            spaceAfter=12,
        ),
        "section": ParagraphStyle(
            "section",
            parent=base["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#0d47a1"),
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontSize=10,
            leading=13,
        ),
        "code": ParagraphStyle(
            "code",
            parent=base["Code"],
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#222222"),
        ),
    }


def _severity_badge(severity: str, risk_score: int) -> Table:
    """One-cell coloured table acting as a severity badge next to the title."""
    color = _SEVERITY_COLOR.get(severity.lower(), colors.grey)
    label = f"  {severity.upper()}  •  RISK {risk_score}/100  "
    tbl = Table([[label]], colWidths=[6 * cm], rowHeights=[0.7 * cm])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return tbl


def _table(data: List[List[str]], col_widths: List[float]) -> Table:
    """Standard zebra-striped data table."""
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d47a1")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return tbl


# ──────────────────────────────────────────────────────────────────────────
# Section builders
# ──────────────────────────────────────────────────────────────────────────


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _incident_section(incident: Incident, styles: dict, with_appendix: bool) -> list:
    """Return a list of Flowables for one incident."""
    flow: list = []

    flow.append(Paragraph(f"INCIDENT — {incident.id}", styles["title"]))
    flow.append(
        Paragraph(
            f"Detected: {incident.detected_at.isoformat()}  •  "
            f"Sectors: {', '.join(incident.targeted_sectors) or 'n/a'}",
            styles["subtitle"],
        )
    )
    flow.append(_severity_badge(incident.severity, incident.risk_score))
    flow.append(Spacer(1, 0.3 * cm))

    flow.append(Paragraph("Executive summary", styles["section"]))
    flow.append(Paragraph(incident.summary or "(no summary provided)", styles["body"]))

    flow.append(Paragraph("Targeted assets", styles["section"]))
    if incident.targeted_assets:
        for asset in incident.targeted_assets:
            flow.append(Paragraph(f"&bull;&nbsp; {asset}", styles["body"]))
    else:
        flow.append(Paragraph("(none recorded)", styles["body"]))

    flow.append(Paragraph("MITRE ATT&amp;CK techniques", styles["section"]))
    if incident.mitre_techniques:
        rows = [["Technique", "Name"]]
        for tid in incident.mitre_techniques:
            rows.append([tid, _MITRE_NAMES.get(tid, "(unknown — see ATT&CK reference)")])
        flow.append(_table(rows, [3 * cm, 13 * cm]))
    else:
        flow.append(Paragraph("(no techniques mapped)", styles["body"]))

    flow.append(Paragraph("Indicators of Compromise", styles["section"]))
    if incident.iocs:
        rows = [["Type", "Value", "Threat", "APT", "Conf.", "Geo"]]
        for ioc in incident.iocs:
            rows.append(
                [
                    ioc.type,
                    _truncate(ioc.value, 60),
                    ioc.threat_type,
                    ioc.apt_attribution or "—",
                    f"{ioc.confidence:.2f}",
                    ioc.geolocation or "—",
                ]
            )
        flow.append(
            _table(rows, [2.0 * cm, 6.0 * cm, 2.5 * cm, 2.0 * cm, 1.5 * cm, 2.0 * cm])
        )
    else:
        flow.append(Paragraph("(no IOCs attached)", styles["body"]))

    flow.append(Paragraph("Compliance breaches", styles["section"]))
    if incident.compliance_breaches:
        rows = [["Framework", "Notification window / context"]]
        for fw in incident.compliance_breaches:
            rows.append([fw, _COMPLIANCE_DEADLINES.get(fw, "Per regulator contract")])
        flow.append(_table(rows, [5 * cm, 11 * cm]))
    else:
        flow.append(Paragraph("(no compliance frameworks tagged)", styles["body"]))

    if with_appendix and incident.iocs:
        flow.append(PageBreak())
        flow.append(Paragraph("Appendix — full IOC payload (JSON)", styles["section"]))
        for ioc in incident.iocs:
            blob = json.dumps(json.loads(ioc.model_dump_json()), indent=2)
            blob_html = (
                blob.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\n", "<br/>")
                .replace(" ", "&nbsp;")
            )
            flow.append(Paragraph(blob_html, styles["code"]))
            flow.append(Spacer(1, 0.2 * cm))

    return flow


def _cover(incidents: List[Incident], styles: dict) -> list:
    """Cover sheet for a multi-incident portfolio export."""
    now = datetime.now(timezone.utc).isoformat()
    flow: list = [
        Paragraph("BANQUE ATLAS", styles["title"]),
        Paragraph("Incident Response Portfolio", styles["subtitle"]),
        Spacer(1, 0.5 * cm),
        Paragraph(f"Generated: {now}", styles["body"]),
        Paragraph(f"Incidents in this report: {len(incidents)}", styles["body"]),
        Spacer(1, 0.5 * cm),
    ]
    rows = [["Incident", "Severity", "Risk", "Detected"]]
    for inc in incidents:
        rows.append(
            [
                inc.id,
                inc.severity.upper(),
                str(inc.risk_score),
                inc.detected_at.isoformat(),
            ]
        )
    flow.append(_table(rows, [6 * cm, 3 * cm, 2 * cm, 5 * cm]))
    flow.append(PageBreak())
    return flow


# ──────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────


def render(incidents: List[Incident]) -> bytes:
    """Render the incidents into a PDF byte-string ready for download.

    Single incident → cover-less detailed report with appendix.
    Multiple incidents → cover sheet + summary section per incident, no
    per-incident appendix to keep the document size manageable.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title="Banque Atlas — Incident Response Report",
        author="CYBERIA Threat Intelligence Platform",
    )
    styles = _styles()

    flow: list = []
    if not incidents:
        flow.append(Paragraph("BANQUE ATLAS", styles["title"]))
        flow.append(Paragraph("Incident Response Report", styles["subtitle"]))
        flow.append(Paragraph("No incidents to report.", styles["body"]))
    elif len(incidents) == 1:
        flow.extend(_incident_section(incidents[0], styles, with_appendix=True))
    else:
        flow.extend(_cover(incidents, styles))
        for i, incident in enumerate(incidents):
            flow.extend(_incident_section(incident, styles, with_appendix=False))
            if i < len(incidents) - 1:
                flow.append(PageBreak())

    doc.build(flow)
    return buf.getvalue()
