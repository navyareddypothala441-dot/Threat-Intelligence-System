import csv
import io
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(data):

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30
    )

    styles = getSampleStyleSheet()

    story = []

    title = Paragraph(
        "OSINT Threat Intelligence Report",
        styles["Title"]
    )

    story.append(title)
    story.append(Spacer(1, 15))

    info = [
        ["IOC", data.get("ioc", "N/A")],
        ["IOC Type", data.get("ioc_type", "N/A")],
        ["Risk Score", f"{data.get('risk_score', 0)}/100"],
        ["Risk Level", data.get("risk_level", "N/A")],
        ["Country", data.get("country", "N/A")],
        ["Region", data.get("region", "N/A")],
        ["City", data.get("city", "N/A")],
        ["ISP", data.get("isp", "N/A")],
        ["Organization", data.get("organization", "N/A")],
        ["ASN", data.get("asn", "N/A")],
        ["Latitude", data.get("latitude", "N/A")],
        ["Longitude", data.get("longitude", "N/A")],
        ["ML Prediction", data.get("ml_prediction", "N/A")],
        ["ML Confidence", data.get("ml_confidence", "N/A")],
        ["Created At", data.get("created_at", "N/A")],
    ]

    table = Table(
        info,
        colWidths=[130, 380]
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#101828")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (0, -1),
                colors.white
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(table)

    story.append(Spacer(1, 18))

    vt = data.get(
        "virustotal",
        {}
    )

    if vt:

        story.append(
            Paragraph(
                "VirusTotal Analysis",
                styles["Heading2"]
            )
        )

        vt_rows = [
            [
                "Malicious",
                vt.get("malicious", 0)
            ],
            [
                "Suspicious",
                vt.get("suspicious", 0)
            ],
            [
                "Harmless",
                vt.get("harmless", 0)
            ],
            [
                "Undetected",
                vt.get("undetected", 0)
            ],
            [
                "Reputation",
                vt.get("reputation", 0)
            ]
        ]

        vt_table = Table(
            vt_rows,
            colWidths=[130, 380]
        )

        vt_table.setStyle(
            TableStyle([
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#eaf4ff")
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    7
                )
            ])
        )

        story.append(vt_table)

    doc.build(story)

    buffer.seek(0)

    return buffer


def generate_csv_report(data):

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Field",
        "Value"
    ])

    rows = [
        ("IOC", data.get("ioc", "N/A")),
        ("IOC Type", data.get("ioc_type", "N/A")),
        ("Risk Score", data.get("risk_score", 0)),
        ("Risk Level", data.get("risk_level", "N/A")),
        ("Country", data.get("country", "N/A")),
        ("Region", data.get("region", "N/A")),
        ("City", data.get("city", "N/A")),
        ("ISP", data.get("isp", "N/A")),
        ("Organization", data.get("organization", "N/A")),
        ("ASN", data.get("asn", "N/A")),
        ("Latitude", data.get("latitude", "N/A")),
        ("Longitude", data.get("longitude", "N/A")),
        ("ML Prediction", data.get("ml_prediction", "N/A")),
        ("ML Confidence", data.get("ml_confidence", "N/A")),
        ("Created At", data.get("created_at", "N/A")),
    ]

    for row in rows:
        writer.writerow(row)

    vt = data.get(
        "virustotal",
        {}
    )

    if vt:

        writer.writerow([])
        writer.writerow([
            "VirusTotal",
            ""
        ])

        writer.writerow([
            "Malicious",
            vt.get("malicious", 0)
        ])

        writer.writerow([
            "Suspicious",
            vt.get("suspicious", 0)
        ])

        writer.writerow([
            "Harmless",
            vt.get("harmless", 0)
        ])

        writer.writerow([
            "Undetected",
            vt.get("undetected", 0)
        ])

        writer.writerow([
            "Reputation",
            vt.get("reputation", 0)
        ])

    return output.getvalue()