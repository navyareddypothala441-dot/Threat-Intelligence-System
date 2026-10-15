from flask import Blueprint, send_file, Response

from database.db import get_connection

from services.report_service import (
    generate_pdf_report,
    generate_csv_report
)


reports_bp = Blueprint(
    "reports",
    __name__,
    url_prefix="/reports"
)


def get_investigation_data(investigation_id):

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                ioc,
                ioc_type,
                country,
                region,
                city,
                latitude,
                longitude,
                isp,
                organization,
                asn,
                risk_score,
                risk_level,
                ml_prediction,
                ml_confidence,
                created_at
            FROM investigations
            WHERE id = %s
            LIMIT 1
            """,
            (
                investigation_id,
            )
        )

        row = cursor.fetchone()

        if not row:
            return None

        data = {
            "id": row[0],
            "ioc": row[1],
            "ioc_type": row[2],
            "country": row[3],
            "region": row[4],
            "city": row[5],
            "latitude": row[6],
            "longitude": row[7],
            "isp": row[8],
            "organization": row[9],
            "asn": row[10],
            "risk_score": row[11],
            "risk_level": row[12],

            # ML data from database
            "ml_prediction": (
                row[13]
                if row[13] is not None
                else "N/A"
            ),

            "ml_confidence": (
                row[14]
                if row[14] is not None
                else "N/A"
            ),

            "created_at": row[15],

            # VirusTotal details are not currently
            # stored in the investigations table
            "virustotal": {}
        }

        return data

    except Exception as e:

        print(
            "Report data error:",
            e
        )

        return None

    finally:

        if cursor:

            try:
                cursor.close()
            except Exception:
                pass

        if connection:

            try:
                connection.close()
            except Exception:
                pass


@reports_bp.route(
    "/pdf/<int:investigation_id>"
)
def download_pdf(investigation_id):

    data = get_investigation_data(
        investigation_id
    )

    if not data:

        return (
            "Investigation not found",
            404
        )

    pdf_buffer = generate_pdf_report(
        data
    )

    filename = (
        f"osint_report_{investigation_id}.pdf"
    )

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


@reports_bp.route(
    "/csv/<int:investigation_id>"
)
def download_csv(investigation_id):

    data = get_investigation_data(
        investigation_id
    )

    if not data:

        return (
            "Investigation not found",
            404
        )

    csv_data = generate_csv_report(
        data
    )

    filename = (
        f"osint_report_{investigation_id}.csv"
    )

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f"attachment; filename={filename}"
        }
    )