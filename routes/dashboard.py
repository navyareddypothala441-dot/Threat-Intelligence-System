from flask import Blueprint, render_template

from database.db import get_connection


dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/dashboard"
)


@dashboard_bp.route("/")
@dashboard_bp.route("")
def dashboard():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        # =====================================================
        # TOTAL INVESTIGATIONS
        # =====================================================

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM investigations
            """
        )

        total_investigations = (
            cursor.fetchone()[0]
        )


        # =====================================================
        # RISK COUNTS
        # =====================================================

        risk_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "SUSPICIOUS": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        cursor.execute(
            """
            SELECT
                risk_level,
                COUNT(*)
            FROM investigations
            GROUP BY risk_level
            """
        )

        for row in cursor.fetchall():

            risk_level = row[0]
            count = row[1]

            if risk_level in risk_counts:

                risk_counts[
                    risk_level
                ] = count


        # =====================================================
        # MAP DATA
        #
        # IMPORTANT:
        # DO NOT FILTER ONLY IP ADDRESS.
        #
        # Domain and URL investigations now also
        # contain latitude and longitude.
        # =====================================================

        cursor.execute(
            """
            SELECT
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
                risk_level
            FROM investigations
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
            ORDER BY created_at DESC
            """
        )

        map_rows = cursor.fetchall()

        map_data = []

        for row in map_rows:

            latitude = row[5]
            longitude = row[6]

            try:

                latitude = float(
                    latitude
                )

                longitude = float(
                    longitude
                )

            except (
                TypeError,
                ValueError
            ):

                continue

            map_data.append({

                "ioc": row[0],

                "ioc_type": row[1],

                "country": (
                    row[2]
                    or "Unknown"
                ),

                "region": (
                    row[3]
                    or "Unknown"
                ),

                "city": (
                    row[4]
                    or "Unknown"
                ),

                "latitude": latitude,

                "longitude": longitude,

                "isp": (
                    row[7]
                    or "Unknown"
                ),

                "organization": (
                    row[8]
                    or "Unknown"
                ),

                "asn": row[9],

                "risk_score": (
                    row[10]
                    or 0
                ),

                "risk_level": (
                    row[11]
                    or "LOW"
                ),
            })


        # =====================================================
        # RECENT INVESTIGATIONS
        # =====================================================

        cursor.execute(
            """
            SELECT
                ioc,
                ioc_type,
                country,
                city,
                risk_score,
                risk_level,
                created_at
            FROM investigations
            ORDER BY created_at DESC
            LIMIT 10
            """
        )

        rows = cursor.fetchall()

        recent_investigations = []

        for row in rows:

            recent_investigations.append({

                "ioc": row[0],

                "ioc_type": row[1],

                "country": row[2],

                "city": row[3],

                "risk_score": row[4],

                "risk_level": row[5],

                "created_at": row[6],
            })


        print(
            "Dashboard map markers:",
            len(map_data)
        )

        for item in map_data:

            print(
                "MAP:",
                item["ioc"],
                item["ioc_type"],
                item["latitude"],
                item["longitude"]
            )


        return render_template(

            "dashboard.html",

            total_investigations=(
                total_investigations
            ),

            risk_counts=risk_counts,

            map_data=map_data,

            recent_investigations=(
                recent_investigations
            ),
        )


    except Exception as e:

        print(
            "Dashboard error:",
            e
        )

        return render_template(

            "dashboard.html",

            total_investigations=0,

            risk_counts={
                "LOW": 0,
                "MEDIUM": 0,
                "SUSPICIOUS": 0,
                "HIGH": 0,
                "CRITICAL": 0,
            },

            map_data=[],

            recent_investigations=[],
        )


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