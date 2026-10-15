from flask import Blueprint, render_template, redirect, url_for
from database.db import get_connection
from services.monitoring_service import monitor_watchlist


alerts_bp = Blueprint(
    "alerts",
    __name__,
    url_prefix="/alerts"
)


@alerts_bp.route("/")
@alerts_bp.route("")
def alerts():

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
                alert_type,
                old_risk_score,
                new_risk_score,
                old_risk_level,
                new_risk_level,
                message,
                status,
                created_at
            FROM alerts
            ORDER BY created_at DESC
            """
        )

        rows = cursor.fetchall()

        alert_items = []

        for row in rows:

            alert_items.append({
                "id": row[0],
                "ioc": row[1],
                "alert_type": row[2],
                "old_risk_score": row[3],
                "new_risk_score": row[4],
                "old_risk_level": row[5],
                "new_risk_level": row[6],
                "message": row[7],
                "status": row[8],
                "created_at": row[9]
            })

        return render_template(
            "alerts.html",
            alerts=alert_items
        )

    except Exception as e:

        print(
            "Alerts page error:",
            e
        )

        return render_template(
            "alerts.html",
            alerts=[]
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



@alerts_bp.route(
    "/run-monitoring",
    methods=["POST"]
)
def run_monitoring():

    result = monitor_watchlist()

    print(
        "Monitoring result:",
        result
    )

    return redirect(
        url_for(
            "alerts.alerts"
        )
    )



@alerts_bp.route(
    "/read/<int:alert_id>",
    methods=["POST"]
)
def mark_read(
    alert_id
):

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE alerts
            SET status = 'READ'
            WHERE id = %s
            """,
            (
                alert_id,
            )
        )

        connection.commit()

    except Exception as e:

        print(
            "Mark alert read error:",
            e
        )

        if connection:

            try:
                connection.rollback()
            except Exception:
                pass

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

    return redirect(
        url_for(
            "alerts.alerts"
        )
    )



@alerts_bp.route(
    "/delete/<int:alert_id>",
    methods=["POST"]
)
def delete_alert(
    alert_id
):

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM alerts
            WHERE id = %s
            """,
            (
                alert_id,
            )
        )

        connection.commit()

    except Exception as e:

        print(
            "Delete alert error:",
            e
        )

        if connection:

            try:
                connection.rollback()
            except Exception:
                pass

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

    return redirect(
        url_for(
            "alerts.alerts"
        )
    )