from database.db import get_connection


def create_alert(
    ioc,
    alert_type,
    old_risk_score,
    new_risk_score,
    old_risk_level,
    new_risk_level,
    message
):

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO alerts
            (
                ioc,
                alert_type,
                old_risk_score,
                new_risk_score,
                old_risk_level,
                new_risk_level,
                message,
                status
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                'UNREAD'
            )
            """,
            (
                ioc,
                alert_type,
                old_risk_score,
                new_risk_score,
                old_risk_level,
                new_risk_level,
                message
            )
        )

        connection.commit()

        print("Alert created:", ioc)

        return True

    except Exception as e:

        print("Create alert error:", e)

        if connection:

            try:
                connection.rollback()
            except Exception:
                pass

        return False

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