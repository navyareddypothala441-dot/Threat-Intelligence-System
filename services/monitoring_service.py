from database.db import get_connection
from services.alert_service import create_alert


RISK_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "SUSPICIOUS": 3,
    "HIGH": 4,
    "CRITICAL": 5
}


def should_create_alert(
    old_score,
    new_score,
    old_level,
    new_level
):

    try:
        old_score = int(old_score or 0)
    except Exception:
        old_score = 0

    try:
        new_score = int(new_score or 0)
    except Exception:
        new_score = 0

    old_level = (
        old_level
        or "LOW"
    ).upper()

    new_level = (
        new_level
        or "LOW"
    ).upper()

    score_difference = abs(
        new_score - old_score
    )

    level_changed = (
        old_level != new_level
    )

    became_more_dangerous = (
        RISK_ORDER.get(
            new_level,
            0
        )
        >
        RISK_ORDER.get(
            old_level,
            0
        )
    )

    if score_difference >= 20:
        return True

    if became_more_dangerous:
        return True

    if level_changed and new_level in [
        "HIGH",
        "CRITICAL"
    ]:
        return True

    return False


def monitor_watchlist():

    connection = None
    cursor = None

    checked = 0
    alerts_created = 0

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                ioc,
                ioc_type,
                last_risk_score,
                last_risk_level
            FROM watchlist
            WHERE status = 'ACTIVE'
            ORDER BY created_at ASC
            """
        )

        watched_items = cursor.fetchall()

        for item in watched_items:

            watchlist_id = item[0]
            ioc = item[1]
            ioc_type = item[2]

            old_risk_score = (
                item[3]
                or 0
            )

            old_risk_level = (
                item[4]
                or "LOW"
            )


            # ============================================
            # GET LATEST SAVED INVESTIGATION
            # ============================================

            cursor.execute(
                """
                SELECT
                    risk_score,
                    risk_level
                FROM investigations
                WHERE ioc = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (
                    ioc,
                )
            )

            latest = cursor.fetchone()

            if not latest:

                print(
                    "No recent investigation found:",
                    ioc
                )

                continue


            new_risk_score = (
                latest[0]
                or 0
            )

            new_risk_level = (
                latest[1]
                or "LOW"
            )


            checked += 1


            print(
                "Monitoring:",
                ioc,
                old_risk_score,
                old_risk_level,
                "->",
                new_risk_score,
                new_risk_level
            )


            # ============================================
            # CHANGE DETECTION
            # ============================================

            if should_create_alert(
                old_risk_score,
                new_risk_score,
                old_risk_level,
                new_risk_level
            ):

                message = (
                    f"Risk changed for {ioc}: "
                    f"{old_risk_score}/100 "
                    f"{old_risk_level} -> "
                    f"{new_risk_score}/100 "
                    f"{new_risk_level}"
                )

                success = create_alert(
                    ioc=ioc,
                    alert_type="RISK_CHANGE",
                    old_risk_score=old_risk_score,
                    new_risk_score=new_risk_score,
                    old_risk_level=old_risk_level,
                    new_risk_level=new_risk_level,
                    message=message
                )

                if success:

                    alerts_created += 1


            # ============================================
            # UPDATE WATCHLIST BASELINE
            # ============================================

            cursor.execute(
                """
                UPDATE watchlist
                SET
                    last_risk_score = %s,
                    last_risk_level = %s,
                    last_checked = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (
                    new_risk_score,
                    new_risk_level,
                    watchlist_id
                )
            )

            connection.commit()


        return {
            "checked": checked,
            "alerts_created": alerts_created
        }


    except Exception as e:

        print(
            "Monitoring service error:",
            e
        )

        if connection:

            try:
                connection.rollback()
            except Exception:
                pass

        return {
            "checked": checked,
            "alerts_created": alerts_created,
            "error": str(e)
        }

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