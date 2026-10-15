from flask import Blueprint, render_template, request, redirect, url_for, flash
from database.db import get_connection


watchlist_bp = Blueprint(
    "watchlist",
    __name__,
    url_prefix="/watchlist"
)


# ============================================================
# SHOW WATCHLIST
# ============================================================

@watchlist_bp.route("/")
@watchlist_bp.route("")
def watchlist():

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
                status,
                last_risk_score,
                last_risk_level,
                last_checked,
                created_at
            FROM watchlist
            ORDER BY created_at DESC
            """
        )

        rows = cursor.fetchall()

        items = []

        for row in rows:

            items.append({

                "id": row[0],

                "ioc": row[1],

                "ioc_type": row[2],

                "status": row[3],

                "last_risk_score": row[4],

                "last_risk_level": row[5],

                "last_checked": row[6],

                "created_at": row[7],

            })

        return render_template(
            "watchlist.html",
            watchlist_items=items
        )

    except Exception as e:

        print(
            "Watchlist error:",
            e
        )

        return render_template(
            "watchlist.html",
            watchlist_items=[]
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



# ============================================================
# ADD IOC TO WATCHLIST
# ============================================================

@watchlist_bp.route(
    "/add",
    methods=["POST"]
)
def add_to_watchlist():

    ioc = request.form.get(
        "ioc",
        ""
    ).strip()

    ioc_type = request.form.get(
        "ioc_type",
        "Unknown"
    ).strip()

    risk_score = request.form.get(
        "risk_score",
        0
    )

    risk_level = request.form.get(
        "risk_level",
        "LOW"
    ).strip()


    if not ioc:

        return redirect(
            url_for(
                "watchlist.watchlist"
            )
        )


    try:

        risk_score = int(
            float(
                risk_score
            )
        )

    except Exception:

        risk_score = 0


    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO watchlist
            (
                ioc,
                ioc_type,
                status,
                last_risk_score,
                last_risk_level,
                last_checked
            )
            VALUES
            (
                %s,
                %s,
                'ACTIVE',
                %s,
                %s,
                CURRENT_TIMESTAMP
            )

            ON CONFLICT (ioc)

            DO UPDATE SET

                ioc_type =
                    EXCLUDED.ioc_type,

                last_risk_score =
                    EXCLUDED.last_risk_score,

                last_risk_level =
                    EXCLUDED.last_risk_level,

                last_checked =
                    CURRENT_TIMESTAMP
            """,
            (
                ioc,
                ioc_type,
                risk_score,
                risk_level
            )
        )

        connection.commit()

        print(
            "IOC added to watchlist:",
            ioc
        )

    except Exception as e:

        print(
            "Add watchlist error:",
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
            "watchlist.watchlist"
        )
    )



# ============================================================
# DELETE IOC FROM WATCHLIST
# ============================================================

@watchlist_bp.route(
    "/delete/<int:item_id>",
    methods=["POST"]
)
def delete_watchlist_item(
    item_id
):

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM watchlist
            WHERE id = %s
            """,
            (
                item_id,
            )
        )

        connection.commit()

    except Exception as e:

        print(
            "Delete watchlist error:",
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
            "watchlist.watchlist"
        )
    )



# ============================================================
# CHANGE ACTIVE / PAUSED STATUS
# ============================================================

@watchlist_bp.route(
    "/toggle/<int:item_id>",
    methods=["POST"]
)
def toggle_watchlist_status(
    item_id
):

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT status
            FROM watchlist
            WHERE id = %s
            """,
            (
                item_id,
            )
        )

        row = cursor.fetchone()

        if row:

            current_status = row[0]

            if current_status == "ACTIVE":

                new_status = "PAUSED"

            else:

                new_status = "ACTIVE"

            cursor.execute(
                """
                UPDATE watchlist
                SET status = %s
                WHERE id = %s
                """,
                (
                    new_status,
                    item_id
                )
            )

            connection.commit()

    except Exception as e:

        print(
            "Toggle watchlist error:",
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
            "watchlist.watchlist"
        )
    )