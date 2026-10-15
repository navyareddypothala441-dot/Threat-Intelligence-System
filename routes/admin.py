from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from database.db import get_connection


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin"
)


def admin_required():

    return (
        session.get("user_id")
        and
        session.get("role") == "ADMIN"
    )


@admin_bp.route("/users")
def users():

    if not admin_required():

        flash(
            "Admin access required.",
            "error"
        )

        return redirect(
            url_for("home")
        )


    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                username,
                email,
                role,
                status,
                created_at
            FROM users
            ORDER BY created_at DESC
            """
        )

        rows = cursor.fetchall()

        user_items = []

        for row in rows:

            user_items.append({
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "role": row[3],
                "status": row[4],
                "created_at": row[5]
            })


        return render_template(
            "admin_users.html",
            users=user_items
        )


    except Exception as e:

        print(
            "Admin users error:",
            e
        )

        return render_template(
            "admin_users.html",
            users=[]
        )


    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


@admin_bp.route(
    "/role/<int:user_id>",
    methods=["POST"]
)
def change_role(user_id):

    if not admin_required():

        return redirect(
            url_for("home")
        )


    new_role = request.form.get(
        "role",
        ""
    ).upper()


    if new_role not in [
        "ADMIN",
        "ANALYST"
    ]:

        return redirect(
            url_for(
                "admin.users"
            )
        )


    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE users
            SET role = %s
            WHERE id = %s
            """,
            (
                new_role,
                user_id
            )
        )

        connection.commit()


    except Exception as e:

        print(
            "Change role error:",
            e
        )

        if connection:
            connection.rollback()


    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


    return redirect(
        url_for(
            "admin.users"
        )
    )


@admin_bp.route(
    "/status/<int:user_id>",
    methods=["POST"]
)
def change_status(user_id):

    if not admin_required():

        return redirect(
            url_for("home")
        )


    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT status
            FROM users
            WHERE id = %s
            """,
            (
                user_id,
            )
        )

        row = cursor.fetchone()

        if not row:

            return redirect(
                url_for(
                    "admin.users"
                )
            )


        current_status = row[0]

        new_status = (
            "DISABLED"
            if current_status == "ACTIVE"
            else "ACTIVE"
        )


        cursor.execute(
            """
            UPDATE users
            SET status = %s
            WHERE id = %s
            """,
            (
                new_status,
                user_id
            )
        )

        connection.commit()


    except Exception as e:

        print(
            "Change status error:",
            e
        )

        if connection:
            connection.rollback()


    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


    return redirect(
        url_for(
            "admin.users"
        )
    )