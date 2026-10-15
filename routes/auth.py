from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from database.db import get_connection


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth"
)


# ============================================================
# LOGIN
# ============================================================

@auth_bp.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
def login():

    if session.get("user_id"):

        return redirect(
            url_for(
                "home"
            )
        )


    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )


        if not username or not password:

            flash(
                "Username and password are required.",
                "error"
            )

            return render_template(
                "login.html"
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
                    password_hash,
                    role,
                    status
                FROM users
                WHERE username = %s
                LIMIT 1
                """,
                (
                    username,
                )
            )

            user = cursor.fetchone()


            if not user:

                flash(
                    "Invalid username or password.",
                    "error"
                )

                return render_template(
                    "login.html"
                )


            user_id = user[0]
            db_username = user[1]
            email = user[2]
            password_hash = user[3]
            role = user[4]
            status = user[5]


            if status != "ACTIVE":

                flash(
                    "Your account is disabled.",
                    "error"
                )

                return render_template(
                    "login.html"
                )


            if not check_password_hash(
                password_hash,
                password
            ):

                flash(
                    "Invalid username or password.",
                    "error"
                )

                return render_template(
                    "login.html"
                )


            session.clear()

            session["user_id"] = user_id

            session["username"] = (
                db_username
            )

            session["email"] = email

            session["role"] = role

            session.permanent = True


            return redirect(
                url_for(
                    "home"
                )
            )


        except Exception as e:

            print(
                "Login error:",
                e
            )

            flash(
                "Login failed. Please try again.",
                "error"
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


    return render_template(
        "login.html"
    )


# ============================================================
# REGISTER
# ============================================================

@auth_bp.route(
    "/register",
    methods=[
        "GET",
        "POST"
    ]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        if not username:

            flash(
                "Username is required.",
                "error"
            )

            return render_template(
                "register.html"
            )


        if not email:

            flash(
                "Email is required.",
                "error"
            )

            return render_template(
                "register.html"
            )


        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "error"
            )

            return render_template(
                "register.html"
            )


        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return render_template(
                "register.html"
            )


        password_hash = (
            generate_password_hash(
                password
            )
        )


        connection = None
        cursor = None


        try:

            connection = get_connection()

            cursor = connection.cursor()


            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE
                    username = %s
                    OR
                    email = %s
                LIMIT 1
                """,
                (
                    username,
                    email
                )
            )


            existing_user = (
                cursor.fetchone()
            )


            if existing_user:

                flash(
                    "Username or email already exists.",
                    "error"
                )

                return render_template(
                    "register.html"
                )


            cursor.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password_hash,
                    role,
                    status
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    'ANALYST',
                    'ACTIVE'
                )
                RETURNING id
                """,
                (
                    username,
                    email,
                    password_hash
                )
            )


            row = cursor.fetchone()

            connection.commit()


            print(
                "User created:",
                row[0]
                if row
                else None
            )


            flash(
                "Registration successful. Please login.",
                "success"
            )


            return redirect(
                url_for(
                    "auth.login"
                )
            )


        except Exception as e:

            print(
                "Registration error:",
                e
            )


            if connection:

                try:
                    connection.rollback()
                except Exception:
                    pass


            flash(
                "Registration failed.",
                "error"
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


    return render_template(
        "register.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@auth_bp.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for(
            "auth.login"
        )
    )