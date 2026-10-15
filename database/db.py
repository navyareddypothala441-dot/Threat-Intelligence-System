import os
import psycopg2


def get_connection():
    database_url = os.environ.get("DATABASE_URL")

    if database_url:
        # Render / production database
        return psycopg2.connect(database_url)

    # Local development database
    return psycopg2.connect(
        host="localhost",
        port=5432,
        database="osint_threat_intelligence",
        user="postgres",
        password="2003"
    )