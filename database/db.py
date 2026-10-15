import psycopg2


DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "osint_threat_intelligence",
    "user": "postgres",
    "password": "2003"
}


def get_connection():
    return psycopg2.connect(**DB_CONFIG)