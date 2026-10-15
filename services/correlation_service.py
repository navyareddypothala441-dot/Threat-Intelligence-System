from database.db import get_connection


def _ensure_table():
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS
            ioc_relationships
            (
                id SERIAL PRIMARY KEY,

                source_ioc TEXT NOT NULL,

                related_ioc TEXT NOT NULL,

                related_type TEXT,

                relationship TEXT,

                source TEXT,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.commit()

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


def _insert_relationship(
    source_ioc,
    related_ioc,
    related_type,
    relationship,
    source
):
    if not related_ioc:
        return False

    connection = None
    cursor = None

    try:
        _ensure_table()

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id
            FROM ioc_relationships
            WHERE source_ioc = %s
            AND related_ioc = %s
            AND relationship = %s
            """,
            (
                source_ioc,
                related_ioc,
                relationship
            )
        )

        existing = cursor.fetchone()

        if existing:
            return False

        cursor.execute(
            """
            INSERT INTO
            ioc_relationships
            (
                source_ioc,
                related_ioc,
                related_type,
                relationship,
                source
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                source_ioc,
                related_ioc,
                related_type,
                relationship,
                source
            )
        )

        connection.commit()

        return True

    except Exception as e:
        print(
            "Relationship insert error:",
            e
        )

        if connection:
            connection.rollback()

        return False

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


def create_relationships_from_vt(
    ioc,
    vt_data
):
    if not isinstance(
        vt_data,
        dict
    ):
        return 0

    if "error" in vt_data:
        return 0

    count = 0

    # DNS records
    for record in vt_data.get(
        "last_dns_records",
        []
    ):
        if not isinstance(
            record,
            dict
        ):
            continue

        value = record.get(
            "value"
        )

        record_type = record.get(
            "type"
        )

        if not value:
            continue

        related_type = (
            "IP Address"
            if record_type
            in ["A", "AAAA"]
            else "Domain"
        )

        if _insert_relationship(
            source_ioc=ioc,
            related_ioc=str(value),
            related_type=related_type,
            relationship="resolves_to",
            source="VirusTotal"
        ):
            count += 1

    return count


def create_relationships_from_shodan(
    ioc,
    shodan_data
):
    if not isinstance(
        shodan_data,
        dict
    ):
        return 0

    if "error" in shodan_data:
        return 0

    count = 0

    for hostname in shodan_data.get(
        "hostnames",
        []
    ):
        if _insert_relationship(
            source_ioc=ioc,
            related_ioc=hostname,
            related_type="Domain",
            relationship="associated_with",
            source="Shodan"
        ):
            count += 1

    for domain in shodan_data.get(
        "domains",
        []
    ):
        if _insert_relationship(
            source_ioc=ioc,
            related_ioc=domain,
            related_type="Domain",
            relationship="associated_with",
            source="Shodan"
        ):
            count += 1

    for port in shodan_data.get(
        "ports",
        []
    ):
        if _insert_relationship(
            source_ioc=ioc,
            related_ioc=str(port),
            related_type="Port",
            relationship="exposes",
            source="Shodan"
        ):
            count += 1

    for vuln in shodan_data.get(
        "vulnerabilities",
        []
    ):
        if _insert_relationship(
            source_ioc=ioc,
            related_ioc=str(vuln),
            related_type="Vulnerability",
            relationship="has_vulnerability",
            source="Shodan"
        ):
            count += 1

    return count


def get_related_iocs(ioc):
    connection = None
    cursor = None

    try:
        _ensure_table()

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                source_ioc,
                related_ioc,
                related_type,
                relationship,
                source
            FROM ioc_relationships
            WHERE source_ioc = %s
            ORDER BY created_at DESC
            """,
            (
                ioc,
            )
        )

        rows = cursor.fetchall()

        relationships = []

        for row in rows:
            relationships.append({
                "source_ioc":
                    row[0],

                "related_ioc":
                    row[1],

                "related_type":
                    row[2],

                "relationship":
                    row[3],

                "source":
                    row[4]
            })

        return relationships

    except Exception as e:
        print(
            "Relationship retrieval error:",
            e
        )

        return []

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


def get_relationship_count(ioc):
    try:
        relationships = (
            get_related_iocs(
                ioc
            )
        )

        return len(
            relationships
        )

    except Exception:
        return 0