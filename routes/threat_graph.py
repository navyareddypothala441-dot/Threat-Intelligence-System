from flask import Blueprint, render_template
from database.db import get_connection


threat_graph_bp = Blueprint(
    "threat_graph",
    __name__,
    url_prefix="/threat-graph"
)


@threat_graph_bp.route("/")
@threat_graph_bp.route("")
def threat_graph():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        # =====================================================
        # GET IOC RELATIONSHIPS
        # =====================================================

        cursor.execute(
            """
            SELECT
                source_ioc,
                related_ioc,
                related_type,
                relationship,
                source
            FROM ioc_relationships
            ORDER BY created_at DESC
            LIMIT 500
            """
        )

        relationship_rows = cursor.fetchall()

        # =====================================================
        # GET INVESTIGATION RISK DATA
        # =====================================================

        cursor.execute(
            """
            SELECT
                ioc,
                ioc_type,
                risk_score,
                risk_level
            FROM investigations
            ORDER BY created_at DESC
            """
        )

        investigation_rows = cursor.fetchall()

        risk_lookup = {}

        for row in investigation_rows:

            ioc = row[0]

            # Keep most recent record
            if ioc not in risk_lookup:

                risk_lookup[ioc] = {
                    "ioc_type": row[1],
                    "risk_score": row[2] or 0,
                    "risk_level": row[3] or "UNKNOWN"
                }

        # =====================================================
        # CREATE GRAPH
        # =====================================================

        nodes = {}
        edges = []

        edge_number = 1

        for row in relationship_rows:

            source_ioc = row[0]
            related_ioc = row[1]
            related_type = row[2] or "Unknown"
            relationship = row[3] or "related_to"
            intel_source = row[4] or "Unknown"

            # =================================================
            # SOURCE NODE
            # =================================================

            if source_ioc not in nodes:

                source_info = risk_lookup.get(
                    source_ioc,
                    {}
                )

                nodes[source_ioc] = {
                    "id": source_ioc,
                    "label": source_ioc,
                    "ioc_type": source_info.get(
                        "ioc_type",
                        "IOC"
                    ),
                    "risk_score": source_info.get(
                        "risk_score",
                        0
                    ),
                    "risk_level": source_info.get(
                        "risk_level",
                        "UNKNOWN"
                    )
                }

            # =================================================
            # RELATED NODE
            # =================================================

            if related_ioc not in nodes:

                related_info = risk_lookup.get(
                    related_ioc,
                    {}
                )

                nodes[related_ioc] = {
                    "id": related_ioc,
                    "label": related_ioc,
                    "ioc_type": related_info.get(
                        "ioc_type",
                        related_type
                    ),
                    "risk_score": related_info.get(
                        "risk_score",
                        0
                    ),
                    "risk_level": related_info.get(
                        "risk_level",
                        "UNKNOWN"
                    )
                }

            # =================================================
            # EDGE
            # =================================================

            edges.append({
                "id": f"edge-{edge_number}",
                "source": source_ioc,
                "target": related_ioc,
                "relationship": relationship,
                "intel_source": intel_source
            })

            edge_number += 1

        graph_data = {
            "nodes": list(nodes.values()),
            "edges": edges
        }

        print(
            "Threat Graph Nodes:",
            len(graph_data["nodes"])
        )

        print(
            "Threat Graph Edges:",
            len(graph_data["edges"])
        )

        return render_template(
            "threat_graph.html",
            graph_data=graph_data
        )

    except Exception as e:

        print(
            "Threat graph error:",
            e
        )

        return render_template(
            "threat_graph.html",
            graph_data={
                "nodes": [],
                "edges": []
            }
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